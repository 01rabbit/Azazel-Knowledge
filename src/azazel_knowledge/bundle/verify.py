"""Offline bundle verification (design doc S6/S7, F-1, F-7).

Bundle layout (a Phase-1 simplification: sync-offline.md's example names
the artifact `.tar.zst`; zstd is not in the Python 3.11 standard library,
so this implementation uses gzip and names bundles `.tar.gz` -- the
manifest's `compression` field records this honestly rather than lying
about the container format):

    manifest.json   # must be the first tar member
    manifest.sig    # must be the second tar member; one or more lines
                     # of "<key_id>:<hex_signature>"
    tables/<table>.jsonl   # full bundle: one JSONL dump per intel table
    deltas/<table>.jsonl   # differential bundle: {"op": "upsert"|"delete", "row": {...}}

Trust never comes from inside the bundle. Active keys, the signature
threshold, and revocations are read exclusively from an `anchors.toml`
path supplied by the caller; the anti-rollback watermark is read
exclusively from a `state.toml` path supplied by the caller (F-7). A
manifest that embeds any field shaped like those trust documents, or
that names a local-tier table, hard-aborts before a single content byte
is written to disk (F-1).

Member names are unique within a bundle: a repeated name aborts with
``BUNDLE_DUPLICATE_MEMBER`` before the second copy is extracted. The
per-member hash check would already stop a *differing* duplicate from
substituting content, but only after writing it, and an identical
duplicate would pass unremarked; the explicit control states the
property instead of leaving it to be inferred.

Uniqueness is only meaningful if two names cannot denote one file, so
member names must also be canonical: anything that is not already its
own ``posixpath.normpath`` aborts with ``BUNDLE_UNSAFE_MEMBER``. Without
that, ``tables/x.jsonl`` and ``tables/./x.jsonl`` are two keys for the
duplicate guard and for ``manifest.files`` but one path on disk, and a
manifest could declare an honest digest for one and a substituted digest
for the other while a single, substituted file lands in staging.

Before any of the trust gates run, the manifest must declare a bundle
**format** version this reader knows how to read. That is a different
question from every other gate here: the others ask whether a document
this reader understands is acceptable, while compatibility asks whether
it is a document this reader understands at all. Asking it first is what
makes an incompatible artifact report as ``BUNDLE_FORMAT_UNSUPPORTED``
rather than as whichever later gate happens to trip over a field a
future format moved, renamed, or gave a new meaning -- a misleading code
is worse than a refusal, because it sends the operator after the wrong
problem. See ``_check_format_compatibility`` for what an absent field
means and why.

The number of members is capped as well (``DEFAULT_MAX_MEMBERS``). The
byte caps below bound how much data lands in staging but say nothing
about how many *files* do, and each declared file costs a
``mkdir -p`` plus a create. An 8 MiB manifest can name on the order of
10**5 files whose bytes sum to almost nothing, which is an inode
exhaustion primitive rather than a disk one, so it needs a count cap of
its own rather than a tighter byte cap.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import tarfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

LOCAL_TIER_TABLES: frozenset[str] = frozenset(
    {
        "reaction",
        "reaction_trust_event",
        "advisory_log",
        "observation",
        "observation_stats",
        "reputation",
        "edge_reported_ioc",
        "pattern",
        "pattern_index",
        "rule_draft",
        "bundle_state",
        "api_client",
        "feed_quarantine",
        "local_meta",
    }
)

_TRUST_ANCHOR_FIELDS: frozenset[str] = frozenset(
    {"threshold", "keys", "revoked", "anchors", "trust"}
)
_ROLLBACK_STATE_FIELDS: frozenset[str] = frozenset(
    {"last_imported_version", "last_import_at", "last_bundle_sha256", "needs_full_rebaseline"}
)
_FORBIDDEN_MANIFEST_FIELDS: frozenset[str] = _TRUST_ANCHOR_FIELDS | _ROLLBACK_STATE_FIELDS

MANIFEST_MEMBER = "manifest.json"
SIGNATURE_MEMBER = "manifest.sig"

#: The manifest field carrying the bundle *format* version. This is not
#: `bundle_version`, which is the monotonic content counter the anti-rollback
#: gate compares against the watermark: two bundles of the same format differ
#: in `bundle_version` on every rebuild, and a change of format is expected to
#: happen a handful of times in the artifact's life, if ever.
MANIFEST_FORMAT_FIELD = "bundle_format_version"

#: The format this builder emits.
BUNDLE_FORMAT_VERSION = 1

#: The format a manifest that carries no `bundle_format_version` is taken to
#: be. See `_check_format_compatibility` for the argument.
IMPLICIT_BUNDLE_FORMAT_VERSION = 1

#: The inclusive range of formats this reader can read.
MIN_SUPPORTED_BUNDLE_FORMAT = 1
MAX_SUPPORTED_BUNDLE_FORMAT = 1

DEFAULT_MAX_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_MAX_RATIO = 100

#: Total tar members a bundle may contain, the two metadata members included.
#:
#: Chosen from what the builders in this repository can actually emit, not from
#: a round number. `tools/bundle_build.py build` emits one member per eligible
#: intel table -- 12 in the current schema (`attack_mitigation`,
#: `attack_relation`, `attack_technique`, `engage_activity`,
#: `engage_attack_map`, `feed_state`, `ioc`, `ioc_cidr`, `ioc_source`, `kev`,
#: `sigma_rule_corpus`, `yara_rule_corpus`) -- plus `manifest.json` and
#: `manifest.sig`: 14. `build-lite` is bounded by `LiteCeilings.max_datasets`,
#: at most 12 under `knowledge-lite-32g`, so 14 there too. 256 is roughly 18x
#: the largest artifact either builder can produce, which leaves room for the
#: intel schema to more than double before a legitimate bundle came near the
#: cap -- and a schema that grew past ~250 tables is an event that deserves a
#: deliberate decision here rather than a cap quietly sized to never fire.
#:
#: The margin sits on the reader's side of the contract, as ADR-0015 D3 puts
#: the per-dataset byte ceiling below `DEFAULT_MAX_FILE_BYTES` for the same
#: reason: a reader may tighten later without invalidating bundles already
#: signed, whereas a builder that outgrew the reader would have signed
#: artifacts no conforming reader accepts.
DEFAULT_MAX_MEMBERS = 256

#: How deep a member's path may be, counted in components.
#:
#: `DEFAULT_MAX_MEMBERS` bounds how many *files* a bundle may declare; it does
#: not bound how many *directories* extracting them creates. Extraction runs
#: `dest_path.parent.mkdir(parents=True)`, which creates one directory per
#: component, so a single declared member named `a/b/c/.../x.jsonl` with two-
#: character components and a name a few million characters long produces
#: directories on the order of millions -- an inode bomb the member cap does
#: not touch, because it is one member. Capping depth is what closes it: at
#: most `DEFAULT_MAX_MEMBERS * DEFAULT_MAX_MEMBER_DEPTH` directories can be
#: created regardless of how the names are shaped.
#:
#: A real bundle is two deep (`tables/<table>.jsonl`, `deltas/<table>.jsonl`)
#: and the two metadata members are one, so 8 is four times the deepest shape
#: either builder emits. Like the member cap this is defence in depth against
#: a compromised or careless signer, not against an anonymous attacker:
#: extraction only runs on an artifact whose signature already verified.
DEFAULT_MAX_MEMBER_DEPTH = 8

#: How long a member name may be, in bytes.
#:
#: Depth alone closes the directory bomb, but a single component may still be
#: arbitrarily long, and the filesystem -- not this module -- is what refuses
#: it, with an `OSError` that carries no `BUNDLE_*` code for a caller to
#: dispatch on. This bound keeps that refusal inside the verifier's own error
#: vocabulary. `POSIX PATH_MAX` is commonly 4096 and a real member name is
#: around thirty bytes, so 1024 is generous while still bounded.
DEFAULT_MAX_MEMBER_NAME_BYTES = 1024

_COPY_CHUNK = 256 * 1024


class BundleVerifyError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class VerifiedBundle:
    manifest: dict
    staging_dir: Path
    file_paths: dict[str, Path] = field(default_factory=dict)


def canonical_manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class TrustAnchors:
    """Everything trust-related, read exclusively from `anchors.toml` (F-7).

    `required_signer_role`, `minimum_security_epoch` and
    `accepted_export_policy_digests` live here rather than in the manifest on
    purpose: a bundle must not be able to state which role may sign it, which
    epoch is acceptable, or which privacy policy the consumer will tolerate, or
    an attacker holding any valid key could simply declare itself eligible. The
    manifest may only *claim* an epoch and *record* the policy digest it was
    built under; whether those claims are good enough is decided locally.
    """

    threshold: int
    keys: dict[str, VerifyKey]
    revoked: frozenset[str]
    key_roles: dict[str, str]
    required_signer_role: str | None
    minimum_security_epoch: int | None
    accepted_export_policy_digests: frozenset[str] | None


def _load_anchors(anchors_path: str | Path) -> TrustAnchors:
    path = Path(anchors_path)
    with path.open("rb") as fh:
        doc = tomllib.load(fh)
    keys: dict[str, VerifyKey] = {}
    for key_id, hex_key in dict(doc.get("keys", {})).items():
        keys[key_id] = VerifyKey(bytes.fromhex(hex_key))

    required_role = doc.get("required_signer_role")
    if required_role is not None and (not isinstance(required_role, str) or not required_role):
        raise BundleVerifyError(
            "BUNDLE_ANCHORS_INVALID", "required_signer_role must be a non-empty string when present"
        )
    minimum_epoch = doc.get("minimum_security_epoch")
    if minimum_epoch is not None and (not isinstance(minimum_epoch, int) or isinstance(minimum_epoch, bool)):
        raise BundleVerifyError(
            "BUNDLE_ANCHORS_INVALID", "minimum_security_epoch must be an integer when present"
        )

    accepted_policies = doc.get("accepted_export_policy_digests")
    if accepted_policies is not None:
        if (
            not isinstance(accepted_policies, list)
            or not accepted_policies
            or not all(isinstance(digest, str) and digest for digest in accepted_policies)
        ):
            raise BundleVerifyError(
                "BUNDLE_ANCHORS_INVALID",
                "accepted_export_policy_digests must be a non-empty list of non-empty strings "
                "when present",
            )
        accepted_policies = frozenset(accepted_policies)

    return TrustAnchors(
        threshold=int(doc.get("threshold", 1)),
        keys=keys,
        revoked=frozenset(doc.get("revoked", [])),
        key_roles={str(k): str(v) for k, v in dict(doc.get("key_roles", {})).items()},
        required_signer_role=required_role,
        minimum_security_epoch=minimum_epoch,
        accepted_export_policy_digests=accepted_policies,
    )


def _read_last_imported_version(state_path: str | Path) -> int:
    path = Path(state_path)
    if not path.exists():
        return 0
    with path.open("rb") as fh:
        doc = tomllib.load(fh)
    return int(doc.get("last_imported_version", 0))


def _parse_signature_lines(raw: bytes) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            raise BundleVerifyError("BUNDLE_SIGNATURE_MALFORMED", f"malformed signature line: {line!r}")
        key_id, _, hex_sig = line.partition(":")
        lines.append((key_id.strip(), hex_sig.strip()))
    return lines


def _check_signature_threshold(
    manifest_bytes: bytes,
    sig_lines: list[tuple[str, str]],
    threshold: int,
    keys: dict[str, VerifyKey],
    revoked: frozenset[str],
) -> set[str]:
    signer_key_ids = {key_id for key_id, _ in sig_lines}
    revoked_signers = signer_key_ids & revoked
    if revoked_signers:
        raise BundleVerifyError(
            "BUNDLE_REVOKED_SIGNER", f"bundle signed by revoked key(s): {sorted(revoked_signers)}"
        )
    verified_key_ids: set[str] = set()
    for key_id, hex_sig in sig_lines:
        verify_key = keys.get(key_id)
        if verify_key is None:
            continue
        try:
            signature = bytes.fromhex(hex_sig)
        except ValueError:
            continue
        try:
            verify_key.verify(manifest_bytes, signature)
        except BadSignatureError:
            continue
        verified_key_ids.add(key_id)
    if len(verified_key_ids) < threshold:
        raise BundleVerifyError(
            "BUNDLE_SIGNATURE_THRESHOLD_NOT_MET",
            f"only {len(verified_key_ids)} of required {threshold} signatures verified",
        )
    return verified_key_ids


def _check_signer_role(verified_key_ids: set[str], anchors: TrustAnchors) -> None:
    """Gate on *which* key signed, separately from whether the signature is valid.

    A cryptographically perfect signature from a key provisioned for another
    purpose -- a full-node bundle key signing a Lite artifact, say -- passes the
    threshold check and must still be refused here. Keeping this separate is the
    point: a role failure reports as a role failure rather than hiding inside a
    threshold count.

    A key with no declared role never satisfies a required role. Silence is not
    permission.
    """
    required = anchors.required_signer_role
    if required is None:
        return
    matching = {k for k in verified_key_ids if anchors.key_roles.get(k) == required}
    if len(matching) < anchors.threshold:
        raise BundleVerifyError(
            "BUNDLE_SIGNER_ROLE_NOT_PERMITTED",
            f"{len(matching)} of required {anchors.threshold} verified signature(s) carry role "
            f"{required!r}; signers present: "
            f"{sorted((k, anchors.key_roles.get(k)) for k in verified_key_ids)}",
        )


def _check_security_epoch(manifest: dict, anchors: TrustAnchors) -> None:
    """Gate on the artifact's security epoch, separately from its version.

    Anti-rollback compares version numbers and so cannot catch an artifact that
    is *newer* yet predates a security event -- a bundle built before a key
    compromise still has a higher bundle_version than everything before it. The
    epoch is the independent statement that such an artifact is no longer
    acceptable, however new and however correctly signed it is.
    """
    minimum = anchors.minimum_security_epoch
    if minimum is None:
        return
    declared = manifest.get("security_epoch")
    if declared is None:
        raise BundleVerifyError(
            "BUNDLE_SECURITY_EPOCH_MISSING",
            f"anchors require security_epoch >= {minimum} but the manifest declares none",
        )
    if not isinstance(declared, int) or isinstance(declared, bool):
        raise BundleVerifyError(
            "BUNDLE_SECURITY_EPOCH_INVALID", f"security_epoch must be an integer, got {declared!r}"
        )
    if declared < minimum:
        raise BundleVerifyError(
            "BUNDLE_SECURITY_EPOCH_TOO_LOW",
            f"bundle security_epoch {declared} is below the required minimum {minimum}",
        )


def _check_export_policy(manifest: dict, anchors: TrustAnchors) -> None:
    """Gate on the privacy policy the artifact was built under.

    `export_policy_digest` is enforced builder-side already, but only against
    the policy the *builder* was handed: `lite_select` refuses to sign content
    that disagrees with the digest recorded beside it. That answers "does this
    artifact describe the rules that produced it", never "are those rules ones
    I accept". Knowledge signs whatever policy its operator supplies, so
    without this gate a consumer has no way to refuse an artifact built under a
    privacy policy it does not accept -- it can only take what it is sent.

    Inert unless the anchors name accepted digests, exactly as
    `required_signer_role` is, so every anchors file written before this gate
    existed keeps working untouched.

    An artifact recording *no* digest never satisfies a requirement. That is
    the same rule as the unroled key and the missing epoch, and for the same
    reason: absence is not a policy a consumer agreed to, and a bundle that
    could opt out of the gate by staying silent would make the gate worthless
    against exactly the artifact it exists to refuse.
    """
    accepted = anchors.accepted_export_policy_digests
    if accepted is None:
        return
    declared: str | None = None
    profile = manifest.get("profile")
    if isinstance(profile, dict):
        selection_inputs = profile.get("selection_inputs")
        if isinstance(selection_inputs, dict):
            value = selection_inputs.get("export_policy_digest")
            if isinstance(value, str) and value:
                declared = value
    if declared is None:
        raise BundleVerifyError(
            "BUNDLE_EXPORT_POLICY_MISSING",
            "anchors accept only export policy digest(s) "
            f"{sorted(accepted)} but the manifest records none at "
            "profile.selection_inputs.export_policy_digest",
        )
    if declared not in accepted:
        raise BundleVerifyError(
            "BUNDLE_EXPORT_POLICY_NOT_ACCEPTED",
            f"bundle was built under export policy digest {declared!r}, which is not among the "
            f"digest(s) these anchors accept: {sorted(accepted)}",
        )


def _check_format_compatibility(manifest: dict) -> None:
    """Gate on whether this reader can read the artifact's *format* at all.

    Versioned here is the shape of the document, not its contents:
    `bundle_version` counts content and moves on every build, while this moves
    only when the manifest or the layout changes incompatibly.

    **An absent field means format 1, not "unknown".** A manifest with no
    `bundle_format_version` can only have been written by a builder older than
    the field, and every such builder emitted exactly one format -- the one
    this reader still parses correctly. Refusing absence would therefore refuse
    every artifact currently in the field to guard against a format that cannot
    exist behind it, which is a breaking change bought for nothing.

    Treating absence as "compatible, skip the check" would be the opposite
    mistake, and this does not do that either: absence is *normalised to the
    concrete version 1* and then run through the same comparison as any
    declared version. So the gate keeps its teeth in both directions. A future
    format 2 must say so, and a reader that supports only 1 refuses it by this
    code rather than mis-parsing it; and on the day format 1 is retired,
    raising `MIN_SUPPORTED_BUNDLE_FORMAT` above 1 refuses the old unversioned
    artifacts automatically, because absence resolves to a value that is then
    out of range. Absence is never an exemption, only a default.
    """
    declared = manifest.get(MANIFEST_FORMAT_FIELD, IMPLICIT_BUNDLE_FORMAT_VERSION)
    if not isinstance(declared, int) or isinstance(declared, bool):
        raise BundleVerifyError(
            "BUNDLE_FORMAT_INVALID",
            f"{MANIFEST_FORMAT_FIELD} must be an integer, got {declared!r}",
        )
    if not MIN_SUPPORTED_BUNDLE_FORMAT <= declared <= MAX_SUPPORTED_BUNDLE_FORMAT:
        raise BundleVerifyError(
            "BUNDLE_FORMAT_UNSUPPORTED",
            f"bundle declares format version {declared}; this reader supports "
            f"{MIN_SUPPORTED_BUNDLE_FORMAT}..{MAX_SUPPORTED_BUNDLE_FORMAT}",
        )


def _check_member_count(manifest: dict, max_members: int) -> None:
    """Cap how many files a bundle may deliver, not just how many bytes.

    The byte caps bound staging's size; nothing bounds its inode count. Every
    declared file costs a `mkdir -p` and a create in `_extract_declared_files`,
    and a manifest within `DEFAULT_MAX_MANIFEST_BYTES` can name on the order of
    10**5 of them while declaring almost no content at all -- each one an empty
    file whose SHA-256 checks out. Exhausting a filesystem's inodes, or its
    directory-entry budget, is a denial of service the byte caps cannot see.

    Counted from `manifest.files` before extraction begins, so the refusal
    costs nothing and lands before the first byte is written. The tar cannot
    carry more members than this bounds: a member not in `manifest.files` is
    refused as undeclared and a repeated name is refused as a duplicate, so the
    physical member count can never exceed the declared count plus the two
    metadata members counted here.

    Worth stating plainly: extraction only runs on a bundle whose signature
    already verified, so this is a control against a compromised or careless
    signer, not against an anonymous one. It is defence in depth, which is why
    it belongs with the other caps rather than with the trust gates.
    """
    declared = manifest["files"]
    total_members = len(declared) + 2  # manifest.json and manifest.sig
    if total_members > max_members:
        raise BundleVerifyError(
            "BUNDLE_TOO_MANY_MEMBERS",
            f"bundle declares {len(declared)} file(s), {total_members} members in all, "
            f"which exceeds the cap of {max_members}",
        )


def _validate_manifest_shape(manifest: dict) -> None:
    if not isinstance(manifest, dict):
        raise BundleVerifyError("BUNDLE_MANIFEST_INVALID", "manifest.json is not a JSON object")
    shadowed = _FORBIDDEN_MANIFEST_FIELDS & manifest.keys()
    if shadowed:
        raise BundleVerifyError(
            "BUNDLE_SHADOWS_TRUST_ANCHOR", f"manifest embeds trust/state fields: {sorted(shadowed)}"
        )
    tables = manifest.get("tables", [])
    touched_local = LOCAL_TIER_TABLES & set(tables)
    if touched_local:
        raise BundleVerifyError(
            "BUNDLE_TOUCHES_LOCAL_TIER", f"bundle names local-tier table(s): {sorted(touched_local)}"
        )
    for required in ("bundle_version", "kind", "files"):
        if required not in manifest:
            raise BundleVerifyError("BUNDLE_MANIFEST_INVALID", f"manifest missing required field {required!r}")
    if manifest["kind"] not in ("full", "differential"):
        raise BundleVerifyError("BUNDLE_MANIFEST_INVALID", f"unknown kind {manifest['kind']!r}")
    # `files` is a name -> digest mapping, and both the member cap and the
    # extractor read it as one. Without this, a manifest declaring `files` as a
    # list or a string reaches `dict(...)` in `_extract_declared_files` and dies
    # with a bare TypeError/ValueError, which is neither a `BundleVerifyError`
    # nor a code a caller can act on. Refusing shape here keeps every rejection
    # on the one exception type callers already handle.
    if not isinstance(manifest["files"], dict):
        raise BundleVerifyError(
            "BUNDLE_MANIFEST_INVALID", f"manifest 'files' must be an object, got {type(manifest['files']).__name__}"
        )


def _check_anti_rollback(manifest: dict, last_imported_version: int) -> None:
    bundle_version = int(manifest["bundle_version"])
    if bundle_version <= last_imported_version:
        raise BundleVerifyError(
            "BUNDLE_VERSION_REGRESSION",
            f"bundle_version {bundle_version} <= last_imported_version {last_imported_version}",
        )
    if manifest["kind"] == "differential":
        base_version = manifest.get("base_version")
        if base_version is None or int(base_version) != last_imported_version:
            raise BundleVerifyError(
                "BUNDLE_BASE_MISMATCH",
                f"differential base_version {base_version!r} != last_imported_version {last_imported_version}",
            )


def _safe_member(
    member: tarfile.TarInfo,
    *,
    max_depth: int = DEFAULT_MAX_MEMBER_DEPTH,
    max_name_bytes: int = DEFAULT_MAX_MEMBER_NAME_BYTES,
) -> str:
    name = member.name
    if name.startswith("/") or name.startswith("\\"):
        raise BundleVerifyError("BUNDLE_UNSAFE_MEMBER", f"absolute path in bundle: {name!r}")
    parts = Path(name).parts
    if ".." in parts or any(p == "" for p in parts):
        raise BundleVerifyError("BUNDLE_UNSAFE_MEMBER", f"unsafe path in bundle: {name!r}")
    # A member name must already be canonical -- not merely normalisable into
    # something safe. `tables/./ioc.jsonl` clears every check above (its
    # `Path.parts` is `('tables', 'ioc.jsonl')`: no `..`, no empty part, not
    # absolute) and yet names the same file on disk as `tables/ioc.jsonl`. That
    # matters because three separate things key off "which file is this": the
    # duplicate-member guard keys on the raw tar name, the `manifest.files`
    # lookup keys on the raw tar name, and the filesystem keys on the path
    # after it has collapsed the `.`. An alias makes the first two see two
    # members while the third sees one, so a manifest can declare the honest
    # digest under the real name and a substituted digest under the alias, and
    # every gate passes while the bytes left in staging are the substituted
    # ones.
    #
    # Rejecting, rather than normalising and carrying on, is the point. After
    # this check the raw tar name, the manifest key and the staging path are
    # provably the *same string*, so those three views cannot disagree at all.
    # Normalising would close this one alias and leave the divergence itself
    # intact, available to the next shape nobody thought of.
    #
    # Tar member names are POSIX-style regardless of the host OS, so
    # `posixpath` is the right normaliser here; `os.path`/`Path` would rewrite
    # separators on Windows and change what counts as canonical. This does not
    # replace the `..`/absolute checks above and must not: `a/../b` normalises
    # to `b`, so a normpath comparison alone would wave it through.
    # `posixpath.normpath("")` is `"."`, so an empty name fails the comparison;
    # a bare `"."` normalises to itself and has to be named explicitly.
    # `tools/bundle_build.py` writes `tables/<table>.jsonl` and
    # `deltas/<table>.jsonl` literally, so no bundle a real builder produces is
    # refused here.
    if name == "." or posixpath.normpath(name) != name:
        raise BundleVerifyError("BUNDLE_UNSAFE_MEMBER", f"non-canonical path in bundle: {name!r}")
    # Depth and length are resource bounds rather than path-safety rules, so
    # they carry their own codes: a caller that wants to tell "this bundle is
    # shaped like an attack" from "this bundle is too big" can, and the tests
    # for each cannot pass because the other fired. They live here because
    # this is the one place that sees a member name before anything is created
    # from it.
    if len(name.encode("utf-8")) > max_name_bytes:
        raise BundleVerifyError(
            "BUNDLE_MEMBER_NAME_TOO_LONG",
            f"member name is {len(name.encode('utf-8'))} bytes, over the cap of {max_name_bytes}",
        )
    depth = len(PurePosixPath(name).parts)
    if depth > max_depth:
        raise BundleVerifyError(
            "BUNDLE_MEMBER_PATH_TOO_DEEP",
            f"member path is {depth} components deep, over the cap of {max_depth}: {name!r}",
        )
    if member.issym() or member.islnk():
        raise BundleVerifyError("BUNDLE_UNSAFE_MEMBER", f"link member not allowed: {name!r}")
    if member.isdev() or member.isfifo() or member.ischr() or member.isblk():
        raise BundleVerifyError("BUNDLE_UNSAFE_MEMBER", f"device/fifo member not allowed: {name!r}")
    if not member.isreg():
        raise BundleVerifyError("BUNDLE_UNSAFE_MEMBER", f"non-regular member not allowed: {name!r}")
    return name


def _read_capped(fileobj: BinaryIO, max_bytes: int, code: str) -> bytes:
    data = fileobj.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise BundleVerifyError(code, f"exceeds cap of {max_bytes} bytes")
    return data


def _read_manifest_and_signature(bundle_path: Path, max_manifest_bytes: int) -> tuple[dict, bytes]:
    with tarfile.open(bundle_path, mode="r|gz") as tar:
        first = tar.next()
        if first is None or first.name != MANIFEST_MEMBER:
            raise BundleVerifyError("BUNDLE_MANIFEST_MISSING", "manifest.json must be the first tar member")
        _safe_member(first)
        extracted = tar.extractfile(first)
        if extracted is None:
            raise BundleVerifyError("BUNDLE_MANIFEST_MISSING", "manifest.json has no content")
        manifest_bytes = _read_capped(extracted, max_manifest_bytes, "BUNDLE_MANIFEST_TOO_LARGE")

        second = tar.next()
        if second is None or second.name != SIGNATURE_MEMBER:
            raise BundleVerifyError("BUNDLE_MANIFEST_MISSING", "manifest.sig must be the second tar member")
        _safe_member(second)
        sig_extracted = tar.extractfile(second)
        if sig_extracted is None:
            raise BundleVerifyError("BUNDLE_MANIFEST_MISSING", "manifest.sig has no content")
        sig_bytes = _read_capped(sig_extracted, max_manifest_bytes, "BUNDLE_MANIFEST_TOO_LARGE")

    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise BundleVerifyError("BUNDLE_MANIFEST_INVALID", f"manifest.json is not valid JSON: {exc}") from exc
    return manifest, sig_bytes


def peek_manifest(bundle_path: str | Path) -> dict:
    """Read the manifest without any trust/rollback checks (for `inspect`)."""
    manifest, _ = _read_manifest_and_signature(Path(bundle_path), DEFAULT_MAX_MANIFEST_BYTES)
    return manifest


def _extract_declared_files(
    bundle_path: Path,
    manifest: dict,
    staging_dir: Path,
    *,
    max_file_bytes: int,
    max_total_bytes: int,
    max_ratio: int,
) -> dict[str, Path]:
    declared: dict[str, str] = dict(manifest.get("files", {}))
    bundle_size_on_disk = max(bundle_path.stat().st_size, 1)
    ratio_cap_bytes = bundle_size_on_disk * max_ratio
    total_bytes = 0
    seen: dict[str, Path] = {}
    # Every member name seen so far, including manifest.json/manifest.sig. A tar
    # may physically carry the same name twice; extraction would then overwrite
    # the first copy with the second. The per-member hash check below already
    # makes that non-substitutive -- it hashes what it just wrote and compares
    # against the single declared digest, so a differing duplicate fails
    # BUNDLE_FILE_HASH_MISMATCH -- but that is safety by accident. Reject the
    # duplicate up front, before any byte of the second copy is written, so the
    # property is stated rather than inferred.
    member_names: set[str] = set()

    with tarfile.open(bundle_path, mode="r|gz") as tar:
        for member in tar:
            if member.name in member_names:
                raise BundleVerifyError(
                    "BUNDLE_DUPLICATE_MEMBER", f"member appears more than once: {member.name!r}"
                )
            member_names.add(member.name)
            if member.name in (MANIFEST_MEMBER, SIGNATURE_MEMBER):
                continue
            name = _safe_member(member)
            if name not in declared:
                raise BundleVerifyError("BUNDLE_UNDECLARED_MEMBER", f"member not in manifest.files: {name!r}")
            source = tar.extractfile(member)
            if source is None:
                raise BundleVerifyError("BUNDLE_MANIFEST_INVALID", f"member has no content: {name!r}")

            dest_path = staging_dir / name
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            file_bytes = 0
            with dest_path.open("wb") as out:
                while True:
                    chunk = source.read(_COPY_CHUNK)
                    if not chunk:
                        break
                    file_bytes += len(chunk)
                    total_bytes += len(chunk)
                    if file_bytes > max_file_bytes:
                        raise BundleVerifyError("BUNDLE_DECOMPRESSION_BOMB", f"{name!r} exceeds per-file cap")
                    if total_bytes > max_total_bytes:
                        raise BundleVerifyError("BUNDLE_DECOMPRESSION_BOMB", "bundle exceeds total size cap")
                    if total_bytes > ratio_cap_bytes:
                        raise BundleVerifyError(
                            "BUNDLE_DECOMPRESSION_BOMB",
                            f"decompression ratio exceeds {max_ratio}:1",
                        )
                    digest.update(chunk)
                    out.write(chunk)

            actual_hash = digest.hexdigest()
            expected_hash = declared[name]
            if actual_hash != expected_hash:
                raise BundleVerifyError(
                    "BUNDLE_FILE_HASH_MISMATCH", f"{name!r} sha256 {actual_hash} != manifest {expected_hash}"
                )
            seen[name] = dest_path

    missing = set(declared) - set(seen)
    if missing:
        raise BundleVerifyError("BUNDLE_FILE_MISSING", f"manifest declares undelivered file(s): {sorted(missing)}")
    return seen


def verify_bundle(
    bundle_path: str | Path,
    anchors_path: str | Path,
    state_path: str | Path,
    staging_dir: str | Path,
    *,
    max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
    max_manifest_bytes: int = DEFAULT_MAX_MANIFEST_BYTES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_ratio: int = DEFAULT_MAX_RATIO,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> VerifiedBundle:
    bundle_path = Path(bundle_path)
    staging_dir = Path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    size = bundle_path.stat().st_size
    if size > max_bundle_bytes:
        raise BundleVerifyError("BUNDLE_TOO_LARGE", f"bundle is {size} bytes, cap is {max_bundle_bytes}")

    manifest, sig_bytes = _read_manifest_and_signature(bundle_path, max_manifest_bytes)
    _validate_manifest_shape(manifest)
    # Compatibility comes before trust, and before everything else that reads a
    # manifest field by name: the trust gates ask whether a document this
    # reader understands is acceptable, and there is no answer to that for a
    # document it does not understand. Run last, an artifact in a format that
    # moved `security_epoch` would be reported as `BUNDLE_SECURITY_EPOCH_MISSING`
    # and send the operator after a problem that is not there.
    _check_format_compatibility(manifest)

    anchors = _load_anchors(anchors_path)
    sig_lines = _parse_signature_lines(sig_bytes)
    manifest_bytes = canonical_manifest_bytes(manifest)
    # Five independent trust gates, plus the compatibility gate above and the
    # resource caps below. Passing one says nothing about the others, which is
    # why they are separate calls with separate error codes rather than one
    # combined "is this bundle acceptable" predicate:
    #   * the signature threshold -- did enough trusted keys sign it;
    #   * the signer role        -- were they keys provisioned for this purpose;
    #   * the security epoch     -- does it postdate the last security event;
    #   * the export policy      -- were the privacy rules ones we accept;
    #   * anti-rollback          -- is it newer than what we already imported.
    verified_key_ids = _check_signature_threshold(
        manifest_bytes, sig_lines, anchors.threshold, anchors.keys, anchors.revoked
    )
    _check_signer_role(verified_key_ids, anchors)
    _check_security_epoch(manifest, anchors)
    _check_export_policy(manifest, anchors)

    last_imported_version = _read_last_imported_version(state_path)
    _check_anti_rollback(manifest, last_imported_version)

    # A resource cap, not a trust gate, so it runs after the trust gates have
    # had their say -- but still before extraction opens its first file.
    _check_member_count(manifest, max_members)

    file_paths = _extract_declared_files(
        bundle_path,
        manifest,
        staging_dir,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        max_ratio=max_ratio,
    )
    return VerifiedBundle(manifest=manifest, staging_dir=staging_dir, file_paths=file_paths)
