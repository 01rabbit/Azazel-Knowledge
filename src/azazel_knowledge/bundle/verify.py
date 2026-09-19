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
"""

from __future__ import annotations

import hashlib
import json
import tarfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
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

DEFAULT_MAX_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_MAX_RATIO = 100
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


def _load_anchors(anchors_path: str | Path) -> tuple[int, dict[str, VerifyKey], frozenset[str]]:
    path = Path(anchors_path)
    with path.open("rb") as fh:
        doc = tomllib.load(fh)
    threshold = int(doc.get("threshold", 1))
    revoked = frozenset(doc.get("revoked", []))
    keys: dict[str, VerifyKey] = {}
    for key_id, hex_key in dict(doc.get("keys", {})).items():
        keys[key_id] = VerifyKey(bytes.fromhex(hex_key))
    return threshold, keys, revoked


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
) -> None:
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


def _safe_member(member: tarfile.TarInfo) -> str:
    name = member.name
    if name.startswith("/") or name.startswith("\\"):
        raise BundleVerifyError("BUNDLE_UNSAFE_MEMBER", f"absolute path in bundle: {name!r}")
    parts = Path(name).parts
    if ".." in parts or any(p == "" for p in parts):
        raise BundleVerifyError("BUNDLE_UNSAFE_MEMBER", f"unsafe path in bundle: {name!r}")
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
) -> VerifiedBundle:
    bundle_path = Path(bundle_path)
    staging_dir = Path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    size = bundle_path.stat().st_size
    if size > max_bundle_bytes:
        raise BundleVerifyError("BUNDLE_TOO_LARGE", f"bundle is {size} bytes, cap is {max_bundle_bytes}")

    manifest, sig_bytes = _read_manifest_and_signature(bundle_path, max_manifest_bytes)
    _validate_manifest_shape(manifest)

    threshold, keys, revoked = _load_anchors(anchors_path)
    sig_lines = _parse_signature_lines(sig_bytes)
    manifest_bytes = canonical_manifest_bytes(manifest)
    _check_signature_threshold(manifest_bytes, sig_lines, threshold, keys, revoked)

    last_imported_version = _read_last_imported_version(state_path)
    _check_anti_rollback(manifest, last_imported_version)

    file_paths = _extract_declared_files(
        bundle_path,
        manifest,
        staging_dir,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        max_ratio=max_ratio,
    )
    return VerifiedBundle(manifest=manifest, staging_dir=staging_dir, file_paths=file_paths)
