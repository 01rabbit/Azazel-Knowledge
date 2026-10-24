#!/usr/bin/env python3
"""Emit deterministic Knowledge Lite fixtures for downstream consumers.

ADR-0015 Consequences 8 and **D7**: consumer fixtures are Azazel-Knowledge's
side of the boundary, while the fail-open behaviour they exercise belongs to
Azazel-Nexus and Azazel-Boot. Those repositories embed a read-only Lite reader
and must prove it keeps the node fully operational when knowledge is missing,
corrupt, or expired -- and they must prove it against what Knowledge *actually
emits*. A broken artifact forged in the consumer's own test suite would differ
from a real one in ways nobody can enumerate, and a reader that only ever sees
forgeries is a reader nobody has tested.

Emitting rather than committing a binary blob is deliberate. ADR-0015 D2 says
the same selection tuple reproduces the same bytes, so a fixture that is
*rebuilt* and compared re-proves that property every time it is used, while a
committed `.tar.gz` would only prove that a file was once checked in. Every
fixture below, negative ones included, is a deterministic function of this
file and `config/lite-export-policy.yaml`.

    python tools/lite_fixture.py emit --out DIR

writes into DIR:

    lite.tar.gz                        signed, valid Lite bundle
    anchors.toml                       the trust anchor it verifies under
    expected.json                      profile block, per-file SHA-256, row counts
    negative/corrupt-signature.tar.gz  fails the signature gate
    negative/corrupt-payload.tar.gz    fails the per-member digest gate
    negative/corrupt-truncated.tar.gz  fails the archive-decode gate
    negative/expired.tar.gz            verifies; every indicator in it is expired
    negative.json                      what each negative fixture is and where it fails

A consumer verifies `lite.tar.gz` against `anchors.toml` with its own reader,
checks what it read against `expected.json`, and then runs the same reader over
each entry in `negative.json` to prove it refuses each one at the stated gate
and keeps serving without knowledge.

**Why three shapes of "corrupt" and not one.** They fail at three different
gates, and which gate a consumer hit is the whole of the information:

* `corrupt-signature` fails **before** anything is read out of the archive.
  Nothing is written to staging. This is the trust gate: the artifact is
  well-formed and its content is intact, and it is refused anyway.
* `corrupt-payload` fails **after** bytes have already been written to
  staging. The manifest and its signature are untouched and still verify, so
  every trust gate passes and only the per-member digest catches the change.
  This is the one that proves staging must never be promoted on failure, and
  it is tampered *meaningfully*: a confidence value is raised, which is
  precisely what ADR-0015 D4 forbids ("bounding the data must not sharpen
  it").
* `corrupt-truncated` fails at the **container** gate, in the tar decoder,
  before the reader has an opinion about anything. The verifier wraps the
  decoder error as `BundleVerifyError` with code `BUNDLE_ARCHIVE_UNREADABLE`
  (the decoder error is kept as `__cause__`) -- see `negative.json`. A reader
  should still treat ANY exception from verification as a refusal, not only
  the verifier's own exception type.

**"Expired" is not a corruption.** It is a perfectly valid, correctly signed
artifact that passes every verification gate, and whose indicators have all
passed their `agg_next_expiry`. Expiry is not a property of the artifact and
has no manifest field: ADR-0015 D4 puts it per claim, evaluated by the
consumer against its own `query_as_of`, never against a timestamp baked in.
So the fixture cannot be "expired" by a filename, a header, or a build flag --
only by the expiry its rows carry. The reference rows in it do *not* expire,
on purpose: a consumer must withhold the expired indicators without discarding
the artifact wholesale.

**"Absent" is not a file.** It is the absence of one, and a consumer cannot
test it deterministically against a path that merely happens to be missing
today. So `negative.json` names a path this emitter guarantees it does not
write, and actively removes if something is there -- while the anchors beside
it do exist, so a consumer proving fail-open knows it is testing a missing
*artifact* and not a missing trust anchor.

**The signing key here is a fixture key and is published in this file on
purpose.** It exists so the fixture is reproducible byte-for-byte. It signs
nothing but fixture data and must never appear in a trust anchor outside a
test -- which is exactly why it is written here in the open rather than looking
like a secret someone might reuse.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sqlite3
import subprocess
import sys
import tarfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from nacl.signing import SigningKey  # noqa: E402

from azazel_knowledge.bundle.verify import peek_manifest  # noqa: E402
from azazel_knowledge.db.repository import apply_migrations  # noqa: E402

#: Fixture-only signing seed. Published deliberately -- see the module docstring.
FIXTURE_SIGNING_SEED_HEX = "00" * 31 + "2a"

#: Fixture-only alias key. Published for the same reason.
FIXTURE_ALIAS_KEY_HEX = "0123456789abcdef0123456789abcdef"

FIXTURE_SCOPE = "fixture-mission"
FIXTURE_AS_OF = "2026-09-19T00:00:00Z"
FIXTURE_PROFILE = "knowledge-lite-16g"

#: The policy this repository ships as its default export profile. The fixture
#: is built with it rather than with a policy of its own so that consumers
#: receive an artifact shaped by the rules Knowledge really applies, and so
#: that a change to the default profile is visible to them on the next rebuild.
#: A private fixture policy would be a second source of truth, free to drift
#: from the one that governs real exports.
DEFAULT_POLICY_PATH = _REPO_ROOT / "config" / "lite-export-policy.yaml"

#: Confidence carried by every fixture indicator, and the value
#: `corrupt-payload` raises. Both spellings are four characters wide so the
#: tamper is an in-place substitution: the tar stays structurally valid and the
#: *only* thing wrong with the artifact is that a member no longer matches its
#: declared digest.
FIXTURE_CONFIDENCE = "72.5"
TAMPERED_CONFIDENCE = "99.9"

#: Where the expired fixture's indicators expired. Far enough in the past that
#: no plausible consumer `query_as_of` makes them live again.
EXPIRED_AT = "2021-01-01T00:00:00Z"
LIVE_UNTIL = "2027-01-01T00:00:00Z"

#: Named once so `negative.json` and the emitter cannot disagree about it.
ABSENT_FIXTURE_PATH = "negative/absent-lite.tar.gz"

# Rows are written in a fixed order with fixed values; nothing here varies
# between runs or between machines.
_FIXTURE_IOCS = (
    ("ip", "203.0.113.10", "2026-09-18T00:00:00Z"),
    ("ip", "203.0.113.11", "2026-09-17T00:00:00Z"),
    ("domain", "example.invalid", "2026-09-16T00:00:00Z"),
    # Outside the 30-day window of FIXTURE_AS_OF: a consumer must not see it,
    # which is what makes the fixture prove freshness rather than merely carry
    # rows.
    ("ip", "203.0.113.99", "2025-01-01T00:00:00Z"),
)

#: Static reference rows. They carry no timestamp column, so the freshness
#: window does not apply to them, and the default policy's dataset-level
#: provenance says they do not expire on a clock. Their job in the fixture is
#: to give a consumer a second dataset -- and, in `expired.tar.gz`, content
#: that is still good while every indicator beside it has expired.
#: Two catalogue entries, one recent and one from 2019. The old one is the
#: point: `kev` is `freshness_exempt` in the default policy, so it must ship,
#: and a consumer that received only the recent one is looking at a windowed
#: catalogue that claims to be whole.
_FIXTURE_KEV: tuple[tuple[str, str, str], ...] = (
    ("CVE-2026-0001", "2026-09-10T00:00:00Z", "2026-10-01T00:00:00Z"),
    ("CVE-2019-0708", "2019-05-14T00:00:00Z", "2019-06-04T00:00:00Z"),
)

_FIXTURE_TECHNIQUES = (
    ("T1046", "Network Service Discovery", ["discovery"]),
    ("T1110", "Brute Force", ["credential-access"]),
)


def _write_source_db(path: Path, *, expiry: str) -> None:
    conn = sqlite3.connect(path)
    try:
        apply_migrations(conn, "intel")
        for kind, value, last_seen in _FIXTURE_IOCS:
            # Aggregated columns are populated because an IOC that has not been
            # through aggregation carries no expiry and no confidence, and so
            # cannot satisfy ADR-0015 D4. Such a row is refused rather than
            # exported without provenance, and a fixture built from
            # pre-aggregation rows would not represent anything exportable.
            conn.execute(
                "INSERT INTO ioc (type, value, first_seen, last_seen, agg_raw_confidence, "
                "agg_next_expiry, agg_computed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (kind, value, "2020-01-01T00:00:00Z", last_seen, float(FIXTURE_CONFIDENCE),
                 expiry, "2026-09-18T12:00:00Z"),
            )
        for cve_id, date_added, due_date in _FIXTURE_KEV:
            # KEV is in the shipped default policy and is declared
            # `freshness_exempt`, so the fixture carries an entry from well
            # outside the freshness window on purpose: a consumer checking this
            # artifact against `expected.json` is checking that the catalogue
            # ships whole rather than windowed.
            conn.execute(
                "INSERT INTO kev (cve_id, catalog_version, date_added, due_date, "
                "vendor_project, product, vulnerability_name, short_description, "
                "required_action) VALUES (?, 'fixture-2026.09', ?, ?, 'ExampleCorp', "
                "'ExampleProduct', 'Fixture vulnerability', 'fixture entry', 'not exported')",
                (cve_id, date_added, due_date),
            )
        for technique_id, name, tactics in _FIXTURE_TECHNIQUES:
            conn.execute(
                "INSERT INTO attack_technique (technique_id, name, tactics, attack_version) "
                "VALUES (?, ?, ?, 'fixture-v1')",
                (technique_id, name, json.dumps(tactics)),
            )
        conn.commit()
    finally:
        conn.close()


def _build_lite(*, source_db: Path, out: Path, work: Path) -> subprocess.CompletedProcess:
    alias_key_path = work / "alias.hex"
    alias_key_path.write_text(FIXTURE_ALIAS_KEY_HEX, encoding="utf-8")
    sign_key_path = work / "sign.hex"
    sign_key_path.write_text(FIXTURE_SIGNING_SEED_HEX, encoding="utf-8")
    if out.exists():
        out.unlink()
    return subprocess.run(
        [
            sys.executable,
            str(_REPO_ROOT / "tools" / "bundle_build.py"),
            "build-lite",
            "--source-db", str(source_db),
            "--out", str(out),
            "--version", "1",
            "--profile", FIXTURE_PROFILE,
            "--export-policy", str(DEFAULT_POLICY_PATH),
            "--alias-key-file", str(alias_key_path),
            "--alias-scope", FIXTURE_SCOPE,
            "--as-of", FIXTURE_AS_OF,
            "--intel-generation", "1",
            "--stats-generation", "1",
            "--attack-version", "fixture-v1",
            "--config-hash", "fixture-config-hash",
            "--security-epoch", "1",
            "--sign-key", str(sign_key_path),
        ],
        capture_output=True,
        text=True,
    )


# --- deterministic derivation of the negative fixtures ----------------------
#
# Each one is derived from the valid artifact's *decompressed tar*, edited, and
# re-gzipped with a zeroed header. Two of the three edits are in-place
# substitutions of equal length, so the tar structure is untouched and the
# artifact differs from the valid one only in the way the fixture's name
# claims. Rebuilding the tar member by member would risk a second, accidental
# difference in member metadata, and a fixture that fails for two reasons
# cannot prove which gate a reader hit.


def _gzip_bytes(data: bytes) -> bytes:
    buf = io.BytesIO()
    # `mtime=0` and an empty filename for the same reason the builder zeroes
    # them: a wall-clock stamp or an embedded path would make an otherwise
    # identical rebuild differ byte for byte.
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()


def _substitute_once(tar_bytes: bytes, old: bytes, new: bytes, what: str) -> bytes:
    """Replace `old` with `new` exactly once, refusing any change of length.

    An equal-length substitution keeps every tar header, offset and size valid.
    The assertions are not defensive noise: if the fixture data ever changes so
    that the needle is absent or appears twice, the emitter must stop rather
    than write a fixture that no longer does what its name says.
    """
    if len(old) != len(new):
        raise SystemExit(f"{what}: substitution must preserve length ({old!r} -> {new!r})")
    count = tar_bytes.count(old)
    if count != 1:
        raise SystemExit(f"{what}: expected exactly one occurrence of {old!r}, found {count}")
    return tar_bytes.replace(old, new, 1)


def _member_span(tar_bytes: bytes, predicate, *, last: bool = False) -> tuple[str, int, int]:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        matched = [m for m in tar.getmembers() if predicate(m)]
    if not matched:
        raise SystemExit("no tar member matched; the fixture layout has changed")
    member = matched[-1] if last else matched[0]
    return member.name, member.offset_data, member.size


def _is_content_member(member: tarfile.TarInfo) -> bool:
    return member.isreg() and member.name not in ("manifest.json", "manifest.sig")


def _corrupt_signature(tar_bytes: bytes) -> bytes:
    """Flip one hex digit of the signature, keeping the line well-formed.

    The key id is left alone on purpose. Corrupting *that* would fail as "no
    such key" rather than "this signature does not verify", which is a
    different statement about a different problem.
    """
    _, offset, size = _member_span(tar_bytes, lambda m: m.name == "manifest.sig")
    line = tar_bytes[offset:offset + size].decode("ascii")
    key_id, sep, hex_sig = line.strip().partition(":")
    if not sep:
        raise SystemExit("manifest.sig is not '<key_id>:<hex>'; the fixture layout has changed")
    flipped = hex_sig[:-1] + ("0" if hex_sig[-1] != "0" else "1")
    replacement = f"{key_id}:{flipped}\n".encode("ascii")
    if len(replacement) != size:
        raise SystemExit("corrupt-signature: replacement changed the member's length")
    return tar_bytes[:offset] + replacement + tar_bytes[offset + size:]


def _corrupt_payload(tar_bytes: bytes) -> bytes:
    """Raise a confidence inside `tables/ioc.jsonl`, leaving manifest and signature intact.

    A random byte flip would also fail the digest check. Raising a confidence
    is the tamper worth shipping, because it is the one ADR-0015 D4 singles
    out: a Lite artifact must never report a claim more confidently than the
    full node would. The manifest is untouched, so this artifact passes the
    format, signature, signer-role, epoch and anti-rollback gates and is caught
    only by the per-member digest.
    """
    # Every fixture indicator carries the same confidence, so the confidence
    # alone is not a unique needle. Each carries a distinct `last_seen`, and
    # the emitted JSONL is canonical (sorted keys, no spaces), which puts the
    # two adjacent -- so anchoring on the pair names exactly one row.
    anchor = f'"last_seen":"{_FIXTURE_IOCS[0][2]}"'
    return _substitute_once(
        tar_bytes,
        f'"agg_raw_confidence":{FIXTURE_CONFIDENCE},{anchor}'.encode("ascii"),
        f'"agg_raw_confidence":{TAMPERED_CONFIDENCE},{anchor}'.encode("ascii"),
        "corrupt-payload",
    )


def _corrupt_truncated(tar_bytes: bytes) -> tuple[bytes, str]:
    """Cut the tar stream part-way through its *last* content member.

    Truncating the *compressed* file at an arbitrary offset would be simpler
    and would be the wrong fixture: which gate it trips depends on where the
    deflate stream happens to break, so the same recipe over slightly different
    content can fail at the manifest, at the signature, or during extraction.
    Cutting at a structural offset instead makes the outcome a property of the
    fixture rather than of the compressor -- `manifest.json` and `manifest.sig`
    are always complete and always verify, and the cut is always inside the
    payload.

    The *last* member, so that every earlier member is complete and has already
    been staged and digest-checked when the decoder gives up. A reader can
    therefore be holding fully verified content and must still promote none of
    it.
    """
    name, offset, size = _member_span(
        tar_bytes, lambda m: _is_content_member(m) and m.size > 0, last=True
    )
    # An *empty* member would make `offset + size // 2` land exactly on a block
    # boundary, producing a shorter but perfectly well-formed archive that
    # decodes without complaint -- a "truncated" fixture that is not truncated.
    # That is not hypothetical: adding an empty dataset to the default policy
    # silently turned this fixture into a valid archive once. The predicate
    # above excludes empty members; the assertions below refuse to emit a
    # fixture that does not actually cut into content.
    cut = offset + size // 2
    if not offset < cut < offset + size:
        raise AssertionError(
            f"truncation offset {cut} does not fall inside member {name!r} "
            f"(data {offset}..{offset + size}); the fixture would not be truncated"
        )
    return tar_bytes[:cut], name


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_negative_index(out_dir: Path, paths: dict[str, Path], truncated_member: str) -> None:
    fixtures = [
        {
            "name": "corrupt-signature",
            "path": "negative/corrupt-signature.tar.gz",
            "exists": True,
            "sha256": _sha256(paths["corrupt-signature"]),
            "gate": "signature threshold",
            "expected_error_code": "BUNDLE_SIGNATURE_THRESHOLD_NOT_MET",
            "expected_exception": "BundleVerifyError",
            "verifies": False,
            "staging_written": False,
            "description": (
                "One hex digit of the ed25519 signature is flipped; the key id and the manifest "
                "are untouched, so the artifact is well-formed and its content is intact. It is "
                "refused on trust alone, before a single content byte is read out of the archive."
            ),
        },
        {
            "name": "corrupt-payload",
            "path": "negative/corrupt-payload.tar.gz",
            "exists": True,
            "sha256": _sha256(paths["corrupt-payload"]),
            "gate": "per-member content digest",
            "expected_error_code": "BUNDLE_FILE_HASH_MISMATCH",
            "expected_exception": "BundleVerifyError",
            "verifies": False,
            "staging_written": True,
            "description": (
                f"An indicator's agg_raw_confidence is raised from {FIXTURE_CONFIDENCE} to "
                f"{TAMPERED_CONFIDENCE} inside tables/ioc.jsonl. manifest.json and manifest.sig "
                "are untouched and still verify, so every trust gate passes and only the "
                "per-member SHA-256 catches it. The tampered bytes ARE written into the staging "
                "directory before the check fails: a reader must never promote staging on a "
                "failed verification. This is the tamper ADR-0015 D4 names -- bounding the data "
                "must not sharpen it."
            ),
        },
        {
            "name": "corrupt-truncated",
            "path": "negative/corrupt-truncated.tar.gz",
            "exists": True,
            "sha256": _sha256(paths["corrupt-truncated"]),
            "gate": "archive decode",
            "expected_error_code": "BUNDLE_ARCHIVE_UNREADABLE",
            "expected_exception": "BundleVerifyError",
            "verifies": False,
            "staging_written": True,
            "truncated_member": truncated_member,
            "description": (
                f"The tar stream ends part-way through {truncated_member}; the gzip container "
                "itself is intact, so the cut shows up at the tar layer. manifest.json and "
                "manifest.sig are complete and verify, and every earlier content member is "
                "complete, staged, and digest-checked before the decoder gives up -- a reader can "
                "be holding fully verified content and must still promote none of it. The "
                "verifier wraps the tar decoder's error as BundleVerifyError with code "
                "BUNDLE_ARCHIVE_UNREADABLE (the decoder error is kept as the cause). NOTE FOR "
                "READERS: do not rely on that wrapping alone. A reader that catches only the "
                "verifier's own exception type is one decoder change away from letting a "
                "truncated artifact through as an unhandled error, so treat ANY exception from "
                "verification as a refusal."
            ),
        },
        {
            "name": "expired",
            "path": "negative/expired.tar.gz",
            "exists": True,
            "sha256": _sha256(paths["expired"]),
            "gate": "none -- this is a consumer-side expiry test, not a verification failure",
            "expected_error_code": None,
            "expected_exception": None,
            "verifies": True,
            "staging_written": True,
            "description": (
                "A valid, correctly signed artifact that passes every verification gate. Every "
                f"row in tables/ioc.jsonl carries agg_next_expiry = {EXPIRED_AT}. Expiry has no "
                "manifest field and no filename convention: ADR-0015 D4 puts it per claim, "
                "evaluated by the consumer against its own query_as_of. A conforming reader "
                "verifies this artifact and then serves NO indicator from it -- an expired entry "
                "is unavailable, not merely labelled. tables/attack_technique.jsonl is static "
                "reference material whose dataset-level provenance says it does not expire on a "
                "clock, and it is here so that withholding the expired indicators can be told "
                "apart from discarding the whole artifact."
            ),
            "indicator_expiry": EXPIRED_AT,
            "valid_indicator_expiry": LIVE_UNTIL,
        },
        {
            "name": "absent",
            "path": ABSENT_FIXTURE_PATH,
            "exists": False,
            "sha256": None,
            "gate": "no artifact at all",
            "expected_error_code": None,
            "expected_exception": None,
            "verifies": False,
            "staging_written": False,
            "description": (
                "This path is guaranteed not to be written by tools/lite_fixture.py, and the "
                "emitter removes anything found there, so a consumer can point its reader at it "
                "and get the same answer on every machine and every run. anchors.toml beside it "
                "DOES exist, so a fail-open test against this path is testing a missing artifact "
                "rather than a missing trust anchor. Absence of knowledge is not an error "
                "condition for a consumer: Edge Core is never blocked by missing knowledge "
                "(ADR-0015 D7, Absolute Constraint 1), so the expected outcome here is a node "
                "that keeps running, not an exception with a code."
            ),
        },
    ]
    document = {
        "anchors": "anchors.toml",
        "valid": "lite.tar.gz",
        "notes": {
            "state": (
                "Verify each fixture with a FRESH state.toml. They all declare bundle_version 1 "
                "because they are independent cases, not a sequence; reusing one watermark across "
                "them would trip anti-rollback and mask the gate under test."
            ),
            "forgery": (
                "These are emitted by Knowledge rather than forged in the consumer's own tests on "
                "purpose (ADR-0015 D7). A locally forged broken artifact differs from what "
                "Knowledge emits in ways nobody can enumerate."
            ),
        },
        "fixtures": fixtures,
    }
    (out_dir / "negative.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def cmd_emit(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / ".work"
    work.mkdir(exist_ok=True)
    negative_dir = out_dir / "negative"
    negative_dir.mkdir(exist_ok=True)

    source_db = work / "intel.db"
    if source_db.exists():
        source_db.unlink()
    _write_source_db(source_db, expiry=LIVE_UNTIL)

    bundle_path = out_dir / "lite.tar.gz"
    result = _build_lite(source_db=source_db, out=bundle_path, work=work)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode

    verify_key = SigningKey(bytes.fromhex(FIXTURE_SIGNING_SEED_HEX)).verify_key.encode().hex()
    key_id = verify_key[:8]
    (out_dir / "anchors.toml").write_text(
        "# Fixture trust anchor. The key below is published in tools/lite_fixture.py\n"
        "# and must never appear in a production anchor.\n"
        f'threshold = 1\n[keys]\n"{key_id}" = "{verify_key}"\n',
        encoding="utf-8",
    )

    manifest = peek_manifest(bundle_path)
    expected = {
        "bundle_sha256": _sha256(bundle_path),
        "profile": manifest["profile"],
        "files": manifest["files"],
        "tables": manifest["tables"],
        "notes": {
            "alias_scope": FIXTURE_SCOPE,
            "stale_row_excluded": "203.0.113.99 predates the freshness window and must be absent",
            "aliased_field": "ioc.value is aliased; no raw indicator appears in the bundle",
            "export_policy": "built with config/lite-export-policy.yaml, this node's default profile",
            "negative_fixtures": "see negative.json",
        },
    }
    (out_dir / "expected.json").write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # --- negative fixtures -------------------------------------------------
    tar_bytes = gzip.decompress(bundle_path.read_bytes())
    truncated_bytes, truncated_member = _corrupt_truncated(tar_bytes)
    derived = {
        "corrupt-signature": _corrupt_signature(tar_bytes),
        "corrupt-payload": _corrupt_payload(tar_bytes),
        "corrupt-truncated": truncated_bytes,
    }
    paths: dict[str, Path] = {}
    for name, data in derived.items():
        if data == tar_bytes:
            raise SystemExit(f"{name}: derivation left the artifact unchanged")
        path = negative_dir / f"{name}.tar.gz"
        path.write_bytes(_gzip_bytes(data))
        paths[name] = path

    expired_db = work / "intel-expired.db"
    if expired_db.exists():
        expired_db.unlink()
    _write_source_db(expired_db, expiry=EXPIRED_AT)
    expired_path = negative_dir / "expired.tar.gz"
    expired_result = _build_lite(source_db=expired_db, out=expired_path, work=work)
    if expired_result.returncode != 0:
        sys.stderr.write(expired_result.stderr)
        return expired_result.returncode
    paths["expired"] = expired_path

    # "Absent" is the absence of a file, which only means something if the
    # emitter guarantees it. Anything left at that path by a previous run, or
    # dropped there by hand, is removed.
    absent_path = out_dir / ABSENT_FIXTURE_PATH
    if absent_path.exists() or absent_path.is_symlink():
        absent_path.unlink()

    _write_negative_index(out_dir, paths, truncated_member)

    print(
        f"emitted fixture into {out_dir} (rows={manifest['profile']['counts']['rows']}, "
        f"negative={len(paths) + 1})"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lite_fixture")
    sub = parser.add_subparsers(dest="command", required=True)
    emit = sub.add_parser("emit", help="write deterministic Lite fixtures for consumers")
    emit.add_argument("--out", required=True)
    emit.set_defaults(func=cmd_emit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
