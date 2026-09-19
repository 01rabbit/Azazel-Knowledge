#!/usr/bin/env python3
"""Emit a deterministic Knowledge Lite fixture for downstream consumers.

ADR-0015 Consequences 8. Azazel-Nexus and Azazel-Boot embed a read-only Lite
reader; this is the artifact they run their reader against in their own CI,
together with the trust anchor it verifies under and a record of what a correct
reader must find inside it.

Emitting the fixture rather than committing a binary blob is deliberate. The
whole point of ADR-0015 D2 is that the same selection tuple reproduces the same
bytes, so a fixture that is *rebuilt* and compared proves that property every
time it is used, while a committed `.tar.gz` would only prove that a file was
once checked in.

    python tools/lite_fixture.py emit --out DIR

writes into DIR:

    lite.tar.gz     signed Lite bundle
    anchors.toml    the trust anchor it verifies under
    expected.json   profile block, per-file SHA-256, and row counts

A consumer verifies `lite.tar.gz` against `anchors.toml` with its own reader,
then checks what it read against `expected.json`.

**The signing key here is a fixture key and is published in this file on
purpose.** It exists so the fixture is reproducible byte-for-byte. It signs
nothing but fixture data and must never appear in a trust anchor outside a test
-- which is exactly why it is written here in the open rather than looking like
a secret someone might reuse.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
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

POLICY_YAML = """\
version: lite-fixture-v1
datasets:
  ioc:
    fields:
      - name: value
        mode: alias
      - name: type
      - name: last_seen
"""

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


def _write_source_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        apply_migrations(conn, "intel")
        for kind, value, last_seen in _FIXTURE_IOCS:
            conn.execute(
                "INSERT INTO ioc (type, value, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                (kind, value, "2020-01-01T00:00:00Z", last_seen),
            )
        conn.commit()
    finally:
        conn.close()


def cmd_emit(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / ".work"
    work.mkdir(exist_ok=True)

    source_db = work / "intel.db"
    if source_db.exists():
        source_db.unlink()
    _write_source_db(source_db)

    policy_path = work / "policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")
    alias_key_path = work / "alias.hex"
    alias_key_path.write_text(FIXTURE_ALIAS_KEY_HEX, encoding="utf-8")
    sign_key_path = work / "sign.hex"
    sign_key_path.write_text(FIXTURE_SIGNING_SEED_HEX, encoding="utf-8")

    bundle_path = out_dir / "lite.tar.gz"
    if bundle_path.exists():
        bundle_path.unlink()

    result = subprocess.run(
        [
            sys.executable,
            str(_REPO_ROOT / "tools" / "bundle_build.py"),
            "build-lite",
            "--source-db", str(source_db),
            "--out", str(bundle_path),
            "--version", "1",
            "--profile", FIXTURE_PROFILE,
            "--export-policy", str(policy_path),
            "--alias-key-file", str(alias_key_path),
            "--alias-scope", FIXTURE_SCOPE,
            "--as-of", FIXTURE_AS_OF,
            "--intel-generation", "1",
            "--stats-generation", "1",
            "--attack-version", "fixture-v1",
            "--config-hash", "fixture-config-hash",
            "--sign-key", str(sign_key_path),
        ],
        capture_output=True,
        text=True,
    )
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
        "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
        "profile": manifest["profile"],
        "files": manifest["files"],
        "tables": manifest["tables"],
        "notes": {
            "alias_scope": FIXTURE_SCOPE,
            "stale_row_excluded": "203.0.113.99 predates the freshness window and must be absent",
            "aliased_field": "ioc.value is aliased; no raw indicator appears in the bundle",
        },
    }
    (out_dir / "expected.json").write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"emitted fixture into {out_dir} (rows={manifest['profile']['counts']['rows']})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lite_fixture")
    sub = parser.add_subparsers(dest="command", required=True)
    emit = sub.add_parser("emit", help="write a deterministic Lite fixture for consumers")
    emit.add_argument("--out", required=True)
    emit.set_defaults(func=cmd_emit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
