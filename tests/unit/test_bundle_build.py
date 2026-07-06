from __future__ import annotations

import json
import subprocess
import sqlite3
import sys
import tarfile
from pathlib import Path

import pytest

from azazel_cti.bundle.verify import LOCAL_TIER_TABLES, peek_manifest
from azazel_cti.db.repository import apply_migrations

_TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _run_cli(*args: str) -> str:
    result = subprocess.run(
        [sys.executable, str(_TOOLS_DIR / "bundle_build.py"), *args],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _make_source_db(path: Path, *, ioc_rows: int = 3) -> None:
    conn = sqlite3.connect(path)
    apply_migrations(conn, "intel")
    for i in range(ioc_rows):
        conn.execute(
            "INSERT INTO ioc (type, value, first_seen, last_seen) VALUES "
            "('ip', ?, '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')",
            (f"10.0.0.{i}",),
        )
        conn.execute(
            "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
            "expires_at, intel_generation) VALUES (?, 'urlhaus', 85, '2026-01-01T00:00:00Z', "
            "'2026-01-02T00:00:00Z', '2030-01-01T00:00:00Z', 1)",
            (i + 1,),
        )
    conn.commit()
    conn.close()


def test_keygen_writes_hex_key_with_restricted_permissions(tmp_path):
    key_path = tmp_path / "key.hex"
    out = _run_cli("keygen", "--out", str(key_path))
    assert "key_id:" in out
    assert "verify_key:" in out
    hex_text = key_path.read_text().strip()
    assert len(hex_text) == 64
    bytes.fromhex(hex_text)
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_build_produces_manifest_first_then_signature(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key_path = tmp_path / "key.hex"
    _run_cli("keygen", "--out", str(key_path))
    out_bundle = tmp_path / "bundle.tar.gz"
    _run_cli(
        "build", "--source-db", str(source_db), "--out", str(out_bundle),
        "--version", "1", "--sign-key", str(key_path),
    )
    with tarfile.open(out_bundle, "r:gz") as tar:
        names = tar.getnames()
    assert names[0] == "manifest.json"
    assert names[1] == "manifest.sig"


def test_build_excludes_local_tier_and_staging_tables(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key_path = tmp_path / "key.hex"
    _run_cli("keygen", "--out", str(key_path))
    out_bundle = tmp_path / "bundle.tar.gz"
    _run_cli(
        "build", "--source-db", str(source_db), "--out", str(out_bundle),
        "--version", "1", "--sign-key", str(key_path),
    )
    manifest = peek_manifest(out_bundle)
    assert not (set(manifest["tables"]) & LOCAL_TIER_TABLES)
    assert not any(t.startswith("_stage_") for t in manifest["tables"])
    assert "schema_migrations" not in manifest["tables"]
    assert "stats_meta" not in manifest["tables"]


def test_build_is_deterministic_same_content_same_hashes(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key_path = tmp_path / "key.hex"
    _run_cli("keygen", "--out", str(key_path))

    bundle_a = tmp_path / "a.tar.gz"
    bundle_b = tmp_path / "b.tar.gz"
    _run_cli("build", "--source-db", str(source_db), "--out", str(bundle_a), "--version", "1", "--sign-key", str(key_path))
    _run_cli("build", "--source-db", str(source_db), "--out", str(bundle_b), "--version", "1", "--sign-key", str(key_path))

    manifest_a = peek_manifest(bundle_a)
    manifest_b = peek_manifest(bundle_b)
    assert manifest_a["files"] == manifest_b["files"]
    assert manifest_a["tables"] == manifest_b["tables"]


def test_build_rows_are_sorted_by_primary_key(tmp_path):
    source_db = tmp_path / "intel.db"
    conn = sqlite3.connect(source_db)
    apply_migrations(conn, "intel")
    for value in ("10.0.0.9", "10.0.0.1", "10.0.0.5"):
        conn.execute(
            "INSERT INTO ioc (type, value, first_seen, last_seen) VALUES ('ip', ?, "
            "'2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            (value,),
        )
    conn.commit()
    conn.close()

    key_path = tmp_path / "key.hex"
    _run_cli("keygen", "--out", str(key_path))
    out_bundle = tmp_path / "bundle.tar.gz"
    _run_cli("build", "--source-db", str(source_db), "--out", str(out_bundle), "--version", "1", "--sign-key", str(key_path))

    with tarfile.open(out_bundle, "r:gz") as tar:
        data = tar.extractfile("tables/ioc.jsonl").read()
    ioc_ids = [json.loads(line)["ioc_id"] for line in data.decode().splitlines()]
    assert ioc_ids == sorted(ioc_ids)


def test_build_two_signers_produce_two_signature_lines(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key1 = tmp_path / "key1.hex"
    key2 = tmp_path / "key2.hex"
    _run_cli("keygen", "--out", str(key1))
    _run_cli("keygen", "--out", str(key2))
    out_bundle = tmp_path / "bundle.tar.gz"
    _run_cli(
        "build", "--source-db", str(source_db), "--out", str(out_bundle),
        "--version", "1", "--sign-key", str(key1), "--sign-key", str(key2),
    )
    with tarfile.open(out_bundle, "r:gz") as tar:
        sig_bytes = tar.extractfile("manifest.sig").read()
    lines = [line for line in sig_bytes.decode().splitlines() if line.strip()]
    assert len(lines) == 2


def test_differential_build_requires_base(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key_path = tmp_path / "key.hex"
    _run_cli("keygen", "--out", str(key_path))
    out_bundle = tmp_path / "bundle.tar.gz"
    result = subprocess.run(
        [sys.executable, str(_TOOLS_DIR / "bundle_build.py"), "build",
         "--source-db", str(source_db), "--out", str(out_bundle),
         "--version", "2", "--kind", "differential", "--sign-key", str(key_path)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0


def test_inspect_prints_manifest_json(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key_path = tmp_path / "key.hex"
    _run_cli("keygen", "--out", str(key_path))
    out_bundle = tmp_path / "bundle.tar.gz"
    _run_cli("build", "--source-db", str(source_db), "--out", str(out_bundle), "--version", "1", "--sign-key", str(key_path))
    out = _run_cli("inspect", str(out_bundle))
    manifest = json.loads(out)
    assert manifest["bundle_version"] == 1
    assert manifest["kind"] == "full"
