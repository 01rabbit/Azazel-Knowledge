from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_AZCTL = _REPO_ROOT / "azctl"


def _run(*args: str, cwd: Path | None = None, expect_ok: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT / "src")
    result = subprocess.run(
        [sys.executable, str(_AZCTL), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        env=env,
    )
    if expect_ok:
        assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    return result


def _provision(tmp_path: Path) -> Path:
    root = tmp_path / "node"
    _run("provision", "--root", str(root))
    return root


_TOOLS_DIR = _REPO_ROOT / "tools"


def _keygen(out_path: Path) -> Path:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT / "src")
    result = subprocess.run(
        [sys.executable, str(_TOOLS_DIR / "bundle_build.py"), "keygen", "--out", str(out_path)],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr
    return out_path


def test_check_config_passes_on_repo_config():
    result = _run("check-config", "--config-dir", str(_REPO_ROOT / "config"))
    assert "weights sum: 1.000000000 (ok)" in result.stdout
    assert "confidence_weights sum: 1.000000000 (ok)" in result.stdout
    assert "OK" in result.stdout


def test_provision_creates_working_tree_with_both_dbs_migrated(tmp_path):
    root = tmp_path / "node"
    result = _run("provision", "--root", str(root), "--check-thermal")

    assert (root / "data" / "db" / "local.db").is_file()
    assert (root / "data" / "db" / "current").is_symlink()
    assert (root / "data" / "db" / "gen-1" / "intel.db").is_file()
    assert (root / "secrets" / "node_signing_key").is_file()
    assert (root / "secrets" / "trust" / "anchors.toml").is_file()
    assert (root / "secrets" / "trust" / "state.toml").is_file()

    local_conn = sqlite3.connect(root / "data" / "db" / "local.db")
    tables = {r[0] for r in local_conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    local_conn.close()
    assert "reaction" in tables
    assert "api_client" in tables

    intel_conn = sqlite3.connect(root / "data" / "db" / "gen-1" / "intel.db")
    intel_tables = {r[0] for r in intel_conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    intel_conn.close()
    assert "ioc" in intel_tables

    assert "first admin API client token" in result.stdout
    assert "azcti_" in result.stdout
    assert "thermal check" in result.stdout


def test_provision_admin_token_verifies_against_stored_hash(tmp_path):
    root = _provision(tmp_path)
    result = _run("provision", "--root", str(root))  # idempotent second run, mints another client
    token_line = [ln for ln in result.stdout.splitlines() if ln.strip().startswith("token:")][0]
    token = token_line.split("token:", 1)[1].strip()
    key_id = token.split("_")[1]

    conn = sqlite3.connect(root / "data" / "db" / "local.db")
    row = conn.execute("SELECT token_sha256 FROM api_client WHERE key_id = ?", (key_id,)).fetchone()
    conn.close()
    assert row is not None

    from azazel_cti.security import auth

    assert auth.verify(token, row[0])


def test_bundle_build_sign_inspect_import_roundtrip(tmp_path):
    root = _provision(tmp_path)

    source_db = tmp_path / "source_intel.db"
    conn = sqlite3.connect(source_db)
    conn.execute(
        "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    from azazel_cti.db.repository import apply_migrations

    conn.close()
    conn = sqlite3.connect(source_db)
    apply_migrations(conn, "intel")
    conn.execute(
        "INSERT INTO ioc (type, value, first_seen, last_seen) VALUES "
        "('ip', '198.51.100.7', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
        "expires_at, intel_generation) VALUES (1, 'urlhaus', 85, '2026-01-01T00:00:00Z', "
        "'2026-01-02T00:00:00Z', '2030-01-01T00:00:00Z', 1)"
    )
    conn.commit()
    conn.close()

    key1 = tmp_path / "key1.hex"
    key2 = tmp_path / "key2.hex"
    _keygen(key1)
    _keygen(key2)

    bundle_path = tmp_path / "bundle.tar.gz"
    _run(
        "bundle", "build",
        "--source-db", str(source_db), "--out", str(bundle_path),
        "--version", "1", "--sign-key", str(key1),
    )

    _run("bundle", "sign", str(bundle_path), "--sign-key", str(key2))

    import tarfile

    with tarfile.open(bundle_path, "r:gz") as tar:
        sig_bytes = tar.extractfile("manifest.sig").read()
    sig_lines = [ln for ln in sig_bytes.decode().splitlines() if ln.strip()]
    assert len(sig_lines) == 2

    inspect_result = _run("bundle", "inspect", str(bundle_path))
    manifest = json.loads(inspect_result.stdout)
    assert manifest["bundle_version"] == 1

    from nacl.signing import SigningKey

    def _anchors_toml(path: Path, *key_paths: Path, threshold: int = 2) -> None:
        lines = [f"threshold = {threshold}", "revoked = []", "", "[keys]"]
        for kp in key_paths:
            sk = SigningKey(bytes.fromhex(kp.read_text().strip()))
            key_id = sk.verify_key.encode().hex()[:8]
            lines.append(f'{key_id} = "{sk.verify_key.encode().hex()}"')
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    _anchors_toml(root / "secrets" / "trust" / "anchors.toml", key1, key2, threshold=2)

    _run(
        "bundle", "import", "--root", str(root),
        str(bundle_path), "--confirm",
    )

    intel_db_path = root / "data" / "db" / "gen-2" / "intel.db"
    assert intel_db_path.is_file()
    conn = sqlite3.connect(intel_db_path)
    values = [r[0] for r in conn.execute("SELECT value FROM ioc").fetchall()]
    conn.close()
    assert values == ["198.51.100.7"]

    state_result = _run("bundle", "resolve-state", "--root", str(root))
    assert "last_imported_version: 1" in state_result.stdout


def test_bundle_import_fingerprint_does_not_import(tmp_path):
    root = _provision(tmp_path)
    source_db = tmp_path / "source_intel.db"
    from azazel_cti.db.repository import apply_migrations

    conn = sqlite3.connect(source_db)
    apply_migrations(conn, "intel")
    conn.close()

    key1 = tmp_path / "key1.hex"
    _keygen(key1)
    bundle_path = tmp_path / "bundle.tar.gz"
    _run(
        "bundle", "build",
        "--source-db", str(source_db), "--out", str(bundle_path),
        "--version", "1", "--sign-key", str(key1),
    )

    result = _run("bundle", "import", "--root", str(root), str(bundle_path), "--fingerprint")
    assert "bundle_version: 1" in result.stdout
    assert "sha256:" in result.stdout
    assert not (root / "data" / "db" / "gen-2").exists()


def test_backup_produces_both_db_files_and_restore_sets_needs_full_rebaseline(tmp_path):
    root = _provision(tmp_path)
    backup_dir = tmp_path / "backup"
    _run("backup", "--root", str(root), "--out-dir", str(backup_dir))
    assert (backup_dir / "local.db").is_file()
    assert (backup_dir / "intel.db").is_file()

    restore_root = tmp_path / "restored"
    _run("provision", "--root", str(restore_root))
    _run("restore", "--root", str(restore_root), "--backup-dir", str(backup_dir), "--confirm")

    from azazel_cti.bundle.rollback_anchor import read_state

    state = read_state(restore_root / "secrets" / "trust" / "state.toml")
    assert state.needs_full_rebaseline is True


def test_restore_without_confirm_is_refused(tmp_path):
    root = _provision(tmp_path)
    backup_dir = tmp_path / "backup"
    _run("backup", "--root", str(root), "--out-dir", str(backup_dir))
    result = _run("restore", "--root", str(root), "--backup-dir", str(backup_dir), expect_ok=False)
    assert result.returncode != 0


def test_audit_verify_passes_on_clean_chain_and_fails_on_tampered_chain(tmp_path):
    root = _provision(tmp_path)
    from azazel_cti.audit.logger import AuditChain

    chain = AuditChain(root / "var" / "audit" / "azctl", "proc1", "boot1", lambda t: t)
    chain.append({"kind": "test", "n": 1})
    chain.append({"kind": "test", "n": 2})
    chain.flush()
    chain_path = chain.path

    ok_result = _run("audit", "verify", "--root", str(root))
    assert "audit verify: PASS" in ok_result.stdout

    lines = chain_path.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["event"]["n"] = 999
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    chain_path.write_text("\n".join(lines) + "\n")

    bad_result = _run("audit", "verify", "--root", str(root), expect_ok=False)
    assert bad_result.returncode != 0
    assert "audit verify: FAIL" in bad_result.stdout


def test_keys_add_list_remove_set_threshold(tmp_path):
    root = _provision(tmp_path)
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    verify_hex = sk.verify_key.encode().hex()
    key_id = verify_hex[:8]

    _run("keys", "add", "--root", str(root), key_id, verify_hex)
    list_result = _run("keys", "list", "--root", str(root))
    assert key_id in list_result.stdout

    _run("keys", "set-threshold", "--root", str(root), "2")
    list_result = _run("keys", "list", "--root", str(root))
    assert "threshold: 2" in list_result.stdout

    _run("keys", "remove", "--root", str(root), key_id, "--revoke")
    list_result = _run("keys", "list", "--root", str(root))
    assert key_id not in list_result.stdout.split("revoked:")[0]
    assert key_id in list_result.stdout.split("revoked:")[1]


def test_client_add_list_revoke(tmp_path):
    root = _provision(tmp_path)
    add_result = _run("client", "add", "--root", str(root), "--scopes", "ingest,query")
    token_line = [ln for ln in add_result.stdout.splitlines() if ln.startswith("token")][0]
    token = token_line.split(":", 1)[1].strip()
    key_id_line = [ln for ln in add_result.stdout.splitlines() if ln.startswith("key_id")][0]
    key_id = key_id_line.split(":", 1)[1].strip()

    list_result = _run("client", "list", "--root", str(root))
    assert key_id in list_result.stdout

    _run("client", "revoke", "--root", str(root), key_id)
    conn = sqlite3.connect(root / "data" / "db" / "local.db")
    enabled = conn.execute("SELECT enabled FROM api_client WHERE key_id = ?", (key_id,)).fetchone()[0]
    conn.close()
    assert enabled == 0

    from azazel_cti.security import auth

    assert token.startswith("azcti_")


def test_health_prints_json_snapshot(tmp_path):
    root = _provision(tmp_path)
    result = _run("health", "--root", str(root))
    snapshot = json.loads(result.stdout)
    assert "feeds" in snapshot
    assert "intel_generation" in snapshot
    assert snapshot["intel_generation"] == 1


def test_scrub_without_force_prints_procedure_and_force_errors(tmp_path):
    result = _run("scrub")
    assert "crypto-erase" in result.stdout

    result = _run("scrub", "--force", expect_ok=False)
    assert result.returncode != 0


def test_feed_pull_offline_from_file(tmp_path):
    root = _provision(tmp_path)
    fixture_dir = _REPO_ROOT / "tests" / "fixtures" / "feeds"
    csv_path = fixture_dir / "geoip_asn.csv"
    if not csv_path.is_file():
        pytest.skip("geoip_asn fixture not present")

    result = _run(
        "feed", "pull", "--root", str(root), "--config-dir", str(_REPO_ROOT / "config"),
        "geoip_asn", "--file", str(csv_path),
    )
    assert "status=applied" in result.stdout

    conn = sqlite3.connect(root / "data" / "db" / "gen-1" / "intel.db")
    count = conn.execute("SELECT COUNT(*) FROM ioc WHERE type = 'asn'").fetchone()[0]
    conn.close()
    assert count > 0
