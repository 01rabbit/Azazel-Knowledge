from __future__ import annotations

import json
import subprocess
import sqlite3
import sys
from pathlib import Path

import pytest

from azazel_knowledge.bundle.importer import BundleImportError, apply_differential, import_full
from azazel_knowledge.bundle.rollback_anchor import read_state
from azazel_knowledge.bundle.verify import BundleVerifyError
from azazel_knowledge.db import generations
from azazel_knowledge.db.repository import apply_migrations

_TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _run_cli(*args: str) -> str:
    result = subprocess.run(
        [sys.executable, str(_TOOLS_DIR / "bundle_build.py"), *args],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _keygen(tmp_path: Path, name: str) -> Path:
    key_path = tmp_path / f"{name}.hex"
    _run_cli("keygen", "--out", str(key_path))
    return key_path


def _verify_hex_and_id(key_path: Path) -> tuple[str, str]:
    from nacl.signing import SigningKey

    sk = SigningKey(bytes.fromhex(key_path.read_text().strip()))
    return sk.verify_key.encode().hex()[:8], sk.verify_key.encode().hex()


def _anchors_toml(tmp_path: Path, key_path: Path, threshold: int = 1) -> Path:
    key_id, verify_hex = _verify_hex_and_id(key_path)
    path = tmp_path / "anchors.toml"
    path.write_text(f'threshold = {threshold}\nrevoked = []\n\n[keys]\n{key_id} = "{verify_hex}"\n', encoding="utf-8")
    return path


def _make_source_db(path: Path, *, values: list[str] | None = None) -> None:
    values = values or ["1.2.3.4", "1.2.3.5"]
    conn = sqlite3.connect(path)
    apply_migrations(conn, "intel")
    for i, value in enumerate(values, start=1):
        conn.execute(
            "INSERT INTO ioc (type, value, first_seen, last_seen) VALUES ('ip', ?, "
            "'2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')",
            (value,),
        )
        conn.execute(
            "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
            "expires_at, intel_generation) VALUES (?, 'urlhaus', 85, '2026-01-01T00:00:00Z', "
            "'2026-01-02T00:00:00Z', '2030-01-01T00:00:00Z', 1)",
            (i,),
        )
    conn.commit()
    conn.close()


def _make_local_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    conn.commit()
    conn.close()


def _build(tmp_path, source_db, out, *, version, sign_keys, base=None, kind=None, since=None):
    args = ["build", "--source-db", str(source_db), "--out", str(out), "--version", str(version)]
    if base is not None:
        args += ["--base", str(base)]
    if kind:
        args += ["--kind", kind]
    if since:
        args += ["--since", since]
    for k in sign_keys:
        args += ["--sign-key", str(k)]
    _run_cli(*args)
    return out


@pytest.fixture
def env(tmp_path):
    source_db = tmp_path / "source_intel.db"
    _make_source_db(source_db)
    key_path = _keygen(tmp_path, "key1")
    anchors_path = _anchors_toml(tmp_path, key_path)
    state_path = tmp_path / "trust" / "state.toml"
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    return {
        "tmp_path": tmp_path,
        "source_db": source_db,
        "key_path": key_path,
        "anchors_path": anchors_path,
        "state_path": state_path,
        "data_db_dir": data_db_dir,
        "local_db_path": local_db_path,
    }


def test_full_import_roundtrip_identical_table_contents(env):
    bundle_path = env["tmp_path"] / "bundle.tar.gz"
    _build(env["tmp_path"], env["source_db"], bundle_path, version=1, sign_keys=[env["key_path"]])

    result = import_full(bundle_path, env["anchors_path"], env["state_path"], env["data_db_dir"])
    assert result.generation == 1
    assert result.tables["ioc"] == 2
    assert result.tables["ioc_source"] == 2

    assert generations.current_generation(env["data_db_dir"]) == 1
    conn = sqlite3.connect(generations.intel_db_path(env["data_db_dir"], 1))
    rows = conn.execute("SELECT value FROM ioc ORDER BY value").fetchall()
    assert [r[0] for r in rows] == ["1.2.3.4", "1.2.3.5"]
    conn.close()

    state = read_state(env["state_path"])
    assert state.last_imported_version == 1


def test_local_rows_never_decrease_across_full_import(env):
    conn = sqlite3.connect(env["local_db_path"])
    conn.execute(
        "INSERT INTO reaction (edge_id, actor_key, action_applied, applied_at, reaction, "
        "reaction_window_s, classifier, classifier_version, created_at) VALUES "
        "('edge-1', '1.2.3.4', 'throttle', '2026-07-06T00:00:00Z', 'disengaged', 60, 'c', '1', "
        "'2026-07-06T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO observation (event_id, edge_id, kind, observed_at, raw, created_at) VALUES "
        "('ev-1', 'edge-1', 'eve_alert', '2026-07-06T00:00:00Z', '{}', '2026-07-06T00:00:00Z')"
    )
    conn.commit()
    conn.close()

    def _counts() -> tuple[int, int]:
        c = sqlite3.connect(env["local_db_path"])
        try:
            return (
                c.execute("SELECT COUNT(*) FROM reaction").fetchone()[0],
                c.execute("SELECT COUNT(*) FROM observation").fetchone()[0],
            )
        finally:
            c.close()

    before = _counts()
    bundle_path = env["tmp_path"] / "bundle.tar.gz"
    _build(env["tmp_path"], env["source_db"], bundle_path, version=1, sign_keys=[env["key_path"]])
    import_full(bundle_path, env["anchors_path"], env["state_path"], env["data_db_dir"])
    after = _counts()

    assert after[0] >= before[0]
    assert after[1] >= before[1]
    assert after == before  # bundle import must not touch local.db at all


def test_full_import_never_opens_local_db_path(env):
    with pytest.raises(AssertionError):
        import_full(
            env["tmp_path"] / "bundle.tar.gz",
            env["anchors_path"],
            env["state_path"],
            env["tmp_path"] / "data" / "local.db",
        )


def test_full_import_gcs_old_generations_keeping_two(env):
    for version in (1, 2, 3, 4):
        bundle_path = env["tmp_path"] / f"bundle{version}.tar.gz"
        _build(env["tmp_path"], env["source_db"], bundle_path, version=version, sign_keys=[env["key_path"]])
        import_full(bundle_path, env["anchors_path"], env["state_path"], env["data_db_dir"])

    remaining = sorted(p.name for p in env["data_db_dir"].iterdir() if p.name.startswith("gen-"))
    assert remaining == ["gen-3", "gen-4"]
    assert generations.current_generation(env["data_db_dir"]) == 4


def test_crash_mid_import_leaves_current_symlink_untouched(env, monkeypatch):
    bundle_path = env["tmp_path"] / "bundle.tar.gz"
    _build(env["tmp_path"], env["source_db"], bundle_path, version=1, sign_keys=[env["key_path"]])
    import_full(bundle_path, env["anchors_path"], env["state_path"], env["data_db_dir"])
    assert generations.current_generation(env["data_db_dir"]) == 1

    bundle2 = env["tmp_path"] / "bundle2.tar.gz"
    _build(env["tmp_path"], env["source_db"], bundle2, version=2, sign_keys=[env["key_path"]])

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated crash before swap")

    monkeypatch.setattr("azazel_knowledge.bundle.importer.generations.swap_current", _boom)

    with pytest.raises(RuntimeError):
        import_full(bundle2, env["anchors_path"], env["state_path"], env["data_db_dir"])

    assert generations.current_generation(env["data_db_dir"]) == 1
    assert read_state(env["state_path"]).last_imported_version == 1
    remaining = sorted(p.name for p in env["data_db_dir"].iterdir() if p.name.startswith("gen-"))
    assert remaining == ["gen-1"]  # gen-2 was cleaned up, not left half-built


def test_full_import_staging_cleaned_up_after_success(env):
    import tempfile

    bundle_path = env["tmp_path"] / "bundle.tar.gz"
    _build(env["tmp_path"], env["source_db"], bundle_path, version=1, sign_keys=[env["key_path"]])
    before = set(Path(tempfile.gettempdir()).glob("azazel-bundle-*"))
    import_full(bundle_path, env["anchors_path"], env["state_path"], env["data_db_dir"])
    after = set(Path(tempfile.gettempdir()).glob("azazel-bundle-*"))
    assert after == before


def test_full_import_rejects_tampered_bundle_before_any_swap(env):
    import tarfile
    import io

    bundle_path = env["tmp_path"] / "bundle.tar.gz"
    _build(env["tmp_path"], env["source_db"], bundle_path, version=1, sign_keys=[env["key_path"]])

    with tarfile.open(bundle_path, "r:gz") as tar:
        members = [(info, tar.extractfile(info).read() if info.isreg() else None) for info in tar.getmembers()]
    with tarfile.open(bundle_path, "w:gz") as tar:
        for info, data in members:
            if info.name == "tables/ioc.jsonl":
                data = b"tampered"
            new_info = tarfile.TarInfo(name=info.name)
            new_info.size = len(data) if data is not None else 0
            tar.addfile(new_info, io.BytesIO(data) if data is not None else None)

    with pytest.raises(BundleVerifyError):
        import_full(bundle_path, env["anchors_path"], env["state_path"], env["data_db_dir"])

    assert generations.current_generation(env["data_db_dir"]) is None


def test_failed_verification_leaves_the_generation_already_in_service_untouched(env):
    """A generation already serving queries survives a bundle that fails verification.

    The test above starts from an empty tree and asserts
    `current_generation(...) is None`, which proves no generation was
    *created*. That is a weaker statement than the one that matters in
    operation: a node with a generation already in service must come out of a
    failed import serving exactly the same bytes it served before. Asserting the
    live database's digest, not just the symlink, is what makes the difference
    -- a swap that pointed `current` back at gen-1 after clobbering its contents
    would satisfy the symlink check alone.
    """
    import hashlib
    import io
    import tarfile

    bundle1 = env["tmp_path"] / "bundle1.tar.gz"
    _build(env["tmp_path"], env["source_db"], bundle1, version=1, sign_keys=[env["key_path"]])
    import_full(bundle1, env["anchors_path"], env["state_path"], env["data_db_dir"])
    assert generations.current_generation(env["data_db_dir"]) == 1

    live_path = generations.intel_db_path(env["data_db_dir"], 1)
    before = hashlib.sha256(live_path.read_bytes()).hexdigest()

    # A newer bundle, correctly signed, whose content no longer matches the
    # digests its manifest declares: it clears signature and anti-rollback and
    # fails during extraction, which is the case that has bytes in flight.
    bundle2 = env["tmp_path"] / "bundle2.tar.gz"
    _build(env["tmp_path"], env["source_db"], bundle2, version=2, sign_keys=[env["key_path"]])
    with tarfile.open(bundle2, "r:gz") as tar:
        members = [(i, tar.extractfile(i).read() if i.isreg() else None) for i in tar.getmembers()]
    with tarfile.open(bundle2, "w:gz") as tar:
        for info, data in members:
            if info.name == "tables/ioc.jsonl":
                data = b"tampered"
            new_info = tarfile.TarInfo(name=info.name)
            new_info.size = len(data) if data is not None else 0
            tar.addfile(new_info, io.BytesIO(data) if data is not None else None)

    with pytest.raises(BundleVerifyError) as exc:
        import_full(bundle2, env["anchors_path"], env["state_path"], env["data_db_dir"])
    assert exc.value.code == "BUNDLE_FILE_HASH_MISMATCH"

    assert generations.current_generation(env["data_db_dir"]) == 1
    assert hashlib.sha256(live_path.read_bytes()).hexdigest() == before
    assert read_state(env["state_path"]).last_imported_version == 1
    remaining = sorted(p.name for p in env["data_db_dir"].iterdir() if p.name.startswith("gen-"))
    assert remaining == ["gen-1"]


def test_differential_import_applies_upserts_to_live_generation(env):
    full_bundle = env["tmp_path"] / "full.tar.gz"
    _build(env["tmp_path"], env["source_db"], full_bundle, version=1, sign_keys=[env["key_path"]])
    import_full(full_bundle, env["anchors_path"], env["state_path"], env["data_db_dir"])

    extra_db = env["tmp_path"] / "extra_intel.db"
    _make_source_db(extra_db, values=["1.2.3.4", "9.9.9.9"])
    diff_bundle = env["tmp_path"] / "diff.tar.gz"
    _build(env["tmp_path"], extra_db, diff_bundle, version=2, sign_keys=[env["key_path"]], base=1, kind="differential")

    live_path = generations.intel_db_path(env["data_db_dir"], 1)
    conn = sqlite3.connect(live_path)
    try:
        result = apply_differential(diff_bundle, env["anchors_path"], env["state_path"], conn)
    finally:
        conn.close()

    assert result.bundle_version == 2
    assert read_state(env["state_path"]).last_imported_version == 2

    conn = sqlite3.connect(live_path)
    values = {r[0] for r in conn.execute("SELECT value FROM ioc").fetchall()}
    conn.close()
    assert "9.9.9.9" in values
    assert "1.2.3.4" in values
    assert generations.current_generation(env["data_db_dir"]) == 1  # differential never creates a new gen


def test_differential_import_delete_op_removes_row(env):
    full_bundle = env["tmp_path"] / "full.tar.gz"
    _build(env["tmp_path"], env["source_db"], full_bundle, version=1, sign_keys=[env["key_path"]])
    import_full(full_bundle, env["anchors_path"], env["state_path"], env["data_db_dir"])

    live_path = generations.intel_db_path(env["data_db_dir"], 1)

    manifest = {
        "bundle_version": 2,
        "base_version": 1,
        "kind": "differential",
        "compression": "gzip",
        "created_at": "2026-07-06T00:00:00Z",
        "attack_version": "",
        "feeds": [],
        "tables": ["ioc"],
        "files": {},
    }
    delta_lines = [json.dumps({"op": "delete", "row": {"ioc_id": 1}})]
    delta_bytes = ("\n".join(delta_lines) + "\n").encode()

    from azazel_knowledge.bundle.verify import canonical_manifest_bytes
    import hashlib

    manifest["files"]["deltas/ioc.jsonl"] = hashlib.sha256(delta_bytes).hexdigest()
    manifest_bytes = canonical_manifest_bytes(manifest)

    from nacl.signing import SigningKey

    sk = SigningKey(bytes.fromhex(env["key_path"].read_text().strip()))
    key_id = sk.verify_key.encode().hex()[:8]
    sig = f"{key_id}:{sk.sign(manifest_bytes).signature.hex()}\n".encode()

    import tarfile
    import io

    diff_bundle = env["tmp_path"] / "diff_delete.tar.gz"
    with tarfile.open(diff_bundle, "w:gz") as tar:
        for name, data in (("manifest.json", manifest_bytes), ("manifest.sig", sig), ("deltas/ioc.jsonl", delta_bytes)):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    conn = sqlite3.connect(live_path)
    before = conn.execute("SELECT COUNT(*) FROM ioc WHERE ioc_id = 1").fetchone()[0]
    assert before == 1
    apply_differential(diff_bundle, env["anchors_path"], env["state_path"], conn)
    after = conn.execute("SELECT COUNT(*) FROM ioc WHERE ioc_id = 1").fetchone()[0]
    conn.close()
    assert after == 0


def test_import_full_wrong_kind_raises(env):
    bundle_path = env["tmp_path"] / "diff.tar.gz"
    _build(env["tmp_path"], env["source_db"], bundle_path, version=1, sign_keys=[env["key_path"]], kind="full")
    state_path = env["state_path"]
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text("last_imported_version = 1\n", encoding="utf-8")
    diff_bundle = env["tmp_path"] / "actually_diff.tar.gz"
    _build(env["tmp_path"], env["source_db"], diff_bundle, version=2, sign_keys=[env["key_path"]], base=1, kind="differential")
    with pytest.raises(BundleImportError):
        import_full(diff_bundle, env["anchors_path"], env["state_path"], env["data_db_dir"])
