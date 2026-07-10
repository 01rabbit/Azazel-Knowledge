from __future__ import annotations

import io
import json
import subprocess
import sqlite3
import sys
import tarfile
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_knowledge.bundle.verify import (
    BundleVerifyError,
    MANIFEST_MEMBER,
    SIGNATURE_MEMBER,
    canonical_manifest_bytes,
    verify_bundle,
)
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


def _keygen(tmp_path: Path, name: str) -> tuple[Path, str, str]:
    key_path = tmp_path / f"{name}.hex"
    out = _run_cli("keygen", "--out", str(key_path))
    lines = dict(line.split(": ", 1) for line in out.strip().splitlines())
    return key_path, lines["key_id"], lines["verify_key"]


def _anchors_toml(tmp_path: Path, keys: dict[str, str], threshold: int = 1, revoked: tuple[str, ...] = ()) -> Path:
    lines = [f"threshold = {threshold}", f"revoked = {json.dumps(list(revoked))}", "", "[keys]"]
    for key_id, verify_hex in keys.items():
        lines.append(f'{key_id} = "{verify_hex}"')
    path = tmp_path / "anchors.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _make_source_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    apply_migrations(conn, "intel")
    conn.execute(
        "INSERT INTO ioc (type, value, first_seen, last_seen) VALUES "
        "('ip', '1.2.3.4', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
        "expires_at, intel_generation) VALUES (1, 'urlhaus', 85, '2026-01-01T00:00:00Z', "
        "'2026-01-02T00:00:00Z', '2030-01-01T00:00:00Z', 1)"
    )
    conn.commit()
    conn.close()


def _build_bundle(tmp_path: Path, source_db: Path, out: Path, *, version: int, sign_keys: list[Path], **kwargs) -> Path:
    args = ["build", "--source-db", str(source_db), "--out", str(out), "--version", str(version)]
    if kwargs.get("base") is not None:
        args += ["--base", str(kwargs["base"])]
    if kwargs.get("kind"):
        args += ["--kind", kwargs["kind"]]
    for key_path in sign_keys:
        args += ["--sign-key", str(key_path)]
    _run_cli(*args)
    return out


def _read_all_members(bundle_path: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    members = []
    with tarfile.open(bundle_path, "r:gz") as tar:
        for info in tar.getmembers():
            data = tar.extractfile(info).read() if info.isreg() else None
            members.append((info, data))
    return members


def _rewrite_tar(
    bundle_path: Path,
    members: list[tuple[tarfile.TarInfo, bytes | None]],
    *,
    replace: dict[str, bytes] | None = None,
    remove: set[str] | None = None,
    to_symlink: dict[str, str] | None = None,
    insert: list[tuple[str, bytes]] | None = None,
) -> None:
    replace = replace or {}
    remove = remove or set()
    to_symlink = to_symlink or {}
    with tarfile.open(bundle_path, "w:gz") as tar:
        for info, data in members:
            if info.name in remove:
                continue
            if info.name in to_symlink:
                sym = tarfile.TarInfo(name=info.name)
                sym.type = tarfile.SYMTYPE
                sym.linkname = to_symlink[info.name]
                tar.addfile(sym)
                continue
            if info.name in replace:
                data = replace[info.name]
            new_info = tarfile.TarInfo(name=info.name)
            new_info.size = len(data) if data is not None else 0
            tar.addfile(new_info, io.BytesIO(data) if data is not None else None)
        for name, data in insert or []:
            new_info = tarfile.TarInfo(name=name)
            new_info.size = len(data)
            tar.addfile(new_info, io.BytesIO(data))


def _decode_manifest(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> dict:
    for info, data in members:
        if info.name == MANIFEST_MEMBER:
            return json.loads(data)
    raise AssertionError("no manifest.json in bundle")


@pytest.fixture
def bundle_env(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key_path, key_id, verify_hex = _keygen(tmp_path, "key1")
    anchors_path = _anchors_toml(tmp_path, {key_id: verify_hex}, threshold=1)
    state_path = tmp_path / "state.toml"
    bundle_path = tmp_path / "bundle.tar.gz"
    _build_bundle(tmp_path, source_db, bundle_path, version=1, sign_keys=[key_path])
    return {
        "tmp_path": tmp_path,
        "source_db": source_db,
        "key_path": key_path,
        "key_id": key_id,
        "verify_hex": verify_hex,
        "anchors_path": anchors_path,
        "state_path": state_path,
        "bundle_path": bundle_path,
    }


def test_valid_full_bundle_verifies(bundle_env):
    staging = bundle_env["tmp_path"] / "staging"
    verified = verify_bundle(
        bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging
    )
    assert verified.manifest["bundle_version"] == 1
    assert verified.manifest["kind"] == "full"
    assert "ioc" in verified.manifest["tables"]
    assert (staging / "tables" / "ioc.jsonl").exists()


def test_tampered_file_hash_rejected(bundle_env):
    members = _read_all_members(bundle_env["bundle_path"])
    _rewrite_tar(bundle_env["bundle_path"], members, replace={"tables/ioc.jsonl": b'{"tampered": true}\n'})
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_FILE_HASH_MISMATCH"


def test_all_invalid_signatures_rejected_even_with_threshold_key_ids_present(bundle_env):
    """Cycle-4 critical regression: a bundle with the right number of
    distinct key_id lines but signatures that don't actually verify
    must be rejected -- presence of key_ids is not verification."""
    members = _read_all_members(bundle_env["bundle_path"])
    bogus_sig = "00" * 64
    bad_sig_bytes = f"{bundle_env['key_id']}:{bogus_sig}\n".encode()
    _rewrite_tar(bundle_env["bundle_path"], members, replace={SIGNATURE_MEMBER: bad_sig_bytes})
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_SIGNATURE_THRESHOLD_NOT_MET"


def test_revoked_signer_rejected(bundle_env):
    anchors_path = _anchors_toml(
        bundle_env["tmp_path"],
        {bundle_env["key_id"]: bundle_env["verify_hex"]},
        threshold=1,
        revoked=(bundle_env["key_id"],),
    )
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], anchors_path, bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_REVOKED_SIGNER"


def test_threshold_two_with_one_valid_signature_rejected(bundle_env):
    _, key_id2, verify_hex2 = _keygen(bundle_env["tmp_path"], "key2")
    anchors_path = _anchors_toml(
        bundle_env["tmp_path"],
        {bundle_env["key_id"]: bundle_env["verify_hex"], key_id2: verify_hex2},
        threshold=2,
    )
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], anchors_path, bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_SIGNATURE_THRESHOLD_NOT_MET"


def test_threshold_two_with_two_valid_signatures_accepted(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key1_path, key_id1, verify_hex1 = _keygen(tmp_path, "key1")
    key2_path, key_id2, verify_hex2 = _keygen(tmp_path, "key2")
    anchors_path = _anchors_toml(tmp_path, {key_id1: verify_hex1, key_id2: verify_hex2}, threshold=2)
    state_path = tmp_path / "state.toml"
    bundle_path = tmp_path / "bundle.tar.gz"
    _build_bundle(tmp_path, source_db, bundle_path, version=1, sign_keys=[key1_path, key2_path])
    staging = tmp_path / "staging"
    verified = verify_bundle(bundle_path, anchors_path, state_path, staging)
    assert verified.manifest["bundle_version"] == 1


def test_manifest_embedding_trust_fields_rejected(bundle_env):
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    manifest["threshold"] = 1
    new_manifest_bytes = canonical_manifest_bytes(manifest)
    signing_key = SigningKey(bytes.fromhex(bundle_env["key_path"].read_text().strip()))
    new_sig = f"{bundle_env['key_id']}:{signing_key.sign(new_manifest_bytes).signature.hex()}\n".encode()
    _rewrite_tar(
        bundle_env["bundle_path"],
        members,
        replace={MANIFEST_MEMBER: new_manifest_bytes, SIGNATURE_MEMBER: new_sig},
    )
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_SHADOWS_TRUST_ANCHOR"


def test_bundle_naming_local_tier_table_rejected(bundle_env):
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    manifest["tables"] = list(manifest["tables"]) + ["reaction"]
    manifest["files"]["tables/reaction.jsonl"] = "e" * 64
    new_manifest_bytes = canonical_manifest_bytes(manifest)
    signing_key = SigningKey(bytes.fromhex(bundle_env["key_path"].read_text().strip()))
    new_sig = f"{bundle_env['key_id']}:{signing_key.sign(new_manifest_bytes).signature.hex()}\n".encode()
    _rewrite_tar(
        bundle_env["bundle_path"],
        members,
        replace={MANIFEST_MEMBER: new_manifest_bytes, SIGNATURE_MEMBER: new_sig},
        insert=[("tables/reaction.jsonl", b"")],
    )
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_TOUCHES_LOCAL_TIER"


def test_version_regression_rejected(bundle_env):
    bundle_env["state_path"].write_text("last_imported_version = 5\n", encoding="utf-8")
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_VERSION_REGRESSION"


def test_differential_with_wrong_base_rejected(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key_path, key_id, verify_hex = _keygen(tmp_path, "key1")
    anchors_path = _anchors_toml(tmp_path, {key_id: verify_hex}, threshold=1)
    state_path = tmp_path / "state.toml"
    state_path.write_text("last_imported_version = 3\n", encoding="utf-8")
    bundle_path = tmp_path / "diff.tar.gz"
    _build_bundle(tmp_path, source_db, bundle_path, version=4, sign_keys=[key_path], base=2, kind="differential")
    staging = tmp_path / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_path, anchors_path, state_path, staging)
    assert exc.value.code == "BUNDLE_BASE_MISMATCH"


def test_differential_with_matching_base_accepted(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    key_path, key_id, verify_hex = _keygen(tmp_path, "key1")
    anchors_path = _anchors_toml(tmp_path, {key_id: verify_hex}, threshold=1)
    state_path = tmp_path / "state.toml"
    state_path.write_text("last_imported_version = 3\n", encoding="utf-8")
    bundle_path = tmp_path / "diff.tar.gz"
    _build_bundle(tmp_path, source_db, bundle_path, version=4, sign_keys=[key_path], base=3, kind="differential")
    staging = tmp_path / "staging"
    verified = verify_bundle(bundle_path, anchors_path, state_path, staging)
    assert verified.manifest["kind"] == "differential"


def test_bomb_guard_absolute_path_rejected(bundle_env):
    members = _read_all_members(bundle_env["bundle_path"])
    _rewrite_tar(bundle_env["bundle_path"], members, insert=[("/etc/evil.jsonl", b"x")])
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_UNSAFE_MEMBER"


def test_bomb_guard_dotdot_path_rejected(bundle_env):
    members = _read_all_members(bundle_env["bundle_path"])
    _rewrite_tar(bundle_env["bundle_path"], members, insert=[("tables/../../evil.jsonl", b"x")])
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_UNSAFE_MEMBER"


def test_bomb_guard_symlink_member_rejected(bundle_env):
    members = _read_all_members(bundle_env["bundle_path"])
    _rewrite_tar(bundle_env["bundle_path"], members, to_symlink={"tables/ioc.jsonl": "/etc/passwd"})
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_UNSAFE_MEMBER"


def test_bomb_guard_decompression_ratio_rejected(bundle_env):
    members = _read_all_members(bundle_env["bundle_path"])
    zeros = b"\x00" * (4 * 1024 * 1024)
    _rewrite_tar(bundle_env["bundle_path"], members, replace={"tables/ioc.jsonl": zeros})
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(
            bundle_env["bundle_path"],
            bundle_env["anchors_path"],
            bundle_env["state_path"],
            staging,
            max_ratio=10,
        )
    assert exc.value.code == "BUNDLE_DECOMPRESSION_BOMB"


def test_undeclared_member_rejected(bundle_env):
    members = _read_all_members(bundle_env["bundle_path"])
    _rewrite_tar(bundle_env["bundle_path"], members, insert=[("tables/sneaky.jsonl", b"{}\n")])
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_UNDECLARED_MEMBER"
