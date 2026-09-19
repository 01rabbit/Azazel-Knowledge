from __future__ import annotations

import hashlib
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
    to_hardlink: dict[str, str] | None = None,
    insert: list[tuple[str, bytes]] | None = None,
    insert_special: list[tarfile.TarInfo] | None = None,
) -> None:
    """Rewrite a bundle's tar with members altered, removed, or added.

    `to_hardlink` and `insert_special` exist so the archive *shapes* a verifier
    must refuse -- hardlinks, FIFOs, character and block devices -- can be put
    into a bundle at all. `insert` can only ever produce a regular file, so on
    its own it cannot reach those branches.
    """
    replace = replace or {}
    remove = remove or set()
    to_symlink = to_symlink or {}
    to_hardlink = to_hardlink or {}
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
            if info.name in to_hardlink:
                lnk = tarfile.TarInfo(name=info.name)
                lnk.type = tarfile.LNKTYPE
                lnk.linkname = to_hardlink[info.name]
                tar.addfile(lnk)
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
        for special in insert_special or []:
            tar.addfile(special)


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


def _first_declared_member(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> tuple[str, bytes]:
    manifest = _decode_manifest(members)
    declared = manifest["files"]
    for info, data in members:
        if info.name in declared:
            return info.name, data
    raise AssertionError("bundle declares no content files")


def test_duplicate_member_rejected_before_the_second_copy_is_written(bundle_env):
    """A repeated member name is refused outright, not merely caught by the hash.

    The extractor writes each member to its declared path, so a second member
    reusing that name would overwrite the first. The per-member hash check makes
    that non-substitutive, but only after the bytes have landed. The verifier
    must reject the duplicate up front instead.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    name, data = _first_declared_member(members)
    # Re-append the same name with the *same* bytes: the hash check cannot see a
    # problem here, so only an explicit duplicate control can reject it.
    _rewrite_tar(bundle_env["bundle_path"], members, insert=[(name, data)])
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_DUPLICATE_MEMBER"


def test_duplicate_member_with_different_content_rejected_as_duplicate(bundle_env):
    """A differing duplicate is a duplicate first, not a hash mismatch.

    Both codes would be safe outcomes, but the duplicate control has to fire
    before extraction for the "no byte of the second copy is written" property
    to hold, which pins the ordering here.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    name, _ = _first_declared_member(members)
    _rewrite_tar(bundle_env["bundle_path"], members, insert=[(name, b'{"evil": true}\n')])
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_DUPLICATE_MEMBER"


def test_duplicate_manifest_member_rejected(bundle_env):
    """A second manifest.json cannot be smuggled in behind the signed first one."""
    members = _read_all_members(bundle_env["bundle_path"])
    forged = json.dumps({"bundle_version": 99, "kind": "full", "files": {}}).encode()
    _rewrite_tar(bundle_env["bundle_path"], members, insert=[(MANIFEST_MEMBER, forged)])
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_DUPLICATE_MEMBER"


def test_nested_archive_member_is_inert_opaque_content(bundle_env):
    """A member whose bytes are themselves a tar.gz gets no special handling.

    Nothing in the reader opens a member's *contents* as an archive, so a nested
    archive is ordinary opaque content and stays subject to the same declared
    SHA-256 gate as any other member. Swapping a declared file's bytes for an
    archive therefore fails the hash, exactly as swapping them for any other
    bytes would -- it is not expanded, and it gets no path of its own.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    name, _ = _first_declared_member(members)

    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:gz") as nested:
        payload = b"payload that must never be expanded\n"
        info = tarfile.TarInfo(name="tables/ioc.jsonl")
        info.size = len(payload)
        nested.addfile(info, io.BytesIO(payload))
    nested_bytes = inner.getvalue()

    _rewrite_tar(bundle_env["bundle_path"], members, replace={name: nested_bytes})
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_FILE_HASH_MISMATCH"
    # And nothing was expanded: no directory was created for the nested entry.
    assert not (staging / "tables" / "ioc.jsonl").is_dir()


# --- signer role and security epoch: separate gates (Azazel-Knowledge#73) ---


def _resign(bundle_env, tmp_path: Path, members, manifest: dict) -> Path:
    """Rewrite a bundle around a modified manifest and sign it properly.

    Every epoch test needs a *validly signed* artifact, because the point is
    that a correct signature is not sufficient. Tampering without re-signing
    would fail at the signature gate and prove nothing about the epoch gate.
    """
    manifest_bytes = canonical_manifest_bytes(manifest)
    signing_key = SigningKey(bytes.fromhex(Path(bundle_env["key_path"]).read_text().strip()))
    key_id = signing_key.verify_key.encode().hex()[:8]
    signature = signing_key.sign(manifest_bytes).signature.hex()
    sig_bytes = f"{key_id}:{signature}\n".encode()

    out = tmp_path / "resigned.tar.gz"
    with tarfile.open(out, "w:gz") as tar:
        for name, data in ((MANIFEST_MEMBER, manifest_bytes), (SIGNATURE_MEMBER, sig_bytes)):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info, data in members:
            if info.name in (MANIFEST_MEMBER, SIGNATURE_MEMBER):
                continue
            new_info = tarfile.TarInfo(name=info.name)
            new_info.size = len(data)
            tar.addfile(new_info, io.BytesIO(data))
    return out


def _anchors_epoch(tmp_path: Path, bundle_env, *, minimum: int) -> Path:
    path = tmp_path / "anchors_epoch.toml"
    path.write_text(
        "threshold = 1\nrevoked = []\n"
        f"minimum_security_epoch = {minimum}\n"
        f'\n[keys]\n{bundle_env["key_id"]} = "{bundle_env["verify_hex"]}"\n',
        encoding="utf-8",
    )
    return path


def _anchors_with_role(tmp_path: Path, key_id: str, verify_hex: str, *, key_role: str, required: str) -> Path:
    path = tmp_path / "anchors_role.toml"
    path.write_text(
        "threshold = 1\n"
        "revoked = []\n"
        f'required_signer_role = "{required}"\n'
        "\n[keys]\n"
        f'{key_id} = "{verify_hex}"\n'
        "\n[key_roles]\n"
        f'{key_id} = "{key_role}"\n',
        encoding="utf-8",
    )
    return path


def test_signer_role_matching_the_requirement_is_accepted(bundle_env, tmp_path):
    anchors = _anchors_with_role(
        tmp_path,
        bundle_env["key_id"],
        bundle_env["verify_hex"],
        key_role="knowledge-lite",
        required="knowledge-lite",
    )
    verify_bundle(bundle_env["bundle_path"], anchors, bundle_env["state_path"], tmp_path / "staging")


def test_valid_signature_from_the_wrong_role_is_refused(bundle_env, tmp_path):
    """A perfect signature from a key provisioned for another purpose still fails.

    This is what makes the role a *separate* gate: the signature verifies and
    the threshold is met, so the only thing that can reject it is the role.
    """
    anchors = _anchors_with_role(
        tmp_path,
        bundle_env["key_id"],
        bundle_env["verify_hex"],
        key_role="knowledge-full",
        required="knowledge-lite",
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_SIGNER_ROLE_NOT_PERMITTED"


def test_key_with_no_declared_role_never_satisfies_a_required_role(bundle_env, tmp_path):
    """Silence is not permission: an unroled key cannot stand in for a role."""
    path = tmp_path / "anchors_noroles.toml"
    path.write_text(
        "threshold = 1\nrevoked = []\n"
        'required_signer_role = "knowledge-lite"\n'
        f'\n[keys]\n{bundle_env["key_id"]} = "{bundle_env["verify_hex"]}"\n',
        encoding="utf-8",
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], path, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_SIGNER_ROLE_NOT_PERMITTED"


def test_role_gate_is_inert_when_anchors_require_no_role(bundle_env, tmp_path):
    """Existing deployments that declare no role keep working unchanged."""
    verify_bundle(
        bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging"
    )


def test_security_epoch_below_the_anchor_minimum_is_refused(bundle_env, tmp_path):
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    manifest["security_epoch"] = 1
    _resign(bundle_env, tmp_path, members, manifest)
    anchors = _anchors_epoch(tmp_path, bundle_env, minimum=5)
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(tmp_path / "resigned.tar.gz", anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_SECURITY_EPOCH_TOO_LOW"


def test_security_epoch_at_or_above_the_minimum_is_accepted(bundle_env, tmp_path):
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    manifest["security_epoch"] = 5
    _resign(bundle_env, tmp_path, members, manifest)
    anchors = _anchors_epoch(tmp_path, bundle_env, minimum=5)
    verify_bundle(tmp_path / "resigned.tar.gz", anchors, bundle_env["state_path"], tmp_path / "staging")


def test_missing_security_epoch_is_refused_when_anchors_require_one(bundle_env, tmp_path):
    anchors = _anchors_epoch(tmp_path, bundle_env, minimum=1)
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_SECURITY_EPOCH_MISSING"


def test_epoch_gate_is_independent_of_anti_rollback(bundle_env, tmp_path):
    """A bundle can be newer by version and still fail the epoch gate.

    Anti-rollback only compares version numbers, so an artifact built before a
    key compromise passes it easily -- it is newer than everything before it.
    The epoch is the separate statement that it is no longer acceptable, and a
    test that did not set a *higher* version would not show the difference.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    manifest["bundle_version"] = 999  # unambiguously newer than any watermark
    manifest["security_epoch"] = 1
    _resign(bundle_env, tmp_path, members, manifest)
    anchors = _anchors_epoch(tmp_path, bundle_env, minimum=7)
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(tmp_path / "resigned.tar.gz", anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_SECURITY_EPOCH_TOO_LOW"


def test_manifest_cannot_supply_its_own_minimum_epoch(bundle_env, tmp_path):
    """The bundle may claim an epoch; it may not decide which epoch suffices.

    Trust comes only from anchors (F-7). A manifest carrying its own minimum is
    simply ignored, so a correctly signed artifact cannot lower the bar for
    itself.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    manifest["security_epoch"] = 1
    manifest["minimum_security_epoch"] = 1  # must have no effect
    _resign(bundle_env, tmp_path, members, manifest)
    anchors = _anchors_epoch(tmp_path, bundle_env, minimum=9)
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(tmp_path / "resigned.tar.gz", anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_SECURITY_EPOCH_TOO_LOW"


# --- archive shapes a verifier must refuse ---------------------------------


def test_bomb_guard_hardlink_member_rejected(bundle_env):
    """A hardlink is refused for the same reason as a symlink, and needs its own test.

    `_safe_member` tests `issym() or islnk()` in one expression, so a symlink
    test alone leaves the hardlink half of it unexecuted -- deleting `islnk()`
    would not turn any test red. A tar hardlink also does not carry content of
    its own, so an extractor that honoured it would produce a staged path whose
    bytes came from somewhere the manifest never hashed.

    The diagnostic is asserted, not just the code, because the catch-all
    `not isreg()` check further down refuses a hardlink too: a test that only
    asserted `BUNDLE_UNSAFE_MEMBER` would stay green with `islnk()` deleted and
    would be pinning nothing. It also matters operationally -- an operator
    reading "link member not allowed" learns the shape of what was refused,
    where "non-regular member" leaves them guessing.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    _rewrite_tar(
        bundle_env["bundle_path"], members, to_hardlink={"tables/ioc.jsonl": "tables/ioc_source.jsonl"}
    )
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_UNSAFE_MEMBER"
    assert "link member not allowed" in str(exc.value)
    assert not (staging / "tables" / "ioc.jsonl").exists()


@pytest.mark.parametrize(
    "member_type, label",
    [
        (tarfile.FIFOTYPE, "fifo"),
        (tarfile.CHRTYPE, "character device"),
        (tarfile.BLKTYPE, "block device"),
    ],
)
def test_bomb_guard_device_member_rejected(bundle_env, member_type, label):
    """FIFO and device members are refused before anything opens them.

    Nothing legitimate puts one in a knowledge bundle, and a reader that
    created one would hand the rest of the pipeline a path that blocks on read
    or addresses hardware, neither of which any declared SHA-256 describes.

    As with the hardlink case the diagnostic is asserted, because the catch-all
    `not isreg()` check would refuse these anyway: asserting only the code would
    leave the device branch dead and the test none the wiser.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    special = tarfile.TarInfo(name="tables/device.jsonl")
    special.type = member_type
    special.devmajor = 1
    special.devminor = 3
    _rewrite_tar(bundle_env["bundle_path"], members, insert_special=[special])
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_UNSAFE_MEMBER", label
    assert "device/fifo member not allowed" in str(exc.value), label
    assert not (staging / "tables" / "device.jsonl").exists()


# --- path aliases: one file on disk must not be two names in the manifest ---


def _alias_of(name: str) -> str:
    head, _, tail = name.rpartition("/")
    return f"{head}/./{tail}"


def _bundle_with_alias_member(bundle_env, tmp_path: Path, payload: bytes) -> tuple[Path, dict, str, str]:
    """A *validly signed* bundle declaring a member twice: real name and `./` alias.

    The manifest declares the honest digest for `tables/<x>.jsonl` and the
    digest of `payload` for `tables/./<x>.jsonl`. Re-signing is essential: a
    manifest edited without re-signing dies at the signature gate and would
    prove nothing about the gates after it.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    victim, _ = _first_declared_member(members)
    alias = _alias_of(victim)
    manifest["files"][alias] = hashlib.sha256(payload).hexdigest()
    members.append((tarfile.TarInfo(name=alias), payload))
    return _resign(bundle_env, tmp_path, members, manifest), manifest, victim, alias


def test_path_alias_member_rejected_though_validly_signed(bundle_env, tmp_path):
    """`tables/./x.jsonl` is refused as a member name, signature notwithstanding.

    Two manifest keys that collapse to one path on disk let a manifest declare
    the honest digest under the real name and a substituted digest under the
    alias: the duplicate guard sees two distinct raw names, the declared-files
    lookup finds each, the hash check hashes what it just wrote against the
    alias's digest -- and every gate passes while the file in staging holds the
    substituted bytes.

    The bundle here is signed with the fixture's own key, so nothing upstream
    of the member check can be what refuses it.
    """
    bundle, _, _, alias = _bundle_with_alias_member(bundle_env, tmp_path, b'{"substituted": true}\n')
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_UNSAFE_MEMBER"
    assert alias in str(exc.value)


@pytest.mark.parametrize(
    "form",
    [
        "tables/./ioc.jsonl",  # a `.` component: Path.parts drops it silently
        "tables//ioc.jsonl",  # a doubled separator
        "tables/ioc.jsonl/",  # a trailing separator
        "./tables/ioc.jsonl",  # a leading `./`
        "tables/",  # a trailing separator on a bare directory name
        ".",  # normalises to itself, so the comparison alone would pass it
        "",  # normalises to ".", so the comparison catches it
    ],
)
def test_non_canonical_member_names_rejected(bundle_env, form):
    """Every spelling that is not already its own normpath is refused.

    Each of these survives the `..`, empty-part and absolute-path checks --
    `Path("tables/./ioc.jsonl").parts` is `('tables', 'ioc.jsonl')`, same as the
    canonical spelling -- so the canonical-form check is the only thing
    standing between them and a staging path that disagrees with the name the
    manifest was keyed on. The members are deliberately *undeclared*: the name
    check has to fire before the `manifest.files` lookup, or a declared alias
    would already have been half-processed by the time anything noticed.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    _rewrite_tar(bundle_env["bundle_path"], members, insert=[(form, b"x")])
    staging = bundle_env["tmp_path"] / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_UNSAFE_MEMBER"


def test_rejected_bundle_stages_no_file_failing_its_declared_digest(bundle_env, tmp_path):
    """The effect, not the code: staging never holds bytes the manifest disowns.

    `verify_bundle`'s promise is that a file it leaves in staging answers to the
    digest `manifest.files` declares **for the path it landed on**. This asserts
    exactly that, sweeping staging after a rejected bundle rather than trusting
    the error code -- so it holds whatever new alias shape someone finds, and it
    would have failed on the `./` alias before that shape was refused: back then
    `verify_bundle` returned successfully with the substituted payload sitting
    at the victim's path while the manifest still declared the honest digest
    there.
    """
    payload = b'{"substituted": true}\n'
    bundle, manifest, victim, _ = _bundle_with_alias_member(bundle_env, tmp_path, payload)
    staging = tmp_path / "staging"

    outcome: BundleVerifyError | None = None
    try:
        verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], staging)
    except BundleVerifyError as exc:
        outcome = exc

    staged = sorted(p for p in staging.rglob("*") if p.is_file())
    for path in staged:
        relative = path.relative_to(staging).as_posix()
        assert relative in manifest["files"], f"staged a path the manifest never declared: {relative}"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest["files"][relative], (
            f"staged bytes at {relative} do not match the digest the manifest declares for it"
        )
    assert payload not in b"".join(p.read_bytes() for p in staged)
    assert victim in manifest["files"]
    assert outcome is not None, "a bundle naming one file under two names must not verify"
    assert outcome.code == "BUNDLE_UNSAFE_MEMBER"
