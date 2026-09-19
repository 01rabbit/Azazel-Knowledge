from __future__ import annotations

import gzip
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

from azazel_knowledge.bundle import verify as verify_module
from pathlib import PurePosixPath

from azazel_knowledge.bundle.verify import (
    DEFAULT_MAX_MEMBER_DEPTH,
    DEFAULT_MAX_MEMBER_NAME_BYTES,
    BUNDLE_FORMAT_VERSION,
    DEFAULT_MAX_MEMBERS,
    DEFAULT_MAX_RATIO,
    MANIFEST_FORMAT_FIELD,
    MAX_SUPPORTED_BUNDLE_FORMAT,
    MIN_SUPPORTED_BUNDLE_FORMAT,
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
    # Three separate caps raise this one code, so the code alone does not say
    # which one fired and a test asserting only the code could be satisfied by
    # either of the other two. The diagnostic is what distinguishes them.
    assert "decompression ratio exceeds 10:1" in str(exc.value)


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


# --- helpers for artifacts the CLI cannot be asked to build -----------------


_OMIT = object()


def _sign_bytes(bundle_env, manifest_bytes: bytes) -> bytes:
    signing_key = SigningKey(bytes.fromhex(Path(bundle_env["key_path"]).read_text().strip()))
    key_id = signing_key.verify_key.encode().hex()[:8]
    return f"{key_id}:{signing_key.sign(manifest_bytes).signature.hex()}\n".encode()


def _custom_bundle(
    bundle_env,
    out: Path,
    *,
    contents: dict[str, bytes] | None = None,
    declared_extra: dict[str, str] | None = None,
    manifest_extra: dict | None = None,
    raw_members: bytes = b"",
) -> Path:
    """A *validly signed* bundle with arbitrary members and manifest fields.

    Every gate downstream of the signature needs an artifact that gets past the
    signature, or the test proves nothing about the gate it names: a tampered
    manifest dies at `BUNDLE_SIGNATURE_THRESHOLD_NOT_MET` and never reaches the
    thing under test. `raw_members` carries pre-encoded tar blocks for shapes
    `tarfile` will not write, such as a GNU sparse member.
    """
    contents = dict(contents or {})
    files = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
    files.update(declared_extra or {})
    manifest = {
        MANIFEST_FORMAT_FIELD: BUNDLE_FORMAT_VERSION,
        "bundle_version": 1,
        "base_version": None,
        "kind": "full",
        "compression": "gzip",
        "files": files,
        "tables": [],
    }
    manifest.update(manifest_extra or {})
    manifest = {key: value for key, value in manifest.items() if value is not _OMIT}

    manifest_bytes = canonical_manifest_bytes(manifest)
    sig_bytes = _sign_bytes(bundle_env, manifest_bytes)

    raw = io.BytesIO()
    tar = tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT)
    for name, data in [(MANIFEST_MEMBER, manifest_bytes), (SIGNATURE_MEMBER, sig_bytes)] + [
        (name, contents[name]) for name in sorted(contents)
    ]:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(data))
    if raw_members:
        tar.fileobj.write(raw_members)
        tar.offset += len(raw_members)
    tar.close()

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as fh:
        with gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0) as gz:
            gz.write(raw.getvalue())
    return out


def _anchors_file(bundle_env, tmp_path: Path, name: str, *, body: str = "", key_role: str | None = None) -> Path:
    """An anchors document with arbitrary top-level fields and the fixture key."""
    path = tmp_path / name
    text = (
        "threshold = 1\n"
        "revoked = []\n"
        f"{body}"
        "\n[keys]\n"
        f'{bundle_env["key_id"]} = "{bundle_env["verify_hex"]}"\n'
    )
    if key_role is not None:
        text += f'\n[key_roles]\n{bundle_env["key_id"]} = "{key_role}"\n'
    path.write_text(text, encoding="utf-8")
    return path


# --- the compatibility gate (Azazel-Knowledge#73) ---------------------------
#
# A fifth gate, and the only one that asks whether the document can be read at
# all rather than whether a readable document is acceptable.


def test_builder_stamps_the_format_version_this_reader_supports(bundle_env):
    """A bundle the builder produces declares a format, and declares one we read.

    Without the builder half there is nothing for the gate to compare against
    and every artifact falls back to the unversioned default forever.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    assert manifest[MANIFEST_FORMAT_FIELD] == BUNDLE_FORMAT_VERSION
    assert MIN_SUPPORTED_BUNDLE_FORMAT <= BUNDLE_FORMAT_VERSION <= MAX_SUPPORTED_BUNDLE_FORMAT


def test_format_version_is_not_the_anti_rollback_counter(bundle_env):
    """The two version fields are different fields with different jobs.

    `bundle_version` moves on every build and is what the watermark compares;
    the format version moves only when the document's shape changes. A reader
    that conflated them would refuse every ordinary rebuild.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    assert MANIFEST_FORMAT_FIELD != "bundle_version"
    assert manifest["bundle_version"] == 1
    assert manifest[MANIFEST_FORMAT_FIELD] == BUNDLE_FORMAT_VERSION


def test_future_format_version_is_refused_though_every_other_gate_passes(bundle_env, tmp_path):
    """Compatibility is a gate of its own, in the way the epoch gate is.

    The artifact here is signed by a key the anchors trust, carrying the role
    those anchors require, declaring an epoch above their minimum, at a version
    far above any watermark. Every other gate is unambiguously satisfied, so
    the only thing that can refuse it is the format it declares.
    """
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "future.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra={
            MANIFEST_FORMAT_FIELD: MAX_SUPPORTED_BUNDLE_FORMAT + 1,
            "bundle_version": 999,
            "security_epoch": 9,
        },
    )
    anchors = _anchors_file(
        bundle_env,
        tmp_path,
        "anchors_all_pass.toml",
        body='required_signer_role = "knowledge-lite"\nminimum_security_epoch = 5\n',
        key_role="knowledge-lite",
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_FORMAT_UNSUPPORTED"
    assert str(MAX_SUPPORTED_BUNDLE_FORMAT + 1) in str(exc.value)


def test_retired_format_version_below_the_floor_is_refused(bundle_env, tmp_path):
    """The range has two ends; a format this reader has dropped is refused too."""
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "ancient.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra={MANIFEST_FORMAT_FIELD: MIN_SUPPORTED_BUNDLE_FORMAT - 1},
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_FORMAT_UNSUPPORTED"


@pytest.mark.parametrize("declared", ["1", 1.0, True, None, [1], {"v": 1}])
def test_non_integer_format_version_is_refused_under_its_own_code(bundle_env, tmp_path, declared):
    """A version that is not a version is refused as malformed, not as a shape error.

    `"1"` compares as neither >= nor <= an integer bound in Python, so a gate
    that skipped the type check would raise `TypeError` out of `verify_bundle`
    -- not a `BundleVerifyError` at all, and nothing a caller can dispatch on.
    `True` is included because `isinstance(True, int)` is true in Python and a
    naive check waves it through.
    """
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "malformed.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra={MANIFEST_FORMAT_FIELD: declared},
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_FORMAT_INVALID"


def test_compatibility_code_is_distinct_from_the_shape_check(bundle_env, tmp_path):
    """An unreadable format and a malformed document are different answers.

    `_validate_manifest_shape` already refuses documents with
    `BUNDLE_MANIFEST_INVALID`. If the compatibility gate reused that code an
    operator could not tell "your reader is too old" from "this file is
    corrupt", which are opposite remedies -- upgrade versus rebuild.
    """
    unsupported = _custom_bundle(
        bundle_env,
        tmp_path / "unsupported.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra={MANIFEST_FORMAT_FIELD: MAX_SUPPORTED_BUNDLE_FORMAT + 1},
    )
    malformed = _custom_bundle(
        bundle_env,
        tmp_path / "badkind.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra={"kind": "sideways"},
    )
    with pytest.raises(BundleVerifyError) as unsupported_exc:
        verify_bundle(unsupported, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "s1")
    with pytest.raises(BundleVerifyError) as malformed_exc:
        verify_bundle(malformed, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "s2")
    assert unsupported_exc.value.code == "BUNDLE_FORMAT_UNSUPPORTED"
    assert malformed_exc.value.code == "BUNDLE_MANIFEST_INVALID"
    assert unsupported_exc.value.code != malformed_exc.value.code


def test_an_incompatible_bundle_reports_incompatibility_not_a_later_gate(bundle_env, tmp_path):
    """Ordering matters, and it is the whole reason the gate exists.

    A future format is free to move, rename, or redefine any manifest field.
    Here the artifact declares an unreadable format *and* no `security_epoch`
    while the anchors demand one. Run after the epoch gate, this would be
    reported as `BUNDLE_SECURITY_EPOCH_MISSING` and send the operator looking
    for a missing epoch instead of an out-of-date reader: a misleading code,
    which is worse than a blunt one.
    """
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "future_no_epoch.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra={MANIFEST_FORMAT_FIELD: MAX_SUPPORTED_BUNDLE_FORMAT + 1},
    )
    anchors = _anchors_file(bundle_env, tmp_path, "anchors_epoch_req.toml", body="minimum_security_epoch = 3\n")
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_FORMAT_UNSUPPORTED"


def test_bundle_without_a_format_version_is_read_as_format_one(bundle_env, tmp_path):
    """Absence means format 1, so artifacts built before the field still verify.

    A manifest with no `bundle_format_version` can only have come from a
    builder older than the field, and every such builder emitted the one format
    this reader still parses. Refusing absence would break every bundle in the
    field to guard against a format that cannot be hiding behind it.
    """
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "unversioned.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra={MANIFEST_FORMAT_FIELD: _OMIT},
    )
    assert MANIFEST_FORMAT_FIELD not in _decode_manifest(_read_all_members(bundle))
    verified = verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging")
    assert MANIFEST_FORMAT_FIELD not in verified.manifest


def test_absent_format_version_is_a_default_not_an_exemption(bundle_env, tmp_path, monkeypatch):
    """Absence resolves to a *value* and is then compared like any other.

    This is what keeps the concession above from becoming a permanent hole. An
    implementation that treated a missing field as "skip the check" would look
    identical today and would still wave the old artifacts through on the day
    format 1 is retired -- exactly the stale artifacts the retirement is aimed
    at. Raising the floor is simulated here rather than waited for.
    """
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "unversioned.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra={MANIFEST_FORMAT_FIELD: _OMIT},
    )
    monkeypatch.setattr(verify_module, "MIN_SUPPORTED_BUNDLE_FORMAT", 2)
    monkeypatch.setattr(verify_module, "MAX_SUPPORTED_BUNDLE_FORMAT", 2)
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_FORMAT_UNSUPPORTED"
    assert "1" in str(exc.value)


# --- the export-policy gate (Azazel-Knowledge#73) ---------------------------
#
# The builder already refuses to sign content that disagrees with the policy
# digest recorded beside it. That answers "does this artifact describe the
# rules that produced it". It cannot answer "are those rules ones I accept",
# because Knowledge signs whatever policy its operator supplies -- so without a
# reader-side gate a consumer has no way to refuse an artifact built under a
# privacy policy it rejects. It can only take what it is sent.


_POLICY_A = "a" * 64
_POLICY_B = "b" * 64


def _policy_manifest_extra(digest: str | object, **overrides) -> dict:
    """A Lite-shaped `profile` block carrying (or omitting) a policy digest."""
    selection_inputs: dict = {
        "intel_generation": 7,
        "stats_generation": 3,
        "attack_version": "v15.1",
        "config_hash": "c" * 16,
        "profile_id": "knowledge-lite-16g",
        "as_of": "2026-01-02T00:00:00Z",
    }
    if digest is not _OMIT:
        selection_inputs["export_policy_digest"] = digest
    extra = {"profile": {"selection_inputs": selection_inputs}}
    extra.update(overrides)
    return extra


def test_export_policy_gate_is_inert_when_anchors_accept_none(bundle_env, tmp_path):
    """Anchors that name no accepted digest keep working exactly as before.

    This mirrors the `required_signer_role` precedent: an optional anchors
    field is inert when absent, so every anchors document written before the
    gate existed stays valid and no deployment is broken by adding it. The
    bundle here records no policy digest at all and must still verify.
    """
    verify_bundle(
        bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging"
    )


def test_bundle_built_under_an_accepted_policy_is_admitted(bundle_env, tmp_path):
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "policy_ok.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra=_policy_manifest_extra(_POLICY_A),
    )
    anchors = _anchors_file(
        bundle_env, tmp_path, "anchors_policy.toml", body=f'accepted_export_policy_digests = ["{_POLICY_A}"]\n'
    )
    verified = verify_bundle(bundle, anchors, bundle_env["state_path"], tmp_path / "staging")
    assert verified.manifest["profile"]["selection_inputs"]["export_policy_digest"] == _POLICY_A


def test_bundle_built_under_an_unaccepted_policy_is_refused(bundle_env, tmp_path):
    """The consumer's answer to a privacy policy it did not agree to.

    The artifact is correctly signed and internally consistent -- the builder's
    own digest check passed on the way out. The only thing wrong with it is the
    policy it was built under, which is a judgement only the consumer can make.
    """
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "policy_bad.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra=_policy_manifest_extra(_POLICY_B),
    )
    anchors = _anchors_file(
        bundle_env, tmp_path, "anchors_policy.toml", body=f'accepted_export_policy_digests = ["{_POLICY_A}"]\n'
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_EXPORT_POLICY_NOT_ACCEPTED"
    assert _POLICY_B in str(exc.value)


@pytest.mark.parametrize(
    "recorded, label",
    [
        (_OMIT, "no export_policy_digest key at all"),
        (None, "an explicit null"),
        ("", "an empty string"),
        (123, "a non-string"),
    ],
)
def test_a_bundle_recording_no_policy_digest_cannot_satisfy_a_requirement(
    bundle_env, tmp_path, recorded, label
):
    """Absence must not satisfy a requirement -- the case a naive gate gets wrong.

    A membership test written as "if a digest is recorded and it is not
    accepted, refuse" admits every artifact that records nothing, which is
    precisely the artifact a consumer most needs to refuse: one whose privacy
    provenance is unstated. Each spelling of "nothing" is checked, because
    `None`, `""` and `123` each pass a bare `in` test differently.
    """
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "policy_silent.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra=_policy_manifest_extra(recorded),
    )
    anchors = _anchors_file(
        bundle_env, tmp_path, "anchors_policy.toml", body=f'accepted_export_policy_digests = ["{_POLICY_A}"]\n'
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_EXPORT_POLICY_MISSING", label


def test_a_bundle_with_no_profile_block_cannot_satisfy_a_policy_requirement(bundle_env, tmp_path):
    """A non-Lite artifact records no policy, so anchors demanding one refuse it.

    Anchors that name accepted digests are stating that this consumer only
    accepts artifacts whose privacy rules it has vetted. A general bundle has
    no `profile` block and therefore no such statement, so it does not qualify.
    """
    anchors = _anchors_file(
        bundle_env, tmp_path, "anchors_policy.toml", body=f'accepted_export_policy_digests = ["{_POLICY_A}"]\n'
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_EXPORT_POLICY_MISSING"


def test_policy_gate_is_independent_of_every_other_gate(bundle_env, tmp_path):
    """Refused on policy alone, with all five other gates unambiguously passing.

    Valid signature over the manifest, signed by a key the anchors trust,
    carrying the role they require, declaring an epoch above their minimum, at
    a `bundle_version` far above any watermark, in a supported format. Nothing
    but the policy digest can be what rejects it.
    """
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "policy_independent.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra=_policy_manifest_extra(_POLICY_B, bundle_version=999, security_epoch=9),
    )
    anchors = _anchors_file(
        bundle_env,
        tmp_path,
        "anchors_everything.toml",
        body=(
            'required_signer_role = "knowledge-lite"\n'
            "minimum_security_epoch = 5\n"
            f'accepted_export_policy_digests = ["{_POLICY_A}"]\n'
        ),
        key_role="knowledge-lite",
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_EXPORT_POLICY_NOT_ACCEPTED"


def test_manifest_cannot_widen_the_set_of_accepted_policies(bundle_env, tmp_path):
    """The bundle records which policy it used; it does not decide which are acceptable.

    Trust comes only from anchors (F-7). A manifest carrying its own
    `accepted_export_policy_digests` is ignored, so a correctly signed artifact
    cannot approve its own privacy rules -- otherwise any holder of a valid key
    could export under any policy at all.
    """
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "policy_selfapproved.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra=_policy_manifest_extra(
            _POLICY_B, accepted_export_policy_digests=[_POLICY_B]
        ),
    )
    anchors = _anchors_file(
        bundle_env, tmp_path, "anchors_policy.toml", body=f'accepted_export_policy_digests = ["{_POLICY_A}"]\n'
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_EXPORT_POLICY_NOT_ACCEPTED"


def test_anchors_may_accept_more_than_one_policy_digest(bundle_env, tmp_path):
    """A policy rotation leaves both digests acceptable for a while."""
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "policy_rotating.tar.gz",
        contents={"tables/ioc.jsonl": b"{}\n"},
        manifest_extra=_policy_manifest_extra(_POLICY_B),
    )
    anchors = _anchors_file(
        bundle_env,
        tmp_path,
        "anchors_two.toml",
        body=f'accepted_export_policy_digests = ["{_POLICY_A}", "{_POLICY_B}"]\n',
    )
    verify_bundle(bundle, anchors, bundle_env["state_path"], tmp_path / "staging")


@pytest.mark.parametrize(
    "body, label",
    [
        ('accepted_export_policy_digests = "aaaa"\n', "a bare string, not a list"),
        ("accepted_export_policy_digests = []\n", "an empty list accepts nothing and is surely a mistake"),
        ('accepted_export_policy_digests = ["aaaa", ""]\n', "an empty digest in the list"),
        ("accepted_export_policy_digests = [1, 2]\n", "non-string digests"),
    ],
)
def test_malformed_accepted_policy_anchors_are_refused(bundle_env, tmp_path, body, label):
    """A misconfigured anchors file fails closed, as the other optional fields do.

    An empty list is included deliberately: read as "accept these", it accepts
    nothing and would refuse every artifact, which is far more likely to be a
    truncated edit than an intention. Guessing which was meant is how a gate
    ends up silently disabled.
    """
    anchors = _anchors_file(bundle_env, tmp_path, "anchors_broken.toml", body=body)
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle_env["bundle_path"], anchors, bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_ANCHORS_INVALID", label


# --- the member-count cap (Azazel-Knowledge#73) -----------------------------
#
# The byte caps bound how much lands in staging and say nothing about how many
# files do. Every declared file costs a `mkdir -p` and a create, and an 8 MiB
# manifest can name on the order of 10**5 of them while declaring no content at
# all -- inode exhaustion, which no byte cap can see.


def _empty_members(count: int, *, prefix: str = "tables/f") -> dict[str, bytes]:
    return {f"{prefix}{index:05d}.jsonl": b"" for index in range(count)}


def test_a_real_full_bundle_stays_far_under_the_member_cap(bundle_env, tmp_path):
    """A cap a legitimate bundle trips is worse than no cap, so pin the margin.

    `bundle_build.py build` emits one member per eligible intel table plus the
    two metadata members. If a schema change ever pushed a real build near the
    cap this fails here, at the cheapest possible moment, rather than in the
    field on an artifact that is already signed.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    assert len(members) <= DEFAULT_MAX_MEMBERS
    assert len(members) * 4 <= DEFAULT_MAX_MEMBERS, (
        f"a full build already emits {len(members)} of {DEFAULT_MAX_MEMBERS} permitted members; "
        "the cap no longer has room for ordinary schema growth"
    )
    verify_bundle(
        bundle_env["bundle_path"], bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging"
    )


def test_inode_bomb_is_refused_at_the_default_cap(bundle_env, tmp_path):
    """Members far beyond the cap, each an empty file whose digest checks out.

    Every byte cap is satisfied here with room to spare -- the content is
    nothing at all -- which is the point: this is a count attack, and only a
    count cap sees it. The default is exercised rather than an override, so the
    shipped value is what the test pins.
    """
    contents = _empty_members(DEFAULT_MAX_MEMBERS + 50)
    bundle = _custom_bundle(bundle_env, tmp_path / "inode_bomb.tar.gz", contents=contents)
    staging = tmp_path / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_TOO_MANY_MEMBERS"
    assert str(DEFAULT_MAX_MEMBERS) in str(exc.value)


def test_member_cap_refuses_before_a_single_path_is_created(bundle_env, tmp_path):
    """Fail-closed means nothing on disk, not merely nothing that verifies.

    The cap exists to stop staging filling with entries, so a refusal that
    happened after the directories were made would have already done the damage
    it was meant to prevent.
    """
    contents = _empty_members(DEFAULT_MAX_MEMBERS + 50, prefix="deep/nest/g")
    bundle = _custom_bundle(bundle_env, tmp_path / "inode_bomb.tar.gz", contents=contents)
    staging = tmp_path / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_TOO_MANY_MEMBERS"
    assert list(staging.rglob("*")) == []


def test_member_cap_counts_the_two_metadata_members(bundle_env, tmp_path):
    """`manifest.json` and `manifest.sig` are members and are counted as members.

    The cap is stated over tar members, so a bundle declaring exactly
    `max_members` content files carries `max_members + 2` and must be refused.
    Counting only `manifest.files` would let every bundle quietly exceed the
    number the cap names -- a small error, but the kind that makes a stated
    bound untrue.
    """
    cap = 8
    at_the_limit = _custom_bundle(
        bundle_env, tmp_path / "exact.tar.gz", contents=_empty_members(cap - 2)
    )
    verify_bundle(
        at_the_limit, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "s_ok", max_members=cap
    )

    one_over = _custom_bundle(bundle_env, tmp_path / "over.tar.gz", contents=_empty_members(cap - 1))
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(
            one_over, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "s_bad", max_members=cap
        )
    assert exc.value.code == "BUNDLE_TOO_MANY_MEMBERS"
    assert f"{cap + 1} members in all" in str(exc.value)


def test_member_cap_is_overridable_like_every_other_cap(bundle_env, tmp_path):
    """The same override plumbing the byte caps have, so a caller can retune it."""
    contents = _empty_members(20)
    bundle = _custom_bundle(bundle_env, tmp_path / "twenty.tar.gz", contents=contents)
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(
            bundle, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "s1", max_members=5
        )
    assert exc.value.code == "BUNDLE_TOO_MANY_MEMBERS"
    verify_bundle(
        bundle, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "s2", max_members=1000
    )


def test_manifest_files_must_be_an_object(bundle_env, tmp_path):
    """A `files` that is not a mapping is refused, not crashed on.

    The member cap and the extractor both read `files` as a name -> digest
    mapping. Without this check a manifest declaring it as a list reached
    `dict(...)` inside the extractor and died with a bare `ValueError`, which
    is not a `BundleVerifyError` and not something a caller can dispatch on.
    """
    bundle = _custom_bundle(
        bundle_env, tmp_path / "files_list.tar.gz", manifest_extra={"files": ["tables/ioc.jsonl"]}
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_MANIFEST_INVALID"
    assert "files" in str(exc.value)


# --- expansion caps, each fired on its own (Azazel-Knowledge#73) ------------
#
# All three raise BUNDLE_DECOMPRESSION_BOMB, so the code alone cannot say which
# one fired: a test asserting only the code would pass while the branch it
# meant to cover was dead. Each test therefore sets the other two caps
# unambiguously non-binding *and* asserts the branch's own diagnostic. The
# code is left shared on purpose -- ADR-0015 records it by name, and splitting
# it would falsify a decided document to buy what the diagnostic already gives.

_NON_BINDING_BYTES = 1024 * 1024 * 1024
_NON_BINDING_RATIO = 10**9


def test_per_file_expansion_cap_fires_with_the_other_caps_non_binding(bundle_env, tmp_path):
    """One member over the per-file cap, where neither other cap can reach.

    The bundle is signed and its digests are honest, so with this branch gone
    nothing else refuses it: the member simply lands in staging whole.
    """
    payload = b"\x00" * (1024 * 1024)
    bundle = _custom_bundle(
        bundle_env, tmp_path / "per_file.tar.gz", contents={"tables/big.jsonl": payload}
    )
    staging = tmp_path / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(
            bundle,
            bundle_env["anchors_path"],
            bundle_env["state_path"],
            staging,
            max_file_bytes=256 * 1024,
            max_total_bytes=_NON_BINDING_BYTES,
            max_ratio=_NON_BINDING_RATIO,
        )
    assert exc.value.code == "BUNDLE_DECOMPRESSION_BOMB"
    assert "exceeds per-file cap" in str(exc.value)
    assert (staging / "tables" / "big.jsonl").stat().st_size <= 256 * 1024


def test_total_expansion_cap_fires_across_members(bundle_env, tmp_path):
    """The total cap is cumulative, which is what makes it not the per-file cap.

    Neither member exceeds the per-file cap; together they exceed the total.
    The first is staged whole and the second is cut off, which is the shape of
    a cumulative bound and could not be produced by a per-member one.
    """
    half = b"\x00" * (1024 * 1024)
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "total.tar.gz",
        contents={"tables/a.jsonl": half, "tables/b.jsonl": half + b"x"},
    )
    staging = tmp_path / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(
            bundle,
            bundle_env["anchors_path"],
            bundle_env["state_path"],
            staging,
            max_file_bytes=4 * 1024 * 1024,
            max_total_bytes=1536 * 1024,
            max_ratio=_NON_BINDING_RATIO,
        )
    assert exc.value.code == "BUNDLE_DECOMPRESSION_BOMB"
    assert "bundle exceeds total size cap" in str(exc.value)
    assert (staging / "tables" / "a.jsonl").stat().st_size == len(half)
    assert (staging / "tables" / "b.jsonl").stat().st_size < len(half)


def test_decompression_ratio_cap_fires_at_its_shipped_default(bundle_env, tmp_path):
    """The ratio cap, exercised at `DEFAULT_MAX_RATIO` rather than an override.

    A cap is only worth what its default is worth, and an override-only test
    says nothing about the number that actually ships. Compressible content
    makes this reachable in a unit test: 4 MiB of zeros gzips to a few KiB, so
    the shipped 100:1 bound is crossed by a wide margin while the per-file
    (512 MiB) and total (4 GiB) defaults stay far away -- the same reason the
    per-file and total defaults cannot be exercised here and are pinned with
    overrides above.
    """
    payload = b"\x00" * (4 * 1024 * 1024)
    bundle = _custom_bundle(bundle_env, tmp_path / "ratio.tar.gz", contents={"tables/zeros.jsonl": payload})
    assert bundle.stat().st_size * DEFAULT_MAX_RATIO < len(payload), (
        "premise of this test: the artifact on disk must be small enough that the default "
        "ratio bound is crossed"
    )
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "staging")
    assert exc.value.code == "BUNDLE_DECOMPRESSION_BOMB"
    assert f"decompression ratio exceeds {DEFAULT_MAX_RATIO}:1" in str(exc.value)


# --- sparse members (ADR-0015, "covered transitively") ----------------------


def _octal_field(value: int, width: int) -> bytes:
    return ("%0*o" % (width - 1, value)).encode("ascii") + b"\0"


def _gnu_sparse_member(name: str, stored: bytes, real_size: int) -> bytes:
    """Tar blocks for a GNU sparse member: `stored` bytes, `real_size` delivered.

    `tarfile` reads GNU sparse archives but will not write one, so the header
    is assembled by hand: typeflag `S`, one sparse region placed at the end of
    the file, `isextended` clear, and the real size in the GNU `realsize`
    field. Everything before the region reads back as holes -- zero bytes the
    archive never carried.
    """
    info = tarfile.TarInfo(name=name)
    info.size = len(stored)
    info.mtime = 0
    info.mode = 0o644
    header = bytearray(info.tobuf(format=tarfile.GNU_FORMAT))
    header[156:157] = b"S"
    header[386:398] = _octal_field(real_size - len(stored), 12)  # region offset
    header[398:410] = _octal_field(len(stored), 12)  # region length
    header[482:483] = b"\0"  # no extended sparse headers follow
    header[483:495] = _octal_field(real_size, 12)  # the size a reader delivers
    header[148:156] = b" " * 8
    unsigned, _signed = tarfile.calc_chksums(bytes(header))
    header[148:156] = ("%06o\0 " % unsigned).encode("ascii")
    padding = b"\0" * (-len(stored) % 512)
    return bytes(header) + stored + padding


def _sparse_expansion(stored: bytes, real_size: int) -> bytes:
    return b"\0" * (real_size - len(stored)) + stored


def test_a_sparse_member_is_not_caught_by_the_non_regular_catch_all(bundle_env, tmp_path):
    """Pin the surprise first: `isreg()` is true for a GNU sparse member.

    ADR-0015 records sparse members as "covered transitively (`isreg()` is
    required and expansion is capped)". Half of that is not so: CPython's
    `REGULAR_TYPES` includes `GNUTYPE_SPARSE`, so `_safe_member`'s
    `not member.isreg()` catch-all lets a sparse member straight through and
    the expansion caps are the *only* thing covering it. Asserting this here
    means the test below cannot be quietly passing because the catch-all fired.
    """
    stored = b"A" * 1024
    real_size = 8 * 1024 * 1024
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "sparse_shape.tar.gz",
        declared_extra={"tables/sparse.jsonl": hashlib.sha256(_sparse_expansion(stored, real_size)).hexdigest()},
        raw_members=_gnu_sparse_member("tables/sparse.jsonl", stored, real_size),
    )
    with tarfile.open(bundle, "r|gz") as tar:
        shapes = {member.name: member for member in tar}
    sparse_member = shapes["tables/sparse.jsonl"]
    assert sparse_member.type == tarfile.GNUTYPE_SPARSE
    assert sparse_member.isreg() is True
    assert sparse_member.islnk() is False and sparse_member.issym() is False
    assert sparse_member.size == real_size  # 1 KiB on the wire, 8 MiB delivered


def test_sparse_member_expansion_is_capped(bundle_env, tmp_path):
    """A sparse member delivers far more than it carries, and the cap stops it.

    1 KiB of archived data expands to 8 MiB of mostly holes. The manifest
    declares the honest digest of that 8 MiB, and the bundle is signed, so
    every other gate passes -- with the per-file cap removed the whole 8 MiB
    verifies and lands in staging. The other two caps are set non-binding so
    the diagnostic identifies which branch refused it.
    """
    stored = b"A" * 1024
    real_size = 8 * 1024 * 1024
    cap = 1024 * 1024
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "sparse_bomb.tar.gz",
        declared_extra={"tables/sparse.jsonl": hashlib.sha256(_sparse_expansion(stored, real_size)).hexdigest()},
        raw_members=_gnu_sparse_member("tables/sparse.jsonl", stored, real_size),
    )
    assert bundle.stat().st_size < 64 * 1024, "the artifact must stay tiny for this to be an expansion"
    staging = tmp_path / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(
            bundle,
            bundle_env["anchors_path"],
            bundle_env["state_path"],
            staging,
            max_file_bytes=cap,
            max_total_bytes=_NON_BINDING_BYTES,
            max_ratio=_NON_BINDING_RATIO,
        )
    assert exc.value.code == "BUNDLE_DECOMPRESSION_BOMB"
    assert "exceeds per-file cap" in str(exc.value)
    staged = staging / "tables" / "sparse.jsonl"
    assert staged.stat().st_size <= cap
    assert staged.stat().st_size < real_size


def test_sparse_member_within_the_caps_is_ordinary_content(bundle_env, tmp_path):
    """Sparseness is not itself a refusal, so the caps are the whole control.

    Stated explicitly because the previous test would read the same if sparse
    members were rejected outright: they are not, and a reader that relied on
    a shape check to stop them would be relying on something that is not there.
    """
    stored = b"A" * 512
    real_size = 4096
    bundle = _custom_bundle(
        bundle_env,
        tmp_path / "sparse_small.tar.gz",
        declared_extra={"tables/sparse.jsonl": hashlib.sha256(_sparse_expansion(stored, real_size)).hexdigest()},
        raw_members=_gnu_sparse_member("tables/sparse.jsonl", stored, real_size),
    )
    staging = tmp_path / "staging"
    verified = verify_bundle(bundle, bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert "tables/sparse.jsonl" in verified.file_paths
    assert (staging / "tables" / "sparse.jsonl").read_bytes() == _sparse_expansion(stored, real_size)


# --- the inode bomb the member cap does not close --------------------------


def _resigned_with_extra_member(bundle_env, tmp_path, member_name: str, payload: bytes) -> Path:
    """A validly signed bundle declaring one extra member under `member_name`.

    Signed properly on purpose: the point of each test below is that a bundle
    which clears every trust gate is still refused, so a signature failure
    would prove nothing.
    """
    members = _read_all_members(bundle_env["bundle_path"])
    manifest = _decode_manifest(members)
    manifest["files"][member_name] = hashlib.sha256(payload).hexdigest()
    out = _resign(bundle_env, tmp_path, members, manifest)

    body = _read_all_members(out)
    with tarfile.open(out, "w:gz") as tar:
        for info, data in body:
            ni = tarfile.TarInfo(name=info.name)
            ni.size = len(data) if data is not None else 0
            tar.addfile(ni, io.BytesIO(data) if data is not None else None)
        ni = tarfile.TarInfo(name=member_name)
        ni.size = len(payload)
        tar.addfile(ni, io.BytesIO(payload))
    return out


def test_a_deep_member_path_is_refused_before_a_directory_is_created(bundle_env, tmp_path):
    """One member, thousands of directories: the member cap cannot see this.

    `DEFAULT_MAX_MEMBERS` bounds declared files. Extraction creates a directory
    per path component, so a *single* member whose name is `a/b/c/...` makes as
    many directories as it has components -- an inode bomb that is one member
    and therefore passes the member cap untouched.

    The assertion that matters is not the error code but that **none of the
    bomb's own directories exist**: a cap that refused after
    `mkdir(parents=True)` had run would have created the very directories it
    exists to prevent. Staging as a whole is not empty and must not be asserted
    to be -- the forged member sits at the end of the tar, so the bundle's
    legitimate members are already extracted when the cap fires, which is the
    normal fail-closed behaviour the importer relies on (it discards staging).
    """
    deep = "/".join(f"d{i}" for i in range(DEFAULT_MAX_MEMBER_DEPTH + 1)) + "/x.jsonl"
    forged = _resigned_with_extra_member(bundle_env, tmp_path, deep, b"{}\n")

    staging = tmp_path / "staging-deep"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(forged, bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_MEMBER_PATH_TOO_DEEP"
    assert not (staging / "d0").exists(), "the bomb's first directory was created"
    assert not (staging / deep).exists()


def test_the_depth_cap_admits_the_deepest_shape_a_builder_emits(bundle_env, tmp_path):
    """A real bundle must not be refused by the bound that guards against bombs.

    Both builders write two-component names (`tables/<t>.jsonl`,
    `deltas/<t>.jsonl`) and the metadata members are one, so the shipped cap has
    to sit above 2. Asserted against the real bundle rather than a copied
    number, so a builder that started nesting deeper fails here rather than in
    the field on a signed artifact.
    """
    deepest = max(
        len(PurePosixPath(info.name).parts)
        for info, _ in _read_all_members(bundle_env["bundle_path"])
    )
    assert deepest <= DEFAULT_MAX_MEMBER_DEPTH
    assert deepest * 4 <= DEFAULT_MAX_MEMBER_DEPTH, (
        f"the deepest real member is {deepest} components against a cap of "
        f"{DEFAULT_MAX_MEMBER_DEPTH}; the headroom this cap was sized for is gone"
    )


def test_an_overlong_member_name_is_refused_with_a_bundle_code(bundle_env, tmp_path):
    """Without this the filesystem refuses it, with an OSError and no BUNDLE_ code.

    A caller that dispatches on `BundleVerifyError` would see an unhandled
    exception instead of a refusal. Depth alone does not cover it: this name is
    two components deep and still far past any `NAME_MAX`.
    """
    overlong = "tables/" + ("a" * (DEFAULT_MAX_MEMBER_NAME_BYTES + 1)) + ".jsonl"
    forged = _resigned_with_extra_member(bundle_env, tmp_path, overlong, b"{}\n")

    staging = tmp_path / "staging-long"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(forged, bundle_env["anchors_path"], bundle_env["state_path"], staging)
    assert exc.value.code == "BUNDLE_MEMBER_NAME_TOO_LONG"
    # Probing the path itself would raise ENAMETOOLONG from the test rather
    # than the code under test, so walk what exists and assert nothing that
    # long was written.
    assert all(
        len(entry.name.encode("utf-8")) <= DEFAULT_MAX_MEMBER_NAME_BYTES
        for entry in staging.rglob("*")
    )


def test_the_two_member_shape_caps_are_independent(bundle_env, tmp_path):
    """Each cap fires on its own shape, so neither test can pass on the other.

    A deep name that is short, and a long name that is shallow.
    """
    deep_short = "/".join("d" for _ in range(DEFAULT_MAX_MEMBER_DEPTH + 1)) + "/x"
    assert len(deep_short.encode()) < DEFAULT_MAX_MEMBER_NAME_BYTES
    forged = _resigned_with_extra_member(bundle_env, tmp_path, deep_short, b"{}\n")
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(forged, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "s1")
    assert exc.value.code == "BUNDLE_MEMBER_PATH_TOO_DEEP"

    long_shallow = "a" * (DEFAULT_MAX_MEMBER_NAME_BYTES + 1)
    assert len(PurePosixPath(long_shallow).parts) <= DEFAULT_MAX_MEMBER_DEPTH
    forged = _resigned_with_extra_member(bundle_env, tmp_path, long_shallow, b"{}\n")
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(forged, bundle_env["anchors_path"], bundle_env["state_path"], tmp_path / "s2")
    assert exc.value.code == "BUNDLE_MEMBER_NAME_TOO_LONG"
