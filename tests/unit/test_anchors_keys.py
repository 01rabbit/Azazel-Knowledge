"""`azctl keys` as the sole writer of anchors.toml: rotation, sealing, locking, durability."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tarfile
import threading
import tomllib
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_knowledge.bundle import anchors_store, importer
from azazel_knowledge.bundle.anchors_store import (
    AnchorsPathUnsafe,
    AnchorsStoreError,
    anchors_lock,
    lock_path_for,
    write_anchors_atomic,
)
from azazel_knowledge.bundle.importer import apply_differential, import_full
from azazel_knowledge.bundle.verify import BundleVerifyError, canonical_manifest_bytes, verify_bundle
from azazel_knowledge.db import generations
from azazel_knowledge.db.repository import apply_migrations

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _azctl(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(_REPO_ROOT / "src")}
    return subprocess.run(
        [sys.executable, str(_REPO_ROOT / "azctl"), *args],
        capture_output=True, text=True, env=env, check=False,
    )


class Node:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.root = tmp_path / "node"
        assert _azctl("provision", "--root", str(self.root)).returncode == 0
        self.anchors = self.root / "secrets" / "trust" / "anchors.toml"
        self.source = tmp_path / "source.db"
        with sqlite3.connect(self.source) as connection:
            connection.execute(
                "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
        with sqlite3.connect(self.source) as connection:
            apply_migrations(connection, "intel")

    def key(self, name: str) -> tuple[str, str, Path]:
        signing = SigningKey.generate()
        path = self.tmp / f"{name}.hex"
        path.write_text(signing.encode().hex() + "\n", encoding="utf-8")
        verify_hex = signing.verify_key.encode().hex()
        return verify_hex[:8], verify_hex, path

    def keys(self, *args: str) -> subprocess.CompletedProcess:
        return _azctl("keys", args[0], "--root", str(self.root), *args[1:])

    def bundle(self, key_file: Path, version: int) -> Path:
        out = self.tmp / f"{key_file.stem}-{version}.tar.gz"
        built = _azctl("bundle", "build", "--source-db", str(self.source), "--out", str(out),
                       "--version", str(version), "--sign-key", str(key_file))
        assert built.returncode == 0, built.stderr
        return out

    def import_(self, bundle: Path) -> subprocess.CompletedProcess:
        return _azctl("bundle", "import", "--root", str(self.root), str(bundle), "--confirm")

    def doc(self) -> dict:
        return tomllib.loads(self.anchors.read_text(encoding="utf-8"))


def _role_anchor(node: Node, key_id: str, verify_hex: str) -> None:
    node.anchors.write_text(
        'threshold = 1\nrevoked = []\nrequired_signer_role = "lite"\n\n'
        f'[keys]\n{key_id} = "{verify_hex}"\n\n[key_roles]\n{key_id} = "lite"\n',
        encoding="utf-8",
    )


def test_role_key_rotation_completes_through_the_cli(tmp_path: Path) -> None:
    node = Node(tmp_path)
    old_id, old_hex, old_file = node.key("old")
    new_id, new_hex, new_file = node.key("new")
    _role_anchor(node, old_id, old_hex)

    assert node.keys("add", new_id, new_hex).returncode == 0
    sealed = node.keys("remove", old_id, "--revoke")
    assert sealed.returncode == 0 and "SEALED" in sealed.stderr  # the new key holds no role yet
    assert node.keys("unseal").returncode != 0
    assert node.keys("set-role", new_id, "lite").returncode == 0
    assert node.keys("unseal").returncode == 0
    assert node.doc()["revoked"] == [old_id]

    old_result = node.import_(node.bundle(old_file, 1))
    assert old_result.returncode != 0 and "BUNDLE_REVOKED_SIGNER" in old_result.stderr
    new_result = node.import_(node.bundle(new_file, 1))
    assert new_result.returncode == 0, new_result.stderr


def test_role_key_rotation_in_the_documented_order_never_seals(tmp_path: Path) -> None:
    node = Node(tmp_path)
    old_id, old_hex, old_file = node.key("old")
    new_id, new_hex, new_file = node.key("new")
    _role_anchor(node, old_id, old_hex)

    assert node.keys("add", new_id, new_hex).returncode == 0
    assert node.keys("set-role", new_id, "lite").returncode == 0
    removed = node.keys("remove", old_id, "--revoke")
    assert removed.returncode == 0 and "SEALED" not in removed.stderr
    assert "sealed" not in node.doc()
    assert node.doc()["key_roles"] == {new_id: "lite"}

    assert node.import_(node.bundle(new_file, 1)).returncode == 0
    old_result = node.import_(node.bundle(old_file, 2))
    assert old_result.returncode != 0 and "BUNDLE_REVOKED_SIGNER" in old_result.stderr


def test_add_with_role_in_one_step(tmp_path: Path) -> None:
    node = Node(tmp_path)
    old_id, old_hex, _ = node.key("old")
    new_id, new_hex, _ = node.key("new")
    _role_anchor(node, old_id, old_hex)
    assert node.keys("add", new_id, new_hex, "--role", "lite").returncode == 0
    assert node.keys("remove", old_id, "--revoke").returncode == 0
    assert "sealed" not in node.doc()


def test_set_role_refuses_an_unknown_key(tmp_path: Path) -> None:
    node = Node(tmp_path)
    old_id, old_hex, _ = node.key("old")
    _role_anchor(node, old_id, old_hex)
    before = node.anchors.read_bytes()
    result = node.keys("set-role", "nobody", "lite")
    assert result.returncode != 0 and "unknown key" in result.stderr
    assert node.anchors.read_bytes() == before


def test_emergency_revocation_of_the_last_key_seals_and_reregistration_reopens(tmp_path: Path) -> None:
    node = Node(tmp_path)
    old_id, old_hex, old_file = node.key("old")
    new_id, new_hex, new_file = node.key("new")
    _role_anchor(node, old_id, old_hex)

    revoked = node.keys("remove", old_id, "--revoke")
    assert revoked.returncode == 0
    assert "SEALED" in revoked.stderr
    doc = node.doc()
    assert doc["sealed"] is True and doc["threshold"] == 1 and doc["revoked"] == [old_id]
    assert doc["required_signer_role"] == "lite"

    sealed = node.import_(node.bundle(old_file, 1))
    assert sealed.returncode != 0 and "BUNDLE_ANCHORS_SEALED" in sealed.stderr

    assert node.keys("unseal").returncode != 0  # nothing eligible yet
    assert node.keys("add", new_id, new_hex, "--role", "lite").returncode == 0
    still = node.import_(node.bundle(new_file, 1))
    assert still.returncode != 0 and "BUNDLE_ANCHORS_SEALED" in still.stderr  # sealed until unsealed

    assert node.keys("unseal").returncode == 0
    assert "sealed" not in node.doc()
    assert node.import_(node.bundle(new_file, 1)).returncode == 0
    old_again = node.import_(node.bundle(old_file, 2))
    assert old_again.returncode != 0 and "BUNDLE_REVOKED_SIGNER" in old_again.stderr


def test_sealed_anchor_refuses_every_bundle_at_the_verifier(tmp_path: Path) -> None:
    signing = SigningKey.generate()
    verify_hex = signing.verify_key.encode().hex()
    anchors = tmp_path / "anchors.toml"
    anchors.write_text(
        f'threshold = 1\nrevoked = []\nsealed = true\n\n[keys]\nk1 = "{verify_hex}"\n', encoding="utf-8"
    )
    bundle = _signed_bundle(tmp_path, "k1", signing)
    with pytest.raises(BundleVerifyError) as error:
        verify_bundle(bundle, anchors, tmp_path / "state.toml", tmp_path / "staging")
    assert error.value.code == "BUNDLE_ANCHORS_SEALED"


@pytest.mark.parametrize("value", ('"yes"', "1"))
def test_non_boolean_seal_is_invalid(tmp_path: Path, value: str) -> None:
    signing = SigningKey.generate()
    anchors = tmp_path / "anchors.toml"
    anchors.write_text(
        f'threshold = 1\nsealed = {value}\n[keys]\nk1 = "{signing.verify_key.encode().hex()}"\n',
        encoding="utf-8",
    )
    with pytest.raises(BundleVerifyError) as error:
        verify_bundle(_signed_bundle(tmp_path, "k1", signing), anchors, tmp_path / "s.toml", tmp_path / "st")
    assert error.value.code == "BUNDLE_ANCHORS_INVALID"


def _signed_bundle(tmp_path: Path, key_id: str, signing: SigningKey, version: int = 1) -> Path:
    payload = b""
    manifest = {
        "bundle_version": version, "kind": "full", "base_version": None, "compression": "gzip",
        "tables": ["ioc"], "files": {"tables/ioc.jsonl": hashlib.sha256(payload).hexdigest()},
    }
    raw = canonical_manifest_bytes(manifest)
    sig = f"{key_id}:{signing.sign(raw).signature.hex()}\n".encode()
    path = tmp_path / f"bundle-{key_id}-{version}.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, data in (("manifest.json", raw), ("manifest.sig", sig), ("tables/ioc.jsonl", payload)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


# --- Rkn110-02: one lock across read -> modify -> validate -> write ----------


def _load_azctl():
    loader = importlib.machinery.SourceFileLoader("azctl_under_test", str(_REPO_ROOT / "azctl"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_a_revocation_is_not_lost_to_a_concurrent_key_add(tmp_path: Path, monkeypatch) -> None:
    node = Node(tmp_path)
    a_signing = SigningKey.generate()
    node.anchors.write_text(
        "threshold = 1\nrevoked = []\n\n[keys]\n"
        f'A = "{a_signing.verify_key.encode().hex()}"\nB = "{SigningKey.generate().verify_key.encode().hex()}"\n',
        encoding="utf-8",
    )
    azctl = _load_azctl()
    real_load = azctl._load_anchor_doc
    p_has_read = threading.Event()
    release_p = threading.Event()

    def load(path):
        doc = real_load(path)
        if threading.current_thread().name == "P":
            p_has_read.set()
            assert release_p.wait(30)
        return doc

    monkeypatch.setattr(azctl, "_load_anchor_doc", load)
    errors: list[BaseException] = []

    def run(func, args):
        try:
            func(args)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    common = {"root": str(node.root), "config_dir": None}
    c_hex = SigningKey.generate().verify_key.encode().hex()
    p = threading.Thread(target=run, name="P", args=(azctl.cmd_keys_add, argparse.Namespace(
        **common, key_id="C", verify_key_hex=c_hex, role=None)))
    q = threading.Thread(target=run, name="Q", args=(azctl.cmd_keys_remove, argparse.Namespace(
        **common, key_id="A", revoke=True)))
    p.start()
    assert p_has_read.wait(30)
    q.start()
    q.join(0.5)
    q_waited = q.is_alive()
    release_p.set()
    p.join(30)
    q.join(30)

    assert not errors
    assert q_waited, "the revocation ran while another command held a stale read"
    doc = node.doc()
    assert doc["revoked"] == ["A"]
    assert set(doc["keys"]) == {"B", "C"}
    with pytest.raises(BundleVerifyError) as error:
        verify_bundle(_signed_bundle(tmp_path, "A", a_signing), node.anchors, tmp_path / "s.toml", tmp_path / "st")
    assert error.value.code == "BUNDLE_REVOKED_SIGNER"


@pytest.mark.parametrize("entrypoint", ("full", "differential"))
def test_import_holds_the_anchors_lock_while_it_verifies(tmp_path: Path, monkeypatch, entrypoint: str) -> None:
    signing = SigningKey.generate()
    anchors = tmp_path / "anchors.toml"
    anchors.write_text(f'threshold = 1\n[keys]\nk1 = "{signing.verify_key.encode().hex()}"\n', encoding="utf-8")
    state = tmp_path / "state.toml"
    data = tmp_path / "db"
    import_full(_signed_bundle(tmp_path, "k1", signing), anchors, state, data)
    observed: list[bool] = []
    real_verify = importer.verify_bundle

    def verify(*args, **kwargs):
        fd = os.open(lock_path_for(anchors), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            observed.append(False)
            fcntl.flock(fd, fcntl.LOCK_UN)
        except BlockingIOError:
            observed.append(True)
        finally:
            os.close(fd)
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(importer, "verify_bundle", verify)
    if entrypoint == "full":
        import_full(_signed_bundle(tmp_path, "k1", signing, version=2), anchors, state, data)
    else:
        raw = canonical_manifest_bytes({
            "bundle_version": 2, "kind": "differential", "base_version": 1, "compression": "gzip",
            "tables": ["ioc"], "files": {"deltas/ioc.jsonl": hashlib.sha256(b"").hexdigest()},
        })
        bundle = tmp_path / "diff.tar.gz"
        with tarfile.open(bundle, "w:gz") as archive:
            for name, payload in (("manifest.json", raw),
                                  ("manifest.sig", f"k1:{signing.sign(raw).signature.hex()}\n".encode()),
                                  ("deltas/ioc.jsonl", b"")):
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        with sqlite3.connect(generations.intel_db_path(data, 1)) as connection:
            apply_differential(bundle, anchors, state, connection)
    assert observed == [True]


# --- Rkn110-03: the live anchors file is replaced, never rewritten ----------


class _FaultyOs:
    """`os` with one call made to fail; everything else passes through."""

    def __init__(self, name: str, nth: int = 1) -> None:
        self._name, self._nth, self._calls = name, nth, 0

    def __getattr__(self, attr):
        real = getattr(os, attr)
        if attr != self._name:
            return real

        def call(*args, **kwargs):
            self._calls += 1
            if self._calls == self._nth:
                raise OSError(28, "injected failure")
            return real(*args, **kwargs)

        return call


def _write(path: Path, text: str) -> None:
    with anchors_lock(path, shared=False) as lock:
        write_anchors_atomic(lock, text)


OLD = 'threshold = 1\n[keys]\nk1 = "' + "11" * 32 + '"\n'
NEW = 'threshold = 1\n[keys]\nk2 = "' + "22" * 32 + '"\n'


@pytest.mark.parametrize("stage, nth", (("write", 1), ("fsync", 1), ("replace", 1)))
def test_failure_before_the_rename_leaves_the_old_anchors(tmp_path: Path, monkeypatch, stage: str, nth: int) -> None:
    anchors = tmp_path / "anchors.toml"
    anchors.write_text(OLD, encoding="utf-8")
    monkeypatch.setattr(anchors_store, "os", _FaultyOs(stage, nth))
    with pytest.raises(OSError):
        _write(anchors, NEW)
    assert anchors.read_text(encoding="utf-8") == OLD
    assert sorted(p.name for p in tmp_path.iterdir() if not p.name.endswith(".lock")) == ["anchors.toml"]


def test_failure_after_the_rename_leaves_the_complete_new_anchors(tmp_path: Path, monkeypatch) -> None:
    anchors = tmp_path / "anchors.toml"
    anchors.write_text(OLD, encoding="utf-8")
    monkeypatch.setattr(anchors_store, "os", _FaultyOs("fsync", 2))  # the directory fsync
    with pytest.raises(OSError):
        _write(anchors, NEW)
    assert anchors.read_text(encoding="utf-8") == NEW
    assert sorted(p.name for p in tmp_path.iterdir() if not p.name.endswith(".lock")) == ["anchors.toml"]


@pytest.mark.parametrize("umask", (0o000, 0o022, 0o277))
def test_written_anchors_are_0600_whatever_the_umask(tmp_path: Path, umask: int) -> None:
    anchors = tmp_path / "anchors.toml"
    anchors.write_text(OLD, encoding="utf-8")
    anchors.chmod(0o644)
    previous = os.umask(umask)
    try:
        _write(anchors, NEW)
        _write(tmp_path / "fresh.toml", NEW)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(anchors.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "fresh.toml").stat().st_mode) == 0o600


def test_a_reader_holding_the_old_file_sees_it_whole(tmp_path: Path) -> None:
    anchors = tmp_path / "anchors.toml"
    anchors.write_text(OLD, encoding="utf-8")
    with anchors.open("r", encoding="utf-8") as reader:
        _write(anchors, NEW)
        assert reader.read() == OLD
    assert anchors.read_text(encoding="utf-8") == NEW


def test_a_symlinked_anchors_path_is_refused_and_its_target_untouched(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.toml"
    target.write_text(OLD, encoding="utf-8")
    anchors = tmp_path / "anchors.toml"
    anchors.symlink_to(target)
    with pytest.raises(AnchorsStoreError):
        _write(anchors, NEW)
    assert anchors.is_symlink()
    assert target.read_text(encoding="utf-8") == OLD


def test_azctl_keys_refuses_a_symlinked_anchors_file(tmp_path: Path) -> None:
    node = Node(tmp_path)
    target = tmp_path / "elsewhere.toml"
    target.write_text(OLD, encoding="utf-8")
    node.anchors.unlink()
    node.anchors.symlink_to(target)
    result = node.keys("add", "k9", "33" * 32)
    assert result.returncode != 0 and "symlink" in result.stderr
    assert target.read_text(encoding="utf-8") == OLD
    assert node.anchors.is_symlink()


def test_keys_list_shows_roles_and_the_seal(tmp_path: Path) -> None:
    node = Node(tmp_path)
    old_id, old_hex, _ = node.key("old")
    _role_anchor(node, old_id, old_hex)
    assert node.keys("remove", old_id, "--revoke").returncode == 0
    listed = node.keys("list").stdout
    assert "required_signer_role: lite" in listed
    assert "sealed: true" in listed
    assert f"revoked: [{old_id!r}]" in listed


# --- Rkn110b-01: the lock and the document are the same file ---------------


def _diff_bundle(tmp_path: Path, signing: SigningKey) -> Path:
    raw = canonical_manifest_bytes({
        "bundle_version": 2, "kind": "differential", "base_version": 1, "compression": "gzip",
        "tables": ["ioc"], "files": {"deltas/ioc.jsonl": hashlib.sha256(b"").hexdigest()},
    })
    bundle = tmp_path / "diff.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        for name, payload in (("manifest.json", raw),
                              ("manifest.sig", f"k1:{signing.sign(raw).signature.hex()}\n".encode()),
                              ("deltas/ioc.jsonl", b"")):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return bundle


def _imported_node(tmp_path: Path) -> tuple[SigningKey, Path, Path, Path]:
    signing = SigningKey.generate()
    trust = tmp_path / "trust"
    trust.mkdir()
    anchors = trust / "anchors.toml"
    anchors.write_text(f'threshold = 1\n[keys]\nk1 = "{signing.verify_key.encode().hex()}"\n', encoding="utf-8")
    state, data = trust / "state.toml", tmp_path / "db"
    import_full(_signed_bundle(tmp_path, "k1", signing), anchors, state, data)
    return signing, anchors, state, data


def _run_import(entrypoint: str, tmp_path: Path, signing: SigningKey, anchors: Path, state: Path, data: Path) -> None:
    if entrypoint == "full":
        import_full(_signed_bundle(tmp_path, "k1", signing, version=2), anchors, state, data)
    else:
        with sqlite3.connect(generations.intel_db_path(data, 1)) as connection:
            apply_differential(_diff_bundle(tmp_path, signing), anchors, state, connection)


@pytest.mark.parametrize("alias", ("symlink", "hardlink"))
@pytest.mark.parametrize("entrypoint", ("full", "differential"))
def test_import_through_an_aliased_anchors_file_is_refused(tmp_path: Path, entrypoint: str, alias: str) -> None:
    signing, anchors, state, data = _imported_node(tmp_path)
    other = tmp_path / "alias.toml"
    if alias == "symlink":
        other.symlink_to(anchors)
    else:
        os.link(anchors, other)
    state_before = state.read_bytes()
    with pytest.raises(BundleVerifyError) as error:
        _run_import(entrypoint, tmp_path, signing, other, state, data)
    assert error.value.code == "BUNDLE_ANCHORS_PATH_UNSAFE"
    assert state.read_bytes() == state_before
    assert generations.current_generation(data) == 1
    assert sorted(p.name for p in data.glob("gen-*")) == ["gen-1"]


def test_azctl_import_refuses_a_symlinked_anchors_argument(tmp_path: Path) -> None:
    node = Node(tmp_path)
    key_id, verify_hex, key_file = node.key("k")
    node.anchors.write_text(f'threshold = 1\n[keys]\n{key_id} = "{verify_hex}"\n', encoding="utf-8")
    alias = tmp_path / "alias.toml"
    alias.symlink_to(node.anchors)
    result = _azctl("bundle", "import", "--root", str(node.root), "--anchors", str(alias),
                    str(node.bundle(key_file, 1)), "--confirm")
    assert result.returncode != 0 and "BUNDLE_ANCHORS_PATH_UNSAFE" in result.stderr


@pytest.mark.parametrize("entrypoint", ("full", "differential"))
def test_a_revocation_waits_for_an_import_stopped_after_verification(
    tmp_path: Path, monkeypatch, entrypoint: str
) -> None:
    signing, anchors, state, data = _imported_node(tmp_path)
    real_verify = importer.verify_bundle
    acquired = threading.Event()
    blocked: list[bool] = []

    def revoke() -> None:
        with anchors_lock(anchors, shared=False):
            acquired.set()

    def verify(*args, **kwargs):
        verified = real_verify(*args, **kwargs)
        writer = threading.Thread(target=revoke)
        writer.start()
        blocked.append(not acquired.wait(0.5))
        verify.writer = writer
        return verified

    monkeypatch.setattr(importer, "verify_bundle", verify)
    _run_import(entrypoint, tmp_path, signing, anchors, state, data)
    verify.writer.join(10)
    assert blocked == [True]
    assert acquired.is_set()


# --- Rkn110b-03: provision is an anchors writer too --------------------------


def test_write_requires_the_held_exclusive_lock(tmp_path: Path) -> None:
    anchors = tmp_path / "anchors.toml"
    with anchors_lock(anchors, shared=True) as shared:
        with pytest.raises(AnchorsStoreError):
            write_anchors_atomic(shared, NEW)
    with anchors_lock(anchors, shared=False) as released:
        pass
    with pytest.raises(AnchorsStoreError):
        write_anchors_atomic(released, NEW)
    assert not anchors.exists()


def test_provision_does_not_overwrite_anchors_written_while_it_waited(tmp_path: Path, monkeypatch) -> None:
    node = Node(tmp_path)
    node.anchors.unlink()
    azctl = _load_azctl()
    paths = azctl.WorkerPaths.from_root(node.root)
    real_lexists = os.path.lexists
    p_at_write = threading.Event()
    release_p = threading.Event()

    def lexists(path):
        present = real_lexists(path)
        if threading.current_thread().name == "P" and Path(path) == node.anchors:
            p_at_write.set()  # P has decided "absent" and has not yet written
            assert release_p.wait(30)
        return present

    monkeypatch.setattr(os.path, "lexists", lexists)
    errors: list[BaseException] = []

    def run(func, *args):
        try:
            func(*args)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    signing = SigningKey.generate()
    common = {"root": str(node.root), "config_dir": None}
    p = threading.Thread(target=run, name="P", args=(azctl._provision_anchors, paths))
    p.start()
    assert p_at_write.wait(30)

    def q_ops() -> None:
        azctl.cmd_keys_add(argparse.Namespace(**common, key_id="k1",
                                              verify_key_hex=signing.verify_key.encode().hex(), role=None))
        azctl.cmd_keys_remove(argparse.Namespace(**common, key_id="k1", revoke=True))

    q = threading.Thread(target=run, name="Q", args=(q_ops,))
    q.start()
    q.join(0.5)
    q_waited = q.is_alive()
    release_p.set()
    p.join(30)
    q.join(30)

    assert not errors
    assert q_waited, "a keys command ran while provision was deciding whether to write"
    doc = node.doc()
    assert doc["revoked"] == ["k1"] and doc["sealed"] is True and doc["keys"] == {}
    with anchors_lock(node.anchors, shared=False):
        pass
    assert not azctl._provision_anchors(paths)
    assert node.doc() == doc


# --- Rkn110b-02: trust-widening changes need a durable audit intent ---------


def _audit_events(node: Node) -> list[dict]:
    events = []
    for path in sorted((node.root / "var" / "audit" / "azctl").glob("*.jsonl")):
        events += [json.loads(line)["event"] for line in path.read_text(encoding="utf-8").splitlines()]
    return events


def _break_audit(node: Node) -> None:
    audit = node.root / "var" / "audit" / "azctl"
    if audit.exists():
        for child in audit.iterdir():
            child.unlink()
        audit.rmdir()
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text("not a directory", encoding="utf-8")


def test_widening_changes_record_intent_then_done(tmp_path: Path) -> None:
    node = Node(tmp_path)
    old_id, old_hex, _ = node.key("old")
    new_id, new_hex, _ = node.key("new")
    _role_anchor(node, old_id, old_hex)
    assert node.keys("add", new_id, new_hex, "--role", "lite").returncode == 0
    events = [e for e in _audit_events(node) if e.get("action") == "keys_add"]
    assert [e["phase"] for e in events] == ["intent", "done"]
    assert events[0]["op_id"] == events[1]["op_id"] and len(events[0]["op_id"]) == 16
    assert events[0]["key_id"] == new_id and events[0]["role"] == "lite"
    assert events[0]["verify_key"] == new_hex

    assert node.keys("set-role", old_id, "other").returncode == 0
    roles = [e for e in _audit_events(node) if e.get("action") == "keys_set_role"]
    assert [e["phase"] for e in roles] == ["intent", "done"]
    assert roles[0]["previous_role"] == "lite" and roles[0]["role"] == "other"


def _sealed_but_satisfiable(node: Node) -> None:
    old_id, old_hex, _ = node.key("old")
    new_id, new_hex, _ = node.key("new")
    _role_anchor(node, old_id, old_hex)
    assert node.keys("remove", old_id, "--revoke").returncode == 0
    assert node.keys("add", new_id, new_hex, "--role", "lite").returncode == 0
    spare_id, spare_hex, _ = node.key("spare")
    assert node.keys("add", spare_id, spare_hex).returncode == 0
    node.spare_id = spare_id


@pytest.mark.parametrize(
    "command",
    (
        lambda node: ("add", "k9", SigningKey.generate().verify_key.encode().hex(), "--role", "lite"),
        lambda node: ("add", "k9", SigningKey.generate().verify_key.encode().hex()),
        lambda node: ("set-role", node.spare_id, "lite"),
        lambda node: ("unseal",),
    ),
)
def test_widening_change_is_refused_when_the_audit_cannot_be_written(tmp_path: Path, command) -> None:
    node = Node(tmp_path)
    _sealed_but_satisfiable(node)
    if command(node)[0] == "set-role":
        assert node.keys("unseal").returncode == 0
    before = node.anchors.read_bytes()
    _break_audit(node)
    result = node.keys(*command(node))
    assert result.returncode != 0
    assert "audit intent could not be recorded" in result.stderr
    assert node.anchors.read_bytes() == before


def test_lowering_the_threshold_needs_the_audit_but_raising_does_not(tmp_path: Path) -> None:
    node = Node(tmp_path)
    _, hex1, _ = node.key("one")
    _, hex2, _ = node.key("two")
    node.anchors.write_text(
        f'threshold = 2\nrevoked = []\n\n[keys]\nk1 = "{hex1}"\nk2 = "{hex2}"\n', encoding="utf-8"
    )
    _break_audit(node)
    before = node.anchors.read_bytes()
    lowered = node.keys("set-threshold", "1")
    assert lowered.returncode != 0 and node.anchors.read_bytes() == before
    assert node.keys("set-threshold", "2").returncode == 0


def test_revocation_and_sealing_are_never_blocked_by_the_audit(tmp_path: Path) -> None:
    node = Node(tmp_path)
    old_id, old_hex, _ = node.key("old")
    _role_anchor(node, old_id, old_hex)
    _break_audit(node)
    result = node.keys("remove", old_id, "--revoke")
    assert result.returncode == 0
    assert "warning: audit event not recorded" in result.stderr
    doc = node.doc()
    assert doc["revoked"] == [old_id] and doc["sealed"] is True


def test_widening_change_is_refused_when_the_audit_fsync_fails(tmp_path: Path, monkeypatch) -> None:
    from azazel_knowledge.audit import logger

    node = Node(tmp_path)
    old_id, old_hex, _ = node.key("old")
    _role_anchor(node, old_id, old_hex)
    node.anchors.write_text(node.anchors.read_text(encoding="utf-8").replace(
        "[key_roles]", f'k2 = "{SigningKey.generate().verify_key.encode().hex()}"\n\n[key_roles]'),
        encoding="utf-8")
    before = node.anchors.read_bytes()
    azctl = _load_azctl()
    monkeypatch.setattr(logger, "os", _FaultyOs("fsync"))
    with pytest.raises(SystemExit) as exit_info:
        azctl.cmd_keys_set_role(argparse.Namespace(
            root=str(node.root), config_dir=None, key_id="k2", role="lite", clear=False))
    assert "audit intent could not be recorded" in str(exit_info.value)
    assert node.anchors.read_bytes() == before
