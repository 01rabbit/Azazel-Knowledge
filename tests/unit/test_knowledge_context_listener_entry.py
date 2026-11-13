"""Product entry for the Knowledge Context mTLS listener: refusals and a real start.

Certificates and keys are generated inside the tests (test-only, ephemeral) and
only loopback is used. Nothing here touches production credentials.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("azazel_fabric.knowledge_context")

from nacl.signing import SigningKey, VerifyKey

from azazel_knowledge.api import knowledge_context_listener as entry
from _api_support import CONFIG_DIR, build_app
from test_knowledge_context_mtls import _CLIENT_SCRIPT, _DOMAIN, _body, _make_pki

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI required")

SRC = Path(__file__).resolve().parents[2] / "src"
SEED = bytes(range(1, 33))


def _fp(pem: Path) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.read_text())).hexdigest()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _private(path: Path, data: bytes | None = None) -> Path:
    if data is not None:
        path.write_bytes(data)
    path.chmod(0o600)
    return path


@pytest.fixture()
def env(tmp_path):
    tmp_path.chmod(0o700)
    pki = tmp_path / "pki"
    pki.mkdir(mode=0o700)
    _make_pki(pki)
    for f in pki.iterdir():
        if f.is_file():
            f.chmod(0o600 if f.suffix == ".key" else 0o644)
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    build_app(root)  # provisions local.db + an intel generation
    # The product layout (WorkerPaths) keeps local.db inside data/db.
    (root / "data" / "local.db").rename(root / "data" / "db" / "local.db")
    for d in (root, root / "data", root / "data" / "db", root / "var"):
        d.chmod(0o755)
    cfg_dir = tmp_path / "cfg"
    shutil.copytree(CONFIG_DIR, cfg_dir)
    cfg_dir.chmod(0o755)
    signing = _private(tmp_path / "response.key", SEED)
    (root / "secrets").mkdir(mode=0o700)
    _private(root / "secrets" / "node_signing_key", bytes(range(50, 82)))
    revoked = tmp_path / "revoked.txt"
    revoked.write_text(entry._REVOCATION_HEADER + "\n# none\n" + "ab" * 32 + "\n")
    revoked.chmod(0o644)
    values = {
        "enabled": True,
        "bind_host": "127.0.0.1",
        "bind_port": _free_port(),
        "knowledge_root": str(root),
        "config_dir": str(cfg_dir),
        "server_cert_file": str(pki / "server.pem"),
        "server_key_file": str(pki / "server.key"),
        "client_ca_file": str(pki / "ca.pem"),
        "expected_peer_id": "nexus-lab",
        "client_cert_sha256": _fp(pki / "nexus.pem"),
        "response_signing_key_file": str(signing),
        "revocation_file": str(revoked),
        "max_ttl_seconds": 30,
        "deadline_seconds": 10,
        "max_concurrency": 4,
        "max_body_bytes": 16384,
    }
    return tmp_path, pki, values


def _toml(values: dict) -> str:
    lines = []
    for k, v in values.items():
        if isinstance(v, bool):
            lines.append(f"{k} = {'true' if v else 'false'}")
        elif isinstance(v, str):
            lines.append(f"{k} = {json.dumps(v)}")
        else:
            lines.append(f"{k} = {v}")
    return "\n".join(lines) + "\n"


def _write_cfg(tmp_path: Path, values: dict, raw: str | None = None) -> Path:
    path = tmp_path / "listener.toml"
    path.write_text(_toml(values) if raw is None else raw)
    path.chmod(0o644)
    return path


def _run_refusal(path: Path, capsys) -> str:
    assert entry.main(["--config", str(path)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("refused: ")
    return err


# ---- refusals ------------------------------------------------------------


def test_enabled_absent_or_false_is_refused(env, capsys):
    tmp, _pki, values = env
    absent = {k: v for k, v in values.items() if k != "enabled"}
    assert "enabled" in _run_refusal(_write_cfg(tmp, absent), capsys)
    assert "enabled" in _run_refusal(_write_cfg(tmp, {**values, "enabled": False}), capsys)
    assert "enabled" in _run_refusal(_write_cfg(tmp, {**values, "enabled": "true"}), capsys)


def test_unknown_missing_and_malformed_config_is_refused(env, capsys):
    tmp, _pki, values = env
    assert "unknown" in _run_refusal(_write_cfg(tmp, {**values, "extra": 1}), capsys)
    assert "missing" in _run_refusal(
        _write_cfg(tmp, {k: v for k, v in values.items() if k != "max_ttl_seconds"}), capsys)
    assert "TOML" in _run_refusal(_write_cfg(tmp, values, raw="enabled = ["), capsys)


@pytest.mark.parametrize("field,value", [
    ("bind_host", "0.0.0.0"), ("bind_host", "::"), ("bind_host", "localhost"),
    ("bind_host", "224.0.0.1"), ("bind_host", "fe80::1%lo"),
    ("bind_port", 0), ("bind_port", 65536), ("bind_port", True),
    ("client_cert_sha256", "AB" * 32), ("client_cert_sha256", "ab" * 31),
    ("max_ttl_seconds", 0), ("max_ttl_seconds", 31),
    ("deadline_seconds", 0), ("deadline_seconds", 61),
    ("max_concurrency", 0), ("max_concurrency", 65),
    ("max_body_bytes", 0), ("max_body_bytes", 10**9),
    ("expected_peer_id", "bad id!"),
])
def test_out_of_bounds_values_are_refused(env, capsys, field, value):
    tmp, _pki, values = env
    _run_refusal(_write_cfg(tmp, {**values, field: value}), capsys)


def test_relative_and_symlinked_paths_are_refused(env, capsys):
    tmp, pki, values = env
    _run_refusal(_write_cfg(tmp, {**values, "server_cert_file": "server.pem"}), capsys)
    link = tmp / "link.key"
    link.symlink_to(pki / "server.key")
    _run_refusal(_write_cfg(tmp, {**values, "server_key_file": str(link)}), capsys)
    _run_refusal(_write_cfg(tmp, {**values, "server_key_file": str(tmp / "missing.key")}), capsys)


def test_unsafe_modes_and_owner_are_refused(env, capsys):
    tmp, pki, values = env
    (pki / "server.key").chmod(0o640)
    assert "mode" in _run_refusal(_write_cfg(tmp, values), capsys)
    (pki / "server.key").chmod(0o600)
    key = Path(values["response_signing_key_file"])
    key.chmod(0o604)
    assert "mode" in _run_refusal(_write_cfg(tmp, values), capsys)
    key.chmod(0o600)
    (pki / "ca.pem").chmod(0o666)
    assert "writable" in _run_refusal(_write_cfg(tmp, values), capsys)
    (pki / "ca.pem").chmod(0o644)
    rev = Path(values["revocation_file"])
    rev.chmod(0o664)
    assert "writable" in _run_refusal(_write_cfg(tmp, values), capsys)
    rev.chmod(0o644)
    # Wrong owner: the check compares st_uid against the effective uid.
    real_geteuid = os.geteuid
    try:
        os.geteuid = lambda: real_geteuid() + 12345  # type: ignore[assignment]
        assert "owner" in _run_refusal(_write_cfg(tmp, values), capsys)
    finally:
        os.geteuid = real_geteuid


def test_malformed_and_mismatched_tls_material_is_refused(env, capsys):
    tmp, pki, values = env
    # key from a different certificate
    other = tmp / "other.key"
    shutil.copy(pki / "other.key", other)
    other.chmod(0o600)
    assert "tls" in _run_refusal(_write_cfg(tmp, {**values, "server_key_file": str(other)}), capsys)
    junk = tmp / "junk.pem"
    junk.write_text("not a pem\n")
    junk.chmod(0o644)
    assert "tls" in _run_refusal(_write_cfg(tmp, {**values, "client_ca_file": str(junk)}), capsys)
    assert "certificate" in _run_refusal(
        _write_cfg(tmp, {**values, "server_cert_file": str(junk)}), capsys)
    empty = tmp / "empty.pem"
    empty.write_text("")
    empty.chmod(0o644)
    assert "tls" in _run_refusal(_write_cfg(tmp, {**values, "client_ca_file": str(empty)}), capsys)


def test_signing_key_problems_are_refused(env, capsys):
    tmp, _pki, values = env
    short = _private(tmp / "short.key", b"x" * 31)
    assert "32-byte" in _run_refusal(
        _write_cfg(tmp, {**values, "response_signing_key_file": str(short)}), capsys)
    root = Path(values["knowledge_root"])
    node = root / "secrets" / "node_signing_key"
    assert "node signing key" in _run_refusal(
        _write_cfg(tmp, {**values, "response_signing_key_file": str(node)}), capsys)
    same = _private(tmp / "same.key", node.read_bytes())
    assert "node signing key" in _run_refusal(
        _write_cfg(tmp, {**values, "response_signing_key_file": str(same)}), capsys)
    _run_refusal(_write_cfg(tmp, {**values, "response_signing_key_file": str(tmp / "nokey")}), capsys)
    assert not (tmp / "nokey").exists()  # never generated


def test_revocation_source_missing_malformed_or_listing_pin_is_refused(env, capsys):
    tmp, _pki, values = env
    rev = Path(values["revocation_file"])
    for content in ("", "ab" * 32 + "\n", entry._REVOCATION_HEADER + "\nnot-hex\n",
                    entry._REVOCATION_HEADER + "\n" + "AB" * 32 + "\n"):
        rev.write_text(content)
        assert "revocation" in _run_refusal(_write_cfg(tmp, values), capsys)
    rev.write_text(entry._REVOCATION_HEADER + "\n" + values["client_cert_sha256"] + "\n")
    assert "revoked" in _run_refusal(_write_cfg(tmp, values), capsys)
    rev.unlink()
    assert "revocation" in _run_refusal(_write_cfg(tmp, values), capsys)
    assert not rev.exists()


def test_key_separation_fails_closed_when_it_cannot_be_proven(env, capsys, monkeypatch):
    tmp, _pki, values = env
    node = Path(values["knowledge_root"]) / "secrets" / "node_signing_key"
    real_open, real_stat = os.open, os.stat

    def deny_open(path, *a, **kw):
        if str(path) == str(node):
            raise PermissionError(13, "denied")
        return real_open(path, *a, **kw)

    # unreadable node key file
    monkeypatch.setattr(os, "open", deny_open)
    assert "cannot be proven" in _run_refusal(_write_cfg(tmp, values), capsys)

    # untraversable secrets directory: the node key looks "missing" but is not proven absent
    def missing_open(path, *a, **kw):
        if str(path) == str(node):
            raise FileNotFoundError(2, "missing")
        return real_open(path, *a, **kw)

    def deny_stat(path, *a, **kw):
        if str(path) == str(node.parent):
            raise PermissionError(13, "denied")
        return real_stat(path, *a, **kw)

    monkeypatch.setattr(os, "open", missing_open)
    monkeypatch.setattr(os, "stat", deny_stat)
    assert "cannot be proven" in _run_refusal(_write_cfg(tmp, values), capsys)
    monkeypatch.undo()

    # copied seed is still refused; a proven absence is accepted
    same = _private(tmp / "copy.key", node.read_bytes())
    assert "node signing key" in _run_refusal(
        _write_cfg(tmp, {**values, "response_signing_key_file": str(same)}), capsys)
    node.unlink()
    entry.FileKeyResponseSigner(values["response_signing_key_file"], forbidden_seed_file=node)
    node.parent.rmdir()
    entry.FileKeyResponseSigner(values["response_signing_key_file"], forbidden_seed_file=node)


def test_expired_server_certificate_is_refused(env, capsys):
    tmp, pki, values = env
    cfg = {**values, "server_cert_file": str(pki / "expired.pem"),
           "server_key_file": str(pki / "expired.key")}
    assert "validity" in _run_refusal(_write_cfg(tmp, cfg), capsys)


def test_importing_the_entry_touches_no_environment_path(tmp_path):
    sentinel = tmp_path / "sentinel-must-not-be-touched"
    script = (
        "import sys\n"
        f"S={str(sentinel)!r}\n"
        "hits=[]\n"
        "def hook(ev,args):\n"
        "    if ev in ('open','os.listdir','os.scandir','os.stat') and S in str(args[0]):\n"
        "        hits.append((ev,str(args[0])))\n"
        "sys.addaudithook(hook)\n"
        "import azazel_knowledge.api.knowledge_context_listener as m\n"
        "import azazel_knowledge.api.app as a\n"
        "assert 'app' not in vars(a), 'module-level app was built on import'\n"
        "assert not hits, hits\n"
        "print('ok')\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=120,
        env={**os.environ, "PYTHONPATH": str(SRC) + os.pathsep + os.environ.get("PYTHONPATH", ""),
             "AZAZEL_ROOT": str(sentinel), "AZAZEL_CONFIG_DIR": str(sentinel / "cfg")})
    assert out.returncode == 0 and out.stdout.strip() == "ok", out.stderr[-800:]


def test_environment_cannot_supply_config_or_trust(env, capsys, monkeypatch):
    tmp, _pki, values = env
    monkeypatch.setenv("AZAZEL_ROOT", "/nonexistent")
    monkeypatch.setenv("AZAZEL_CONFIG_DIR", "/nonexistent")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent")
    with pytest.raises(SystemExit):
        entry.main([])  # --config is required; there is no env fallback
    capsys.readouterr()
    path = _write_cfg(tmp, {**values, "bind_port": _free_port()})
    listener = entry.build_listener(entry.parse_config(path.read_bytes()))
    settings = listener.app.state.settings
    assert str(settings.local_db_path).startswith(values["knowledge_root"])
    assert settings.config_dir == Path(values["config_dir"])


def test_refusal_output_never_contains_secrets(env, capsys):
    tmp, _pki, values = env
    err = _run_refusal(_write_cfg(tmp, {**values, "bind_port": 0}), capsys)
    assert SEED.hex() not in err and str(SEED) not in err


def test_signer_repr_has_no_key_material(env):
    _tmp, _pki, values = env
    signer = entry.FileKeyResponseSigner(values["response_signing_key_file"])
    assert SEED.hex() not in repr(signer) and "SigningKey" not in repr(signer)


# ---- positive start + signer verification --------------------------------


def _read_line(proc: subprocess.Popen, timeout: float = 90.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"listener exited rc={proc.returncode}: {proc.stderr.read()}")
        ready, _, _ = select.select([proc.stdout], [], [], 0.2)
        if ready:
            line = proc.stdout.readline()
            if line:
                return line
    raise AssertionError("readiness timeout")


def _request(port: int, pki: Path, tmp: Path, cert: str = "nexus") -> dict:
    body_file = tmp / "body.json"
    body_file.write_bytes(_body())
    out = subprocess.run(
        [sys.executable, "-I", "-c", _CLIENT_SCRIPT, "127.0.0.1", str(port), str(pki / "ca.pem"),
         str(pki / f"{cert}.pem"), str(pki / f"{cert}.key"), str(body_file)],
        capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


def _nexus_verify_detached():
    nexus_src = os.environ.get("AZAZEL_NEXUS_SRC")
    if not nexus_src or not (Path(nexus_src) / "azazel_nexus" / "signature.py").is_file():
        return None
    sys.path.insert(0, nexus_src)
    try:
        from azazel_nexus.signature import verify_detached
    finally:
        sys.path.remove(nexus_src)
    return verify_detached


def test_console_entry_starts_serves_one_real_mtls_request_and_stops(env):
    tmp, pki, values = env
    cfg = _write_cfg(tmp, values)
    proc = subprocess.Popen(
        [sys.executable, "-m", "azazel_knowledge.api.knowledge_context_listener",
         "--config", str(cfg)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(
            [str(SRC)] + [p for p in os.environ.get("PYTHONPATH", "").split(os.pathsep) if p])},
    )
    try:
        line = _read_line(proc)
        expected_key_id = "sha256:" + hashlib.sha256(
            bytes(SigningKey(SEED).verify_key)).hexdigest()
        assert line.split()[:3] == ["listening", "127.0.0.1", str(values["bind_port"])]
        assert expected_key_id in line and SEED.hex() not in line

        result = _request(values["bind_port"], pki, tmp)
        assert result["status"] == 200, result
        raw = bytes.fromhex(result["body"])
        signature, envelope = raw[:64], raw[64:]
        public_key = bytes(SigningKey(SEED).verify_key)
        VerifyKey(public_key).verify(_DOMAIN + envelope, signature)
        doc = json.loads(envelope)
        assert doc["key_id"] == expected_key_id
        # Real wall clock, not a fixed fixture: the envelope is currently valid.
        issued = time.mktime(time.strptime(doc["issued_at"][:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
        assert abs(time.time() - issued) < 120

        verify_detached = _nexus_verify_detached()
        if verify_detached is not None:
            assert verify_detached(public_key=public_key, message=_DOMAIN + envelope,
                                   signature=signature) is True
            assert verify_detached(public_key=public_key, message=_DOMAIN + envelope + b" ",
                                   signature=signature) is False

        # The unpinned (but CA-trusted) client is refused by the same process.
        other = _request(values["bind_port"], pki, tmp, cert="other")
        assert other["status"] == 401, other
        assert proc.poll() is None
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        for stream in (proc.stdout, proc.stderr):
            stream.close()
    assert proc.returncode == 0


def test_revocation_file_unreadable_after_start_denies_real_request(env):
    tmp, pki, values = env
    cfg = _write_cfg(tmp, values)
    proc = subprocess.Popen(
        [sys.executable, "-m", "azazel_knowledge.api.knowledge_context_listener",
         "--config", str(cfg)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(
            [str(SRC)] + [p for p in os.environ.get("PYTHONPATH", "").split(os.pathsep) if p])},
    )
    rev = Path(values["revocation_file"])
    try:
        _read_line(proc)
        assert _request(values["bind_port"], pki, tmp)["status"] == 200
        rev.unlink()  # source disappears: unknown revocation state must deny
        assert _request(values["bind_port"], pki, tmp)["status"] == 401
        rev.write_text("garbage\n")
        rev.chmod(0o644)
        assert _request(values["bind_port"], pki, tmp)["status"] == 401
        rev.write_text(entry._REVOCATION_HEADER + "\n")
        assert _request(values["bind_port"], pki, tmp)["status"] == 200  # restored
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        for stream in (proc.stdout, proc.stderr):
            stream.close()


def test_pyproject_declares_the_console_script():
    text = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text()
    assert ('azazel-knowledge-context-listener = '
            '"azazel_knowledge.api.knowledge_context_listener:main"') in text
