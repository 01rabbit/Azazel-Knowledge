"""mTLS listener tests, including a real client in a separate Python process.

Certificates are ephemeral, generated with the `openssl` CLI into tmp_path.
Nothing here touches production credentials or listens on a non-loopback address.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import select
import shutil
import socket
import time
import ssl
import subprocess
import sys
import threading
import textwrap
from pathlib import Path

import pytest
pytest.importorskip("azazel_fabric.knowledge_context")

from nacl.signing import SigningKey, VerifyKey
from starlette.requests import Request

from azazel_knowledge.api import limits
from azazel_knowledge.api.knowledge_context_mtls import (
    KnowledgeContextMtlsListener,
    MtlsListenerConfig,
    PinnedCertificatePeerAuthenticator,
    VerifiedTlsPeer,
    _SCOPE_KEY,
)
from azazel_knowledge.api.knowledge_context_transport import KnowledgeContextTransportConfig
from _api_support import build_app

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI required")

_DOMAIN = b"azazel-nexus/knowledge-context-envelope/v1\x00"

_CLIENT_SCRIPT = textwrap.dedent(
    """
    import http.client, json, ssl, sys
    host, port, ca, cert, key, body_file = sys.argv[1:7]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=ca)
    if cert != "-":
        ctx.load_cert_chain(cert, key)
    try:
        conn = http.client.HTTPSConnection(host, int(port), context=ctx, timeout=10)
        conn.request("POST", "/v1/knowledge-context", body=open(body_file, "rb").read(),
                     headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        print(json.dumps({"status": r.status, "body": r.read().hex()}))
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__}))
    """
)


def _run(args: list[str], cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def _make_pki(d: Path) -> None:
    _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
          "-out", "ca.pem", "-subj", "/CN=test-ca", "-days", "2"], d)
    (d / "server.ext").write_text("subjectAltName=IP:127.0.0.1\n")
    (d / "client.ext").write_text("extendedKeyUsage=clientAuth\n")
    for name, ext in (("server", "server.ext"), ("nexus", "client.ext"), ("other", "client.ext")):
        _run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
              "-out", f"{name}.csr", "-subj", f"/CN={name}"], d)
        _run(["openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey",
              "ca.key", "-CAcreateserial", "-out", f"{name}.pem", "-days", "2",
              "-extfile", ext], d)
    # A client certificate issued by the TRUSTED CA whose notAfter is in the past.
    # `openssl ca` is used because it takes explicit validity dates on every version.
    (d / "db").mkdir()
    (d / "db" / "index.txt").write_text("")
    (d / "db" / "serial").write_text("1000\n")
    (d / "ca.cnf").write_text(
        "[ca]\ndefault_ca=c\n[c]\ndatabase=db/index.txt\nserial=db/serial\nnew_certs_dir=db\n"
        "default_md=sha256\npolicy=p\nunique_subject=no\n[p]\ncommonName=supplied\n"
    )
    _run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "expired.key",
          "-out", "expired.csr", "-subj", "/CN=expired"], d)
    _run(["openssl", "ca", "-config", "ca.cnf", "-batch", "-notext", "-in", "expired.csr",
          "-out", "expired.pem", "-cert", "ca.pem", "-keyfile", "ca.key",
          "-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
          "-extfile", "client.ext"], d)
    # A client certificate issued by an unrelated CA.
    _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rogue.key",
          "-out", "rogue.pem", "-subj", "/CN=rogue", "-days", "2"], d)


def _fingerprint(pem: Path) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.read_text())).hexdigest()


class _Signer:
    def __init__(self, fail: bool = False):
        self.key = SigningKey(bytes(range(32)))
        self.public_key = bytes(self.key.verify_key)
        self.key_id = "sha256:" + hashlib.sha256(self.public_key).hexdigest()
        self.fail = fail

    def sign(self, message: bytes) -> bytes:
        if self.fail:
            raise RuntimeError("signer offline")
        return self.key.sign(message).signature


def _body() -> bytes:
    return json.dumps({
        "schema_version": "knowledge-context-request/v1",
        "request_id": "req-0123456789abcdef",
        "correlation_id": "corr-0123456789abcdef",
        "source_product": "azazel_nexus",
        "source_ref": "nexus:lab-query-01",
        "requested_at": "2026-07-06T12:00:00Z",
        "entities": [{"entity_type": "ip", "value": "203.0.113.7"}],
    }).encode()


@pytest.fixture
def pki(tmp_path):
    d = tmp_path / "pki"
    d.mkdir()
    _make_pki(d)
    return d


def _start(tmp_path, pki, *, signer=None, revoked=frozenset(), now=None, **cfg):
    app, settings, _db, _data = build_app(tmp_path)
    signer = signer or _Signer()
    kwargs = {"now": now} if now else {}
    settings.knowledge_context_transport = KnowledgeContextTransportConfig(
        peer_authenticator=PinnedCertificatePeerAuthenticator(
            peer_id="nexus-lab",
            cert_sha256=_fingerprint(pki / "nexus.pem"),
            is_revoked=lambda fp: fp in revoked,
            **kwargs,
        ),
        signer=signer, max_ttl_seconds=30, expected_peer_id="nexus-lab", enabled=True,
    )
    listener = KnowledgeContextMtlsListener(
        app,
        MtlsListenerConfig(
            bind_host="127.0.0.1", bind_port=0,
            server_cert_file=pki / "server.pem", server_key_file=pki / "server.key",
            client_ca_file=pki / "ca.pem", **cfg,
        ),
    )
    listener.start()
    return listener, signer


def _client(listener, pki, tmp_path, cert="nexus", body: bytes | None = None) -> dict:
    body_file = tmp_path / "body.json"
    body_file.write_bytes(_body() if body is None else body)
    host, port = listener.address
    args = [sys.executable, "-I", "-c", _CLIENT_SCRIPT, host, str(port), str(pki / "ca.pem"),
            "-" if cert is None else str(pki / f"{cert}.pem"),
            "-" if cert is None else str(pki / f"{cert}.key"), str(body_file)]
    out = subprocess.run(args, capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


_SERVER_SCRIPT = Path(__file__).with_name("_knowledge_context_mtls_server.py")


def _read_ready(proc: subprocess.Popen, timeout: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"server exited early rc={proc.returncode}: "
                                 f"{proc.stderr.read()}")
        ready, _, _ = select.select([proc.stdout], [], [], 0.2)
        if ready:
            return json.loads(proc.stdout.readline())
    raise AssertionError("server readiness timeout")


def test_isolated_server_process_serves_signed_response_over_real_mtls(tmp_path, pki):
    proc = subprocess.Popen(
        [sys.executable, str(_SERVER_SCRIPT), str(tmp_path / "server-root"), str(pki)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        cwd=_SERVER_SCRIPT.parent,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(
            [str(Path(__file__).resolve().parents[2] / "src"),
             os.environ.get("PYTHONPATH", "")])},
    )
    try:
        ready = _read_ready(proc)
        assert ready["ready"] is True
        assert ready["pid"] == proc.pid != os.getpid()
        assert ready["host"] == "127.0.0.1"

        class _Addr:
            address = (ready["host"], ready["port"])

        result = _client(_Addr, pki, tmp_path)  # separate client process
        assert result["status"] == 200, result
        raw = bytes.fromhex(result["body"])
        signature, envelope = raw[:64], raw[64:]
        public_key = bytes.fromhex(ready["public_key"])
        assert ready["key_id"] == "sha256:" + hashlib.sha256(public_key).hexdigest()
        VerifyKey(public_key).verify(_DOMAIN + envelope, signature)
        assert "private" not in json.dumps(ready) and "seed" not in json.dumps(ready)
        doc = json.loads(envelope)
        assert doc["key_id"] == ready["key_id"]
        assert doc["payload"]["request_id"] == "req-0123456789abcdef"

        # Unauthenticated (no client cert) is refused by the same server process.
        refused = _client(_Addr, pki, tmp_path, cert=None)
        assert "error" in refused and "status" not in refused, refused
        assert proc.poll() is None  # server survived the refused handshake

        # Real X.509 expiry: trusted CA, notAfter in 2020. Must die at the TLS
        # handshake (no HTTP status, so never reaches the app), server stays up.
        expired = _client(_Addr, pki, tmp_path, cert="expired")
        assert "error" in expired and "status" not in expired, expired
        assert proc.poll() is None
        again = _client(_Addr, pki, tmp_path)  # still serving valid peers
        assert again["status"] == 200, again
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            raise AssertionError("server did not exit on SIGTERM")
    assert proc.returncode == 0
    assert (tmp_path / "server-root" / "data" / "local.db").exists()  # temp-root DBs only
    with pytest.raises(OSError):  # port released: only the child was listening
        socket.create_connection((ready["host"], ready["port"]), timeout=2).close()
    proc.stdout.close()
    proc.stderr.close()


def test_listener_context_is_cert_required_tls12_minimum(tmp_path, pki):
    listener, _ = _start(tmp_path, pki)
    try:
        assert listener.ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert listener.ssl_context.minimum_version == ssl.TLSVersion.TLSv1_2
        assert listener._server is not None and listener.address[0] == "127.0.0.1"
    finally:
        listener.stop()


def test_no_client_cert_and_untrusted_ca_are_refused(tmp_path, pki):
    listener, _ = _start(tmp_path, pki)
    try:
        for cert in (None, "rogue"):
            result = _client(listener, pki, tmp_path, cert=cert)
            assert "error" in result and "status" not in result, result
    finally:
        listener.stop()


def test_trusted_but_unpinned_cert_is_401_without_signing(tmp_path, pki):
    listener, _ = _start(tmp_path, pki)
    try:
        result = _client(listener, pki, tmp_path, cert="other")
    finally:
        listener.stop()
    assert result["status"] == 401
    assert json.loads(bytes.fromhex(result["body"])) == {
        "detail": {"error": "peer_authentication_failed"}
    }


def test_revoked_pinned_cert_is_401(tmp_path, pki):
    fp = _fingerprint(pki / "nexus.pem")
    listener, _ = _start(tmp_path, pki, revoked=frozenset({fp}))
    try:
        assert _client(listener, pki, tmp_path)["status"] == 401
    finally:
        listener.stop()


def test_expired_by_clock_pinned_cert_is_401(tmp_path, pki):
    listener, _ = _start(tmp_path, pki, now=lambda: 4_000_000_000.0)
    try:
        assert _client(listener, pki, tmp_path)["status"] == 401
    finally:
        listener.stop()


def test_signer_failure_fails_closed_503(tmp_path, pki):
    listener, _ = _start(tmp_path, pki, signer=_Signer(fail=True))
    try:
        result = _client(listener, pki, tmp_path)
    finally:
        listener.stop()
    assert result["status"] == 503
    assert json.loads(bytes.fromhex(result["body"]))["detail"]["error"] == (
        "knowledge_context_signing_unavailable"
    )


def test_oversized_declared_body_is_rejected_before_read(tmp_path, pki):
    listener, _ = _start(tmp_path, pki)
    try:
        result = _client(listener, pki, tmp_path, body=b"x" * (limits.CONTEXT_MAX_BODY_BYTES + 1))
    finally:
        listener.stop()
    # The listener answers 413 and closes without draining; the client may see
    # either the 413 or a reset while still sending. A 200/401 would be a bug.
    assert result.get("status") == 413 or "error" in result, result


def test_audit_failure_fails_closed(tmp_path, pki):
    listener, _ = _start(tmp_path, pki)
    try:
        class _Down:
            healthy = False

            def append(self, event):
                from azazel_knowledge.audit.logger import AuditUnavailable
                raise AuditUnavailable("down")

        listener.app.state.audit = _Down()
        result = _client(listener, pki, tmp_path)
    finally:
        listener.stop()
    assert result["status"] == 503, result
    assert json.loads(bytes.fromhex(result["body"]))["detail"]["error"] == "audit_unavailable"


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "localhost", ""])
def test_wildcard_and_non_literal_binds_are_refused(host, tmp_path):
    with pytest.raises(ValueError):
        MtlsListenerConfig(host, 0, tmp_path / "a", tmp_path / "b", tmp_path / "c")


def test_listener_requires_enabled_pinned_profile(tmp_path, pki):
    app, settings, _db, _data = build_app(tmp_path)
    cfg = MtlsListenerConfig(
        "127.0.0.1", 0, pki / "server.pem", pki / "server.key", pki / "ca.pem"
    )
    with pytest.raises(ValueError):
        KnowledgeContextMtlsListener(app, cfg)  # opt-in: no transport => refuse


def test_authenticator_ignores_forged_header_and_wrong_scope_type():
    auth = PinnedCertificatePeerAuthenticator(
        peer_id="nexus-lab", cert_sha256="a" * 64, is_revoked=lambda fp: False
    )
    forged = Request({
        "type": "http", "headers": [(b"x-client-cert-sha256", b"a" * 64)],
        "extensions": {_SCOPE_KEY: {"cert_sha256": "a" * 64, "not_after_epoch": 9e12}},
    })
    assert auth.authenticate(forged) is None
    ok = Request({
        "type": "http", "headers": [],
        "extensions": {_SCOPE_KEY: VerifiedTlsPeer("a" * 64, 9e12)},
    })
    assert auth.authenticate(ok) == "nexus-lab"
    boom = PinnedCertificatePeerAuthenticator(
        peer_id="nexus-lab", cert_sha256="a" * 64, is_revoked=lambda fp: 1 / 0
    )
    assert boom.authenticate(ok) is None


def _raw_tls(listener, pki, payload_chunks, *, delay=0.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(pki / "ca.pem"))
    ctx.load_cert_chain(str(pki / "nexus.pem"), str(pki / "nexus.key"))
    host, port = listener.address
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
            try:
                for chunk in payload_chunks:
                    tls.sendall(chunk)
                    if delay:
                        time.sleep(delay)
                return tls.recv(4096)
            except OSError as exc:
                return repr(exc).encode()


def test_oversized_headers_are_refused_with_bounded_431(tmp_path, pki):
    from azazel_knowledge.api import knowledge_context_mtls as mod

    listener, _ = _start(tmp_path, pki)
    try:
        # One huge header, no terminator ever sent: refused once the cap is reached.
        flood = b"POST /v1/knowledge-context HTTP/1.1\r\nX-A: " + b"a" * (mod._MAX_HEADER_BYTES * 4)
        reply = _raw_tls(listener, pki, [flood])
        # Only an explicit 431, or the connection being closed/reset/errored at the
        # TLS layer (empty read = close_notify/EOF), is acceptable. Any other HTTP
        # response, notably a 2xx/4xx/5xx other than 431, fails here.
        closed = reply == b"" or reply.startswith((
            b"ConnectionResetError", b"BrokenPipeError", b"ConnectionAbortedError",
            b"SSLError", b"SSLEOFError", b"SSLZeroReturnError",
        ))
        assert reply.startswith(b"HTTP/1.0 431 ") or closed, reply
        # Many small headers within the byte cap but over the count cap.
        many = b"POST /v1/knowledge-context HTTP/1.1\r\n" + b"".join(
            b"X-%d: 1\r\n" % i for i in range(mod._MAX_HEADER_COUNT + 5)) + b"\r\n"
        assert b" 431 " in _raw_tls(listener, pki, [many]).split(b"\r\n", 1)[0]
        # The listener is still serving afterwards.
        assert _client(listener, pki, tmp_path)["status"] == 200
    finally:
        listener.stop()


def test_slow_incomplete_headers_hit_the_connection_deadline(tmp_path, pki):
    listener, _ = _start(tmp_path, pki, deadline_seconds=1.0)
    try:
        started = time.monotonic()
        trickle = [b"POST /v1/knowledge-context HTTP/1.1\r\n"] + [b"X: 1\r\n"] * 20
        reply = _raw_tls(listener, pki, trickle, delay=0.3)
        assert time.monotonic() - started < 8
        assert b" 503 " in reply.split(b"\r\n", 1)[0] or reply.startswith(b"HTTP/1.0 503") \
            or b"Error" in reply or b"Errno" in reply, reply
    finally:
        listener.stop()


def test_stalled_tls_handshake_uses_deadline_and_releases_connection_slot(tmp_path, pki):
    listener, _ = _start(tmp_path, pki, deadline_seconds=1.0, max_concurrency=1)
    host, port = listener.address
    stalled = socket.create_connection((host, port), timeout=2)
    try:
        time.sleep(1.3)
        assert _client(listener, pki, tmp_path)["status"] == 200
    finally:
        stalled.close()
        listener.stop()


def test_timed_out_app_keeps_its_concurrency_slot_until_worker_finishes(tmp_path, pki):
    listener, _ = _start(tmp_path, pki, max_concurrency=1)
    release = threading.Event()
    calls = 0

    async def slow_once(*_args):
        nonlocal calls
        calls += 1
        if calls == 1:
            await asyncio.to_thread(release.wait)
        return 200, [("Content-Type", "application/json")], b"{}"

    listener._call_app = slow_once
    args = {
        "method": "POST", "headers": [], "body": b"{}", "peer": None,
        "client": ("127.0.0.1", 1),
    }
    try:
        first = listener._dispatch(**args, timeout=0.02)
        assert first[0] == 503
        assert json.loads(first[2]) == {"detail": {"error": "context_timeout"}}
        busy = listener._dispatch(**args, timeout=0.1)
        assert busy[0] == 503
        assert json.loads(busy[2]) == {"detail": {"error": "context_busy"}}
        release.set()
        deadline = time.monotonic() + 2
        result = busy
        while result[0] == 503 and time.monotonic() < deadline:
            time.sleep(0.01)
            result = listener._dispatch(**args, timeout=0.2)
        assert result[0] == 200
    finally:
        release.set()
        listener.stop()
