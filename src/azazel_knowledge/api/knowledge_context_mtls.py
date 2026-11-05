"""Optional, explicitly constructed mTLS listener for the Knowledge Context profile.

Opt-in only: nothing here runs unless an integrator builds a
:class:`KnowledgeContextMtlsListener` and calls ``start()``. There is no
environment switch, no default certificate path and no default bind address.

* The listener owns the TLS handshake with a real ``ssl.SSLContext``
  (``CERT_REQUIRED``, TLS 1.2 minimum). That same context is the one that
  serves connections (exposed as ``listener.ssl_context``).
* Client identity is decided from the verified peer certificate only: its DER
  SHA-256 must equal the single commissioned fingerprint, it must be inside its
  validity window now, and it must not be revoked. Request headers are never an
  identity source; the verified facts reach the app through the ASGI scope.
* Only ``POST /v1/knowledge-context`` is served here. The ordinary HTTP
  routes of ``create_app`` are not touched.
* Bounded: header size, body size, per-connection deadline, concurrency. One
  request per connection. Any listener-side failure answers a fixed 503.
"""

from __future__ import annotations

import asyncio
import hashlib
import http.server
import ipaddress
import json
import select
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request

from azazel_knowledge.api import limits

ROUTE_PATH = "/v1/knowledge-context"
_SCOPE_KEY = "azazel.knowledge_context.tls_peer"
_MAX_HEADER_BYTES = 16 * 1024
_MAX_HEADER_COUNT = 64
_SHA256_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class VerifiedTlsPeer:
    """Facts about a peer certificate already verified by the TLS handshake."""

    cert_sha256: str
    not_after_epoch: float


class PinnedCertificatePeerAuthenticator:
    """Bind one commissioned peer ID to one pinned client certificate.

    Checks (all must hold, evaluated per request): the scope carries a
    :class:`VerifiedTlsPeer` set by the listener, its fingerprint equals the pin,
    it has not expired, and it is not revoked. A revocation-lookup error is
    treated as revoked (fail closed).
    """

    def __init__(
        self,
        *,
        peer_id: str,
        cert_sha256: str,
        is_revoked: Callable[[str], bool],
        now: Callable[[], float] = time.time,
    ) -> None:
        pin = cert_sha256.lower()
        if len(pin) != 64 or not set(pin) <= _SHA256_HEX:
            raise ValueError("cert_sha256 must be 64 lowercase hex characters")
        self._peer_id = peer_id
        self._pin = pin
        self._is_revoked = is_revoked
        self._now = now

    def authenticate(self, request: Request) -> str | None:
        peer = request.scope.get("extensions", {}).get(_SCOPE_KEY)
        if type(peer) is not VerifiedTlsPeer:
            return None
        if peer.cert_sha256 != self._pin:
            return None
        if not self._now() < peer.not_after_epoch:
            return None
        try:
            if self._is_revoked(peer.cert_sha256) is not False:
                return None
        except Exception:  # noqa: BLE001 -- revocation unknown => deny
            return None
        return self._peer_id



@dataclass(frozen=True)
class MtlsListenerConfig:
    bind_host: str
    bind_port: int
    server_cert_file: Path
    server_key_file: Path
    client_ca_file: Path
    deadline_seconds: float = 10.0
    max_concurrency: int = 4
    max_body_bytes: int = limits.CONTEXT_MAX_BODY_BYTES

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.bind_host)
        except ValueError:
            raise ValueError("bind_host must be an exact IP address literal") from None
        if address.is_unspecified or address.is_multicast:
            raise ValueError("wildcard or multicast bind is not allowed")
        if type(self.bind_port) is not int or not 0 <= self.bind_port <= 65535:
            raise ValueError("bind_port must be 0..65535")
        if not 0 < self.deadline_seconds <= 60:
            raise ValueError("deadline_seconds must be in (0, 60]")
        if type(self.max_concurrency) is not int or not 1 <= self.max_concurrency <= 64:
            raise ValueError("max_concurrency must be 1..64")
        if (type(self.max_body_bytes) is not int
                or not 1 <= self.max_body_bytes <= limits.CONTEXT_MAX_BODY_BYTES):
            raise ValueError("max_body_bytes must not exceed the context body cap")


def build_server_ssl_context(config: MtlsListenerConfig) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(str(config.server_cert_file), str(config.server_key_file))
    context.load_verify_locations(cafile=str(config.client_ca_file))
    return context


def _json(status: int, error: str) -> tuple[int, list[tuple[str, str]], bytes]:
    body = json.dumps({"detail": {"error": error}}, separators=(",", ":")).encode()
    return status, [("Content-Type", "application/json")], body


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def __init__(self, listener: "KnowledgeContextMtlsListener") -> None:
        self.listener = listener
        cfg = listener.config
        super().__init__((cfg.bind_host, cfg.bind_port), _Handler, bind_and_activate=False)
        if ":" in cfg.bind_host:
            self.address_family = socket.AF_INET6
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.server_bind()
        self.server_activate()

    def process_request(self, request, client_address):  # type: ignore[override]
        if not self.listener._slots.acquire(blocking=False):
            self.shutdown_request(request)  # over capacity: drop before any TLS work
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.listener._slots.release()
            raise

    def process_request_thread(self, request, client_address):  # type: ignore[override]
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.listener._slots.release()

    def finish_request(self, request, client_address):  # type: ignore[override]
        cfg = self.listener.config
        deadline = time.monotonic() + cfg.deadline_seconds
        request.settimeout(max(0.001, deadline - time.monotonic()))
        try:
            tls = self.listener.ssl_context.wrap_socket(
                request, server_side=True, do_handshake_on_connect=False
            )
            tls.setblocking(False)
            self._handshake_until(tls, deadline)
        except (OSError, ssl.SSLError, TimeoutError):
            return  # handshake refused (incl. no/invalid client cert): no response
        try:
            _Handler(tls, client_address, self, deadline=deadline)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    @staticmethod
    def _handshake_until(tls: ssl.SSLSocket, deadline: float) -> None:
        """Complete TLS under the same absolute deadline used for the HTTP request."""
        while True:
            try:
                tls.do_handshake()
                return
            except ssl.SSLWantReadError:
                readable, writable = [tls], []
            except ssl.SSLWantWriteError:
                readable, writable = [], [tls]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("TLS handshake deadline")
            ready_read, ready_write, _ = select.select(readable, writable, [], remaining)
            if not ready_read and not ready_write:
                raise TimeoutError("TLS handshake deadline")


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # one request per connection
    server_version = "azazel-knowledge"
    sys_version = ""

    def __init__(self, request, client_address, server, *, deadline: float) -> None:
        self._deadline = deadline
        super().__init__(request, client_address, server)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def _remaining(self) -> float:
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("deadline")
        return left

    def _reply(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        try:
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def _recv(self, limit: int) -> bytes:
        # Every receive re-arms the timeout from the single connection deadline,
        # so trickled bytes cannot extend the total time.
        self.connection.settimeout(self._remaining())
        return self.connection.recv(limit)

    def _read_head(self) -> tuple[bytes, bytes] | None:
        """Read request line + headers under one strict byte cap, before any parsing.

        Returns (head_without_terminator, leftover_body_bytes), or None after a
        bounded refusal was sent. At most _MAX_HEADER_BYTES + one recv are held.
        """
        buf = bytearray()
        while True:
            end = buf.find(b"\r\n\r\n")
            if end >= 0:
                if end + 4 > _MAX_HEADER_BYTES:
                    break
                return bytes(buf[:end]), bytes(buf[end + 4:])
            if len(buf) >= _MAX_HEADER_BYTES:
                break
            chunk = self._recv(min(4096, _MAX_HEADER_BYTES - len(buf)))
            if not chunk:
                self._reply(*_json(400, "incomplete_request"))
                return None
            buf += chunk
        self._reply(*_json(431, "request_header_too_large"))
        return None

    def handle(self) -> None:
        self.close_connection = True
        self.request_version = "HTTP/1.0"
        self.requestline = ""
        listener: KnowledgeContextMtlsListener = self.server.listener  # type: ignore[attr-defined]
        try:
            head = self._read_head()
            if head is not None:
                self._serve(listener, *head)
        except (TimeoutError, socket.timeout):
            self._reply(*_json(503, "context_timeout"))
        except OSError:
            return
        except Exception:  # noqa: BLE001 -- listener failures fail closed
            self._reply(*_json(503, "knowledge_context_unavailable"))

    def _serve(self, listener: "KnowledgeContextMtlsListener", head: bytes, leftover: bytes) -> None:
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
            return self._reply(*_json(400, "malformed_request_line"))
        method, path, _version = parts
        if len(lines) - 1 > _MAX_HEADER_COUNT:
            return self._reply(*_json(431, "too_many_headers"))
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if (not sep or not name or name != name.strip() or "\n" in line
                    or "\r" in line or name.lower() in headers):
                return self._reply(*_json(400, "malformed_header"))
            headers[name.lower()] = value.strip()
        if method != "POST" or path != ROUTE_PATH:
            return self._reply(*_json(404, "not_found"))
        if "transfer-encoding" in headers:
            return self._reply(*_json(400, "transfer_encoding_unsupported"))
        declared = headers.get("content-length")
        if declared is None or not declared.isascii() or not declared.isdecimal() or len(declared) > 9:
            return self._reply(*_json(411, "content_length_required"))
        length = int(declared)
        if length > listener.config.max_body_bytes:
            return self._reply(*_json(413, "context_request_too_large"))
        if len(leftover) > length:
            return self._reply(*_json(400, "unexpected_trailing_bytes"))

        body = bytearray(leftover)
        while len(body) < length:
            chunk = self._recv(min(65536, length - len(body)))
            if not chunk:
                return self._reply(*_json(400, "truncated_body"))
            body += chunk

        peer = self._verified_peer(listener)
        status, out_headers, payload = listener._dispatch(
            method="POST",
            headers=[(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()],
            body=bytes(body),
            peer=peer,
            client=self.client_address,
            timeout=self._remaining(),
        )
        self._reply(status, out_headers, payload)

    def _verified_peer(self, listener: "KnowledgeContextMtlsListener") -> VerifiedTlsPeer | None:
        conn = self.connection
        try:
            der = conn.getpeercert(binary_form=True)
            parsed = conn.getpeercert()
            if not der or not parsed or "notAfter" not in parsed:
                return None
            return VerifiedTlsPeer(
                cert_sha256=hashlib.sha256(der).hexdigest(),
                not_after_epoch=float(ssl.cert_time_to_seconds(parsed["notAfter"])),
            )
        except Exception:  # noqa: BLE001
            return None


class KnowledgeContextMtlsListener:
    """Serve the Knowledge Context route over mutually authenticated TLS."""

    def __init__(self, app: FastAPI, config: MtlsListenerConfig) -> None:
        transport = app.state.settings.knowledge_context_transport
        if transport is None or not transport.enabled:
            raise ValueError("an enabled knowledge_context_transport profile is required")
        if not isinstance(transport.peer_authenticator, PinnedCertificatePeerAuthenticator):
            raise ValueError("the transport must use PinnedCertificatePeerAuthenticator")
        self.app = app
        self.config = config
        self.ssl_context = build_server_ssl_context(config)
        self._slots = threading.BoundedSemaphore(config.max_concurrency)
        self._app_slots = threading.BoundedSemaphore(config.max_concurrency)
        self._server: _Server | None = None
        self._threads: list[threading.Thread] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("listener not started")
        return self._server.server_address[:2]  # type: ignore[return-value]

    def start(self) -> None:
        if self._server is not None:
            raise RuntimeError("listener already started")
        loop = asyncio.new_event_loop()
        self._loop = loop
        loop_thread = threading.Thread(target=loop.run_forever, daemon=True)
        loop_thread.start()
        self._server = _Server(self)
        serve = threading.Thread(target=self._server.serve_forever, daemon=True)
        serve.start()
        self._threads = [loop_thread, serve]

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._threads[0].join(timeout=5)
            self._loop = None

    def __enter__(self) -> "KnowledgeContextMtlsListener":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _dispatch(self, *, method, headers, body, peer, client, timeout):
        assert self._loop is not None
        if not self._app_slots.acquire(blocking=False):
            return _json(503, "context_busy")
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._call_app(method, headers, body, peer, client), self._loop
            )
        except Exception:
            self._app_slots.release()
            return _json(503, "knowledge_context_unavailable")
        future.add_done_callback(lambda _future: self._app_slots.release())
        try:
            return future.result(timeout=timeout)
        except (TimeoutError, asyncio.TimeoutError):
            # Cancelling the asyncio wrapper cannot stop a synchronous endpoint
            # already running in a worker thread. Hold the slot until completion.
            return _json(503, "context_timeout")
        except Exception:  # noqa: BLE001
            return _json(503, "knowledge_context_unavailable")

    async def _call_app(self, method, headers, body, peer, client):
        extensions: dict[str, Any] = {}
        if peer is not None:
            extensions[_SCOPE_KEY] = peer
        host, port = self.address
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": ROUTE_PATH,
            "raw_path": ROUTE_PATH.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "server": (host, port),
            "client": (client[0], client[1]),
            "extensions": extensions,
        }
        sent = False
        status = 500
        out_headers: list[tuple[str, str]] = []
        chunks: list[bytes] = []

        async def receive():
            nonlocal sent
            if sent:
                await asyncio.sleep(3600)
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            nonlocal status, out_headers
            if message["type"] == "http.response.start":
                status = message["status"]
                out_headers = [
                    (k.decode("latin-1"), v.decode("latin-1"))
                    for k, v in message.get("headers", [])
                    if k.lower() not in (b"content-length", b"connection")
                ]
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b""))

        await self.app(scope, receive, send)
        return status, out_headers, b"".join(chunks)


__all__ = [
    "KnowledgeContextMtlsListener",
    "MtlsListenerConfig",
    "PinnedCertificatePeerAuthenticator",
    "ROUTE_PATH",
    "VerifiedTlsPeer",
    "build_server_ssl_context",
]
