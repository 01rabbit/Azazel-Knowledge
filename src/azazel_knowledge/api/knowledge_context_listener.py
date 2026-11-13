"""Default-disabled product entry for the Nexus Knowledge Context mTLS listener.

Lab / interop-only until commissioning. This module assembles only existing
product classes (``create_app`` settings, ``KnowledgeContextTransportConfig``,
``PinnedCertificatePeerAuthenticator``, ``KnowledgeContextMtlsListener``) plus
two small pieces that did not exist: a response signer backed by a dedicated
key file and a client-certificate revocation source.

Rules enforced here, all fail-closed with a fixed, secret-free message:

* a closed TOML schema; every field is required and ``enabled`` must be ``true``;
* no environment variable, default path, default trust store or default value is
  consulted; keys are never generated;
* every path is absolute, symlink-free, a regular file owned by the running user
  (or root for public material) with no group/other write, and no group/other
  access at all for private keys;
* the response key must not be the audit-anchor ``secrets/node_signing_key``.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import signal
import stat
import sys
import threading
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from azazel_knowledge.api import limits
from azazel_knowledge.api.app import create_app, settings_from_env
from azazel_knowledge.api.knowledge_context_mtls import (
    KnowledgeContextMtlsListener,
    MtlsListenerConfig,
    PinnedCertificatePeerAuthenticator,
)
from azazel_knowledge.api.knowledge_context_transport import (
    KnowledgeContextTransportConfig,
)
from azazel_knowledge.core.clock import SystemClock

_SHA256_HEX = frozenset("0123456789abcdef")
_REVOCATION_HEADER = "# azazel-knowledge-revoked-client-cert-sha256 v1"
_MAX_FILE_BYTES = 1024 * 1024


class ListenerConfigError(Exception):
    """A refusal to start. The message is fixed text and never carries secrets."""


def _refuse(message: str) -> ListenerConfigError:
    return ListenerConfigError(message)


# --------------------------------------------------------------------------
# safe file access
# --------------------------------------------------------------------------


def read_safe_file(path: object, *, field: str, private: bool, max_bytes: int = _MAX_FILE_BYTES) -> bytes:
    """Read a file after proving the path is an unlinked, owner-safe regular file.

    ``private`` files (keys) must have no group/other permission bits. Public
    files must not be group/other writable. Owner must be the running user
    (root is also accepted for public files). Checked on the opened descriptor.
    """
    if not isinstance(path, str) or not path or "\x00" in path or not os.path.isabs(path):
        raise _refuse(f"{field}: absolute path required")
    if os.path.realpath(path) != os.path.normpath(path):
        raise _refuse(f"{field}: symlink or non-canonical path")
    parent = os.path.dirname(path)
    pst = os.stat(parent) if os.path.isdir(parent) else None
    if pst is None:
        raise _refuse(f"{field}: parent directory missing")
    if pst.st_mode & 0o022 and not pst.st_mode & stat.S_ISVTX:
        raise _refuse(f"{field}: parent directory is group/other writable")
    euid = os.geteuid()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise _refuse(f"{field}: cannot open") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _refuse(f"{field}: not a regular file")
        allowed_owners = {euid} if private else {euid, 0}
        if st.st_uid not in allowed_owners:
            raise _refuse(f"{field}: unsafe owner")
        if private and st.st_mode & 0o077:
            raise _refuse(f"{field}: mode must not allow group/other access")
        if st.st_mode & 0o022:
            raise _refuse(f"{field}: group/other writable")
        if st.st_size > max_bytes:
            raise _refuse(f"{field}: file too large")
        data = b""
        while len(data) <= max_bytes:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
        if len(data) > max_bytes:
            raise _refuse(f"{field}: file too large")
        return data
    except OSError:
        raise _refuse(f"{field}: read failed") from None
    finally:
        os.close(fd)


# --------------------------------------------------------------------------
# response signer (dedicated key file)
# --------------------------------------------------------------------------


def _prove_not_node_key(key_file: str, seed: bytes, node_key: Path) -> None:
    """Refuse unless it is proven that ``seed`` is not the node signing key.

    Proven means: the node key was read and differs, or it is positively absent
    (ENOENT at the final component while its directory is traversable). Any
    other error (permissions, loops, not-a-directory, I/O) refuses to start.
    """
    if os.path.realpath(key_file) == os.path.realpath(node_key):
        raise _refuse("response_signing_key_file: must not be the node signing key")
    try:
        fd = os.open(node_key, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        try:
            os.stat(node_key.parent)  # absence is only proven if the directory is traversable
        except FileNotFoundError:
            return  # no secrets directory at all: no node key can exist
        except OSError:
            raise _refuse("node signing key separation cannot be proven") from None
        try:
            os.lstat(node_key)
        except FileNotFoundError:
            return
        except OSError:
            raise _refuse("node signing key separation cannot be proven") from None
        raise _refuse("node signing key separation cannot be proven")
    except OSError:
        raise _refuse("node signing key separation cannot be proven") from None
    try:
        other = b""
        while len(other) <= 4096:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            other += chunk
    except OSError:
        raise _refuse("node signing key separation cannot be proven") from None
    finally:
        os.close(fd)
    if other == seed:
        raise _refuse("response_signing_key_file: must not reuse the node signing key")


def _check_cert_window(pem: bytes, field: str) -> None:
    import ssl
    import tempfile
    import time

    try:
        with tempfile.NamedTemporaryFile("wb", suffix=".pem") as fh:
            fh.write(pem)
            fh.flush()
            info = ssl._ssl._test_decode_cert(fh.name)  # type: ignore[attr-defined]
        not_before = ssl.cert_time_to_seconds(info["notBefore"])
        not_after = ssl.cert_time_to_seconds(info["notAfter"])
    except Exception:  # noqa: BLE001
        raise _refuse(f"{field}: certificate cannot be parsed") from None
    if not not_before <= time.time() < not_after:
        raise _refuse(f"{field}: certificate is outside its validity window")


class FileKeyResponseSigner:
    """Ed25519 response signer loaded from a dedicated 32-byte raw seed file.

    Same algorithm and wire use as the Knowledge Context route
    (``signature(64) || envelope`` over the domain-prefixed envelope; ``key_id``
    is ``sha256:`` plus the SHA-256 of the raw public key). The seed file format
    matches ``secrets/node_signing_key``, but that file must never be used here.
    """

    def __init__(self, key_file: object, *, forbidden_seed_file: Path | None = None) -> None:
        seed = read_safe_file(key_file, field="response_signing_key_file", private=True, max_bytes=64)
        if len(seed) != 32:
            raise _refuse("response_signing_key_file: expected a 32-byte raw Ed25519 seed")
        if forbidden_seed_file is not None:
            _prove_not_node_key(str(key_file), seed, Path(forbidden_seed_file))
        self._key = SigningKey(seed)
        self.public_key: bytes = bytes(self._key.verify_key)
        self.key_id: str = "sha256:" + hashlib.sha256(self.public_key).hexdigest()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature

    def __repr__(self) -> str:  # never expose key material
        return f"FileKeyResponseSigner(key_id={self.key_id})"


# --------------------------------------------------------------------------
# certificate revocation source
# --------------------------------------------------------------------------


def _parse_revocation(data: bytes) -> frozenset[str]:
    try:
        lines = data.decode("ascii").split("\n")
    except UnicodeDecodeError:
        raise _refuse("revocation_file: not ASCII") from None
    if not lines or lines[0] != _REVOCATION_HEADER:
        raise _refuse("revocation_file: missing or wrong header line")
    revoked: set[str] = set()
    for line in lines[1:]:
        if line == "" or line.startswith("#"):
            continue
        if len(line) != 64 or not set(line) <= _SHA256_HEX:
            raise _refuse("revocation_file: malformed entry")
        revoked.add(line)
    return frozenset(revoked)


class FileRevocationSource:
    """Revoked client-certificate DER SHA-256 values read from one file.

    The file is validated strictly at construction (missing or malformed means
    the caller refuses to start) and re-read on every lookup so a revocation
    takes effect without a restart. Any later failure raises; the existing
    authenticator treats a raising lookup as revoked (deny).
    """

    def __init__(self, path: object) -> None:
        self._path = path
        self._parse_current()

    def _parse_current(self) -> frozenset[str]:
        return _parse_revocation(read_safe_file(self._path, field="revocation_file", private=False))

    def is_revoked(self, cert_sha256: str) -> bool:
        return cert_sha256 in self._parse_current()


# --------------------------------------------------------------------------
# closed config schema
# --------------------------------------------------------------------------

_STR_FIELDS = (
    "bind_host", "knowledge_root", "config_dir", "server_cert_file", "server_key_file",
    "client_ca_file", "expected_peer_id", "client_cert_sha256", "response_signing_key_file",
    "revocation_file",
)
_INT_FIELDS = ("bind_port", "max_ttl_seconds", "max_concurrency", "max_body_bytes")
_NUM_FIELDS = ("deadline_seconds",)
FIELDS = frozenset(("enabled", *_STR_FIELDS, *_INT_FIELDS, *_NUM_FIELDS))


@dataclass(frozen=True)
class ListenerProductConfig:
    bind_host: str
    bind_port: int
    knowledge_root: str
    config_dir: str
    server_cert_file: str
    server_key_file: str
    client_ca_file: str
    expected_peer_id: str
    client_cert_sha256: str
    response_signing_key_file: str
    revocation_file: str
    max_ttl_seconds: int
    deadline_seconds: float
    max_concurrency: int
    max_body_bytes: int


def parse_config(raw: bytes) -> ListenerProductConfig:
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise _refuse("config: not valid TOML") from None
    if doc.get("enabled") is not True:
        raise _refuse("config: enabled must be explicitly true")
    unknown = set(doc) - FIELDS
    if unknown:
        raise _refuse("config: unknown field(s): " + ", ".join(sorted(map(str, unknown))[:5]))
    missing = FIELDS - set(doc)
    if missing:
        raise _refuse("config: missing field(s): " + ", ".join(sorted(missing)))
    for name in _STR_FIELDS:
        if not isinstance(doc[name], str) or not doc[name]:
            raise _refuse(f"config: {name} must be a non-empty string")
    for name in _INT_FIELDS:
        if type(doc[name]) is not int:
            raise _refuse(f"config: {name} must be an integer")
    for name in _NUM_FIELDS:
        if type(doc[name]) not in (int, float):
            raise _refuse(f"config: {name} must be a number")
    return ListenerProductConfig(**{k: doc[k] for k in FIELDS if k != "enabled"})


def _check_bounds(cfg: ListenerProductConfig) -> None:
    host = cfg.bind_host
    if "%" in host:
        raise _refuse("bind_host: scoped address not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise _refuse("bind_host: must be an exact IP literal") from None
    if address.is_unspecified or address.is_multicast:
        raise _refuse("bind_host: wildcard or multicast not allowed")
    if not 1 <= cfg.bind_port <= 65535:
        raise _refuse("bind_port: must be 1..65535")
    pin = cfg.client_cert_sha256
    if len(pin) != 64 or not set(pin) <= _SHA256_HEX:
        raise _refuse("client_cert_sha256: expected 64 lowercase hex characters")
    if not 1 <= cfg.max_ttl_seconds <= 30:
        raise _refuse("max_ttl_seconds: must be 1..30")
    if not 0 < cfg.deadline_seconds <= 60:
        raise _refuse("deadline_seconds: must be in (0, 60]")
    if not 1 <= cfg.max_concurrency <= 64:
        raise _refuse("max_concurrency: must be 1..64")
    if not 1 <= cfg.max_body_bytes <= limits.CONTEXT_MAX_BODY_BYTES:
        raise _refuse("max_body_bytes: outside the context body cap")


def _check_dir(value: str, field: str) -> None:
    if not os.path.isabs(value) or os.path.realpath(value) != os.path.normpath(value):
        raise _refuse(f"{field}: absolute, symlink-free directory required")
    try:
        st = os.stat(value)
    except OSError:
        raise _refuse(f"{field}: directory missing") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in {os.geteuid(), 0} or st.st_mode & 0o022:
        raise _refuse(f"{field}: unsafe directory")


def build_listener(cfg: ListenerProductConfig) -> KnowledgeContextMtlsListener:
    """Validate everything and assemble the (not yet started) listener."""
    _check_bounds(cfg)
    _check_dir(cfg.knowledge_root, "knowledge_root")
    _check_dir(cfg.config_dir, "config_dir")
    # Validate TLS material files before handing them to the ssl module.
    _check_cert_window(
        read_safe_file(cfg.server_cert_file, field="server_cert_file", private=False),
        "server_cert_file",
    )
    read_safe_file(cfg.server_key_file, field="server_key_file", private=True)
    read_safe_file(cfg.client_ca_file, field="client_ca_file", private=False)

    signer = FileKeyResponseSigner(
        cfg.response_signing_key_file,
        forbidden_seed_file=Path(cfg.knowledge_root) / "secrets" / "node_signing_key",
    )
    revocation = FileRevocationSource(cfg.revocation_file)
    if revocation.is_revoked(cfg.client_cert_sha256):
        raise _refuse("client_cert_sha256: pinned certificate is listed as revoked")

    try:
        transport = KnowledgeContextTransportConfig(
            peer_authenticator=PinnedCertificatePeerAuthenticator(
                peer_id=cfg.expected_peer_id,
                cert_sha256=cfg.client_cert_sha256,
                is_revoked=revocation.is_revoked,
            ),
            signer=signer,
            max_ttl_seconds=cfg.max_ttl_seconds,
            expected_peer_id=cfg.expected_peer_id,
            enabled=True,
        )
        listener_config = MtlsListenerConfig(
            bind_host=cfg.bind_host,
            bind_port=cfg.bind_port,
            server_cert_file=Path(cfg.server_cert_file),
            server_key_file=Path(cfg.server_key_file),
            client_ca_file=Path(cfg.client_ca_file),
            deadline_seconds=float(cfg.deadline_seconds),
            max_concurrency=cfg.max_concurrency,
            max_body_bytes=cfg.max_body_bytes,
        )
    except ValueError as exc:
        raise _refuse(f"config: {exc}") from None

    # Both paths are passed explicitly, so settings_from_env consults no environment.
    settings = settings_from_env(cfg.knowledge_root, cfg.config_dir)
    settings.clock = SystemClock()
    settings.knowledge_context_transport = transport
    app = create_app(settings)
    try:
        # Malformed or mismatched cert/key/CA surface here (ssl.SSLError / OSError).
        return KnowledgeContextMtlsListener(app, listener_config)
    except (OSError, ValueError):
        raise _refuse("tls: server certificate, key or client CA is malformed or mismatched") from None


# --------------------------------------------------------------------------
# console entry point
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="azazel-knowledge-context-listener",
        description="Lab/interop-only Knowledge Context mTLS listener (disabled unless configured).",
    )
    parser.add_argument("--config", required=True, help="absolute path to the listener TOML file")
    args = parser.parse_args(argv)
    try:
        raw = read_safe_file(args.config, field="config", private=False)
        listener = build_listener(parse_config(raw))
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        listener.start()
    except ListenerConfigError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 -- never print exception text (may carry paths)
        print(f"refused: startup failed ({type(exc).__name__})", file=sys.stderr)
        return 2
    try:
        host, port = listener.address
        signer = listener.app.state.settings.knowledge_context_transport.signer
        print(f"listening {host} {port} key_id={signer.key_id}", flush=True)
        stop.wait()
    finally:
        listener.stop()
    return 0


__all__ = [
    "FIELDS",
    "FileKeyResponseSigner",
    "FileRevocationSource",
    "ListenerConfigError",
    "ListenerProductConfig",
    "build_listener",
    "main",
    "parse_config",
    "read_safe_file",
]

if __name__ == "__main__":
    sys.exit(main())
