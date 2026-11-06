"""Test-only server process: the real `create_app` app behind the real mTLS listener.

Usage: python _knowledge_context_mtls_server.py <temp_root> <pki_dir>

All databases live under <temp_root>; the certs/keys are the ephemeral ones in
<pki_dir>. Binds 127.0.0.1 on an ephemeral port and prints exactly one JSON
readiness line on stdout. Exits cleanly on SIGTERM/SIGINT. Not a product entrypoint.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import ssl
import sys
import threading
from pathlib import Path

from nacl.signing import SigningKey

from _api_support import build_app
from azazel_knowledge.core.clock import SystemClock
from azazel_knowledge.api.knowledge_context_mtls import (
    KnowledgeContextMtlsListener,
    MtlsListenerConfig,
    PinnedCertificatePeerAuthenticator,
)
from azazel_knowledge.api.knowledge_context_transport import KnowledgeContextTransportConfig


class _Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()  # per-process; private key never leaves this process
        self.public_key = bytes(self.key.verify_key)
        self.key_id = "sha256:" + hashlib.sha256(self.public_key).hexdigest()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def main(root: Path, pki: Path) -> int:
    root.mkdir(parents=True, exist_ok=True)
    app, settings, _local, _data = build_app(root)
    # The separate Nexus process validates response expiry against its own
    # current clock. Keep the producer process on real time too; the fixed
    # fixture clock would make an otherwise valid short-lived response stale.
    settings.clock = SystemClock()
    app.state.clock = settings.clock
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert((pki / "nexus.pem").read_text())).hexdigest()
    signer = _Signer()
    settings.knowledge_context_transport = KnowledgeContextTransportConfig(
        peer_authenticator=PinnedCertificatePeerAuthenticator(
            peer_id="nexus-lab", cert_sha256=pin, is_revoked=lambda fp: False
        ),
        signer=signer, max_ttl_seconds=30, expected_peer_id="nexus-lab", enabled=True,
    )
    listener = KnowledgeContextMtlsListener(
        app,
        MtlsListenerConfig(
            bind_host="127.0.0.1", bind_port=0,
            server_cert_file=pki / "server.pem", server_key_file=pki / "server.key",
            client_ca_file=pki / "ca.pem",
        ),
    )
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    listener.start()
    try:
        host, port = listener.address
        print(json.dumps({"ready": True, "pid": os.getpid(), "host": host, "port": port,
                          "key_id": signer.key_id,
                          "public_key": signer.public_key.hex()}), flush=True)
        stop.wait()
    finally:
        listener.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
