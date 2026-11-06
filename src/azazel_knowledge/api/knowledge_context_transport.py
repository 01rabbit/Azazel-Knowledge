"""Explicitly injected transport dependencies for the optional Nexus profile.

This module contains interfaces only. It does not load keys, configure TLS,
trust request headers, or enable a network route by default.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Protocol

from fastapi import Request


class KnowledgeContextSigner(Protocol):
    """A commissioned signer; key custody and signing stay outside the API."""

    @property
    def key_id(self) -> str: ...

    @property
    def public_key(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


class KnowledgeContextPeerAuthenticator(Protocol):
    """Authenticate the TLS client at a trusted listener boundary.

    Implementations must validate the client certificate and return a stable,
    non-secret commissioned peer identifier. They must not trust caller headers.
    """

    def authenticate(self, request: Request) -> str | None: ...


_PEER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class KnowledgeContextTransportConfig:
    """One explicitly commissioned, optional Knowledge Context peer profile."""

    peer_authenticator: KnowledgeContextPeerAuthenticator
    signer: KnowledgeContextSigner
    max_ttl_seconds: int
    expected_peer_id: str
    enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.max_ttl_seconds) is not int or not 1 <= self.max_ttl_seconds <= 30:
            raise ValueError("max_ttl_seconds must be between 1 and 30")
        if not isinstance(self.expected_peer_id, str) or not _PEER_ID.fullmatch(
            self.expected_peer_id
        ):
            raise ValueError("expected_peer_id must be a stable commissioned identifier")
        public_key = getattr(self.signer, "public_key", None)
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("signer public_key must be a 32-byte Ed25519 public key")
        expected = "sha256:" + hashlib.sha256(public_key).hexdigest()
        if not isinstance(getattr(self.signer, "key_id", None), str) or not _KEY_ID.fullmatch(
            self.signer.key_id
        ) or self.signer.key_id != expected:
            raise ValueError("signer key_id must fingerprint its Ed25519 public key")

    def authenticate_peer(self, request: Request) -> str | None:
        try:
            peer_id = self.peer_authenticator.authenticate(request)
        except Exception:  # noqa: BLE001 -- auth failures are indistinguishable
            return None
        if (not isinstance(peer_id, str) or not _PEER_ID.fullmatch(peer_id)
                or peer_id != self.expected_peer_id):
            return None
        return peer_id


__all__ = [
    "KnowledgeContextPeerAuthenticator",
    "KnowledgeContextSigner",
    "KnowledgeContextTransportConfig",
]
