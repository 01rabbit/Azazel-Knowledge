from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable
from enum import Enum

TOKEN_PREFIX = "azcti"


class Scope(Enum):
    INGEST = "ingest"
    QUERY = "query"
    READ = "read"
    ADMIN = "admin"


class InvalidToken(ValueError):
    pass


class Forbidden(Exception):
    pass


def parse_token(token: str) -> tuple[str, str]:
    if not isinstance(token, str):
        raise InvalidToken("token must be a string")
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not parts[1] or not parts[2]:
        raise InvalidToken(f"malformed token: {token!r}")
    return parts[1], parts[2]


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify(token: str, stored_sha256: str) -> bool:
    try:
        _, secret = parse_token(token)
    except InvalidToken:
        return False
    computed = hash_secret(secret)
    return hmac.compare_digest(computed, stored_sha256)


def mint_token(key_id: str) -> tuple[str, str]:
    if not key_id:
        raise ValueError("key_id must be non-empty")
    secret = secrets.token_urlsafe(32)
    token = f"{TOKEN_PREFIX}_{key_id}_{secret}"
    return token, hash_secret(secret)


def require_scope(client_scopes: Iterable[Scope], needed: Scope) -> None:
    if needed not in set(client_scopes):
        raise Forbidden(f"scope {needed.value!r} required")
