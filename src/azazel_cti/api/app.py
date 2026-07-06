"""`create_app(settings) -> FastAPI` factory (design S2/S4/S7).

Wires the read-only `Repository`, the durable ingest `SpoolWriter`, a
per-process `AuditChain`, and a `Clock` into a FastAPI app; every piece
is passed in via `Settings` so tests can substitute a `FixedClock` and
`tmp_path`-scoped databases without touching module globals. The
bearer-token auth dependency and the cold-cache warmup gate live here
because every router needs them; router modules are imported lazily
inside `create_app` so this module has no import-time dependency on
them (and they can import back from here without a cycle).
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Request

from azazel_cti.api import limits
from azazel_cti.audit.logger import AuditChain, AuditUnavailable
from azazel_cti.core.clock import Clock, SystemClock
from azazel_cti.core.config import TrackedConfigLoader
from azazel_cti.db import generations
from azazel_cti.db.repository import Repository
from azazel_cti.ingest.spool import DEFAULT_QUOTA_BYTES, SpoolWriter
from azazel_cti.security.auth import (
    Forbidden,
    InvalidToken,
    Scope,
    parse_token,
    require_scope,
    verify,
)
from azazel_cti.security.redact import SecretRegistry


@dataclass
class Settings:
    config_dir: Path
    local_db_path: Path
    data_db_dir: Path
    spool_root: Path
    audit_dir: Path
    secrets_dir: Path | None = None
    proc_id: str = field(default_factory=lambda: f"api-{os.getpid()}")
    boot_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    clock: Clock = field(default_factory=SystemClock)
    pool_size: int = 4
    ingest_quota_bytes: int = DEFAULT_QUOTA_BYTES
    context_deadline_ms: int | None = None


@dataclass(frozen=True)
class AuthContext:
    key_id: str
    scopes: frozenset[Scope]


def _parse_scopes(raw: str | None) -> frozenset[Scope]:
    if not raw:
        return frozenset()
    values = json.loads(raw)
    scopes: set[Scope] = set()
    for value in values:
        try:
            scopes.add(Scope(value))
        except ValueError:
            continue
    return frozenset(scopes)


def open_local_readonly(local_db_path: Path) -> sqlite3.Connection:
    """Open a plain query-only connection to `local.db` alone.

    `Repository.connection()` ATTACHes the current intel generation on
    every acquire, which does not exist before the first bundle import;
    callers that only need a local-tier table (`api_client`,
    `local_meta`, ...) and must keep working through the cold-boot
    window (auth, `/v1/health`) use this instead.
    """
    conn = sqlite3.connect(local_db_path, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA query_only = ON")
    conn.row_factory = sqlite3.Row
    return conn


def _lookup_client(
    local_db_path: Path, key_id: str
) -> tuple[str, frozenset[Scope], bool] | None:
    conn = open_local_readonly(local_db_path)
    try:
        row = conn.execute(
            "SELECT token_sha256, scopes, enabled FROM api_client WHERE key_id = ?",
            (key_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return row["token_sha256"], _parse_scopes(row["scopes"]), bool(row["enabled"])


def authenticate(request: Request) -> AuthContext:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail={"error": "missing_bearer_token"})
    token = header[len("Bearer ") :].strip()
    try:
        key_id, _secret = parse_token(token)
    except InvalidToken:
        raise HTTPException(status_code=401, detail={"error": "invalid_token"})

    local_db_path: Path = request.app.state.settings.local_db_path
    record = _lookup_client(local_db_path, key_id)
    if record is None:
        raise HTTPException(status_code=401, detail={"error": "invalid_token"})
    stored_hash, scopes, enabled = record
    if not enabled or not verify(token, stored_hash):
        raise HTTPException(status_code=401, detail={"error": "invalid_token"})
    return AuthContext(key_id=key_id, scopes=scopes)


def require_scope_dep(scope: Scope) -> Callable[[AuthContext], AuthContext]:
    def _dep(auth: AuthContext = Depends(authenticate)) -> AuthContext:
        try:
            require_scope(auth.scopes, scope)
        except Forbidden:
            raise HTTPException(
                status_code=403, detail={"error": "forbidden", "scope": scope.value}
            )
        return auth

    return _dep


async def read_raw_body(request: Request) -> bytes:
    """Async dependency that resolves the raw body on the event loop.

    Route handlers themselves are plain `def`s (design F-4): FastAPI
    dispatches a sync endpoint to its bounded threadpool, which is the
    whole point -- spool fsync and SQLite reads must never block the
    event loop. Dependencies, however, always run on the loop, so the
    one unavoidable `await request.body()` lives here instead of in a
    handler body.
    """
    return await request.body()


async def read_json_body(request: Request) -> object:
    return await request.json()


def ensure_warm_cache(request: Request) -> None:
    """Cold-boot gate (design S9): fail closed on lookup/context until a
    live intel generation exists. Ingest routes never call this -- they
    keep spooling through the warmup window."""
    data_db_dir: Path = request.app.state.settings.data_db_dir
    if generations.current_generation(data_db_dir) is None:
        raise HTTPException(
            status_code=503,
            detail={"error": "cache_state_cold"},
            headers={"Retry-After": str(limits.WARMUP_RETRY_AFTER_S)},
        )


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI):
    yield
    audit: AuditChain = app.state.audit
    repo: Repository = app.state.repo
    try:
        audit.close()
    except AuditUnavailable:
        pass
    repo.close()


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="Azazel-CTI API", lifespan=_lifespan)

    registry = SecretRegistry()
    if settings.secrets_dir is not None:
        registry.register_dir(settings.secrets_dir)

    loader = TrackedConfigLoader(settings.config_dir)
    repo = Repository(
        settings.local_db_path, settings.data_db_dir, pool_size=settings.pool_size
    )
    spool = SpoolWriter(settings.spool_root, quota_bytes=settings.ingest_quota_bytes)
    audit = AuditChain(
        settings.audit_dir, settings.proc_id, settings.boot_id, registry.redact
    )

    app.state.settings = settings
    app.state.loader = loader
    app.state.repo = repo
    app.state.spool = spool
    app.state.audit = audit
    app.state.registry = registry
    app.state.clock = settings.clock
    app.state.metrics = {"context_total": 0, "context_breaker_total": 0}

    from azazel_cti.api.middleware import AuditMiddleware

    app.add_middleware(AuditMiddleware)

    from azazel_cti.api.routers import admin, context, ingest, lookup, reads
    from azazel_cti.taxii import inbox as taxii_inbox

    app.include_router(ingest.router)
    app.include_router(lookup.router)
    app.include_router(context.router)
    app.include_router(reads.router)
    app.include_router(admin.router)
    app.include_router(taxii_inbox.router)

    return app
