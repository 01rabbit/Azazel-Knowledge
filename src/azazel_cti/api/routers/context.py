"""`POST /v1/context` (design S4/S5, F-2, F-10, F-17).

Runs `correlate.pipeline.run_context` under a monotonic deadline
measured from handler entry, mints the advisory's public ULID (the
pipeline's own `advisory_id` is a plain random token used only for its
internal determinism replay tests -- the ULID here is what leaves the
process), appends the advisory line to the process `AuditChain` on the
request thread, and durably spools a mirror of that line so the worker
can materialize the `advisory_log` row at P0. A chain-append failure
fails the whole call closed (`503 audit_unavailable`): advice is never
served unauditable.
"""

from __future__ import annotations

import json
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from azazel_cti.api import limits
from azazel_cti.api.app import AuthContext, ensure_warm_cache, read_raw_body, require_scope_dep
from azazel_cti.api.models import ContextApiRequest, ContextResponse
from azazel_cti.audit.logger import AuditUnavailable
from azazel_cti.core.clock import to_rfc3339
from azazel_cti.ingest.spool import QuotaExceeded
from azazel_cti.correlate.pipeline import (
    ContextRequest,
    ContextRequestTooLarge as PipelineRequestTooLarge,
    ContextTimeout,
    Entity,
    run_context,
)
from azazel_cti.security.auth import Scope

router = APIRouter(prefix="/v1", tags=["context"])

_QUERY_SCOPE = Depends(require_scope_dep(Scope.QUERY))
_RAW_BODY = Depends(read_raw_body)
_CROCKFORD32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_advisory_ulid(now_ms: int | None = None) -> str:
    ts = now_ms if now_ms is not None else int(time.time() * 1000)
    rand = secrets.randbits(80)
    value = ((ts & ((1 << 48) - 1)) << 80) | rand
    chars = [_CROCKFORD32[(value >> (5 * i)) & 0x1F] for i in range(26)]
    return "".join(reversed(chars))


@router.post("/context", response_model=ContextResponse)
def post_context(
    request: Request,
    body: ContextApiRequest,
    raw_body: bytes = _RAW_BODY,
    auth: AuthContext = _QUERY_SCOPE,
) -> ContextResponse:
    ensure_warm_cache(request)

    try:
        limits.check_context_body_size(raw_body)
    except limits.ContextRequestTooLarge:
        raise HTTPException(
            status_code=413, detail={"error": "context_request_too_large"}
        )
    if len(body.entities) > limits.CONTEXT_MAX_ENTITIES:
        raise HTTPException(
            status_code=413, detail={"error": "context_request_too_large"}
        )

    state = request.app.state
    loader = state.loader
    repo = state.repo
    clock = state.clock

    deadline_ms = state.settings.context_deadline_ms
    if deadline_ms is None:
        deadline_ms = loader.deadline_ms()
    deadline = time.monotonic() + (deadline_ms / 1000.0)

    actor_key = auth.key_id or body.actor_key or body.edge_id
    ctx_request = ContextRequest(
        entities=[Entity(e.type, e.value) for e in body.entities],
        event=body.event,
        edge_id=body.edge_id,
        actor_key=actor_key,
        event_id=body.event_id,
    )

    try:
        result = run_context(repo, loader, ctx_request, clock, deadline=deadline)
    except ContextTimeout:
        state.metrics["context_total"] += 1
        state.metrics["context_breaker_total"] += 1
        raise HTTPException(status_code=503, detail={"error": "context_timeout"})
    except PipelineRequestTooLarge:
        raise HTTPException(
            status_code=413, detail={"error": "context_request_too_large"}
        )

    state.metrics["context_total"] += 1

    advisory_id = new_advisory_ulid()
    created_at = to_rfc3339(clock.query_as_of())
    advisory_event = {
        "type": "advisory",
        "advisory_id": advisory_id,
        "event_id": body.event_id,
        "actor_key": actor_key,
        "edge_id": body.edge_id,
        "content_hash": result.content_hash,
        "intel_generation": result.determinism["intel_generation"],
        "local_generation": result.determinism["local_generation"],
        "stats_generation": result.determinism["stats_generation"],
        "attack_version": result.determinism["attack_version"],
        "config_hash": result.determinism["config_hash"],
        "created_at": created_at,
    }
    try:
        state.audit.append(advisory_event)
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail={"error": "audit_unavailable"})

    line = json.dumps(advisory_event, sort_keys=True)
    try:
        state.spool.write_batch("advisory", auth.key_id, [line])
    except QuotaExceeded:
        pass

    return ContextResponse(
        threat_context=result.threat_context,
        threat_score=result.threat_score,
        confidence=result.confidence,
        reason=list(result.reason),
        confidence_reason=list(result.confidence_reason),
        recommendation=result.recommendation,
        source_freshness=result.source_freshness,
        advisory_notice=result.advisory_notice,
        advisory_id=advisory_id,
        multi_ioc_scope=result.multi_ioc_scope,
    )
