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

from azazel_knowledge.api import limits
from azazel_knowledge.api.app import AuthContext, ensure_warm_cache, read_raw_body, require_scope_dep
from azazel_knowledge.api.contracts import (
    AdvisoryInvariantViolation,
    assert_response_advisory_only,
)
from azazel_knowledge.api.models import ContextApiRequest, ContextResponse
from azazel_knowledge.audit.logger import AuditUnavailable
from azazel_knowledge.core.clock import to_rfc3339
from azazel_knowledge.ingest.spool import QuotaExceeded
from azazel_knowledge.correlate.engage_rule_refs import lookup_engage_refs, lookup_rule_refs
from azazel_knowledge.correlate.pipeline import (
    ContextRequest,
    ContextRequestTooLarge as PipelineRequestTooLarge,
    ContextTimeout,
    Entity,
    run_context,
)
from azazel_knowledge.security.auth import Scope

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

    # Additive, advisory-only enrichment (ADR-0012/ADR-0013 usage seam,
    # #60/#61): match-gated Engage/rule-corpus annotations keyed off the
    # ATT&CK technique(s) the pipeline already attributed to this event
    # (`threat_context.attack_mapping`, already deterministically sorted --
    # see `correlate.pipeline._evaluate_attack`). Reuses the SAME intel read
    # path the pipeline just used (`repo.connection()`); the pipeline's own
    # connection is already released back to the pool by the time
    # `run_context` returns, so a fresh acquire through the same Repository
    # is "the same path", not an ad hoc handle. Best-effort (Constraint 6):
    # any failure here degrades silently to empty lists and never turns this
    # 200 into a 500 -- it can never touch `result.content_hash` or any
    # scored field, since it runs entirely after scoring has completed.
    techniques = [
        m["technique"]
        for m in result.threat_context.get("attack_mapping", [])
        if isinstance(m, dict) and m.get("technique")
    ]
    engage_refs: list[dict] = []
    rule_refs: list[dict] = []
    try:
        with repo.connection() as conn:
            engage_refs = lookup_engage_refs(conn, techniques)
            rule_refs = lookup_rule_refs(conn, techniques)
    except Exception:  # noqa: BLE001 -- best-effort enrichment, fail-open to []
        engage_refs = []
        rule_refs = []

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

    # Fabric advisory-only invariant (ADR-0010): assert the assembled advisory
    # carries no directive-shaped field, on a COPY built from pipeline output.
    # Fail closed (500) rather than ever emit a directive-shaped response; the
    # original bytes below are untouched, so byte-identical replay is preserved
    # (this check never re-serializes the response).
    advisory_view = {
        "threat_context": result.threat_context,
        "recommendation": result.recommendation,
        "multi_ioc_scope": result.multi_ioc_scope,
        "reason": list(result.reason),
        "confidence_reason": list(result.confidence_reason),
        "source_freshness": result.source_freshness,
        "advisory_notice": result.advisory_notice,
        "engage_refs": engage_refs,
        "rule_refs": rule_refs,
    }
    try:
        assert_response_advisory_only(advisory_view)
    except AdvisoryInvariantViolation:
        raise HTTPException(
            status_code=500, detail={"error": "advisory_invariant_violation"}
        )

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
        engage_refs=engage_refs,
        rule_refs=rule_refs,
    )
