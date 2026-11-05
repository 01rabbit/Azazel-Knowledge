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
from azazel_knowledge.api.app import (
    AuthContext,
    ensure_warm_cache,
    open_local_readonly,
    read_raw_body,
    require_scope_dep,
)
from azazel_knowledge.api.contracts import (
    AdvisoryInvariantViolation,
    assert_response_advisory_only,
    build_engagement_advisory,
    classify_reported_defensive_state,
)
from azazel_knowledge.api.models import ContextApiRequest, ContextResponse
from azazel_knowledge.audit.logger import AuditUnavailable
from azazel_knowledge.core.clock import to_rfc3339
from azazel_knowledge.ingest.spool import QuotaExceeded
from azazel_knowledge.correlate.engage_rule_refs import lookup_engage_refs, lookup_rule_refs
from azazel_knowledge.correlate.engagement_advisory import summarize_engagement
from azazel_knowledge.db.defensive_state_memory import lookup_reported_defensive_state
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


def _reported_state_fact(reported_state) -> dict | None:
    """Serve the stored fact plus whether it is canonical (Knowledge#65 AC-6).

    The classification is added beside the stored value, never over it: the
    fact keeps `reported_state` exactly as the producer sent it, and the
    canonical reading is a separate, clearly-named field a consumer may ignore.
    """

    if reported_state is None:
        return None
    fact = reported_state.as_fact()
    canonical, recognized = classify_reported_defensive_state(fact["reported_state"])
    fact["is_canonical"] = recognized
    fact["canonical_state"] = canonical
    return fact


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
    # Keep response/audit metadata on the same instant the scoring pipeline
    # captured for this query; do not read a second query_as_of value here.
    created_at = result.determinism["query_as_of"]
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

    # Additive, advisory-only enrichment (ADR-0012/ADR-0013 usage seam,
    # #60/#61): match-gated Engage/rule-corpus annotations keyed off the
    # ATT&CK technique(s) the pipeline already attributed to this event
    # (`threat_context.attack_mapping`, already deterministically sorted).
    # Deliberately placed AFTER the audit-chain append so it can NEVER block or
    # delay the audit/fail-closed path (F-12/F-17, per both ADRs), and skipped
    # when the request deadline is already spent so it cannot blow the context
    # SLA. Best-effort (Constraint 6): it degrades silently to empty lists,
    # never turns this 200 into a 500, and never touches any scored field or
    # `content_hash` (scoring completed inside `run_context`). Reuses the same
    # intel read path (`repo.connection()`) the pipeline used.
    # The authoritative Defensive State **fact lane** (Knowledge#65).
    #
    # Knowledge advises; it never sets Defensive State. This reports what an
    # authoritative producer said about itself, and is kept structurally apart
    # from `recommendation`, which is Knowledge's own inference. The two must
    # never be merged: a consumer has to be able to tell "Edge says it is in X"
    # from "Knowledge suggests considering Y".
    #
    # `None` means unknown -- nothing reported, unreadable, or newer than this
    # query. Knowledge never substitutes a default.
    engage_refs: list[dict] = []
    rule_refs: list[dict] = []
    reported_state = None
    # Engagement-effectiveness context (Knowledge#52). Folded from the
    # immutable `reaction` and `behavior_pattern` lanes, after scoring, so it
    # can never move a scored field. `None` when Knowledge has nothing to say.
    engagement_advisory: dict | None = None
    engagement_repeatability: int | None = None
    if time.monotonic() < deadline:
        techniques = [
            m["technique"]
            for m in result.threat_context.get("attack_mapping", [])
            if isinstance(m, dict) and m.get("technique")
        ]
        try:
            with repo.connection() as conn:
                engage_refs = lookup_engage_refs(conn, techniques)
                rule_refs = lookup_rule_refs(conn, techniques)
        except Exception:  # noqa: BLE001 -- best-effort enrichment, fail-open to []
            engage_refs = []
            rule_refs = []
        if body.trace_id:
            # `local.db` alone, not `repo.connection()`: the fact lane lives in
            # the local tier and must keep working through the cold-boot window
            # before any intel generation exists.
            try:
                local_conn = open_local_readonly(state.settings.local_db_path)
                try:
                    reported_state = lookup_reported_defensive_state(
                        local_conn, body.trace_id, query_as_of=created_at
                    )
                finally:
                    local_conn.close()
            except Exception:  # noqa: BLE001 -- unknown, never an error, never a state
                reported_state = None
        try:
            local_conn = open_local_readonly(state.settings.local_db_path)
            try:
                # `body.actor_key` ONLY, never the `actor_key` local above.
                #
                # Those are two different concepts wearing one name. The local
                # is `auth.key_id or body.actor_key or body.edge_id` -- the
                # *client's* identity, used to attribute the advisory audit
                # event. `reaction.actor_key` is the *source entity* (ip / ja3 /
                # session cluster) the caller observed. Folding one actor's
                # history under another actor's key is exactly the cross-actor
                # leak this advisory must not have, and the fallback chain would
                # produce it silently whenever the caller omitted the field.
                folded = summarize_engagement(
                    local_conn,
                    body.actor_key,
                    query_as_of=created_at,
                    config=loader.engagement_advisory(),
                )
            finally:
                local_conn.close()
            if folded is not None:
                engagement_repeatability = folded.get("repeatability_score")
                engagement_advisory = build_engagement_advisory(
                    folded, advisory_id=advisory_id, advisor="azazel-knowledge"
                )
        except AdvisoryInvariantViolation:
            # Named for the reader, not load-bearing: the generic handler below
            # produces the same outcome, and a mutation test confirms removing
            # this clause changes nothing. It stays because the case is the one
            # worth understanding -- an advisory that cannot satisfy the
            # advisory-only contract is dropped rather than weakened, so a
            # consumer sees "nothing to say" instead of something unvalidated,
            # and the rest of the response is unaffected.
            engagement_advisory = None
            engagement_repeatability = None
        except Exception:  # noqa: BLE001 -- best-effort, never turns a 200 into a 500
            engagement_advisory = None
            engagement_repeatability = None

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
        "reported_defensive_state": _reported_state_fact(reported_state),
        "engagement_advisory": engagement_advisory,
    }
    try:
        assert_response_advisory_only(advisory_view)
    except AdvisoryInvariantViolation:
        raise HTTPException(
            status_code=500, detail={"error": "advisory_invariant_violation"}
        )

    response = ContextResponse(
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
        reported_defensive_state=_reported_state_fact(reported_state),
        engagement_advisory=engagement_advisory,
        engagement_repeatability_score=engagement_repeatability,
    )
    # These private attributes bind the optional Fabric projection to the exact
    # index generation and query instant used by this invocation. They are not
    # part of the existing `/v1/context` public response.
    response._knowledge_snapshot_ref = (
        f"knowledge:intel-generation:{result.determinism['intel_generation']}"
    )
    response._knowledge_snapshot_as_of = result.determinism["query_as_of"]
    return response
