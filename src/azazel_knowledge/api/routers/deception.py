"""AZ-06 deception observation ingest + effectiveness advisory (ADR-0011).

Two boundary surfaces for the deception-effectiveness loop:

* ``POST /v1/deception-observations`` -- fire-and-forget ingest of Fabric
  ``InteractionObservation`` facts, following ``routers/ingest.py`` EXACTLY:
  the accept path never validates a line's content (that happens at drain), so
  a single malformed JSONL line is quarantined later, never failing the batch
  (design S4/F-4). The only rejections here are the whole-request byte cap
  (``413``), a client's spool quota (``503``), and -- for a caller that opts
  into the batch **envelope** -- a Fabric envelope-contract violation
  (``422``), mirroring the ``Cti<Kind>Batch`` handling. Same INGEST scope/auth.

* ``GET /v1/deception-effectiveness`` -- read-side advisory. Runs the
  deterministic ``correlate.deception_effectiveness`` summary under a monotonic
  deadline pinned from handler entry, type-enforces the result as a Fabric
  ``EffectivenessAdvisory`` (advisory-only, non-executable), appends it to the
  audit chain, and fails closed: ``503 context_timeout`` on deadline
  (F-12), ``503 audit_unavailable`` on a chain-append failure (F-17). Advice is
  never served unauditable. This handler is READ-scoped and read-only (the
  static write-SQL scan, ``test_api_static.py``, still holds).
"""

from __future__ import annotations

import time  # monotonic budget guard only (not a scoring input)
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from azazel_knowledge.api import limits
from azazel_knowledge.api.app import (
    AuthContext,
    open_local_readonly,
    read_raw_body,
    require_scope_dep,
)
from azazel_knowledge.api.contracts import (
    AdvisoryInvariantViolation,
    IngestBatchInvalid,
    assert_response_advisory_only,
    build_effectiveness_advisory,
    maybe_fabric_observation_lines,
)
from azazel_knowledge.api.models import IngestAcceptedResponse
from azazel_knowledge.audit.logger import AuditUnavailable
from azazel_knowledge.core.clock import to_rfc3339
from azazel_knowledge.correlate.deception_effectiveness import (
    DeceptionEffectivenessTimeout,
    summarize_effectiveness,
)
from azazel_knowledge.ingest.spool import QuotaExceeded, SpoolWriter
from azazel_knowledge.security.auth import Scope

router = APIRouter(prefix="/v1", tags=["deception"])

_INGEST_SCOPE = Depends(require_scope_dep(Scope.INGEST))
_READ_SCOPE = Depends(require_scope_dep(Scope.READ))
_RAW_BODY = Depends(read_raw_body)

_ENDPOINT = "deception-observations"


def _split_lines(raw_text: str) -> list[str]:
    return [line for line in raw_text.split("\n") if line.strip()]


@router.post(
    "/deception-observations", status_code=202, response_model=IngestAcceptedResponse
)
def post_deception_observations(
    request: Request, raw_body: bytes = _RAW_BODY, auth: AuthContext = _INGEST_SCOPE
) -> IngestAcceptedResponse:
    try:
        limits.check_ingest_batch_size(raw_body)
    except limits.IngestBatchTooLarge:
        raise HTTPException(status_code=413, detail={"error": "ingest_batch_too_large"})

    # Fabric boundary (ADR-0010/0011): an envelope caller is type-enforced and
    # fails closed (422); legacy per-line JSONL falls through untouched and a bad
    # line is quarantined at drain, never rejecting the batch.
    try:
        batch_lines = maybe_fabric_observation_lines(raw_body, _ENDPOINT)
    except IngestBatchInvalid:
        raise HTTPException(status_code=422, detail={"error": "ingest_batch_invalid"})
    if batch_lines is not None:
        lines = batch_lines
    else:
        lines = _split_lines(raw_body.decode("utf-8", errors="replace"))

    spool: SpoolWriter = request.app.state.spool
    try:
        batch_id = spool.write_batch(_ENDPOINT, auth.key_id, lines)
    except QuotaExceeded:
        raise HTTPException(
            status_code=503,
            detail={"error": "ingest_quota_exceeded"},
            headers={"Retry-After": str(limits.INGEST_QUOTA_RETRY_AFTER_S)},
        )
    return IngestAcceptedResponse(batch_id=batch_id)


@router.get("/deception-effectiveness")
def get_deception_effectiveness(
    request: Request,
    environment_id: str,
    package_id: str | None = None,
    auth: AuthContext = _READ_SCOPE,
) -> dict[str, Any]:
    if not environment_id.strip():
        raise HTTPException(
            status_code=422, detail={"error": "environment_id_required"}
        )

    state = request.app.state
    loader = state.loader
    clock = state.clock

    # Pin query_as_of exactly once at handler entry (design S5 / Constraint 3).
    now = clock.query_as_of()

    deadline_ms = state.settings.context_deadline_ms
    if deadline_ms is None:
        deadline_ms = loader.deadline_ms()
    deadline = time.monotonic() + (deadline_ms / 1000.0)

    conn = open_local_readonly(state.settings.local_db_path)
    try:
        summary = summarize_effectiveness(
            conn,
            environment_id=environment_id,
            package_id=package_id,
            config=loader.deception_effectiveness(),
            query_as_of=now,
            config_hash=loader.config_hash,
            deadline=deadline,
        )
    except DeceptionEffectivenessTimeout:
        state.metrics["context_total"] = state.metrics.get("context_total", 0) + 1
        state.metrics["context_breaker_total"] = (
            state.metrics.get("context_breaker_total", 0) + 1
        )
        raise HTTPException(status_code=503, detail={"error": "context_timeout"})
    finally:
        conn.close()

    state.metrics["context_total"] = state.metrics.get("context_total", 0) + 1

    # Type-enforce the output as a Fabric EffectivenessAdvisory (advisory-only,
    # non-executable) and reject any directive-shaped field on a copy. Both fail
    # closed (500) rather than ever emit a directive-shaped advisory.
    try:
        advisory = build_effectiveness_advisory(summary.advisory)
        assert_response_advisory_only(advisory)
    except AdvisoryInvariantViolation:
        raise HTTPException(
            status_code=500, detail={"error": "advisory_invariant_violation"}
        )

    # Advice is never served unauditable (F-17): append to the chain on the
    # request thread and fail closed on a chain-append failure.
    audit_event = {
        "type": "effectiveness_advisory",
        "advisory_id": advisory["advisory_id"],
        "environment_id": environment_id,
        "package_id": advisory["package_id"],
        "content_hash": summary.content_hash,
        "config_hash": loader.config_hash,
        "created_at": to_rfc3339(now),
    }
    try:
        state.audit.append(audit_event)
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail={"error": "audit_unavailable"})

    return advisory
