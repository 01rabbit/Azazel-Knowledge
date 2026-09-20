"""Ingest endpoints (design S4, F-4): fire-and-forget spooling.

`POST /v1/events|flows|reactions` never parses or validates a line's
content -- that happens later, at drain time, in
`ingest/validators.py` + `ingest/drain.py` on the worker side. The only
reasons a call there is rejected are a client's spool quota (`503`) or
the whole-request byte cap (`413`); a single malformed JSONL line never
fails the surrounding batch (design S4).

Two lanes narrow that. A caller that opts into a Fabric envelope has its
items type-enforced here and gets a `422` for a contract violation
(ADR-0010/0011), and `/v1/outcome-evidence` accepts *only* that envelope --
it has no per-line callers predating Fabric to fall through for, so there is
no unvalidated way into it. Neither changes the fire-and-forget contract for
the lanes that have one.

Handlers are plain `def`s dispatched to FastAPI's bounded threadpool
(design F-4): the durable spool write does an fsync + atomic rename per
batch, and that must never block the event loop. The raw body itself
is read by an async dependency (`read_raw_body`), the one part of the
request that has to run on the loop.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from azazel_knowledge.api import limits
from azazel_knowledge.api.app import AuthContext, read_raw_body, require_scope_dep
from azazel_knowledge.api.contracts import (
    IngestBatchInvalid,
    fabric_outcome_evidence_lines,
    maybe_fabric_batch_lines,
    maybe_fabric_engagement_lines,
)
from azazel_knowledge.api.models import IngestAcceptedResponse, IngestStatusResponse
from azazel_knowledge.ingest.spool import QuotaExceeded, SpoolWriter
from azazel_knowledge.security.auth import Scope

router = APIRouter(prefix="/v1", tags=["ingest"])

_INGEST_SCOPE = Depends(require_scope_dep(Scope.INGEST))
_RAW_BODY = Depends(read_raw_body)


def _split_lines(raw_text: str) -> list[str]:
    return [line for line in raw_text.split("\n") if line.strip()]


def _accept(
    request: Request, auth: AuthContext, raw_body: bytes, endpoint: str
) -> IngestAcceptedResponse:
    try:
        limits.check_ingest_batch_size(raw_body)
    except limits.IngestBatchTooLarge:
        raise HTTPException(
            status_code=413, detail={"error": "ingest_batch_too_large"}
        )

    # Fabric boundary contract (ADR-0010): a caller that opts into the
    # canonical `Cti<Kind>Batch` envelope is type-enforced here and fails
    # closed (422) on an envelope-contract violation. Legacy per-line JSONL
    # callers get `None` back and take the unchanged fire-and-forget path,
    # where a malformed *line* is quarantined at drain, never rejected.
    try:
        batch_lines = maybe_fabric_batch_lines(raw_body, endpoint)
        if batch_lines is None:
            batch_lines = maybe_fabric_engagement_lines(raw_body, endpoint)
        if batch_lines is None:
            # Returns `None` only off its own endpoint -- `/v1/outcome-evidence`
            # has no legacy per-line path to fall through to, so a body that is
            # not a valid Fabric envelope raises instead of being spooled
            # unvalidated.
            batch_lines = fabric_outcome_evidence_lines(raw_body, endpoint)
    except IngestBatchInvalid:
        raise HTTPException(
            status_code=422, detail={"error": "ingest_batch_invalid"}
        )
    if batch_lines is not None:
        lines = batch_lines
    else:
        lines = _split_lines(raw_body.decode("utf-8", errors="replace"))
    spool: SpoolWriter = request.app.state.spool
    try:
        batch_id = spool.write_batch(endpoint, auth.key_id, lines)
    except QuotaExceeded:
        raise HTTPException(
            status_code=503,
            detail={"error": "ingest_quota_exceeded"},
            headers={"Retry-After": str(limits.INGEST_QUOTA_RETRY_AFTER_S)},
        )
    return IngestAcceptedResponse(batch_id=batch_id)


@router.post("/events", status_code=202, response_model=IngestAcceptedResponse)
def post_events(
    request: Request, raw_body: bytes = _RAW_BODY, auth: AuthContext = _INGEST_SCOPE
) -> IngestAcceptedResponse:
    return _accept(request, auth, raw_body, "events")


@router.post("/flows", status_code=202, response_model=IngestAcceptedResponse)
def post_flows(
    request: Request, raw_body: bytes = _RAW_BODY, auth: AuthContext = _INGEST_SCOPE
) -> IngestAcceptedResponse:
    return _accept(request, auth, raw_body, "flows")


@router.post(
    "/engagement-events", status_code=202, response_model=IngestAcceptedResponse
)
def post_engagement_events(
    request: Request, raw_body: bytes = _RAW_BODY, auth: AuthContext = _INGEST_SCOPE
) -> IngestAcceptedResponse:
    """Ingest Azazel-Edge `EngagementEvent` records (Azazel-Fabric#23, R1c).

    Edge builds these "for audit / Knowledge ingest" -- its own words -- and
    this is the boundary that reads one. An engagement event is a record of
    something already done; storing it is memory, not selection.

    The envelope carries `edge_id` and `actor_key` because the Fabric contract
    models neither: it says what was done, not to whom. Same accept discipline
    as every other ingest endpoint -- `413` on the byte cap, `503` on quota,
    `422` only for an envelope that declared the Fabric shape and violated it.
    """

    return _accept(request, auth, raw_body, "engagement-events")


@router.post(
    "/outcome-evidence", status_code=202, response_model=IngestAcceptedResponse
)
def post_outcome_evidence(
    request: Request, raw_body: bytes = _RAW_BODY, auth: AuthContext = _INGEST_SCOPE
) -> IngestAcceptedResponse:
    """Ingest Outcome-as-Evidence facts (Azazel-Fabric `outcome_contracts`, R1c).

    Azazel-Edge exports the four Fabric records with "deliberately no
    fallback"; this is the reader. The body is a
    `{"items": [...]}` envelope whose every item is type-enforced against the
    Fabric model its own `schema_version` names, and there is no unvalidated
    path in: `422` for anything the contract rejects, `413` on the byte cap,
    `503` on quota, as with every other ingest endpoint.

    Storing these facts is memory. The four records are kept separate on
    purpose -- execution, mechanism, observation and assessment -- so that
    nothing here can be read as a verdict that the action worked. Knowledge
    does not supply one, and the contract has nowhere to put one.
    """

    return _accept(request, auth, raw_body, "outcome-evidence")


@router.post("/reactions", status_code=202, response_model=IngestAcceptedResponse)
def post_reactions(
    request: Request, raw_body: bytes = _RAW_BODY, auth: AuthContext = _INGEST_SCOPE
) -> IngestAcceptedResponse:
    return _accept(request, auth, raw_body, "reactions")


def _batch_still_pending(spool: SpoolWriter, batch_id: str) -> bool:
    if not spool.root.is_dir():
        return False
    return any(spool.root.glob(f"*/{batch_id}.jsonl"))


@router.get("/ingest/{batch_id}", response_model=IngestStatusResponse)
def get_ingest_status(
    batch_id: str, request: Request, auth: AuthContext = _INGEST_SCOPE
) -> IngestStatusResponse:
    spool: SpoolWriter = request.app.state.spool
    status = spool.read_status(batch_id)
    if status is not None:
        return IngestStatusResponse(**status.to_dict())
    if _batch_still_pending(spool, batch_id):
        return IngestStatusResponse(
            batch_id=batch_id, accepted="", line_count=0, valid=0, invalid=[], drained=False
        )
    raise HTTPException(status_code=404, detail={"error": "batch_not_found"})
