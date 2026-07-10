"""Ingest endpoints (design S4, F-4): fire-and-forget spooling only.

`POST /v1/events|flows|reactions` never parses or validates a line's
content -- that happens later, at drain time, in
`ingest/validators.py` + `ingest/drain.py` on the worker side. The only
reasons a call here is rejected are a client's spool quota (`503`) or
the whole-request byte cap (`413`); a single malformed JSONL line never
fails the surrounding batch (design S4).

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
