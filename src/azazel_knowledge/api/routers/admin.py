"""Admin-scoped operator actions (design S4/S6/S8).

The API process holds no writer handle to any database -- `worker` is
the sole writer (design S2) -- so every action here is durably spooled
the same way ingest lines are, and a background drain applies it later
(reaction trust-event append via `reactions/eligibility.py`, edge-ioc
promotion via `feeds/promotion.py`, quarantine release via
`reactions/quarantine.py`). All three routes require the `admin` scope;
an `ingest`-scoped token is refused with `403` (deny-by-default).
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request

from azazel_knowledge.api import limits
from azazel_knowledge.api.app import AuthContext, require_scope_dep
from azazel_knowledge.api.models import AdminAcceptedResponse
from azazel_knowledge.core.clock import to_rfc3339
from azazel_knowledge.ingest.spool import QuotaExceeded
from azazel_knowledge.security.auth import Scope

router = APIRouter(prefix="/v1", tags=["admin"])

_ADMIN_SCOPE = Depends(require_scope_dep(Scope.ADMIN))
_SPOOL_ENDPOINT = "admin"


def _spool_action(request: Request, auth: AuthContext, payload: dict) -> None:
    now = request.app.state.clock.query_as_of()
    payload = {**payload, "actor": auth.key_id, "requested_at": to_rfc3339(now)}
    line = json.dumps(payload, sort_keys=True)
    try:
        request.app.state.spool.write_batch(_SPOOL_ENDPOINT, auth.key_id, [line])
    except QuotaExceeded:
        raise HTTPException(
            status_code=503,
            detail={"error": "ingest_quota_exceeded"},
            headers={"Retry-After": str(limits.INGEST_QUOTA_RETRY_AFTER_S)},
        )


@router.post("/reactions/{reaction_id}/confirm", status_code=202, response_model=AdminAcceptedResponse)
def confirm_reaction(
    reaction_id: int, request: Request, auth: AuthContext = _ADMIN_SCOPE
) -> AdminAcceptedResponse:
    _spool_action(request, auth, {"kind": "reaction_confirm", "reaction_id": reaction_id})
    return AdminAcceptedResponse(detail=f"reaction {reaction_id} confirmation queued")


@router.post("/iocs/{ioc_ref}/confirm", status_code=202, response_model=AdminAcceptedResponse)
def confirm_ioc(
    ioc_ref: str, request: Request, auth: AuthContext = _ADMIN_SCOPE
) -> AdminAcceptedResponse:
    _spool_action(request, auth, {"kind": "ioc_confirm", "ioc_ref": ioc_ref})
    return AdminAcceptedResponse(detail=f"ioc {ioc_ref} confirmation queued")


@router.post("/edge-intel/{edge_id}/release", status_code=202, response_model=AdminAcceptedResponse)
def release_edge_quarantine(
    edge_id: str, request: Request, auth: AuthContext = _ADMIN_SCOPE
) -> AdminAcceptedResponse:
    _spool_action(request, auth, {"kind": "quarantine_release", "edge_id": edge_id})
    return AdminAcceptedResponse(detail=f"edge {edge_id} quarantine release queued")
