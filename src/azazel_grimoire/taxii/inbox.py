"""TAXII 2.1 minimal inbox (design S4/S6, F-9).

`POST /taxii2/inbox/objects` accepts a STIX envelope `{"objects": [...]}`
from the existing Azazel-Edge push client. Only two STIX types ever
reach a native table, and never a scored one directly: `indicator`
objects map through `bundle/stix_map.stix_to_native` and land in the
`edge_reported` quarantine spool (the same durable-spool pattern as
`/v1/events`); `observed-data` objects carrying the
`x-azazel-reaction` extension are unwrapped back to the native reaction
shape and routed into the identical `reactions` spool endpoint that
`/v1/reactions` uses, so they get the same validation/classification
path on drain, entering at `provisional`. Every other object type is
refused with `422 INBOX_TYPE_NOT_ACCEPTED` and audit-logged; nothing
here ever touches a scored or ATT&CK table.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from azazel_grimoire.api.app import AuthContext, read_json_body, require_scope_dep
from azazel_grimoire.audit.logger import AuditUnavailable
from azazel_grimoire.bundle.stix_map import observed_data_to_reaction, stix_to_native
from azazel_grimoire.security.auth import Scope

router = APIRouter(tags=["taxii"])

_INGEST_SCOPE = Depends(require_scope_dep(Scope.INGEST))
_JSON_BODY = Depends(read_json_body)

DISCOVERY: dict[str, Any] = {
    "title": "Azazel-Grimoire TAXII 2.1",
    "description": "Azazel-Grimoire advisory-only threat intelligence node",
    "default": "/taxii2/",
    "api_roots": ["/taxii2/"],
}

API_ROOT: dict[str, Any] = {
    "title": "Azazel-Grimoire",
    "description": "Azazel-Grimoire TAXII 2.1 API root",
    "versions": ["application/taxii+json;version=2.1"],
    "max_content_length": 8 * 1024 * 1024,
}


@router.get("/taxii2/")
def discovery() -> dict[str, Any]:
    return DISCOVERY


@router.get("/taxii2/api-root")
def api_root() -> dict[str, Any]:
    return API_ROOT


def _spool_indicator(request: Request, auth: AuthContext, stix_obj: dict[str, Any]) -> None:
    native = stix_to_native(stix_obj)
    payload = {"kind": "edge_reported_indicator", "actor": auth.key_id, "ioc": native}
    request.app.state.spool.write_batch(
        "edge_reported", auth.key_id, [json.dumps(payload, sort_keys=True)]
    )


def _spool_reaction(request: Request, auth: AuthContext, stix_obj: dict[str, Any]) -> bool:
    extensions = stix_obj.get("extensions", {}) or {}
    if "x-azazel-reaction" not in extensions:
        return False
    native = observed_data_to_reaction(stix_obj)
    request.app.state.spool.write_batch(
        "reactions", auth.key_id, [json.dumps(native, sort_keys=True)]
    )
    return True


def _audit_rejected(request: Request, auth: AuthContext, object_type: str | None) -> None:
    try:
        request.app.state.audit.append(
            {"type": "taxii_rejected", "object_type": object_type, "key_id": auth.key_id}
        )
    except AuditUnavailable:
        pass


@router.post("/taxii2/inbox/objects", status_code=202)
def inbox_objects(
    request: Request, body: object = _JSON_BODY, auth: AuthContext = _INGEST_SCOPE
) -> dict[str, Any]:
    objects = body.get("objects", []) if isinstance(body, dict) else []

    accepted = 0
    rejected: list[str | None] = []
    for stix_obj in objects:
        object_type = stix_obj.get("type") if isinstance(stix_obj, dict) else None
        handled = False
        try:
            if object_type == "indicator":
                _spool_indicator(request, auth, stix_obj)
                handled = True
            elif object_type == "observed-data":
                handled = _spool_reaction(request, auth, stix_obj)
        except ValueError:
            handled = False

        if handled:
            accepted += 1
        else:
            rejected.append(object_type)
            _audit_rejected(request, auth, object_type)

    if rejected:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "INBOX_TYPE_NOT_ACCEPTED",
                "type": rejected[0],
                "rejected": rejected,
                "accepted": accepted,
            },
        )
    return {"accepted": accepted}
