"""Optional, mTLS-gated Nexus Knowledge Context v1 producer endpoint."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from azazel_fabric.knowledge_context import (
    KnowledgeContextRequestV1,
    canonical_knowledge_context_bytes,
)
from azazel_knowledge.api import limits
from azazel_knowledge.api.app import AuthContext, read_raw_body
from azazel_knowledge.api.knowledge_context_adapter import (
    from_knowledge_context_request,
    to_knowledge_context_response,
)
from azazel_knowledge.api.models import ContextResponse
from azazel_knowledge.api.routers.context import post_context
from azazel_knowledge.core.clock import to_rfc3339
from azazel_knowledge.security.auth import Scope

router = APIRouter(prefix="/v1", tags=["knowledge-context"])
_RAW_BODY = Depends(read_raw_body)
_ENVELOPE_SCHEMA = "azazel-nexus/knowledge-context-envelope/1"
_ENVELOPE_DOMAIN = b"azazel-nexus/knowledge-context-envelope/v1\x00"
_MAX_ENVELOPE_BYTES = 256 * 1024


def _canonical(document: dict) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@router.post("/knowledge-context", response_class=Response)
def post_knowledge_context(
    request: Request,
    body: KnowledgeContextRequestV1,
    raw_body: bytes = _RAW_BODY,
) -> Response:
    config = request.app.state.settings.knowledge_context_transport
    if config is None or not config.enabled:
        raise HTTPException(status_code=404, detail={"error": "knowledge_context_unavailable"})
    peer_id = config.authenticate_peer(request)
    if peer_id is None:
        raise HTTPException(status_code=401, detail={"error": "peer_authentication_failed"})
    if body.source_product != "azazel_nexus":
        raise HTTPException(status_code=403, detail={"error": "peer_profile_mismatch"})
    try:
        limits.check_context_body_size(raw_body)
    except limits.ContextRequestTooLarge:
        raise HTTPException(status_code=413, detail={"error": "context_request_too_large"})

    context_request = from_knowledge_context_request(body)
    auth = AuthContext(key_id=peer_id, scopes=frozenset({Scope.QUERY}))
    # Reuse the ordinary query path so cold-cache, deadline, audit and spool
    # behavior are identical. The peer ID is a commissioned non-secret label.
    context_response: ContextResponse = post_context(
        request, context_request, raw_body=raw_body, auth=auth
    )
    snapshot_ref = getattr(context_response, "_knowledge_snapshot_ref", None)
    snapshot_as_of = getattr(context_response, "_knowledge_snapshot_as_of", None)
    if not isinstance(snapshot_ref, str) or not isinstance(snapshot_as_of, str):
        raise HTTPException(status_code=503, detail={"error": "snapshot_metadata_unavailable"})

    clock = request.app.state.clock
    generated = clock.query_as_of()
    expires = generated + timedelta(seconds=config.max_ttl_seconds)
    try:
        semantic = to_knowledge_context_response(
            context_response,
            body,
            provider_id="azazel-knowledge",
            snapshot_ref=snapshot_ref,
            # Current Knowledge output does not expose per-feed expiry metadata.
            # `partial` avoids claiming that every source is fresh.
            snapshot_state="partial",
            snapshot_as_of=snapshot_as_of,
            generated_at=generated,
            expires_at=expires,
            limitations=(
                "source-level freshness deadlines are not included in this projection",
            ),
        )
        semantic_bytes = canonical_knowledge_context_bytes(semantic)
        document = {
            "schema": _ENVELOPE_SCHEMA,
            "key_id": config.signer.key_id,
            "issued_at": to_rfc3339(generated),
            "expires_at": to_rfc3339(expires),
            "payload": json.loads(semantic_bytes),
        }
        public_key = config.signer.public_key
        expected_key_id = "sha256:" + hashlib.sha256(public_key).hexdigest()
        if (not isinstance(public_key, bytes) or len(public_key) != 32
                or config.signer.key_id != expected_key_id):
            raise ValueError("signing key identity changed after commissioning")
        envelope = _canonical(document)
        if len(envelope) + 64 > _MAX_ENVELOPE_BYTES:
            raise ValueError("signed response exceeds envelope size limit")
        signature = config.signer.sign(_ENVELOPE_DOMAIN + envelope)
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError("signer returned an invalid Ed25519 signature")
    except Exception:  # noqa: BLE001 -- signer/provider failures fail closed
        raise HTTPException(
            status_code=503, detail={"error": "knowledge_context_signing_unavailable"}
        ) from None
    return Response(
        content=signature + envelope,
        media_type="application/octet-stream",
        headers={"Cache-Control": "no-store"},
    )


__all__ = ["post_knowledge_context", "router"]
