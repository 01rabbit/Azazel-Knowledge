"""Optional, mTLS-gated Nexus Knowledge Context v1 producer endpoint."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import ValidationError
from nacl.signing import VerifyKey

from azazel_fabric.knowledge_context import (
    KnowledgeContextRequestV1,
    canonical_knowledge_context_bytes,
)
from azazel_knowledge.api import limits
from azazel_knowledge.api import attack_technique_context as attack_ctx
from azazel_knowledge.api.app import AuthContext, ensure_warm_cache
from azazel_knowledge.api.knowledge_context_adapter import (
    KnowledgeContextAdaptationError,
    from_knowledge_context_request,
    to_knowledge_context_response,
)
from azazel_knowledge.api.models import ContextResponse
from azazel_knowledge.api.routers.context import post_context
from azazel_knowledge.audit.logger import AuditUnavailable
from azazel_knowledge.core.clock import parse_rfc3339, to_rfc3339
from azazel_knowledge.db import generations
from azazel_knowledge.security.auth import Scope

router = APIRouter(prefix="/v1", tags=["knowledge-context"])
_ENVELOPE_SCHEMA = "azazel-nexus/knowledge-context-envelope/1"
_ENVELOPE_DOMAIN = b"azazel-nexus/knowledge-context-envelope/v1\x00"
_MAX_ENVELOPE_BYTES = 256 * 1024


_DEFS_PREFIX = "#/$defs/"


def _inline_defs(node: object, defs: dict, _stack: tuple[str, ...] = ()) -> object:
    """Resolve `#/$defs/*` references so the schema stands alone in an operation.

    Sibling keywords next to a `$ref` (description, default, ...) are kept and
    take precedence over the resolved definition. Cycles and missing targets
    raise explicitly so a bad schema fails at import instead of looping.
    """
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith(_DEFS_PREFIX):
            name = ref[len(_DEFS_PREFIX):]
            if name in _stack:
                raise RuntimeError(f"cyclic $defs reference while inlining: {name}")
            if name not in defs:
                raise RuntimeError(f"missing $defs entry while inlining: {name}")
            siblings = {
                k: _inline_defs(v, defs, _stack) for k, v in node.items() if k != "$ref"
            }
            resolved = _inline_defs(defs[name], defs, (*_stack, name))
            return {**resolved, **siblings}
        return {
            k: _inline_defs(v, defs, _stack) for k, v in node.items() if k != "$defs"
        }
    if isinstance(node, list):
        return [_inline_defs(v, defs, _stack) for v in node]
    return node


# The body is read manually (gates run first), so FastAPI cannot derive the
# requestBody itself. The schema is taken from the Fabric model, not re-declared.
_REQUEST_SCHEMA = KnowledgeContextRequestV1.model_json_schema()
_REQUEST_BODY = {
    "required": True,
    "content": {
        "application/json": {
            "schema": _inline_defs(
                {k: v for k, v in _REQUEST_SCHEMA.items() if k != "$defs"},
                _REQUEST_SCHEMA.get("$defs", {}),
            )
        }
    },
}
_MAX_STREAMED_BYTES = limits.CONTEXT_MAX_BODY_BYTES
_CAP_DECIMAL = str(_MAX_STREAMED_BYTES)
_ASCII_DECIMAL = re.compile(r"[0-9]+")
_HTTP_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9a-z-]+", re.ASCII)


def _declared_length_exceeds_cap(declared: str | None) -> bool:
    """Early reject only. Never calls int(); non-ASCII-decimal values return False.

    Comparison is done on normalized decimal strings, so arbitrarily long
    numerals cannot raise (int() has a digit limit) and Unicode digit look-alikes
    (e.g. superscripts) are not accepted. Anything that is not ASCII decimal falls
    through to the streamed cap, which is the actual bound.
    """
    if declared is None or _ASCII_DECIMAL.fullmatch(declared) is None:
        return False
    digits = declared.lstrip("0") or "0"
    if len(digits) != len(_CAP_DECIMAL):
        return len(digits) > len(_CAP_DECIMAL)
    return digits > _CAP_DECIMAL


def _canonical(document: dict) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _authenticated_peer(request: Request) -> str:
    """Gate 1 (sync, threadpool): disabled -> 404, unauthenticated -> 401.

    Runs before any body byte is read, so neither error depends on the body.
    """
    config = request.app.state.settings.knowledge_context_transport
    if config is None or not config.enabled:
        raise HTTPException(status_code=404, detail={"error": "knowledge_context_unavailable"})
    peer_id = config.authenticate_peer(request)
    if peer_id is None:
        raise HTTPException(status_code=401, detail={"error": "peer_authentication_failed"})
    return peer_id


async def _bounded_envelope(
    request: Request, peer_id: str = Depends(_authenticated_peer)
) -> bytes:
    """Gate 2 (async, loop): only an authenticated, enabled peer's bytes are read.

    The body is streamed into a bounded accumulator that stops at cap+1 bytes.
    Content-Length is used only as an early reject; it is never trusted to bound
    the read, so an under-declared length cannot bypass the cap.
    """
    if _declared_length_exceeds_cap(request.headers.get("content-length")):
        raise HTTPException(status_code=413, detail={"error": "context_request_too_large"})
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_STREAMED_BYTES:
            raise HTTPException(status_code=413, detail={"error": "context_request_too_large"})
        chunks.append(chunk)
    return b"".join(chunks)


def _is_json_media_type(content_type: str | None) -> bool:
    # An absent (or empty) Content-Type is not JSON: the protocol is explicit, so a
    # missing media type gets the same fixed 422 as an unsupported one. Only
    # `application/json` or `application/*+json` (with parameters) is accepted.
    if not content_type:
        return False
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == "application/json":
        return True
    if not media_type.startswith("application/"):
        return False
    subtype = media_type.removeprefix("application/")
    return (
        len(subtype) > len("+json")
        and subtype.endswith("+json")
        and _HTTP_TOKEN.fullmatch(subtype) is not None
    )


def _parse_envelope(request: Request, raw_body: bytes) -> KnowledgeContextRequestV1:
    invalid = HTTPException(
        status_code=422, detail={"error": "invalid_knowledge_context_request"}
    )
    if not _is_json_media_type(request.headers.get("content-type")):
        raise invalid
    try:
        return KnowledgeContextRequestV1.model_validate(json.loads(raw_body))
    except (ValueError, ValidationError, RecursionError):
        # ValueError covers JSON decode and UnicodeDecodeError; pydantic's
        # ValidationError is a ValueError too; RecursionError is raised by the
        # JSON decoder or validator on deeply nested input. No input values are echoed.
        raise invalid from None


def _ordinary_response(request, body, config, peer_id, raw_body):
    """Existing IOC/legacy path, unchanged: Knowledge /v1/context -> Fabric projection."""
    try:
        context_request = from_knowledge_context_request(body)
    except (KnowledgeContextAdaptationError, ValidationError, TypeError, ValueError):
        raise HTTPException(
            status_code=422, detail={"error": "knowledge_context_request_unrepresentable"}
        ) from None
    except Exception:  # noqa: BLE001 -- internal adapter faults fail closed without echoing input
        raise HTTPException(
            status_code=503, detail={"error": "knowledge_context_request_unavailable"}
        ) from None
    auth = AuthContext(key_id=f"mtls:{peer_id}", scopes=frozenset({Scope.QUERY}))
    # Reuse the ordinary query path so cold-cache, deadline, audit and spool
    # behavior are identical. Namespace the commissioned peer ID so it cannot
    # collide with a local API key ID in audit attribution or spool accounting.
    context_response: ContextResponse = post_context(
        request, context_request, raw_body=raw_body, auth=auth
    )
    snapshot_ref = getattr(context_response, "_knowledge_snapshot_ref", None)
    snapshot_as_of = getattr(context_response, "_knowledge_snapshot_as_of", None)
    if not isinstance(snapshot_ref, str) or not isinstance(snapshot_as_of, str):
        raise HTTPException(status_code=503, detail={"error": "snapshot_metadata_unavailable"})

    try:
        # Reuse the query's pinned snapshot time; the request has exactly one
        # query_as_of instant across Knowledge and the signed projection.
        generated = parse_rfc3339(snapshot_as_of)
        expires = generated + timedelta(seconds=config.max_ttl_seconds)
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
    except Exception:  # noqa: BLE001 -- projection errors fail closed without echoing input
        raise HTTPException(
            status_code=503, detail={"error": "knowledge_context_projection_unavailable"}
        ) from None
    return semantic, generated, expires


def _technique_response(request, body, config, peer_id):
    """ATT&CK technique reference lookup (reserved attack-technique/v1 namespace)."""
    ensure_warm_cache(request)
    state = request.app.state
    generated = state.clock.query_as_of()
    max_age = timedelta(seconds=config.attack_max_age_seconds)
    technique_ids = [e.value for e in body.entities]
    try:
        current = generations.current_generation(state.settings.data_db_dir)
        with state.repo.connection() as conn:
            generation_row = conn.execute(
                "SELECT value FROM intel.stats_meta WHERE key = 'intel_generation'"
            ).fetchone()
            snapshot_ref = (
                f"knowledge:intel-generation:{generation_row[0] if generation_row else current}"
            )
            corpus = attack_ctx.assess_corpus(
                conn, generated_at=generated, max_age=max_age, current_generation=current,
                technique_ids=technique_ids, snapshot_ref=snapshot_ref,
            )
        semantic = attack_ctx.build_response(
            body, corpus, provider_id="azazel-knowledge", generated_at=generated,
            response_ttl=timedelta(seconds=config.max_ttl_seconds), max_age=max_age,
            fallback_snapshot_ref=snapshot_ref,
        )
    except Exception:  # noqa: BLE001 -- projection errors fail closed without echoing input
        raise HTTPException(
            status_code=503, detail={"error": "knowledge_context_projection_unavailable"}
        ) from None
    coverage = [f.value for f in semantic.facts if f.predicate == "coverage"]
    try:
        state.audit.append({
            "type": "technique_context",
            "event_id": body.request_id,
            "actor_key": f"mtls:{peer_id}",
            "snapshot_ref": semantic.snapshot.ref,
            "snapshot_state": semantic.snapshot.state,
            "coverage": coverage,
            "created_at": to_rfc3339(generated),
        })
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail={"error": "audit_unavailable"}) from None
    return semantic, generated, semantic.expires_at


@router.post(
    "/knowledge-context",
    response_class=Response,
    openapi_extra={"requestBody": _REQUEST_BODY},
)
def post_knowledge_context(
    request: Request,
    peer_id: str = Depends(_authenticated_peer),
    raw_body: bytes = Depends(_bounded_envelope),
) -> Response:
    # Parsing runs in the threadpool, only after both gates have passed.
    body = _parse_envelope(request, raw_body)
    config = request.app.state.settings.knowledge_context_transport
    if body.source_product != "azazel_nexus":
        raise HTTPException(status_code=403, detail={"error": "peer_profile_mismatch"})

    try:
        technique_request = attack_ctx.is_technique_request(body)
    except attack_ctx.TechniqueRequestError:
        raise HTTPException(
            status_code=422, detail={"error": "attack_technique_request_invalid"}
        ) from None

    if technique_request:
        semantic, generated, expires = _technique_response(request, body, config, peer_id)
    else:
        semantic, generated, expires = _ordinary_response(request, body, config, peer_id, raw_body)
    try:
        semantic_bytes = canonical_knowledge_context_bytes(semantic)
    except Exception:  # noqa: BLE001 -- projection errors fail closed without echoing input
        raise HTTPException(
            status_code=503, detail={"error": "knowledge_context_projection_unavailable"}
        ) from None

    try:
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
        VerifyKey(public_key).verify(_ENVELOPE_DOMAIN + envelope, signature)
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
