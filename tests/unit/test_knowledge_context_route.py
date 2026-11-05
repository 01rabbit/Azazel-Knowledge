from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import timedelta

import pytest
pytest.importorskip("azazel_fabric.knowledge_context")

from fastapi import HTTPException
from nacl.signing import SigningKey
from starlette.requests import Request

from azazel_knowledge.api import limits
from azazel_knowledge.api.knowledge_context_transport import KnowledgeContextTransportConfig
from azazel_knowledge.api.routers.knowledge_context import (
    _bounded_envelope,
    _declared_length_exceeds_cap,
)
from azazel_knowledge.core.clock import parse_rfc3339, to_rfc3339
from _api_support import add_api_client, make_client

_DOMAIN = b"azazel-nexus/knowledge-context-envelope/v1\x00"
_SCHEMA = "azazel-nexus/knowledge-context-envelope/1"
_MALFORMED = b'{"schema_version": "knowledge-context-request/v1", "entities": [ }'
_INVALID_ERROR = {"detail": {"error": "invalid_knowledge_context_request"}}


class _TestSigner:
    def __init__(self):
        self.key = SigningKey(bytes(range(32)))
        self.public_key = bytes(self.key.verify_key)
        self.key_id = "sha256:" + hashlib.sha256(self.public_key).hexdigest()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


class _TestPeer:
    def __init__(self, peer_id: str | None = "nexus-lab"):
        self.peer_id = peer_id

    def authenticate(self, request) -> str | None:
        return self.peer_id


def _request():
    return {
        "schema_version": "knowledge-context-request/v1",
        "request_id": "req-0123456789abcdef",
        "correlation_id": "corr-0123456789abcdef",
        "source_product": "azazel_nexus",
        "source_ref": "nexus:lab-query-01",
        "requested_at": "2026-07-06T12:00:00Z",
        "entities": [
            {"entity_type": "ip", "value": "203.0.113.7"},
            {"entity_type": "domain", "value": "no-match.example"},
        ],
    }


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _configure(settings, peer_id="nexus-lab"):
    signer = _TestSigner()
    settings.knowledge_context_transport = KnowledgeContextTransportConfig(
        peer_authenticator=_TestPeer(peer_id), signer=signer, max_ttl_seconds=30,
        expected_peer_id="nexus-lab", enabled=True,
    )
    return signer


def _post_raw(client, content: bytes):
    return client.post(
        "/v1/knowledge-context",
        content=content,
        headers={"Content-Type": "application/json"},
    )


def test_endpoint_is_disabled_without_explicit_transport_config(tmp_path):
    client, _settings, _local_db, _data = make_client(tmp_path)
    response = client.post("/v1/knowledge-context", json=_request())
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "knowledge_context_unavailable"

    # Disabled wins over body content: neither malformed nor schema-valid bodies are parsed.
    malformed = _post_raw(client, _MALFORMED)
    assert malformed.status_code == 404
    assert malformed.json() == {"detail": {"error": "knowledge_context_unavailable"}}
    non_nexus = _post_raw(client, b'{"source_product": "azazel_nexus"}')
    assert non_nexus.status_code == 404
    assert non_nexus.json()["detail"]["error"] == "knowledge_context_unavailable"

    # The OpenAPI requestBody is derived from the Fabric model, not re-declared.
    from azazel_fabric.knowledge_context import KnowledgeContextRequestV1

    operation = client.get("/openapi.json").json()["paths"]["/v1/knowledge-context"]["post"]
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    model_schema = KnowledgeContextRequestV1.model_json_schema()

    # Expected schema: resolve the Fabric model's $refs, keeping $ref siblings.
    defs = model_schema.get("$defs", {})

    def resolve(node):
        if isinstance(node, dict):
            if "$ref" in node:
                target = resolve(defs[node["$ref"].rsplit("/", 1)[1]])
                return {**target, **{k: resolve(v) for k, v in node.items() if k != "$ref"}}
            return {k: resolve(v) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    expected = resolve({k: v for k, v in model_schema.items() if k != "$defs"})
    assert schema == expected
    assert "$ref" not in json.dumps(schema)
    assert "$defs" not in schema
    assert set(schema["required"]) == {
        "schema_version",
        "request_id",
        "correlation_id",
        "source_product",
        "source_ref",
        "requested_at",
        "entities",
    }
    assert schema["properties"]["schema_version"]["const"] == "knowledge-context-request/v1"
    entity_schema = schema["properties"]["entities"]["items"]
    assert set(entity_schema["properties"]) == {"entity_type", "value"}
    assert set(entity_schema["required"]) == {"entity_type", "value"}


def test_endpoint_requires_authenticated_peer(tmp_path):
    client, settings, _local_db, _data = make_client(tmp_path)
    _configure(settings, peer_id=None)
    response = client.post("/v1/knowledge-context", json=_request())
    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "peer_authentication_failed"

    # Unauthenticated wins over body content: no parse and no size check happen first.
    malformed = _post_raw(client, _MALFORMED)
    assert malformed.status_code == 401
    assert malformed.json() == {"detail": {"error": "peer_authentication_failed"}}
    oversized = _post_raw(client, b"x" * (limits.CONTEXT_MAX_BODY_BYTES + 1))
    assert oversized.status_code == 401
    assert oversized.json() == {"detail": {"error": "peer_authentication_failed"}}


def test_endpoint_refuses_invalid_bodies_and_non_nexus_source_product(tmp_path):
    client, settings, _local_db, _data = make_client(tmp_path)
    _configure(settings)

    response = client.post(
        "/v1/knowledge-context", json={**_request(), "source_product": "azazel-edge"}
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "peer_profile_mismatch"

    # Malformed JSON: fixed 422, input not echoed.
    malformed = _post_raw(client, _MALFORMED)
    assert malformed.status_code == 422
    assert malformed.json() == _INVALID_ERROR
    assert "entities" not in malformed.text

    # Deep nesting raises RecursionError in the JSON decoder; it must stay a fixed 422.
    deep = _post_raw(client, b"[" * 100_000)
    assert deep.status_code == 422
    assert deep.json() == _INVALID_ERROR

    # Valid JSON under an unrelated Content-Type is not accepted.
    wrong_type = client.post(
        "/v1/knowledge-context",
        content=_canonical(_request()),
        headers={"Content-Type": "text/plain"},
    )
    assert wrong_type.status_code == 422
    assert wrong_type.json() == _INVALID_ERROR
    malformed_type = client.post(
        "/v1/knowledge-context",
        content=_canonical(_request()),
        headers={"Content-Type": "application/+json"},
    )
    assert malformed_type.status_code == 422
    assert malformed_type.json() == _INVALID_ERROR
    invalid_token_type = client.post(
        "/v1/knowledge-context",
        content=_canonical(_request()),
        headers={"Content-Type": "application/a/b+json"},
    )
    assert invalid_token_type.status_code == 422
    assert invalid_token_type.json() == _INVALID_ERROR

    # Valid JSON bytes with no Content-Type at all are also rejected with the fixed 422.
    no_content_type = client.post("/v1/knowledge-context", content=_canonical(_request()))
    assert no_content_type.status_code == 422
    assert no_content_type.json() == _INVALID_ERROR

    schema_invalid = _post_raw(client, b'{"source_product": "azazel_nexus"}')
    assert schema_invalid.status_code == 422
    assert schema_invalid.json() == _INVALID_ERROR

    oversized = _post_raw(client, b"x" * (limits.CONTEXT_MAX_BODY_BYTES + 1))
    assert oversized.status_code == 413
    assert oversized.json() == {"detail": {"error": "context_request_too_large"}}
    oversized_without_type = client.post(
        "/v1/knowledge-context", content=b"x" * (limits.CONTEXT_MAX_BODY_BYTES + 1)
    )
    assert oversized_without_type.status_code == 413
    assert oversized_without_type.json() == {"detail": {"error": "context_request_too_large"}}

    # An under-declared Content-Length must not bypass the streamed cap.
    under_declared = client.post(
        "/v1/knowledge-context",
        content=b"x" * (limits.CONTEXT_MAX_BODY_BYTES + 1),
        headers={"Content-Type": "application/json", "Content-Length": "10"},
    )
    assert under_declared.status_code == 413
    assert under_declared.json() == {"detail": {"error": "context_request_too_large"}}

    # Multi-chunk overflow with no Content-Length: the cap must hold across several
    # ASGI chunks, not one read. Drive _bounded_envelope directly with a receive that
    # yields two http.request messages; the second pushes the total over the cap.
    async def _receive_chunks(chunks):
        pending = list(chunks)

        async def receive():
            if pending:
                chunk = pending.pop(0)
                return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
            return {"type": "http.disconnect"}

        return receive

    first_chunk = b"x" * (limits.CONTEXT_MAX_BODY_BYTES - 1024)
    second_chunk = b"x" * 2048
    receive = asyncio.run(_receive_chunks([first_chunk, second_chunk]))
    scope = {"type": "http", "method": "POST", "headers": []}
    with pytest.raises(HTTPException) as chunked:
        asyncio.run(_bounded_envelope(Request(scope, receive), peer_id="nexus-lab"))
    assert chunked.value.status_code == 413
    assert chunked.value.detail == {"error": "context_request_too_large"}

    # Non-decimal Content-Length values must not raise: a Latin-1 superscript
    # (isdigit() is True, but int() rejects it) falls through to the streamed cap.
    # A huge ASCII numeral is compared safely (no int()) and early-rejected as larger
    # than the cap. Both still produce the fixed 413 rather than a 500.
    oversized_body = b"x" * (limits.CONTEXT_MAX_BODY_BYTES + 1)
    assert not _declared_length_exceeds_cap(None)
    assert not _declared_length_exceeds_cap(str(limits.CONTEXT_MAX_BODY_BYTES))
    assert _declared_length_exceeds_cap(str(limits.CONTEXT_MAX_BODY_BYTES + 1))
    assert _declared_length_exceeds_cap("0000" + str(limits.CONTEXT_MAX_BODY_BYTES + 1))
    assert _declared_length_exceeds_cap("9" * 5000)
    assert not _declared_length_exceeds_cap("²")
    assert not _declared_length_exceeds_cap("12 ")
    assert not _declared_length_exceeds_cap("123\n")

    # A huge declared length is rejected before the request stream is touched.
    async def _unexpected_receive():
        raise AssertionError("early Content-Length rejection read the request body")

    huge_length_request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-length", (b"9" * 5000))],
        },
        _unexpected_receive,
    )
    with pytest.raises(HTTPException) as early_rejected:
        asyncio.run(_bounded_envelope(huge_length_request, peer_id="nexus-lab"))
    assert early_rejected.value.status_code == 413

    for declared in ("9" * 5000, b"\xb2"):
        response = client.post(
            "/v1/knowledge-context",
            content=oversized_body,
            headers={"Content-Type": "application/json", "Content-Length": declared},
        )
        assert response.status_code == 413
        assert response.json() == {"detail": {"error": "context_request_too_large"}}


def test_endpoint_returns_signed_bounded_partial_snapshot(tmp_path):
    client, settings, _local_db, _data = make_client(tmp_path)
    signer = _configure(settings)
    fixed_clock = settings.clock

    class CountingClock:
        calls = 0

        def query_as_of(self):
            self.calls += 1
            return fixed_clock.query_as_of()

    settings.clock = CountingClock()
    client.app.state.clock = settings.clock
    response = client.post("/v1/knowledge-context", json=_request())

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    raw = response.content
    signature, payload = raw[:64], raw[64:]
    signer.key.verify_key.verify(_DOMAIN + payload, signature)
    document = json.loads(payload)
    assert _canonical(document) == payload
    assert document["schema"] == _SCHEMA
    assert document["key_id"] == signer.key_id
    semantic = document["payload"]
    assert settings.clock.calls == 1
    pinned_query_time = parse_rfc3339(semantic["snapshot"]["as_of"])
    assert document["issued_at"] == to_rfc3339(pinned_query_time)
    assert document["expires_at"] == to_rfc3339(
        pinned_query_time + timedelta(seconds=30)
    )
    assert semantic["request_id"] == _request()["request_id"]
    assert semantic["correlation_id"] == _request()["correlation_id"]
    assert semantic["snapshot"] == {
        "ref": "knowledge:intel-generation:1",
        "state": "partial",
        "as_of": "2026-07-06T12:00:00Z",
    }
    assert "source-level freshness deadlines are not included in this projection" in (
        semantic["limitations"]
    )
    assert semantic["authority"] == "advisory_only"
    assert len(semantic["facts"]) == 1
    assert semantic["facts"][0]["provenance"] == ["knowledge:intel-index"]
    assert semantic["facts"][0]["subject"] == {
        "entity_type": "ip", "value": "203.0.113.7"
    }
    assert semantic["unknowns"]

    client_ids = list((settings.spool_root / "advisory").glob("*.client"))
    assert len(client_ids) == 1
    assert client_ids[0].read_text(encoding="utf-8") == "mtls:nexus-lab"
    client.app.state.audit.flush()
    audit_path = settings.audit_dir / "test-proc.test-boot.jsonl"
    audit_event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])["event"]
    assert audit_event["actor_key"] == "mtls:nexus-lab"

    # The same valid request sent as raw application/json bytes is signed identically.
    valid_body = _canonical(_request())
    raw_response = _post_raw(client, valid_body)
    assert raw_response.status_code == 200
    signature, payload = raw_response.content[:64], raw_response.content[64:]
    signer.key.verify_key.verify(_DOMAIN + payload, signature)

    # Both supported JSON media-type forms accept a valid request body.
    for content_type in (
        "application/vnd.fabric+json; charset=utf-8",
        "APPLICATION/JSON",
    ):
        typed_response = client.post(
            "/v1/knowledge-context",
            content=valid_body,
            headers={"Content-Type": content_type},
        )
        assert typed_response.status_code == 200
        typed_signature, typed_payload = (
            typed_response.content[:64],
            typed_response.content[64:],
        )
        signer.key.verify_key.verify(_DOMAIN + typed_payload, typed_signature)

    # The bound is inclusive: a valid JSON body padded with whitespace to exactly
    # the configured maximum remains acceptable.
    exact_cap = valid_body + b" " * (limits.CONTEXT_MAX_BODY_BYTES - len(valid_body))
    at_cap = _post_raw(client, exact_cap)
    assert at_cap.status_code == 200
    at_cap_signature, at_cap_payload = at_cap.content[:64], at_cap.content[64:]
    signer.key.verify_key.verify(_DOMAIN + at_cap_payload, at_cap_signature)


def test_endpoint_rejects_a_64_byte_but_invalid_signature(tmp_path):
    client, settings, _local_db, _data = make_client(tmp_path)
    signer = _configure(settings)
    signer.sign = lambda _message: bytes(64)

    response = client.post("/v1/knowledge-context", json=_request())

    assert response.status_code == 503
    assert response.json() == {
        "detail": {"error": "knowledge_context_signing_unavailable"}
    }


@pytest.mark.parametrize("failure", ["adapter", "type", "canonicalizer", "unexpected"])
def test_projection_failure_has_a_distinct_fixed_error(tmp_path, monkeypatch, failure):
    client, settings, _local_db, _data = make_client(tmp_path)
    _configure(settings)

    from azazel_knowledge.api.routers import knowledge_context as route
    if failure == "canonicalizer":
        def fail_canonicalization(_semantic):
            raise ValueError("private input detail")

        monkeypatch.setattr(route, "canonical_knowledge_context_bytes", fail_canonicalization)
    else:
        def fail_projection(*_args, **_kwargs):
            if failure == "type":
                raise TypeError("private input detail")
            if failure == "unexpected":
                raise RuntimeError("private input detail")
            from azazel_knowledge.api.knowledge_context_adapter import KnowledgeContextAdaptationError
            raise KnowledgeContextAdaptationError("private input detail")

        monkeypatch.setattr(route, "to_knowledge_context_response", fail_projection)

    response = client.post("/v1/knowledge-context", json=_request())

    assert response.status_code == 503
    assert response.json() == {
        "detail": {"error": "knowledge_context_projection_unavailable"}
    }
    assert "private input detail" not in response.text


def test_invalid_snapshot_time_fails_closed_as_projection_unavailable(tmp_path, monkeypatch):
    from azazel_knowledge.api.routers import knowledge_context as route

    client, settings, _local_db, _data = make_client(tmp_path)
    _configure(settings)
    original_post_context = route.post_context

    def invalid_snapshot_time(*args, **kwargs):
        result = original_post_context(*args, **kwargs)
        result._knowledge_snapshot_as_of = "not-a-timestamp"
        return result

    monkeypatch.setattr(route, "post_context", invalid_snapshot_time)
    response = client.post("/v1/knowledge-context", json=_request())

    assert response.status_code == 503
    assert response.json() == {
        "detail": {"error": "knowledge_context_projection_unavailable"}
    }


def test_unexpected_request_conversion_error_is_fixed_and_private(tmp_path, monkeypatch):
    from azazel_knowledge.api.routers import knowledge_context as route

    client, settings, _local_db, _data = make_client(tmp_path)
    _configure(settings)

    def fail_request_conversion(*_args, **_kwargs):
        raise RuntimeError("private input detail")

    monkeypatch.setattr(route, "from_knowledge_context_request", fail_request_conversion)
    response = client.post("/v1/knowledge-context", json=_request())

    assert response.status_code == 503
    assert response.json() == {
        "detail": {"error": "knowledge_context_request_unavailable"}
    }
    assert "private input detail" not in response.text


def test_existing_context_response_does_not_expose_private_snapshot_binding(tmp_path):
    client, settings, local_db_path, _data = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    response = client.post(
        "/v1/context",
        json={"entities": [{"type": "ip", "value": "203.0.113.7"}]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "_knowledge_snapshot_ref" not in response.json()
    assert "_knowledge_snapshot_as_of" not in response.json()


def test_transport_config_requires_bounded_ttl_and_fingerprint():
    signer = _TestSigner()
    with pytest.raises(ValueError):
        KnowledgeContextTransportConfig(
            peer_authenticator=_TestPeer(), signer=signer, max_ttl_seconds=0,
            expected_peer_id="nexus-lab",
        )
    signer.key_id = "key-id"
    with pytest.raises(ValueError):
        KnowledgeContextTransportConfig(
            peer_authenticator=_TestPeer(), signer=signer, max_ttl_seconds=30,
            expected_peer_id="nexus-lab",
        )
