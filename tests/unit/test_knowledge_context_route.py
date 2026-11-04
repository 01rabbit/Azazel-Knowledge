from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import pytest
from nacl.signing import SigningKey

from azazel_knowledge.api.knowledge_context_transport import KnowledgeContextTransportConfig
from azazel_knowledge.core.clock import to_rfc3339
from _api_support import add_api_client, make_client

_DOMAIN = b"azazel-nexus/knowledge-context-envelope/v1\x00"
_SCHEMA = "azazel-nexus/knowledge-context-envelope/1"


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


def test_endpoint_is_disabled_without_explicit_transport_config(tmp_path):
    client, _settings, _local_db, _data = make_client(tmp_path)
    response = client.post("/v1/knowledge-context", json=_request())
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "knowledge_context_unavailable"


def test_endpoint_requires_authenticated_peer(tmp_path):
    client, settings, _local_db, _data = make_client(tmp_path)
    _configure(settings, peer_id=None)
    response = client.post("/v1/knowledge-context", json=_request())
    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "peer_authentication_failed"


def test_endpoint_refuses_non_nexus_source_product(tmp_path):
    client, settings, _local_db, _data = make_client(tmp_path)
    _configure(settings)
    response = client.post(
        "/v1/knowledge-context", json={**_request(), "source_product": "azazel-edge"}
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "peer_profile_mismatch"


def test_endpoint_returns_signed_bounded_partial_snapshot(tmp_path):
    client, settings, _local_db, _data = make_client(tmp_path)
    signer = _configure(settings)
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
    assert document["issued_at"] == to_rfc3339(settings.clock.query_as_of())
    assert document["expires_at"] == to_rfc3339(
        settings.clock.query_as_of() + timedelta(seconds=30)
    )
    semantic = document["payload"]
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
