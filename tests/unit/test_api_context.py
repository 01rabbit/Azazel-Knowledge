from __future__ import annotations

from azazel_grimoire.api import limits
from azazel_grimoire.audit.logger import AuditUnavailable
from _api_support import add_api_client, auth_header, make_client

_ADVISORY_NOTICE = (
    "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
)


def _context_body(**overrides):
    body = {
        "entities": [{"type": "ip", "value": "203.0.113.7"}],
        "event": {"kind": "eve_alert", "event_types": ["eve_alert"], "cves": ["CVE-2024-0001"]},
        "edge_id": "edge-1",
        "actor_key": "actor-1",
    }
    body.update(overrides)
    return body


def test_context_happy_path_full_contract(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.json()

    assert body["advisory_notice"] == _ADVISORY_NOTICE
    assert isinstance(body["advisory_id"], str) and len(body["advisory_id"]) == 26
    assert [l["component"] for l in body["reason"]] == [
        "ioc_match", "history", "attack_map", "campaign", "geo_asn", "cve_exploited",
    ]
    assert len(body["confidence_reason"]) == 4
    assert body["threat_score"] > 0
    assert body["confidence"] > 0
    assert body["recommendation"]["action"] in {"isolate", "throttle", "redirect", "observe"}
    assert "rejected_alternatives" in body["recommendation"]
    assert body["source_freshness"]["attack_version"]
    assert body["multi_ioc_scope"]["matched_count"] == 1
    assert body["threat_context"]["ioc_matches"][0]["value"] == "203.0.113.7"


def test_two_calls_yield_distinct_advisory_ids(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    r1 = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    r2 = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert r1.json()["advisory_id"] != r2.json()["advisory_id"]


def test_deadline_exceeded_returns_unscored_503(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path, deadline_ms=0)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "context_timeout"
    assert "reason" not in resp.json()


def test_audit_chain_failure_returns_503_audit_unavailable(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    def _boom(event):
        raise AuditUnavailable("disk error")

    client.app.state.audit.append = _boom
    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "audit_unavailable"


def test_context_body_too_large_returns_413(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    body = _context_body(event={"padding": "x" * (limits.CONTEXT_MAX_BODY_BYTES + 1024)})
    resp = client.post("/v1/context", json=body, headers=auth_header(token))
    assert resp.status_code == 413
    assert resp.json()["detail"]["error"] == "context_request_too_large"


def test_context_entity_cap_returns_413(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    entities = [{"type": "ip", "value": f"10.0.{i // 256}.{i % 256}"} for i in range(65)]
    resp = client.post(
        "/v1/context", json=_context_body(entities=entities), headers=auth_header(token)
    )
    assert resp.status_code == 413


def test_context_no_match_still_returns_complete_reason(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    body = _context_body(entities=[{"type": "ip", "value": "172.16.99.99"}], event={})
    resp = client.post("/v1/context", json=body, headers=auth_header(token))
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["reason"]) == 6
    assert all(l["contribution"] == 0 for l in data["reason"])
    assert data["multi_ioc_scope"]["matched_count"] == 0
