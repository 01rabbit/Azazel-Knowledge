from __future__ import annotations

import json
import sqlite3

from _api_support import add_api_client, auth_header, make_client


def test_campaigns_empty_in_phase1(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "reader1", ["read"])
    resp = client.get("/v1/campaigns", headers=auth_header(token))
    assert resp.status_code == 200
    assert resp.json() == {"campaigns": []}


def test_campaign_by_id_not_found(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "reader1", ["read"])
    resp = client.get("/v1/campaigns/c1", headers=auth_header(token))
    assert resp.status_code == 404


def test_recommendation_rules_lists_draft_and_reviewed(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "reader1", ["read"])

    conn = sqlite3.connect(local_db_path)
    conn.execute(
        "INSERT INTO rule_draft (sid, format, status, provenance, confidence, content, "
        "content_hash, created_at) VALUES ('sid-1', 'suricata', 'draft', '{}', 80.0, "
        "'alert ...', 'hash1', '2026-07-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO rule_draft (sid, format, status, provenance, confidence, content, "
        "content_hash, created_at) VALUES ('sid-2', 'sigma', 'superseded', '{}', 40.0, "
        "'title: x', 'hash2', '2026-07-02T00:00:00Z')"
    )
    conn.commit()
    conn.close()

    resp = client.get("/v1/recommendations/rules", headers=auth_header(token))
    assert resp.status_code == 200
    sids = {r["sid"] for r in resp.json()["rules"]}
    assert sids == {"sid-1"}


def test_reactions_summary_aggregates(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "reader1", ["read"])

    conn = sqlite3.connect(local_db_path)
    conn.execute(
        "INSERT INTO reaction (edge_id, actor_key, action_applied, applied_at, reaction, "
        "reaction_window_s, classifier, classifier_version, evidence_refs, advisory_id, "
        "advisory_linkage, created_at) VALUES ('edge-1', 'actor-1', 'throttle', "
        "'2026-07-06T10:00:00Z', 'continued_scanning', 300, 'reaction_ladder', '1', '[]', "
        "NULL, 'none', '2026-07-06T10:00:01Z')"
    )
    conn.commit()
    conn.close()

    resp = client.get("/v1/reactions/summary", headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["breakdown"] == [
        {"action_applied": "throttle", "reaction": "continued_scanning", "count": 1}
    ]
    assert body["windows"]["24h"] == 1
    assert 0.0 <= body["ambiguous_linkage_rate"] <= 1.0


def test_edge_intel_lists_quarantined_entries(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "reader1", ["read"])

    conn = sqlite3.connect(local_db_path)
    conn.execute(
        "INSERT INTO edge_reported_ioc (entity_key, type, value, edge_id, first_reported, "
        "report_count, status) VALUES (?, 'ip', '198.51.100.50', 'edge-1', "
        "'2026-07-01T00:00:00Z', 1, 'quarantined')",
        (b"\x01" * 16,),
    )
    conn.commit()
    conn.close()

    resp = client.get("/v1/edge-intel", headers=auth_header(token))
    assert resp.status_code == 200
    entries = resp.json()["entries"]
    assert len(entries) == 1
    assert entries[0]["value"] == "198.51.100.50"
    assert entries[0]["status"] == "quarantined"


def test_health_reports_expected_fields(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "reader1", ["read"])
    resp = client.get("/v1/health", headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["cache_state"] == "warm"
    assert body["intel_generation"] == 1
    assert body["local_generation"] == 3
    assert body["stats_generation"] == 7
    assert body["audit_writer_ok"] is True
    assert body["feeds"][0]["feed_id"] == "urlhaus"
    assert body["feeds"][0]["age_days"] is not None
    assert "context_breaker_total" in body
    assert "pending_confirmations" in body


def test_health_cache_state_cold_when_no_generation(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path, warm=False)
    token = add_api_client(local_db_path, "reader1", ["read"])
    resp = client.get("/v1/health", headers=auth_header(token))
    assert resp.status_code == 200
    assert resp.json()["cache_state"] == "cold"
    assert resp.json()["intel_generation"] is None
