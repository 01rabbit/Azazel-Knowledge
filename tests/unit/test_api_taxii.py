from __future__ import annotations

import json

from _api_support import add_api_client, auth_header, make_client


def _indicator(value: str = "203.0.113.7") -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--00000000-0000-0000-0000-000000000001",
        "created": "2026-07-01T00:00:00Z",
        "modified": "2026-07-01T00:00:00Z",
        "valid_from": "2026-07-01T00:00:00Z",
        "pattern_type": "stix",
        "pattern": f"[ipv4-addr:value = '{value}']",
        "labels": [],
        "confidence": 50,
    }


def _observed_data_reaction() -> dict:
    return {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--00000000-0000-0000-0000-000000000002",
        "created": "2026-07-01T00:00:00Z",
        "modified": "2026-07-01T00:00:00Z",
        "first_observed": "2026-07-01T00:00:00Z",
        "last_observed": "2026-07-01T00:00:00Z",
        "number_observed": 1,
        "object_refs": [],
        "extensions": {
            "x-azazel-reaction": {
                "edge_id": "edge-1",
                "actor_key": "actor-1",
                "action_applied": "throttle",
                "reaction": "continued_scanning",
                "reaction_window_s": 300,
                "events_in_window": 3,
                "classifier": "reaction_ladder",
                "classifier_version": "1",
                "evidence_refs": ["ev-1"],
                "evidence_modality_count": 1,
                "trust_tier": "provisional",
                "advisory_id": None,
                "advisory_linkage": "none",
            }
        },
    }


def test_discovery_and_api_root_are_static(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    resp = client.get("/taxii2/")
    assert resp.status_code == 200
    assert resp.json()["title"] == "Azazel-Knowledge TAXII 2.1"
    root = client.get("/taxii2/api-root")
    assert root.status_code == 200
    assert "application/taxii+json;version=2.1" in root.json()["versions"]


def test_indicator_accepted_and_spooled_to_edge_reported(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post(
        "/taxii2/inbox/objects",
        json={"objects": [_indicator()]},
        headers=auth_header(token),
    )
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 1
    files = list((settings.spool_root / "edge_reported").glob("*.jsonl"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text().strip())
    assert payload["ioc"]["type"] == "ip"
    assert payload["ioc"]["value"] == "203.0.113.7"


def test_observed_data_with_reaction_extension_routed_to_reactions(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post(
        "/taxii2/inbox/objects",
        json={"objects": [_observed_data_reaction()]},
        headers=auth_header(token),
    )
    assert resp.status_code == 202
    files = list((settings.spool_root / "reactions").glob("*.jsonl"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text().strip())
    assert payload["action_applied"] == "throttle"


def test_unaccepted_type_rejected_422(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post(
        "/taxii2/inbox/objects",
        json={"objects": [{"type": "campaign", "id": "campaign--1"}]},
        headers=auth_header(token),
    )
    assert resp.status_code == 422
    body = resp.json()["detail"]
    assert body["error"] == "INBOX_TYPE_NOT_ACCEPTED"
    assert body["type"] == "campaign"


def test_observed_data_without_reaction_extension_rejected(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    obj = {
        "type": "observed-data",
        "id": "observed-data--x",
        "first_observed": "2026-07-01T00:00:00Z",
        "last_observed": "2026-07-01T00:00:00Z",
        "number_observed": 1,
        "object_refs": [],
    }
    resp = client.post(
        "/taxii2/inbox/objects", json={"objects": [obj]}, headers=auth_header(token)
    )
    assert resp.status_code == 422


def test_mixed_batch_accepts_valid_and_rejects_invalid(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post(
        "/taxii2/inbox/objects",
        json={"objects": [_indicator(), {"type": "malware", "id": "malware--1"}]},
        headers=auth_header(token),
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["accepted"] == 1
    assert "malware" in detail["rejected"]


def test_query_scoped_token_forbidden_on_inbox(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post(
        "/taxii2/inbox/objects", json={"objects": []}, headers=auth_header(token)
    )
    assert resp.status_code == 403
