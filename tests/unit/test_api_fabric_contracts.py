"""Azazel-Fabric `cti_contracts` boundary adoption (ADR-0010).

Exercises the additive Fabric layer wired in at the API boundary:

* ingest accepts the canonical `Cti<Kind>Batch` envelope and fails an
  envelope-contract violation closed with `422`, while legacy JSONL is
  untouched;
* the `/v1/context` response advisory-only invariant fails closed (`500`)
  when a directive-shaped field is present, never emitting the advisory;
* `/v1/context` byte-identical replay still holds (the added check does not
  perturb the emitted response).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from _api_support import add_api_client, auth_header, make_client


def _event_batch(**overrides) -> dict:
    body = {
        "batch_id": "batch-1",
        "source_product": "edge",
        "source_device_id": "edge-demo-01",
        "generated_at": "2026-07-06T11:00:00Z",
        "items": [
            {"event_id": "e1", "kind": "dns", "observed_at": "2026-07-06T11:00:00Z"},
            {"event_id": "e2", "kind": "http", "observed_at": "2026-07-06T11:00:01Z"},
        ],
    }
    body.update(overrides)
    return body


def _context_body(**overrides):
    body = {
        "entities": [{"type": "ip", "value": "203.0.113.7"}],
        "event": {"kind": "eve_alert", "event_types": ["eve_alert"], "cves": ["CVE-2024-0001"]},
        "edge_id": "edge-1",
        "actor_key": "actor-1",
    }
    body.update(overrides)
    return body


# --- ingest: Fabric batch envelope --------------------------------------


def test_valid_fabric_event_batch_passes_through_to_spool(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post("/v1/events", json=_event_batch(), headers=auth_header(token))
    assert resp.status_code == 202
    batch_id = resp.json()["batch_id"]
    assert batch_id

    files = list((settings.spool_root / "events").glob("*.jsonl"))
    assert len(files) == 1
    lines = [l for l in files[0].read_text().splitlines() if l.strip()]
    # Envelope items were flattened one-per-line for the existing drain path.
    assert len(lines) == 2
    assert {json.loads(l)["event_id"] for l in lines} == {"e1", "e2"}


def test_malformed_fabric_batch_bad_source_product_returns_422(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post(
        "/v1/events", json=_event_batch(source_product="mainframe"), headers=auth_header(token)
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "ingest_batch_invalid"


def test_malformed_fabric_batch_missing_field_returns_422(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    bad = _event_batch()
    del bad["batch_id"]
    resp = client.post("/v1/events", json=bad, headers=auth_header(token))
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "ingest_batch_invalid"


def test_flows_and_reactions_envelopes_are_type_enforced(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    for endpoint in ("flows", "reactions"):
        ok = client.post(f"/v1/{endpoint}", json=_event_batch(), headers=auth_header(token))
        assert ok.status_code == 202
        bad = client.post(
            f"/v1/{endpoint}",
            json=_event_batch(source_product="BAD"),
            headers=auth_header(token),
        )
        assert bad.status_code == 422
        assert bad.json()["detail"]["error"] == "ingest_batch_invalid"


def test_legacy_jsonl_ingest_still_accepted_unchanged(tmp_path):
    """A body that is not a Fabric envelope keeps the fire-and-forget path."""
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    # Bare single item (no envelope markers) and a malformed line both 202.
    line = json.dumps({"event_id": "e1", "kind": "dns"})
    r1 = client.post("/v1/events", content=(line + "\n").encode(), headers=auth_header(token))
    assert r1.status_code == 202
    r2 = client.post("/v1/events", content=b"not json at all\n", headers=auth_header(token))
    assert r2.status_code == 202


# --- context response: advisory-only invariant --------------------------


def _fake_result_with(recommendation: dict) -> SimpleNamespace:
    return SimpleNamespace(
        threat_context={"ioc_matches": []},
        threat_score=10.0,
        confidence=20.0,
        reason=[{"component": "ioc_match", "contribution": 0}],
        confidence_reason=[{"driver": "source_count", "contribution": 0}],
        recommendation=recommendation,
        source_freshness={"attack_version": "15.1"},
        advisory_notice="advisory",
        multi_ioc_scope={"matched_count": 0},
        content_hash="deadbeef",
        determinism={
            "intel_generation": 1,
            "local_generation": 3,
            "stats_generation": 7,
            "attack_version": "15.1",
            "config_hash": "cfg",
        },
    )


def test_directive_field_in_response_fails_closed_500(tmp_path, monkeypatch):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    # Craft a pipeline result whose recommendation smuggles a banned directive
    # field. The boundary check must reject it before emission.
    tainted = _fake_result_with({"action": "throttle", "override": "block-now"})
    monkeypatch.setattr(
        "azazel_knowledge.api.routers.context.run_context",
        lambda *a, **k: tainted,
    )
    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert resp.status_code == 500
    assert resp.json()["detail"]["error"] == "advisory_invariant_violation"
    # Fail closed: no advisory payload leaked.
    assert "threat_score" not in resp.json()
    assert "recommendation" not in resp.json()


def test_clean_response_passes_advisory_only_check(tmp_path, monkeypatch):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    clean = _fake_result_with(
        {"action": "throttle", "rejected_alternatives": [{"action": "isolate", "why_not": "x"}]}
    )
    monkeypatch.setattr(
        "azazel_knowledge.api.routers.context.run_context",
        lambda *a, **k: clean,
    )
    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert resp.status_code == 200
    assert resp.json()["recommendation"]["action"] == "throttle"


def test_context_response_replay_byte_identical_except_advisory_id(tmp_path):
    """The added advisory-only check must not perturb the emitted response:
    two identical requests differ only in the per-request advisory_id."""
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    r1 = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    r2 = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert r1.status_code == r2.status_code == 200
    b1, b2 = r1.json(), r2.json()
    assert b1["advisory_id"] != b2["advisory_id"]
    del b1["advisory_id"]
    del b2["advisory_id"]
    # Byte-identical once the per-request id is removed.
    assert json.dumps(b1, sort_keys=True) == json.dumps(b2, sort_keys=True)
