from __future__ import annotations

import json

from azazel_knowledge.api import limits
from _api_support import add_api_client, auth_header, make_client


def test_events_accepted_returns_batch_id(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    line = json.dumps({"event_id": "e1", "edge_id": "edge-1", "kind": "dns", "observed_at": "2026-07-06T11:00:00Z"})
    resp = client.post("/v1/events", content=(line + "\n").encode(), headers=auth_header(token))
    assert resp.status_code == 202
    batch_id = resp.json()["batch_id"]
    assert batch_id


def test_malformed_line_still_accepted_202(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post("/v1/events", content=b"not json at all\n", headers=auth_header(token))
    assert resp.status_code == 202


def test_flows_and_reactions_accepted(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post("/v1/flows", content=b'{"a": 1}\n', headers=auth_header(token))
    assert resp.status_code == 202
    resp = client.post("/v1/reactions", content=b'{"a": 1}\n', headers=auth_header(token))
    assert resp.status_code == 202


def test_batch_status_pending_before_drain(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post("/v1/events", content=b'{"a": 1}\n', headers=auth_header(token))
    batch_id = resp.json()["batch_id"]
    status = client.get(f"/v1/ingest/{batch_id}", headers=auth_header(token))
    assert status.status_code == 200
    assert status.json()["drained"] is False


def test_batch_status_unknown_is_404(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.get("/v1/ingest/does-not-exist", headers=auth_header(token))
    assert resp.status_code == 404


def test_batch_status_reflects_drained_status_file(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post("/v1/events", content=b'{"a": 1}\n', headers=auth_header(token))
    batch_id = resp.json()["batch_id"]

    from azazel_knowledge.ingest.spool import BatchStatus, SpoolWriter

    spool = SpoolWriter(settings.spool_root)
    spool.write_status(
        "events",
        batch_id,
        BatchStatus(batch_id=batch_id, accepted="2026-07-06T12:00:00Z", line_count=1, valid=1, invalid=[], drained=True),
    )
    status = client.get(f"/v1/ingest/{batch_id}", headers=auth_header(token))
    assert status.status_code == 200
    body = status.json()
    assert body["drained"] is True
    assert body["valid"] == 1


def test_ingest_quota_exceeded_returns_503(tmp_path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    from _api_support import make_intel_generation, make_local_db
    from azazel_knowledge.api.app import Settings, create_app
    from azazel_knowledge.core.clock import FixedClock
    from _api_support import CONFIG_DIR, QUERY_AS_OF
    from fastapi.testclient import TestClient

    make_local_db(local_db_path)
    make_intel_generation(data_db_dir, 1)
    settings = Settings(
        config_dir=CONFIG_DIR,
        local_db_path=local_db_path,
        data_db_dir=data_db_dir,
        spool_root=tmp_path / "var" / "ingest",
        audit_dir=tmp_path / "var" / "audit" / "api",
        clock=FixedClock(QUERY_AS_OF),
        ingest_quota_bytes=64,
    )
    client = TestClient(create_app(settings))
    token = add_api_client(local_db_path, "edge1", ["ingest"])

    big_line = "x" * 128
    resp = client.post("/v1/events", content=(big_line + "\n").encode(), headers=auth_header(token))
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "ingest_quota_exceeded"
    assert "Retry-After" in resp.headers


def test_ingest_batch_too_large_returns_413(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    oversized = ("x" * (limits.INGEST_BATCH_MAX_BYTES + 10)).encode()
    resp = client.post("/v1/events", content=oversized, headers=auth_header(token))
    assert resp.status_code == 413
