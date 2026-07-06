from __future__ import annotations

from _api_support import add_api_client, auth_header, make_client


def test_no_token_is_401(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post("/v1/ioc/search", json={"type": "ip", "value": "203.0.113.7"})
    assert resp.status_code == 401


def test_malformed_token_is_401(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    resp = client.post(
        "/v1/ioc/search",
        json={"type": "ip", "value": "203.0.113.7"},
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert resp.status_code == 401


def test_unknown_key_id_is_401(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    resp = client.post(
        "/v1/ioc/search",
        json={"type": "ip", "value": "203.0.113.7"},
        headers={"Authorization": "Bearer azcti_ghost_deadbeef"},
    )
    assert resp.status_code == 401


def test_disabled_client_is_401(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"], enabled=False)
    resp = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "203.0.113.7"}, headers=auth_header(token)
    )
    assert resp.status_code == 401


def test_query_scoped_token_may_search(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "203.0.113.7"}, headers=auth_header(token)
    )
    assert resp.status_code == 200


def test_ingest_scoped_token_forbidden_on_search(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "203.0.113.7"}, headers=auth_header(token)
    )
    assert resp.status_code == 403


def test_query_scoped_token_forbidden_on_ingest(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post("/v1/events", content=b"", headers=auth_header(token))
    assert resp.status_code == 403


def test_ingest_scoped_token_forbidden_on_admin_confirm(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest", "query"])
    resp = client.post("/v1/reactions/1/confirm", headers=auth_header(token))
    assert resp.status_code == 403


def test_admin_scoped_token_may_confirm(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "admin1", ["admin"])
    resp = client.post("/v1/reactions/1/confirm", headers=auth_header(token))
    assert resp.status_code == 202


def test_read_scoped_token_forbidden_on_admin(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "reader1", ["read"])
    resp = client.post("/v1/reactions/1/confirm", headers=auth_header(token))
    assert resp.status_code == 403


def test_read_scoped_token_may_hit_reads(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "reader1", ["read"])
    resp = client.get("/v1/health", headers=auth_header(token))
    assert resp.status_code == 200


def test_warmup_gate_blocks_search_when_cold(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path, warm=False)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "203.0.113.7"}, headers=auth_header(token)
    )
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "cache_state_cold"
    assert "Retry-After" in resp.headers


def test_warmup_gate_blocks_context_when_cold(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path, warm=False)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post(
        "/v1/context",
        json={"entities": [{"type": "ip", "value": "203.0.113.7"}], "edge_id": "edge-1"},
        headers=auth_header(token),
    )
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "cache_state_cold"


def test_ingest_still_spools_when_cold(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path, warm=False)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.post("/v1/events", content=b'{"a": 1}\n', headers=auth_header(token))
    assert resp.status_code == 202
    assert "batch_id" in resp.json()


def test_authorization_header_never_reaches_audit_log(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "203.0.113.7"}, headers=auth_header(token)
    )
    assert resp.status_code == 200
    client.app.state.audit.flush()

    files = list(settings.audit_dir.glob("*.jsonl"))
    assert files
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert token not in text
        assert token.rsplit("_", 1)[-1] not in text
        assert "authorization" not in text.lower()


def test_warmup_gate_clears_once_warm(tmp_path):
    from _api_support import make_intel_generation

    client, settings, local_db_path, data_db_dir = make_client(tmp_path, warm=False)
    token = add_api_client(local_db_path, "edge1", ["query"])
    cold = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "203.0.113.7"}, headers=auth_header(token)
    )
    assert cold.status_code == 503

    make_intel_generation(data_db_dir, 1)
    warm = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "203.0.113.7"}, headers=auth_header(token)
    )
    assert warm.status_code == 200
