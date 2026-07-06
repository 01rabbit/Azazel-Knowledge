from __future__ import annotations

import json

from _api_support import add_api_client, auth_header, make_client


def test_confirm_reaction_spools_admin_line(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "admin1", ["admin"])
    resp = client.post("/v1/reactions/42/confirm", headers=auth_header(token))
    assert resp.status_code == 202

    admin_dir = settings.spool_root / "admin"
    files = list(admin_dir.glob("*.jsonl"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text().strip())
    assert payload["kind"] == "reaction_confirm"
    assert payload["reaction_id"] == 42
    assert payload["actor"] == "admin1"


def test_confirm_ioc_spools_admin_line(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "admin1", ["admin"])
    resp = client.post("/v1/iocs/deadbeef/confirm", headers=auth_header(token))
    assert resp.status_code == 202
    admin_dir = settings.spool_root / "admin"
    files = list(admin_dir.glob("*.jsonl"))
    payload = json.loads(files[0].read_text().strip())
    assert payload["kind"] == "ioc_confirm"
    assert payload["ioc_ref"] == "deadbeef"


def test_release_quarantine_spools_admin_line(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "admin1", ["admin"])
    resp = client.post("/v1/edge-intel/edge-9/release", headers=auth_header(token))
    assert resp.status_code == 202
    admin_dir = settings.spool_root / "admin"
    files = list(admin_dir.glob("*.jsonl"))
    payload = json.loads(files[0].read_text().strip())
    assert payload["kind"] == "quarantine_release"
    assert payload["edge_id"] == "edge-9"


def test_ingest_scoped_token_forbidden_on_all_admin_routes(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest", "query", "read"])
    assert client.post("/v1/reactions/1/confirm", headers=auth_header(token)).status_code == 403
    assert client.post("/v1/iocs/x/confirm", headers=auth_header(token)).status_code == 403
    assert client.post("/v1/edge-intel/e/release", headers=auth_header(token)).status_code == 403


def test_admin_route_without_token_is_401(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    resp = client.post("/v1/reactions/1/confirm")
    assert resp.status_code == 401
