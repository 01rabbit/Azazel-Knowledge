from __future__ import annotations

import sqlite3

from _api_support import add_api_client, auth_header, make_client


def test_search_match_shape_matches_api_md(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "203.0.113.7"}, headers=auth_header(token)
    )
    assert resp.status_code == 200
    body = resp.json()
    for key in (
        "match", "confidence", "confidence_reason", "sources", "first_seen",
        "last_seen", "source_freshness_days", "basis",
    ):
        assert key in body
    assert body["match"] is True
    assert body["sources"] == ["urlhaus"]
    assert body["basis"]["source_count"] == 1
    assert body["basis"]["groups"] == ["abusech"]
    assert len(body["confidence_reason"]) == 4
    assert {l["component"] for l in body["confidence_reason"]} == {
        "source_count", "source_independence", "source_freshness", "local_corroboration",
    }


def test_search_miss_still_emits_four_zero_lines(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "8.8.8.8"}, headers=auth_header(token)
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["match"] is False
    assert body["confidence"] == 0.0
    assert len(body["confidence_reason"]) == 4
    assert all(l["contribution"] == 0 for l in body["confidence_reason"])
    assert body["sources"] == []
    assert body["first_seen"] is None
    assert body["basis"] == {"groups": [], "source_count": 0, "freshest_last_seen": None}


def test_cidr_containment_match_for_ip_miss(tmp_path):
    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    intel_path = data_db_dir / "gen-1" / "intel.db"
    conn = sqlite3.connect(intel_path)
    conn.execute(
        "INSERT INTO ioc (ioc_id, type, value, first_seen, last_seen, agg_raw_confidence) "
        "VALUES (5, 'ip', '192.0.2.99', '2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 55.0)"
    )
    conn.execute(
        "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
        "intel_generation) VALUES (5, 'urlhaus', 85, '2026-06-01T00:00:00Z', "
        "'2026-07-02T00:00:00Z', 1)"
    )
    conn.execute(
        "INSERT INTO ioc_cidr (tier, range_start, range_end, ioc_id, feed_id) "
        "VALUES ('/24', ?, ?, 5, 'urlhaus')",
        (
            int.from_bytes(bytes([192, 0, 2, 0]), "big"),
            int.from_bytes(bytes([192, 0, 2, 255]), "big"),
        ),
    )
    conn.commit()
    conn.close()

    resp = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "192.0.2.50"}, headers=auth_header(token)
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["match"] is True
    assert body["last_seen"] == "2026-07-02T00:00:00Z"


def test_ja3_search_discloses_type_cap(tmp_path):
    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    intel_path = data_db_dir / "gen-1" / "intel.db"
    conn = sqlite3.connect(intel_path)
    ja3_value = "a" * 32
    conn.execute(
        "INSERT INTO ioc (ioc_id, type, value, first_seen, last_seen, agg_raw_confidence) "
        "VALUES (9, 'ja3', ?, '2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 90.0)",
        (ja3_value,),
    )
    conn.execute(
        "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
        "intel_generation) VALUES (9, 'urlhaus', 85, '2026-06-01T00:00:00Z', "
        "'2026-07-02T00:00:00Z', 1)"
    )
    conn.commit()
    conn.close()

    resp = client.post("/v1/ja3/search", json={"value": ja3_value}, headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["match"] is True
    assert body["confidence_basis"] == "type_cap"


def test_invalid_value_returns_422(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post(
        "/v1/ioc/search", json={"type": "ip", "value": "not-an-ip"}, headers=auth_header(token)
    )
    assert resp.status_code == 422


def test_ja4_search_endpoint(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post("/v1/ja4/search", json={"value": "t13d1516h2_abc"}, headers=auth_header(token))
    assert resp.status_code == 200
    assert resp.json()["match"] is False
