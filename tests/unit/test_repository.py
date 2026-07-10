from __future__ import annotations

import os
import sqlite3

from azazel_knowledge.db import generations
from azazel_knowledge.db.repository import Repository, apply_migrations, entity_key


def _make_local_db(path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    conn.close()


def _make_intel_generation(data_db_dir, n: int, *, seed_value: str = "1.2.3.4") -> None:
    intel_path = generations.build_next_generation(data_db_dir)
    assert intel_path == generations.intel_db_path(data_db_dir, n)
    conn = sqlite3.connect(intel_path)
    apply_migrations(conn, "intel")
    conn.execute(
        "INSERT INTO ioc (type, value, first_seen, last_seen, agg_raw_confidence, "
        "agg_next_expiry, agg_computed_at) VALUES "
        "('ip', ?, '2026-07-01T00:00:00Z', '2026-07-05T00:00:00Z', 72.5, "
        "'2026-08-01T00:00:00Z', '2026-07-05T00:00:00Z')",
        (seed_value,),
    )
    conn.execute(
        "INSERT INTO ioc_cidr (tier, range_start, range_end, ioc_id, feed_id, expires_at) "
        "VALUES ('/24', 16909056, 16909311, 1, 'urlhaus', NULL)"
    )
    conn.execute(
        "INSERT INTO kev (cve_id, catalog_version, date_added) VALUES "
        "('CVE-2024-0001', 'v1', '2026-01-01')"
    )
    conn.commit()
    conn.close()
    generations.swap_current(data_db_dir, n)


def test_entity_key_is_stable_and_distinguishes_inputs():
    a = entity_key("ip", "1.2.3.4")
    b = entity_key("ip", "1.2.3.4")
    c = entity_key("ip", "1.2.3.5")
    d = entity_key("domain", "1.2.3.4")
    assert a == b
    assert len(a) == 16
    assert a != c
    assert a != d


def test_entity_key_normalizes_case_and_whitespace():
    a = entity_key("ip", " 1.2.3.4 ")
    b = entity_key("IP", "1.2.3.4")
    assert a == b


def test_repository_reads_ioc_and_cidr_and_kev(tmp_path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    _make_intel_generation(data_db_dir, 1)

    repo = Repository(local_db_path, data_db_dir, pool_size=2)
    try:
        with repo.connection() as conn:
            row = repo.get_ioc(conn, "ip", "1.2.3.4")
            assert row is not None
            assert row["agg_raw_confidence"] == 72.5

            cidr_row = repo.find_cidr_containing(conn, "/24", 16909200)
            assert cidr_row is not None
            assert cidr_row["feed_id"] == "urlhaus"

            missing = repo.find_cidr_containing(conn, "/24", 999)
            assert missing is None

            kev_rows = repo.get_kev(conn, ["CVE-2024-0001", "CVE-9999-9999"])
            assert len(kev_rows) == 1
            assert kev_rows[0]["cve_id"] == "CVE-2024-0001"

            assert repo.get_kev(conn, []) == []
    finally:
        repo.close()


def test_repository_reads_local_only_tables(tmp_path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    _make_intel_generation(data_db_dir, 1)

    conn = sqlite3.connect(local_db_path)
    key = entity_key("ip", "1.2.3.4")
    conn.execute(
        "INSERT INTO reputation (entity_key, score, contributing_sources, updated_at) "
        "VALUES (?, 55.0, '[]', '2026-07-06T00:00:00Z')",
        (key,),
    )
    conn.execute(
        "INSERT INTO observation_stats (entity_key, window_start, window_end, "
        "event_count, trend, stats_generation, updated_at) VALUES "
        "(?, '2026-07-05T00:00:00Z', '2026-07-06T00:00:00Z', 4, 0.1, 1, "
        "'2026-07-06T00:00:00Z')",
        (key,),
    )
    conn.commit()
    conn.close()

    repo = Repository(local_db_path, data_db_dir, pool_size=1)
    try:
        with repo.connection() as conn:
            rep = repo.get_reputation(conn, key)
            assert rep is not None
            assert rep["score"] == 55.0

            stats = repo.get_observation_stats(conn, key)
            assert len(stats) == 1
            assert stats[0]["event_count"] == 4
    finally:
        repo.close()


def test_repository_recycles_connection_after_generation_swap(tmp_path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    _make_intel_generation(data_db_dir, 1, seed_value="10.0.0.1")

    repo = Repository(local_db_path, data_db_dir, pool_size=1)
    try:
        with repo.connection() as conn:
            assert repo.get_ioc(conn, "ip", "10.0.0.1") is not None
            assert repo.get_ioc(conn, "ip", "10.0.0.2") is None

        _make_intel_generation(data_db_dir, 2, seed_value="10.0.0.2")
        assert os.readlink(data_db_dir / "current") == "gen-2"

        with repo.connection() as conn:
            assert repo.get_ioc(conn, "ip", "10.0.0.2") is not None
            assert repo.get_ioc(conn, "ip", "10.0.0.1") is None
    finally:
        repo.close()
