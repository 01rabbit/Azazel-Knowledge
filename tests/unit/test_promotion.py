from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from azazel_grimoire.core.clock import to_rfc3339
from azazel_grimoire.db.repository import entity_key
from azazel_grimoire.feeds.promotion import PromotionEngine, PromotionReason, PromotionResult

from _feeds_support import make_intel_writer, make_local_writer

NOW = datetime(2026, 7, 6, 0, 0, 0, tzinfo=timezone.utc)
FEED_GROUPS = {
    "urlhaus": "abusech",
    "malwarebazaar": "abusech",
    "threatfox": "abusech",
    "edge_reported": "edge_reported",
}


def _exec(writer, fn) -> Any:
    box: dict[str, Any] = {}

    def wrapper(conn: Any) -> None:
        box["value"] = fn(conn)

    writer.submit(2, wrapper)
    writer.process_pending()
    return box.get("value")


def _make_engine(tmp_path) -> PromotionEngine:
    intel = make_intel_writer(tmp_path)
    local = make_local_writer(tmp_path)
    return PromotionEngine(intel, local, feed_groups=FEED_GROUPS)


def _seed_edge_report(engine: PromotionEngine, type_: str, value: str, edge_id: str, reported_at: datetime) -> None:
    key = entity_key(type_, value)

    def txn(conn: Any) -> None:
        conn.execute(
            "INSERT INTO edge_reported_ioc (entity_key, type, value, edge_id, first_reported, "
            "report_count, status) VALUES (?, ?, ?, ?, ?, 1, 'quarantined')",
            (key, type_, value, edge_id, to_rfc3339(reported_at)),
        )

    _exec(engine.local_writer, txn)


def _seed_external_source(engine: PromotionEngine, type_: str, value: str, feed_id: str) -> None:
    def txn(conn: Any) -> None:
        conn.execute(
            "INSERT INTO ioc (type, value, first_seen, last_seen) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(type, value) DO NOTHING",
            (type_, value, to_rfc3339(NOW), to_rfc3339(NOW)),
        )
        ioc_id = conn.execute(
            "SELECT ioc_id FROM ioc WHERE type = ? AND value = ?", (type_, value)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
            "expires_at, intel_generation) VALUES (?, ?, 85, ?, ?, NULL, 0)",
            (ioc_id, feed_id, to_rfc3339(NOW), to_rfc3339(NOW)),
        )

    _exec(engine.intel_writer, txn)


def _statuses(engine: PromotionEngine, type_: str, value: str) -> set[str]:
    key = entity_key(type_, value)

    def query(conn: Any):
        return {
            row[0]
            for row in conn.execute(
                "SELECT status FROM edge_reported_ioc WHERE entity_key = ?", (key,)
            ).fetchall()
        }

    return _exec(engine.local_writer, query)


def _edge_reported_source(engine: PromotionEngine, type_: str, value: str) -> tuple | None:
    def query(conn: Any):
        return conn.execute(
            "SELECT s.feed_id, s.source_confidence FROM ioc_source s "
            "JOIN ioc i ON i.ioc_id = s.ioc_id WHERE i.type = ? AND i.value = ? "
            "AND s.feed_id = 'edge_reported'",
            (type_, value),
        ).fetchone()

    return _exec(engine.intel_writer, query)


def test_three_distinct_edges_within_window_promote(tmp_path):
    engine = _make_engine(tmp_path)
    for edge in ("edge-1", "edge-2", "edge-3"):
        _seed_edge_report(engine, "ip", "203.0.113.50", edge, NOW - timedelta(days=1))

    result = engine.evaluate("ip", "203.0.113.50", NOW)
    assert result.promoted
    assert result.reason is PromotionReason.DISTINCT_EDGES


def test_two_distinct_edges_do_not_promote(tmp_path):
    engine = _make_engine(tmp_path)
    _seed_edge_report(engine, "ip", "203.0.113.51", "edge-1", NOW - timedelta(days=1))
    _seed_edge_report(engine, "ip", "203.0.113.51", "edge-2", NOW - timedelta(days=2))

    result = engine.evaluate("ip", "203.0.113.51", NOW)
    assert not result.promoted


def test_edges_outside_seven_day_window_do_not_count(tmp_path):
    engine = _make_engine(tmp_path)
    _seed_edge_report(engine, "ip", "203.0.113.52", "edge-1", NOW - timedelta(days=1))
    _seed_edge_report(engine, "ip", "203.0.113.52", "edge-2", NOW - timedelta(days=2))
    _seed_edge_report(engine, "ip", "203.0.113.52", "edge-3", NOW - timedelta(days=8))

    result = engine.evaluate("ip", "203.0.113.52", NOW)
    assert not result.promoted


def test_cross_group_corroboration_promotes(tmp_path):
    engine = _make_engine(tmp_path)
    _seed_edge_report(engine, "domain", "bad.example.com", "edge-1", NOW - timedelta(days=1))
    _seed_external_source(engine, "domain", "bad.example.com", "urlhaus")

    result = engine.evaluate("domain", "bad.example.com", NOW)
    assert result.promoted
    assert result.reason is PromotionReason.CROSS_GROUP_CORROBORATION


def test_edge_reported_source_alone_is_not_corroboration(tmp_path):
    engine = _make_engine(tmp_path)
    _seed_edge_report(engine, "domain", "solo.example.com", "edge-1", NOW - timedelta(days=1))
    _seed_external_source(engine, "domain", "solo.example.com", "edge_reported")

    result = engine.evaluate("domain", "solo.example.com", NOW)
    assert not result.promoted


def test_promote_writes_scored_ioc_and_logs_reason(tmp_path):
    engine = _make_engine(tmp_path)
    for edge in ("edge-1", "edge-2", "edge-3"):
        _seed_edge_report(engine, "ip", "203.0.113.60", edge, NOW - timedelta(days=1))

    result = engine.evaluate("ip", "203.0.113.60", NOW)
    engine.promote("ip", "203.0.113.60", NOW, result)

    assert _statuses(engine, "ip", "203.0.113.60") == {"promoted"}
    source = _edge_reported_source(engine, "ip", "203.0.113.60")
    assert source is not None
    assert source[1] == 35

    key = entity_key("ip", "203.0.113.60")

    def read_log(conn: Any):
        return conn.execute(
            "SELECT value FROM local_meta WHERE key LIKE ?", (f"promotion_log:{key.hex()}:%",)
        ).fetchall()

    logs = _exec(engine.local_writer, read_log)
    assert len(logs) == 1
    payload = json.loads(logs[0][0])
    assert payload["status"] == "promoted"
    assert payload["reason"] == "distinct_edges"


def test_analyst_confirm_promotes_without_other_gates(tmp_path):
    engine = _make_engine(tmp_path)
    _seed_edge_report(engine, "ip", "203.0.113.61", "edge-1", NOW - timedelta(days=1))

    result = engine.confirm("ip", "203.0.113.61", "edge-1", "analyst-7", NOW)
    assert result.promoted
    assert result.reason is PromotionReason.ANALYST_CONFIRM
    assert _statuses(engine, "ip", "203.0.113.61") == {"promoted"}
    assert _edge_reported_source(engine, "ip", "203.0.113.61") is not None


def test_promotion_is_revocable(tmp_path):
    engine = _make_engine(tmp_path)
    for edge in ("edge-1", "edge-2", "edge-3"):
        _seed_edge_report(engine, "ip", "203.0.113.62", edge, NOW - timedelta(days=1))

    result = engine.evaluate("ip", "203.0.113.62", NOW)
    engine.promote("ip", "203.0.113.62", NOW, result)
    assert _statuses(engine, "ip", "203.0.113.62") == {"promoted"}

    engine.revoke("ip", "203.0.113.62", NOW + timedelta(hours=1), "false positive")
    assert _statuses(engine, "ip", "203.0.113.62") == {"revoked"}
    assert _edge_reported_source(engine, "ip", "203.0.113.62") is None


def test_promote_with_unsatisfied_gate_raises(tmp_path):
    engine = _make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.promote("ip", "203.0.113.63", NOW, PromotionResult(False))
