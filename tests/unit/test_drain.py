from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from azazel_cti.core.clock import FixedClock
from azazel_cti.db.repository import apply_migrations
from azazel_cti.db.writer import PrioritySingleWriterQueue
from azazel_cti.ingest.burst_guard import BurstGuard
from azazel_cti.ingest.drain import drain_endpoint
from azazel_cti.ingest.spool import SpoolWriter

NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)


def _make_writer(tmp_path) -> PrioritySingleWriterQueue:
    db_path = tmp_path / "local.db"
    conn = sqlite3.connect(db_path)
    apply_migrations(conn, "local")
    conn.close()
    writer = PrioritySingleWriterQueue(db_path, tmp_path / "writer.lock")
    writer.open()
    return writer


def test_drain_events_inserts_observations_and_quarantines_bad_lines(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        good = json.dumps(
            {
                "event_id": "ev-1", "edge_id": "edge-1", "kind": "eve_alert",
                "observed_at": "2026-07-06T11:00:00Z", "src_ip": "203.0.113.7",
            }
        )
        bad = "{not json"
        batch_id = spool.write_batch("events", "client-1", [good, bad])

        stats = drain_endpoint("events", spool, writer, clock=FixedClock(NOW))
        assert stats.batches_drained == 1
        assert stats.lines_valid == 1
        assert stats.lines_invalid == 1

        rows = writer._conn.execute("SELECT event_id, edge_id FROM observation").fetchall()
        assert rows == [("ev-1", "edge-1")]

        status = spool.read_status(batch_id)
        assert status is not None
        assert status.drained is True
        assert status.valid == 1
        assert status.invalid[0]["line_no"] == 2

        pending = spool.pending_batches("events")
        assert pending == []
    finally:
        writer.close()


def test_drain_is_idempotent_across_replay(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        line = json.dumps(
            {
                "event_id": "ev-1", "edge_id": "edge-1", "kind": "dns",
                "observed_at": "2026-07-06T11:00:00Z",
            }
        )
        spool.write_batch("events", "client-1", [line])
        drain_endpoint("events", spool, writer, clock=FixedClock(NOW))

        # Simulate a crash-replay: reset the drained marker and re-drain the
        # same underlying jsonl file with a fresh SpoolWriter-visible batch.
        count_after_first = writer._conn.execute(
            "SELECT COUNT(*) FROM observation"
        ).fetchone()[0]
        assert count_after_first == 1

        second_stats = drain_endpoint("events", spool, writer, clock=FixedClock(NOW))
        assert second_stats.batches_drained == 0

        count_after_second = writer._conn.execute(
            "SELECT COUNT(*) FROM observation"
        ).fetchone()[0]
        assert count_after_second == 1
    finally:
        writer.close()


def test_drain_dedupes_duplicate_event_id_within_and_across_batches(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        line = json.dumps(
            {
                "event_id": "ev-1", "edge_id": "edge-1", "kind": "dns",
                "observed_at": "2026-07-06T11:00:00Z",
            }
        )
        # Same event_id/edge_id repeated within a single batch.
        spool.write_batch("events", "client-1", [line, line])
        stats = drain_endpoint("events", spool, writer, clock=FixedClock(NOW))
        assert stats.duplicates_skipped == 1

        count = writer._conn.execute("SELECT COUNT(*) FROM observation").fetchone()[0]
        assert count == 1
    finally:
        writer.close()


def test_drain_bumps_stats_generation_on_aggregation(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        def _meta_gen() -> int:
            row = writer._conn.execute(
                "SELECT value FROM local_meta WHERE key = 'stats_generation'"
            ).fetchone()
            return int(row[0]) if row else 0

        assert _meta_gen() == 0

        line = json.dumps(
            {
                "event_id": "ev-1", "edge_id": "edge-1", "kind": "eve_alert",
                "observed_at": "2026-07-06T11:00:00Z", "src_ip": "203.0.113.7",
            }
        )
        spool.write_batch("events", "client-1", [line])
        drain_endpoint("events", spool, writer, clock=FixedClock(NOW))
        first_gen = _meta_gen()
        assert first_gen >= 1

        line2 = json.dumps(
            {
                "event_id": "ev-2", "edge_id": "edge-1", "kind": "eve_alert",
                "observed_at": "2026-07-06T11:05:00Z", "src_ip": "203.0.113.8",
            }
        )
        spool.write_batch("events", "client-1", [line2])
        drain_endpoint("events", spool, writer, clock=FixedClock(NOW))
        assert _meta_gen() > first_gen
    finally:
        writer.close()


def test_drain_marks_over_cap_events_excluded_from_stats(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    guard = BurstGuard(cap=2, window_s=3600.0)
    try:
        lines = [
            json.dumps(
                {
                    "event_id": f"ev-{i}", "edge_id": "edge-1", "kind": "eve_alert",
                    "observed_at": "2026-07-06T11:00:00Z", "src_ip": "203.0.113.7",
                }
            )
            for i in range(4)
        ]
        spool.write_batch("events", "client-1", lines)
        drain_endpoint("events", spool, writer, clock=FixedClock(NOW), burst_guard=guard)

        rows = writer._conn.execute(
            "SELECT entities FROM observation ORDER BY event_id"
        ).fetchall()
        excluded_flags = [json.loads(r[0])["excluded_from_stats"] for r in rows]
        assert excluded_flags == [False, False, True, True]
    finally:
        writer.close()


def test_drain_reactions_endpoint_inserts_immutable_rows(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        line = json.dumps(
            {
                "edge_id": "edge-1", "actor_key": "203.0.113.9",
                "action_applied": "throttle", "applied_at": "2026-07-06T11:00:00Z",
                "reaction": "continued_scanning", "reaction_window_s": 120,
                "evidence_refs": ["ev-1"],
            }
        )
        spool.write_batch("reactions", "client-1", [line])
        stats = drain_endpoint("reactions", spool, writer, clock=FixedClock(NOW))
        assert stats.lines_valid == 1

        rows = writer._conn.execute(
            "SELECT edge_id, actor_key, reaction FROM reaction"
        ).fetchall()
        assert rows == [("edge-1", "203.0.113.9", "continued_scanning")]
    finally:
        writer.close()
