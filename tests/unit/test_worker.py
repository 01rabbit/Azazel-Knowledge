from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.core.config import TrackedConfigLoader
from azazel_knowledge.db.repository import apply_migrations
from azazel_knowledge.db.writer import PrioritySingleWriterQueue
from azazel_knowledge.db import generations
from azazel_knowledge.ingest.spool import SpoolWriter
from azazel_knowledge import worker

NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)


def _config_dir():
    from pathlib import Path

    return Path(__file__).resolve().parents[2] / "config"


def _make_paths(tmp_path) -> worker.WorkerPaths:
    return worker.WorkerPaths.from_root(tmp_path, config_dir=_config_dir())


def _open_writers(paths: worker.WorkerPaths) -> tuple[PrioritySingleWriterQueue, PrioritySingleWriterQueue]:
    paths.ensure_dirs()
    worker.ensure_local_db(paths.local_db_path)
    intel_db_path = worker.current_intel_db_path(paths.data_db_dir)
    local_writer = PrioritySingleWriterQueue(paths.local_db_path, paths.local_lock_path)
    local_writer.open()
    intel_writer = PrioritySingleWriterQueue(intel_db_path, paths.intel_lock_path)
    intel_writer.open()
    return local_writer, intel_writer


def _seed_advisory_line(paths: worker.WorkerPaths, *, advisory_id: str) -> None:
    spool = SpoolWriter(paths.ingest_root)
    line = json.dumps(
        {
            "advisory_id": advisory_id,
            "event_id": "ev-1",
            "actor_key": "203.0.113.9",
            "edge_id": "edge-1",
            "content_hash": "deadbeef",
            "intel_generation": 1,
            "local_generation": 1,
            "stats_generation": 1,
            "attack_version": "16.1",
            "config_hash": "cfg-hash",
            "created_at": "2026-07-06T11:59:00Z",
        }
    )
    spool.write_batch("advisory", "api-proc", [line])


def _seed_echoed_pending_reaction(local_db_path, *, advisory_id: str) -> None:
    conn = sqlite3.connect(local_db_path)
    try:
        conn.execute(
            "INSERT INTO reaction (edge_id, actor_key, action_applied, applied_at, reaction, "
            "reaction_window_s, classifier, classifier_version, advisory_id, advisory_linkage, "
            "created_at) VALUES ('edge-1', '203.0.113.9', 'throttle', '2026-07-06T11:58:00Z', "
            "'continued_scanning', 120, 'c', '1', ?, 'echoed_pending', '2026-07-06T11:58:05Z')",
            (advisory_id,),
        )
        conn.commit()
    finally:
        conn.close()


def test_run_once_drains_advisory_spool_and_resolves_linkage(tmp_path):
    paths = _make_paths(tmp_path)
    local_writer, intel_writer = _open_writers(paths)
    config_loader = TrackedConfigLoader(paths.config_dir)
    try:
        advisory_id = "01ADV0000000000000000001"
        _seed_advisory_line(paths, advisory_id=advisory_id)
        _seed_echoed_pending_reaction(paths.local_db_path, advisory_id=advisory_id)

        stats = worker.run_once(
            paths, local_writer, intel_writer, config_loader,
            clock=FixedClock(NOW), online=False,
        )

        assert stats.p0["advisory_lines_valid"] == 1
        assert stats.p0["linkage_resolved"] == 1

        row = local_writer._conn.execute(
            "SELECT advisory_id, event_id FROM advisory_log WHERE advisory_id = ?", (advisory_id,)
        ).fetchone()
        assert row == (advisory_id, "ev-1")

        from azazel_knowledge.reactions import linkage

        reaction_id = local_writer._conn.execute(
            "SELECT reaction_id FROM reaction WHERE advisory_id = ?", (advisory_id,)
        ).fetchone()[0]
        assert linkage.linkage_state(local_writer._conn, reaction_id) == "echoed_resolved"

        spool = SpoolWriter(paths.ingest_root)
        assert spool.pending_batches("advisory") == []
    finally:
        local_writer.close()
        intel_writer.close()


def test_run_once_is_idempotent_on_replay(tmp_path):
    paths = _make_paths(tmp_path)
    local_writer, intel_writer = _open_writers(paths)
    config_loader = TrackedConfigLoader(paths.config_dir)
    try:
        advisory_id = "01ADV0000000000000000002"
        _seed_advisory_line(paths, advisory_id=advisory_id)

        worker.run_once(paths, local_writer, intel_writer, config_loader, clock=FixedClock(NOW))
        count_after_first = local_writer._conn.execute(
            "SELECT COUNT(*) FROM advisory_log"
        ).fetchone()[0]
        assert count_after_first == 1

        second = worker.run_once(paths, local_writer, intel_writer, config_loader, clock=FixedClock(NOW))
        assert second.p0["advisory_batches_drained"] == 0
        count_after_second = local_writer._conn.execute(
            "SELECT COUNT(*) FROM advisory_log"
        ).fetchone()[0]
        assert count_after_second == 1
    finally:
        local_writer.close()
        intel_writer.close()


def test_p0_runs_before_p2_in_single_cycle(tmp_path):
    paths = _make_paths(tmp_path)
    local_writer, intel_writer = _open_writers(paths)
    config_loader = TrackedConfigLoader(paths.config_dir)
    try:
        order: list[str] = []
        worker.run_once(
            paths, local_writer, intel_writer, config_loader,
            clock=FixedClock(NOW), stage_hook=order.append,
        )
        assert order == ["p0", "p1", "p2", "p3"]
    finally:
        local_writer.close()
        intel_writer.close()


def test_run_once_drains_event_spool_at_p1(tmp_path):
    paths = _make_paths(tmp_path)
    local_writer, intel_writer = _open_writers(paths)
    config_loader = TrackedConfigLoader(paths.config_dir)
    try:
        spool = SpoolWriter(paths.ingest_root)
        line = json.dumps(
            {
                "event_id": "ev-9", "edge_id": "edge-9", "kind": "dns",
                "observed_at": "2026-07-06T11:00:00Z",
            }
        )
        spool.write_batch("events", "client-1", [line])

        stats = worker.run_once(paths, local_writer, intel_writer, config_loader, clock=FixedClock(NOW))
        assert stats.p1["events"]["lines_valid"] == 1

        rows = local_writer._conn.execute("SELECT event_id FROM observation").fetchall()
        assert rows == [("ev-9",)]
    finally:
        local_writer.close()
        intel_writer.close()


def test_run_p3_prunes_old_advisory_log_rows_without_reaction_reference(tmp_path):
    paths = _make_paths(tmp_path)
    local_writer, intel_writer = _open_writers(paths)
    try:
        local_writer._conn.execute(
            "INSERT INTO advisory_log (advisory_id, event_id, actor_key, edge_id, content_hash, "
            "intel_generation, local_generation, stats_generation, attack_version, config_hash, "
            "created_at) VALUES ('old-1', 'ev-1', 'a', 'e', 'h', 1, 1, 1, 'v', 'c', "
            "'2020-01-01T00:00:00Z')"
        )
        local_writer._conn.commit()

        stats = worker.run_p3(paths, local_writer, clock=FixedClock(NOW))
        assert stats["advisory_pruned"] == 1
        remaining = local_writer._conn.execute("SELECT COUNT(*) FROM advisory_log").fetchone()[0]
        assert remaining == 0
    finally:
        local_writer.close()
        intel_writer.close()


def test_run_p3_keeps_advisory_log_rows_referenced_by_a_reaction(tmp_path):
    paths = _make_paths(tmp_path)
    local_writer, intel_writer = _open_writers(paths)
    try:
        local_writer._conn.execute(
            "INSERT INTO advisory_log (advisory_id, event_id, actor_key, edge_id, content_hash, "
            "intel_generation, local_generation, stats_generation, attack_version, config_hash, "
            "created_at) VALUES ('old-2', 'ev-1', 'a', 'e', 'h', 1, 1, 1, 'v', 'c', "
            "'2020-01-01T00:00:00Z')"
        )
        local_writer._conn.execute(
            "INSERT INTO reaction (edge_id, actor_key, action_applied, applied_at, reaction, "
            "reaction_window_s, classifier, classifier_version, advisory_id, advisory_linkage, "
            "created_at) VALUES ('e', 'a', 'throttle', '2020-01-01T00:00:00Z', 'disengaged', 60, "
            "'c', '1', 'old-2', 'echoed_resolved', '2020-01-01T00:00:00Z')"
        )
        local_writer._conn.commit()

        stats = worker.run_p3(paths, local_writer, clock=FixedClock(NOW))
        assert stats["advisory_pruned"] == 0
        remaining = local_writer._conn.execute("SELECT COUNT(*) FROM advisory_log").fetchone()[0]
        assert remaining == 1
    finally:
        local_writer.close()
        intel_writer.close()


def test_run_once_with_online_false_never_calls_feed_endpoints(tmp_path, monkeypatch):
    paths = _make_paths(tmp_path)
    local_writer, intel_writer = _open_writers(paths)
    config_loader = TrackedConfigLoader(paths.config_dir)

    def _boom(*args, **kwargs):
        raise AssertionError("should not be called when online=False")

    monkeypatch.setattr(worker, "run_scheduled_feed_pulls", _boom)
    try:
        stats = worker.run_once(paths, local_writer, intel_writer, config_loader, clock=FixedClock(NOW), online=False)
        assert stats.p2["feeds"] == []
    finally:
        local_writer.close()
        intel_writer.close()


# --- drain cadence is separate from maintenance cadence ---------------------


def test_a_drain_pass_runs_no_feed_pull_or_retention(tmp_path):
    """The drains must be cheap enough to run often, which means running only
    the drains.

    P0/P1 read whatever is pending and stop; P2 talks to the internet and P3
    walks the spool. Lowering one cadence for ingest latency must not multiply
    the other work -- on a Pi 4 that is the difference between a better default
    and a worse node.
    """
    paths = _make_paths(tmp_path)
    local_writer, intel_writer = _open_writers(paths)
    try:
        order: list[str] = []
        worker.run_drain_stages(
            paths, local_writer, clock=FixedClock(NOW), stage_hook=order.append
        )
        assert order == ["p0", "p1"]
    finally:
        local_writer.close()
        intel_writer.close()


def test_a_full_cycle_still_runs_every_stage_in_order(tmp_path):
    """Splitting the stages must not change what `--once` and azctl do."""
    paths = _make_paths(tmp_path)
    local_writer, intel_writer = _open_writers(paths)
    config_loader = TrackedConfigLoader(paths.config_dir)
    try:
        order: list[str] = []
        worker.run_once(
            paths, local_writer, intel_writer, config_loader,
            clock=FixedClock(NOW), stage_hook=order.append,
        )
        assert order == ["p0", "p1", "p2", "p3"]
    finally:
        local_writer.close()
        intel_writer.close()


def test_maintenance_runs_on_the_first_pass_then_waits_its_interval():
    """Never having run is not the same as having just run.

    Treating an unset last-run as "recent" would delay the first feed pull and
    the first retention sweep by a whole interval after every restart.
    """
    assert worker.maintenance_is_due(100.0, None, 5.0) is True
    assert worker.maintenance_is_due(101.0, 100.0, 5.0) is False
    assert worker.maintenance_is_due(104.999, 100.0, 5.0) is False
    assert worker.maintenance_is_due(105.0, 100.0, 5.0) is True


def test_equal_cadences_reproduce_the_single_loop_behaviour():
    """Setting the drain interval to the maintenance interval must give back
    exactly what earlier versions did, so an operator can undo this change
    without a patch. A non-positive interval means every pass, not never."""
    assert worker.maintenance_is_due(100.0, 100.0, 0.0) is True
    assert worker.maintenance_is_due(100.0, 100.0, -1.0) is True
