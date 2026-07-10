from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from azazel_grimoire.db.repository import apply_migrations
from azazel_grimoire.reactions import classifier, linkage

NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)


def _make_conn(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    return conn


def _insert_advisory_log(conn, advisory_id: str, *, actor_key: str, edge_id: str, created_at: str) -> None:
    conn.execute(
        "INSERT INTO advisory_log (advisory_id, event_id, actor_key, edge_id, content_hash, "
        "intel_generation, local_generation, stats_generation, attack_version, config_hash, "
        "created_at) VALUES (?, NULL, ?, ?, 'hash', 1, 1, 1, '15.1', 'cfg', ?)",
        (advisory_id, actor_key, edge_id, created_at),
    )
    conn.commit()


def _validated_reaction(**overrides) -> dict:
    base = {
        "edge_id": "edge-1",
        "actor_key": "203.0.113.9",
        "action_applied": "throttle",
        "applied_at": "2026-07-06T11:00:00Z",
        "reaction": "continued_scanning",
        "reaction_window_s": 120,
        "evidence_refs": ["ev-1"],
        "advisory_id": None,
    }
    base.update(overrides)
    return base


def test_initial_linkage_state_echoed_pending_when_advisory_id_present(tmp_path):
    conn = _make_conn(tmp_path)
    reaction_id = classifier.ingest_reaction(
        conn, _validated_reaction(advisory_id="adv-1"), now=NOW
    )
    conn.commit()
    column = conn.execute(
        "SELECT advisory_linkage FROM reaction WHERE reaction_id = ?", (reaction_id,)
    ).fetchone()[0]
    assert column == "echoed_pending"


def test_initial_linkage_state_temporal_when_advisory_log_matches_by_time_and_actor(tmp_path):
    conn = _make_conn(tmp_path)
    _insert_advisory_log(
        conn, "adv-unrelated", actor_key="203.0.113.9", edge_id="edge-1",
        created_at="2026-07-06T11:10:00Z",
    )
    reaction_id = classifier.ingest_reaction(conn, _validated_reaction(), now=NOW)
    conn.commit()
    column = conn.execute(
        "SELECT advisory_linkage FROM reaction WHERE reaction_id = ?", (reaction_id,)
    ).fetchone()[0]
    assert column == "temporal"


def test_initial_linkage_state_none_when_no_advisory_id_and_no_temporal_match(tmp_path):
    conn = _make_conn(tmp_path)
    reaction_id = classifier.ingest_reaction(conn, _validated_reaction(), now=NOW)
    conn.commit()
    column = conn.execute(
        "SELECT advisory_linkage FROM reaction WHERE reaction_id = ?", (reaction_id,)
    ).fetchone()[0]
    assert column == "none"


def test_resolve_pending_upgrades_to_echoed_resolved_when_advisory_log_lands_late(tmp_path):
    conn = _make_conn(tmp_path)
    reaction_id = classifier.ingest_reaction(
        conn, _validated_reaction(advisory_id="adv-1"), now=NOW
    )
    conn.commit()

    # advisory_log row is still missing: nothing to resolve yet.
    resolved = linkage.resolve_pending(conn, NOW + timedelta(minutes=1))
    conn.commit()
    assert resolved == 0
    assert linkage.linkage_state(conn, reaction_id) == "echoed_pending"

    # advisory_log lands late.
    _insert_advisory_log(
        conn, "adv-1", actor_key="203.0.113.9", edge_id="edge-1",
        created_at="2026-07-06T12:30:00Z",
    )
    resolved = linkage.resolve_pending(conn, NOW + timedelta(hours=1))
    conn.commit()
    assert resolved == 1
    assert linkage.linkage_state(conn, reaction_id) == "echoed_resolved"

    # Idempotent: a second resolve pass finds nothing left pending.
    assert linkage.resolve_pending(conn, NOW + timedelta(hours=2)) == 0


def test_resolve_pending_marks_echoed_unresolved_after_24h(tmp_path):
    conn = _make_conn(tmp_path)
    reaction_id = classifier.ingest_reaction(
        conn, _validated_reaction(advisory_id="adv-1"), now=NOW
    )
    conn.commit()

    just_under = linkage.resolve_pending(conn, NOW + timedelta(hours=23, minutes=59))
    conn.commit()
    assert just_under == 0
    assert linkage.linkage_state(conn, reaction_id) == "echoed_pending"

    resolved = linkage.resolve_pending(conn, NOW + timedelta(hours=24))
    conn.commit()
    assert resolved == 1
    assert linkage.linkage_state(conn, reaction_id) == "echoed_unresolved"


def test_linkage_state_falls_back_to_frozen_column_without_events(tmp_path):
    conn = _make_conn(tmp_path)
    reaction_id = classifier.ingest_reaction(conn, _validated_reaction(), now=NOW)
    conn.commit()
    assert linkage.linkage_state(conn, reaction_id) == "none"


def test_ambiguous_linkage_rate_counts_pending_unresolved_and_temporal(tmp_path):
    conn = _make_conn(tmp_path)
    resolved_reaction = classifier.ingest_reaction(
        conn, _validated_reaction(advisory_id="adv-resolved", actor_key="a1"), now=NOW
    )
    conn.commit()
    _insert_advisory_log(
        conn, "adv-resolved", actor_key="a1", edge_id="edge-1",
        created_at="2026-07-06T12:05:00Z",
    )
    linkage.resolve_pending(conn, NOW + timedelta(minutes=10))
    conn.commit()

    classifier.ingest_reaction(
        conn, _validated_reaction(advisory_id="adv-pending", actor_key="a2"), now=NOW
    )
    conn.commit()

    rate = linkage.ambiguous_linkage_rate(conn)
    assert rate == 0.5
