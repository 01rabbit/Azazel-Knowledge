from __future__ import annotations

import sqlite3

import pytest

from azazel_knowledge.db.repository import apply_migrations

INTEL_TABLES = {
    "ioc",
    "ioc_source",
    "ioc_cidr",
    "kev",
    "attack_technique",
    "attack_mitigation",
    "attack_relation",
    "engage_activity",
    "engage_attack_map",
    "sigma_rule_corpus",
    "yara_rule_corpus",
    "feed_state",
    "_stage_ioc",
    "_stage_ioc_source",
    "stats_meta",
}

LOCAL_TABLES = {
    "reaction",
    "reaction_trust_event",
    "advisory_log",
    "observation",
    "observation_stats",
    "reputation",
    "edge_reported_ioc",
    "pattern",
    "pattern_index",
    "rule_draft",
    "bundle_state",
    "api_client",
    "feed_quarantine",
    "local_meta",
    "behavior_pattern",
    "behavior_pattern_evidence",
    "behavior_pattern_similarity",
    "behavior_meta",
    "deception_observation",
    "outcome_execution_v0",
    "outcome_mechanism_v0",
    "outcome_observation_v0",
    "outcome_effect_assessment_v0",
}


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {r[0] for r in rows}


def test_intel_migrations_apply_cleanly(tmp_path):
    conn = sqlite3.connect(tmp_path / "intel.db")
    applied = apply_migrations(conn, "intel")
    assert applied == ["0001_init", "0002_engage", "0003_rule_corpus"]
    tables = _table_names(conn)
    assert INTEL_TABLES <= tables
    assert "schema_migrations" in tables


def test_intel_migrations_idempotent(tmp_path):
    conn = sqlite3.connect(tmp_path / "intel.db")
    apply_migrations(conn, "intel")
    assert apply_migrations(conn, "intel") == []


def test_local_migrations_apply_cleanly(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    applied = apply_migrations(conn, "local")
    assert applied == [
        "0001_init",
        "0002_behavior",
        "0003_reaction_ext",
        "0004_deception_observation",
        "0005_outcome_evidence_v0",
    ]
    tables = _table_names(conn)
    assert LOCAL_TABLES <= tables


def test_local_migrations_idempotent(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    assert apply_migrations(conn, "local") == []


def _insert_reaction(conn: sqlite3.Connection) -> int:
    conn.execute(
        """
        INSERT INTO reaction (
            edge_id, actor_key, action_applied, applied_at, reaction,
            reaction_window_s, events_in_window, classifier, classifier_version,
            evidence_refs, evidence_modality_count, trust_tier, advisory_id,
            advisory_linkage, created_at
        ) VALUES (
            'edge-1', 'actor-1', 'throttle', '2026-07-06T00:00:00.000Z', 'shifted_port',
            60, 3, 'ladder-v1', '1', '[]', 1, 'provisional', NULL, 'none',
            '2026-07-06T00:00:00.000Z'
        )
        """
    )
    conn.commit()
    return conn.execute("SELECT reaction_id FROM reaction").fetchone()[0]


def test_reaction_is_immutable_on_update(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    reaction_id = _insert_reaction(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE reaction SET events_in_window = 99 WHERE reaction_id = ?",
            (reaction_id,),
        )


def test_reaction_is_immutable_on_delete(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    reaction_id = _insert_reaction(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM reaction WHERE reaction_id = ?", (reaction_id,))


def test_reaction_trust_event_is_immutable(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    reaction_id = _insert_reaction(conn)
    conn.execute(
        "INSERT INTO reaction_trust_event "
        "(reaction_id, edge_id, actor_key, event_type, detail, created_at) "
        "VALUES (?, 'edge-1', 'actor-1', 'corroborated', NULL, '2026-07-06T00:00:00.000Z')",
        (reaction_id,),
    )
    conn.commit()
    event_id = conn.execute("SELECT event_id FROM reaction_trust_event").fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE reaction_trust_event SET event_type = 'other' WHERE event_id = ?",
            (event_id,),
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM reaction_trust_event WHERE event_id = ?", (event_id,))


def test_advisory_log_roundtrip(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    conn.execute(
        """
        INSERT INTO advisory_log (
            advisory_id, event_id, actor_key, edge_id, content_hash,
            intel_generation, local_generation, stats_generation, attack_version,
            config_hash, created_at
        ) VALUES (
            'adv-1', 'evt-1', 'actor-1', 'edge-1', 'hash-1',
            1, 1, 1, '15.1', 'confhash-1', '2026-07-06T00:00:00.000Z'
        )
        """
    )
    conn.commit()
    row = conn.execute(
        "SELECT advisory_id, event_id, content_hash FROM advisory_log WHERE advisory_id = ?",
        ("adv-1",),
    ).fetchone()
    assert row == ("adv-1", "evt-1", "hash-1")


def test_unknown_migrations_dir_yields_no_migrations(tmp_path):
    conn = sqlite3.connect(tmp_path / "other.db")
    assert apply_migrations(conn, "does-not-exist") == []