from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.db.repository import apply_migrations
from azazel_knowledge.db.writer import PrioritySingleWriterQueue
from azazel_knowledge.ingest.drain import drain_endpoint
from azazel_knowledge.ingest.spool import SpoolWriter
from azazel_knowledge.ingest.validators import validate_reaction_line
from azazel_knowledge.reactions import classifier

NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)


def _make_conn(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    return conn


def _make_writer(tmp_path) -> PrioritySingleWriterQueue:
    db_path = tmp_path / "local.db"
    conn = sqlite3.connect(db_path)
    apply_migrations(conn, "local")
    conn.close()
    writer = PrioritySingleWriterQueue(db_path, tmp_path / "writer.lock")
    writer.open()
    return writer


def _seed_observation(conn: sqlite3.Connection, event_id: str, kind: str = "eve_alert") -> None:
    conn.execute(
        "INSERT INTO observation (event_id, edge_id, kind, observed_at, entity_key, "
        "entities, raw, created_at) VALUES (?, 'edge-pi4-07', ?, '2026-07-08T03:10:00Z', "
        "NULL, '[]', '{}', '2026-07-08T03:10:00Z')",
        (event_id, kind),
    )


def _phase2_payload(**overrides) -> dict:
    payload = {
        "edge_id": "edge-demo-01",
        "actor_key": "ip:203.0.113.7",
        "actor_cluster_key": "optional-session-or-ja3-cluster",
        "action_applied": "delay",
        "action_profile": "aggressive-30s",
        "applied_at": "2026-07-08T01:00:00Z",
        "reaction": "shifted_protocol",
        "reaction_window_s": 60,
        "pre_action_summary": {
            "ports": [22, 80],
            "protocols": ["tcp", "http"],
            "event_count": 12,
        },
        "post_action_summary": {
            "ports": [8080, 2222],
            "protocols": ["http", "ssh"],
            "event_count": 8,
        },
        "decoy_touched": True,
        "decoy_profile": "ssh-canary-profile-2",
        "retry_interval_ms": 1400,
        "timeout_adaptation": "increased",
        "evidence_refs": ["obs-1", "obs-2"],
        "raw_refs": ["edge-audit-1"],
    }
    payload.update(overrides)
    return payload


def test_validate_reaction_line_accepts_phase2_payload():
    ok, result = validate_reaction_line(json.dumps(_phase2_payload()), now=NOW)
    assert ok is True
    assert result["actor_cluster_key"] == "optional-session-or-ja3-cluster"
    assert result["action_profile"] == "aggressive-30s"
    assert result["decoy_touched"] == 1
    assert result["retry_interval_ms"] == 1400
    assert result["payload_ext"] == {
        "pre_action_summary": {
            "ports": [22, 80],
            "protocols": ["tcp", "http"],
            "event_count": 12,
        },
        "post_action_summary": {
            "ports": [8080, 2222],
            "protocols": ["http", "ssh"],
            "event_count": 8,
        },
        "raw_refs": ["edge-audit-1"],
    }


def test_reaction_batch_quarantines_missing_evidence_refs_without_failing_valid_rows(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        good = json.dumps(_phase2_payload())
        bad = json.dumps(
            {
                "edge_id": "edge-demo-01",
                "actor_key": "ip:203.0.113.9",
                "action_applied": "delay",
                "applied_at": "2026-07-08T01:00:00Z",
                "reaction": "shifted_protocol",
                "reaction_window_s": 60,
            }
        )
        batch_id = spool.write_batch("reactions", "client-1", [good, bad])

        stats = drain_endpoint("reactions", spool, writer, clock=FixedClock(NOW))
        assert stats.lines_valid == 1
        assert stats.lines_invalid == 1

        count = writer._conn.execute("SELECT COUNT(*) FROM reaction").fetchone()[0]
        assert count == 1

        status = spool.read_status(batch_id)
        assert status is not None
        assert status.invalid == [{"line_no": 2, "error": "missing field: evidence_refs"}]
    finally:
        writer.close()


def test_ingest_reaction_preserves_unknown_optional_fields_in_payload_ext(tmp_path):
    conn = _make_conn(tmp_path)
    _seed_observation(conn, "obs-1")
    _seed_observation(conn, "obs-2")

    ok, validated = validate_reaction_line(
        json.dumps(_phase2_payload(unexpected_extension={"foo": "bar"})),
        now=NOW,
    )
    assert ok is True

    reaction_id = classifier.ingest_reaction(conn, validated, now=NOW)
    payload_ext = json.loads(
        conn.execute(
            "SELECT payload_ext FROM reaction WHERE reaction_id = ?",
            (reaction_id,),
        ).fetchone()[0]
    )
    assert payload_ext["unexpected_extension"] == {"foo": "bar"}


def test_ingest_reaction_saves_promoted_phase2_columns(tmp_path):
    conn = _make_conn(tmp_path)
    _seed_observation(conn, "obs-1")
    _seed_observation(conn, "obs-2")

    ok, validated = validate_reaction_line(
        json.dumps(_phase2_payload(decoy_touched=True, action_profile="jittered_delay")),
        now=NOW,
    )
    assert ok is True

    reaction_id = classifier.ingest_reaction(conn, validated, now=NOW)
    row = conn.execute(
        "SELECT decoy_touched, action_profile FROM reaction WHERE reaction_id = ?",
        (reaction_id,),
    ).fetchone()
    assert row == (1, "jittered_delay")


def test_reaction_batch_quarantines_invalid_taxonomy_value(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        batch_id = spool.write_batch(
            "reactions",
            "client-1",
            [json.dumps(_phase2_payload(reaction="teleported"))],
        )

        stats = drain_endpoint("reactions", spool, writer, clock=FixedClock(NOW))
        assert stats.lines_valid == 0
        assert stats.lines_invalid == 1
        status = spool.read_status(batch_id)
        assert status is not None
        assert status.invalid[0]["error"] == "unknown reaction: 'teleported'"
    finally:
        writer.close()


def test_ingest_reaction_normalizes_applied_at_to_utc(tmp_path):
    conn = _make_conn(tmp_path)
    _seed_observation(conn, "obs-1")
    _seed_observation(conn, "obs-2")

    ok, validated = validate_reaction_line(
        json.dumps(_phase2_payload(applied_at="2026-07-08T10:00:00+09:00")),
        now=NOW,
    )
    assert ok is True
    assert validated["applied_at"] == "2026-07-08T01:00:00Z"

    reaction_id = classifier.ingest_reaction(conn, validated, now=NOW)
    stored = conn.execute(
        "SELECT applied_at FROM reaction WHERE reaction_id = ?",
        (reaction_id,),
    ).fetchone()[0]
    assert stored == "2026-07-08T01:00:00Z"


def test_phase1_minimal_reaction_record_remains_valid(tmp_path):
    conn = _make_conn(tmp_path)
    _seed_observation(conn, "ev-1")
    minimal = {
        "edge_id": "edge-1",
        "actor_key": "203.0.113.9",
        "action_applied": "throttle",
        "applied_at": "2026-07-06T11:00:00Z",
        "reaction": "continued_scanning",
        "reaction_window_s": 120,
        "evidence_refs": ["ev-1"],
    }

    ok, validated = validate_reaction_line(json.dumps(minimal), now=NOW)
    assert ok is True
    assert validated["payload_ext"] == {}

    reaction_id = classifier.ingest_reaction(conn, validated, now=NOW)
    row = conn.execute(
        "SELECT actor_cluster_key, action_profile, payload_ext FROM reaction WHERE reaction_id = ?",
        (reaction_id,),
    ).fetchone()
    assert row == (None, None, "{}")


def test_local_migration_0003_is_idempotent(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    assert apply_migrations(conn, "local") == [
        "0001_init",
        "0002_behavior",
        "0003_reaction_ext",
        "0004_deception_observation",
        "0005_outcome_evidence_v0",
        "0006_defensive_state_observation",
        "0007_engagement_event",
    ]
    assert apply_migrations(conn, "local") == []