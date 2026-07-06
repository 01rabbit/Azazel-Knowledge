from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from azazel_cti.db.repository import apply_migrations
from azazel_cti.reactions import classifier, eligibility, quarantine

NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)


def _make_conn(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    return conn


def _seed_observation(conn, event_id: str, kind: str) -> None:
    conn.execute(
        "INSERT INTO observation (event_id, edge_id, kind, observed_at, entity_key, "
        "entities, raw, created_at) VALUES (?, 'edge-1', ?, '2026-07-06T11:00:00Z', "
        "NULL, '[]', '{}', '2026-07-06T11:00:00Z')",
        (event_id, kind),
    )


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


def test_ingest_reaction_inserts_row_with_classifier_metadata(tmp_path):
    conn = _make_conn(tmp_path)
    _seed_observation(conn, "ev-1", "eve_alert")
    _seed_observation(conn, "ev-2", "dns")

    validated = _validated_reaction(evidence_refs=["ev-1", "ev-2"])
    reaction_id = classifier.ingest_reaction(conn, validated, now=NOW)
    conn.commit()

    assert reaction_id is not None
    row = conn.execute(
        "SELECT classifier, classifier_version, evidence_modality_count, trust_tier, "
        "advisory_linkage FROM reaction WHERE reaction_id = ?",
        (reaction_id,),
    ).fetchone()
    assert row[0] == classifier.CLASSIFIER_NAME
    assert row[1] == classifier.CLASSIFIER_VERSION
    assert row[2] == 2
    assert row[3] == "provisional"
    assert row[4] == "none"

    events = conn.execute(
        "SELECT event_type FROM reaction_trust_event WHERE reaction_id = ?",
        (reaction_id,),
    ).fetchall()
    assert ("classifier_verdict",) in events


def test_ingest_reaction_replay_is_deduped_via_insert_or_ignore(tmp_path):
    conn = _make_conn(tmp_path)
    validated = _validated_reaction()

    first = classifier.ingest_reaction(conn, validated, now=NOW)
    conn.commit()
    second = classifier.ingest_reaction(conn, validated, now=NOW)
    conn.commit()

    assert first is not None
    assert second is None
    count = conn.execute("SELECT COUNT(*) FROM reaction").fetchone()[0]
    assert count == 1


def test_reaction_rows_are_immutable(tmp_path):
    conn = _make_conn(tmp_path)
    reaction_id = classifier.ingest_reaction(conn, _validated_reaction(), now=NOW)
    conn.commit()

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE reaction SET trust_tier = 'human_confirmed' WHERE reaction_id = ?",
            (reaction_id,),
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM reaction WHERE reaction_id = ?", (reaction_id,))


def test_reaction_trust_event_rows_are_immutable(tmp_path):
    conn = _make_conn(tmp_path)
    reaction_id = classifier.ingest_reaction(conn, _validated_reaction(), now=NOW)
    conn.commit()

    event_id = conn.execute(
        "SELECT event_id FROM reaction_trust_event WHERE reaction_id = ? LIMIT 1",
        (reaction_id,),
    ).fetchone()[0]

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE reaction_trust_event SET detail = '{}' WHERE event_id = ?",
            (event_id,),
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM reaction_trust_event WHERE event_id = ?", (event_id,))


def test_eligibility_tier_defaults_to_provisional(tmp_path):
    reaction = {"edge_id": "edge-1", "evidence_modality_count": 0}
    assert eligibility.recompute_trust_tier(reaction, []) == "provisional"


def test_eligibility_tier_same_edge_corroborated_at_two_modalities(tmp_path):
    reaction = {"edge_id": "edge-1", "evidence_modality_count": 2}
    assert eligibility.recompute_trust_tier(reaction, []) == "same_edge_corroborated"


def test_eligibility_tier_human_confirmed_wins(tmp_path):
    reaction = {"edge_id": "edge-1", "evidence_modality_count": 0}
    events = [{"event_type": "human_confirmed", "edge_id": "edge-1"}]
    assert eligibility.recompute_trust_tier(reaction, events) == "human_confirmed"


def test_eligibility_tier_corroborated_requires_distinct_edge(tmp_path):
    reaction = {"edge_id": "edge-1", "evidence_modality_count": 2}
    same_edge_events = [{"event_type": "classifier_verdict", "edge_id": "edge-1"}]
    assert eligibility.recompute_trust_tier(reaction, same_edge_events) == "same_edge_corroborated"

    distinct_edge_events = [{"event_type": "classifier_verdict", "edge_id": "edge-2"}]
    assert eligibility.recompute_trust_tier(reaction, distinct_edge_events) == "corroborated"


def test_metrics_eligible_strict_matches_research_metrics_config():
    eligible_reaction = {
        "edge_id": "edge-1", "evidence_modality_count": 2, "advisory_linkage": "temporal",
    }
    assert eligibility.metrics_eligible_strict(eligible_reaction, []) is True

    excluded_linkage = dict(eligible_reaction, advisory_linkage="none")
    assert eligibility.metrics_eligible_strict(excluded_linkage, []) is False

    too_few_modalities = {
        "edge_id": "edge-1", "evidence_modality_count": 1, "advisory_linkage": "temporal",
    }
    assert eligibility.metrics_eligible_strict(too_few_modalities, []) is False


def test_quarantine_flags_reaction_without_mutating_row(tmp_path):
    conn = _make_conn(tmp_path)
    reaction_id = classifier.ingest_reaction(conn, _validated_reaction(), now=NOW)
    conn.commit()

    quarantine.quarantine_edge(conn, "edge-1", "cross_feed_anomaly", now=NOW)
    conn.commit()

    flagged = quarantine.maybe_flag_reaction(
        conn, reaction_id=reaction_id, edge_id="edge-1", actor_key="203.0.113.9", now=NOW
    )
    conn.commit()
    assert flagged is True

    row = conn.execute(
        "SELECT trust_tier FROM reaction WHERE reaction_id = ?", (reaction_id,)
    ).fetchone()
    assert row[0] == "provisional"

    events = conn.execute(
        "SELECT event_type FROM reaction_trust_event WHERE reaction_id = ?",
        (reaction_id,),
    ).fetchall()
    assert ("edge_quarantined_source",) in events


def test_quarantine_release_stops_future_flagging(tmp_path):
    conn = _make_conn(tmp_path)
    quarantine.quarantine_edge(conn, "edge-1", "manual", now=NOW)
    conn.commit()
    assert quarantine.is_edge_quarantined(conn, "edge-1") is True

    quarantine.release_edge(conn, "edge-1", now=NOW)
    conn.commit()
    assert quarantine.is_edge_quarantined(conn, "edge-1") is False
