from __future__ import annotations

import json
import sqlite3

import pytest

from azazel_knowledge.db.outcome_memory import (
    OutcomeMemoryError,
    export_trajectory_bundle,
    ingest_outcome_fact,
)
from azazel_knowledge.db.repository import apply_migrations


def db():
    conn = sqlite3.connect(":memory:")
    apply_migrations(conn, "local")
    return conn


def execution(**overrides):
    data = {
        "schema_version": "outcome-execution/v0.1",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "execution-1",
        "action": "throttle",
        "status": "applied",
        "observed_at": "2026-08-26T00:00:00Z",
        "release_ref": None,
        "evidence_refs": ["rust:event:1"],
        "authority_class": "producer_execution_fact",
    }
    data.update(overrides)
    return data


def mechanism(**overrides):
    data = {
        "schema_version": "outcome-mechanism/v0.1",
        "observation_id": "mechanism-1",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "execution-1",
        "mechanism_kind": "traffic_shaping",
        "status": "observed",
        "observed_parameters": {"rate": "256kbit"},
        "observed_at": "2026-08-26T00:00:01Z",
        "evidence_refs": ["tc:qdisc:1"],
        "limitations": [],
        "authority_class": "producer_mechanism_fact",
    }
    data.update(overrides)
    return data


def outcome(observation_id="outcome-1", phase="after", **overrides):
    data = {
        "schema_version": "outcome-observation/v0.1",
        "observation_id": observation_id,
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "execution-1",
        "mechanism_observation_ref": "mechanism-1",
        "subject_ref": "src-ip:198.51.100.9",
        "window_start": "2026-08-26T00:00:01Z",
        "window_end": "2026-08-26T00:00:30Z",
        "phase": phase,
        "observation_class": "network_activity",
        "observation_values": {"source_ip_event_count": 4},
        "telemetry_coverage": {"sample_ratio": 1.0},
        "confounders": ["source_ip_is_not_actor_identity"],
        "resource_impact": {"load1_mean": 0.2},
        "evidence_refs": ["outcome:1"],
        "observed_at": "2026-08-26T00:00:30Z",
        "authority_class": "producer_outcome_fact",
    }
    data.update(overrides)
    return data


def assessment(**overrides):
    data = {
        "schema_version": "tactical-effect-assessment/v0.1",
        "assessment_id": "assessment-1",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "execution-1",
        "mechanism_observation_ref": "mechanism-1",
        "outcome_observation_refs": ["outcome-1"],
        "tactical_effect": "delay",
        "assessment": "inconclusive",
        "evaluator": "azazel-edge:assessor/v1",
        "policy_ref": "policy:research-1",
        "evidence_refs": ["outcome:1"],
        "limitations": ["causal_support_inconclusive"],
        "observed_at": "2026-08-26T00:00:31Z",
        "executable": False,
        "authority_class": "producer_assessment_fact",
    }
    data.update(overrides)
    return data


def ingest_chain(conn):
    assert ingest_outcome_fact(conn, execution(), received_at="r1")
    assert ingest_outcome_fact(conn, mechanism(), received_at="r2")
    assert ingest_outcome_fact(conn, outcome(), received_at="r3")
    assert ingest_outcome_fact(conn, assessment(), received_at="r4")


def test_migration_creates_four_separate_immutable_fact_tables():
    conn = db()
    names = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert {
        "outcome_execution_v0",
        "outcome_mechanism_v0",
        "outcome_observation_v0",
        "outcome_effect_assessment_v0",
    }.issubset(names)
    ingest_chain(conn)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("UPDATE outcome_execution_v0 SET status='failed'")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("DELETE FROM outcome_observation_v0")


def test_identical_replay_is_idempotent_but_identity_redefinition_is_rejected():
    conn = db()
    payload = execution()
    assert ingest_outcome_fact(conn, payload, received_at="r1") is True
    assert ingest_outcome_fact(conn, payload, received_at="later") is False
    changed = execution(status="failed")
    with pytest.raises(OutcomeMemoryError, match="identity collision"):
        ingest_outcome_fact(conn, changed, received_at="r2")
    assert conn.execute("SELECT COUNT(*) FROM outcome_execution_v0").fetchone()[0] == 1


def test_mechanism_requires_existing_execution_and_exact_chain():
    conn = db()
    with pytest.raises(OutcomeMemoryError, match="execution fact"):
        ingest_outcome_fact(conn, mechanism(), received_at="r")
    ingest_outcome_fact(conn, execution(), received_at="r")
    with pytest.raises(OutcomeMemoryError, match="cross-trace"):
        ingest_outcome_fact(conn, mechanism(trace_id="other"), received_at="r")


def test_outcome_cannot_join_to_different_mechanism():
    conn = db()
    ingest_outcome_fact(conn, execution(), received_at="r")
    ingest_outcome_fact(conn, mechanism(), received_at="r")
    with pytest.raises(OutcomeMemoryError, match="mechanism fact"):
        ingest_outcome_fact(conn, outcome(mechanism_observation_ref="missing"), received_at="r")


def test_assessment_requires_real_outcomes_from_same_chain():
    conn = db()
    ingest_outcome_fact(conn, execution(), received_at="r")
    ingest_outcome_fact(conn, mechanism(), received_at="r")
    with pytest.raises(OutcomeMemoryError, match="outcome fact"):
        ingest_outcome_fact(conn, assessment(), received_at="r")
    ingest_outcome_fact(conn, outcome(), received_at="r")
    with pytest.raises(OutcomeMemoryError, match="outcome fact"):
        ingest_outcome_fact(conn, assessment(outcome_observation_refs=["missing"]), received_at="r")


@pytest.mark.parametrize(
    "payload",
    [
        lambda: {**outcome(), "success": True},
        lambda: {**outcome(), "attacker_belief": "fooled"},
        lambda: {**outcome(), "execute": "isolate"},
        lambda: {**outcome(), "model_recommendation": "delay"},
    ],
)
def test_overclaim_or_directive_fields_are_rejected(payload):
    conn = db()
    ingest_outcome_fact(conn, execution(), received_at="r")
    ingest_outcome_fact(conn, mechanism(), received_at="r")
    with pytest.raises(OutcomeMemoryError):
        ingest_outcome_fact(conn, payload(), received_at="r")


def test_tactical_assessment_is_separate_non_executable_fact():
    conn = db()
    ingest_chain(conn)
    row = conn.execute(
        "SELECT tactical_effect, assessment, executable FROM outcome_effect_assessment_v0"
    ).fetchone()
    assert row == ("delay", "inconclusive", 0)
    execution_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(outcome_execution_v0)").fetchall()
    }
    assert "tactical_effect" not in execution_columns
    assert "effect_class" not in execution_columns


def test_telemetry_loss_is_preserved_as_confounder_not_success():
    conn = db()
    ingest_outcome_fact(conn, execution(), received_at="r")
    ingest_outcome_fact(conn, mechanism(), received_at="r")
    payload = outcome(
        telemetry_coverage={"sample_ratio": 0.0},
        confounders=["missing_post_telemetry"],
        observation_values={},
    )
    ingest_outcome_fact(conn, payload, received_at="r")
    stored = json.loads(
        conn.execute("SELECT raw FROM outcome_observation_v0").fetchone()[0]
    )
    assert stored["confounders"] == ["missing_post_telemetry"]
    assert "success" not in stored


def test_trajectory_export_is_byte_deterministic_and_non_executable():
    conn = db()
    ingest_chain(conn)
    first = export_trajectory_bundle(conn, "trace-1")
    second = export_trajectory_bundle(conn, "trace-1")
    assert first == second
    decoded = json.loads(first)
    assert decoded["replay_context"] is True
    assert decoded["executable"] is False
    assert len(decoded["facts"]) == 4
    assert all("provider_command" not in fact for fact in decoded["facts"])
