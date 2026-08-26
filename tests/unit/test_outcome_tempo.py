from __future__ import annotations

import json
import sqlite3

import pytest

from azazel_knowledge.db.outcome_memory import ingest_outcome_fact
from azazel_knowledge.db.outcome_tempo import TempoDerivationError, derive_tempo_features
from azazel_knowledge.db.repository import apply_migrations


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    apply_migrations(conn, "local")
    return conn


def execution(trace_id: str = "trace-1") -> dict:
    return {
        "schema_version": "outcome-execution/v0.1",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": trace_id,
        "decision_ref": "decision-1",
        "execution_ref": "execution-1",
        "action": "throttle",
        "status": "applied",
        "observed_at": "2026-08-26T00:00:00Z",
        "release_ref": None,
        "evidence_refs": ["execution:1"],
        "authority_class": "producer_execution_fact",
    }


def mechanism(trace_id: str = "trace-1") -> dict:
    return {
        "schema_version": "outcome-mechanism/v0.1",
        "observation_id": "mechanism-1",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": trace_id,
        "decision_ref": "decision-1",
        "execution_ref": "execution-1",
        "mechanism_kind": "traffic_shaping",
        "status": "observed",
        "observed_parameters": {"verification_basis": "independent_postcondition"},
        "observed_at": "2026-08-26T00:00:01Z",
        "evidence_refs": ["mechanism:1"],
        "limitations": [],
        "authority_class": "producer_mechanism_fact",
    }


def outcome(
    observation_id: str,
    *,
    observed_at: str,
    values: dict,
    coverage: dict | None = None,
    confounders: list[str] | None = None,
) -> dict:
    return {
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
        "window_end": observed_at,
        "phase": "after",
        "observation_class": "edge_outcome_record",
        "observation_values": values,
        "telemetry_coverage": coverage if coverage is not None else {"sample_ratio": 1.0},
        "confounders": confounders or [],
        "resource_impact": {},
        "evidence_refs": [f"outcome:{observation_id}"],
        "observed_at": observed_at,
        "authority_class": "producer_outcome_fact",
    }


def seed_chain(conn: sqlite3.Connection) -> None:
    ingest_outcome_fact(conn, execution(), received_at="r1")
    ingest_outcome_fact(conn, mechanism(), received_at="r2")


def test_no_outcome_rows_is_insufficient_not_zero_tempo():
    conn = db()
    summary = derive_tempo_features(conn, "trace-1")
    assert summary.status == "insufficient"
    assert summary.features == {}
    assert "no_outcome_observations" in summary.limitations
    assert "tempo_score" not in summary.to_dict()
    assert summary.executable is False


def test_explicit_retry_interval_is_usable_with_known_coverage():
    conn = db()
    seed_chain(conn)
    ingest_outcome_fact(
        conn,
        outcome(
            "outcome-1",
            observed_at="2026-08-26T00:00:30Z",
            values={"adversary_response": {"retry_interval_ms": 1400}},
        ),
        received_at="r3",
    )
    summary = derive_tempo_features(conn, "trace-1")
    assert summary.status == "usable"
    assert summary.features["retry_interval_ms"] == {
        "sample_count": 1,
        "median": 1400.0,
        "minimum": 1400.0,
        "maximum": 1400.0,
        "latest": 1400.0,
    }
    assert summary.coverage["minimum_known_coverage"] == 1.0


def test_multiple_samples_produce_deterministic_descriptive_statistics_only():
    conn = db()
    seed_chain(conn)
    for index, value in enumerate((1000, 2000, 1500), start=1):
        ingest_outcome_fact(
            conn,
            outcome(
                f"outcome-{index}",
                observed_at=f"2026-08-26T00:00:{20 + index:02d}Z",
                values={
                    "cadence": {
                        "retry_interval_ms": value,
                        "port_switch_count": index,
                    }
                },
            ),
            received_at=f"r{index + 2}",
        )
    first = derive_tempo_features(conn, "trace-1")
    second = derive_tempo_features(conn, "trace-1")
    assert first == second
    assert first.features["retry_interval_ms"]["median"] == 1500.0
    assert first.features["retry_interval_ms"]["minimum"] == 1000.0
    assert first.features["retry_interval_ms"]["maximum"] == 2000.0
    assert first.features["port_switch_count"]["maximum"] == 3.0
    assert "tempo_score" not in first.features


def test_missing_post_telemetry_blocks_strong_tempo_interpretation():
    conn = db()
    seed_chain(conn)
    ingest_outcome_fact(
        conn,
        outcome(
            "outcome-1",
            observed_at="2026-08-26T00:00:30Z",
            values={"retry_interval_ms": 1200},
            coverage={"before_present": True, "after_present": False},
            confounders=["missing_post_telemetry"],
        ),
        received_at="r3",
    )
    summary = derive_tempo_features(conn, "trace-1")
    assert summary.status == "partial"
    assert "missing_post_telemetry" in summary.confounders
    assert "tempo_interpretation_blocked_by_telemetry_confounder" in summary.limitations
    assert summary.features["retry_interval_ms"]["latest"] == 1200.0


def test_unknown_coverage_keeps_explicit_feature_partial():
    conn = db()
    seed_chain(conn)
    ingest_outcome_fact(
        conn,
        outcome(
            "outcome-1",
            observed_at="2026-08-26T00:00:30Z",
            values={"metrics": {"protocol_switch_count": 2}},
            coverage={},
        ),
        received_at="r3",
    )
    summary = derive_tempo_features(conn, "trace-1")
    assert summary.status == "partial"
    assert summary.coverage["unknown_coverage_count"] == 1
    assert "telemetry_coverage_unknown_for_some_observations" in summary.limitations


def test_outcomes_without_explicit_tempo_fields_are_insufficient():
    conn = db()
    seed_chain(conn)
    ingest_outcome_fact(
        conn,
        outcome(
            "outcome-1",
            observed_at="2026-08-26T00:00:30Z",
            values={"baseline_metrics": {"connection_latency_ms": 100}, "post_metrics": {"connection_latency_ms": 900}},
        ),
        received_at="r3",
    )
    summary = derive_tempo_features(conn, "trace-1")
    assert summary.status == "insufficient"
    assert summary.features == {}
    assert "no_explicit_tempo_features" in summary.limitations


def test_invalid_or_negative_candidate_values_are_not_interpreted_as_tempo():
    conn = db()
    seed_chain(conn)
    ingest_outcome_fact(
        conn,
        outcome(
            "outcome-1",
            observed_at="2026-08-26T00:00:30Z",
            values={
                "retry_interval_ms": -5,
                "probe_interval_ms": "1000",
                "port_switch_count": True,
            },
        ),
        received_at="r3",
    )
    summary = derive_tempo_features(conn, "trace-1")
    assert summary.status == "insufficient"
    assert summary.features == {}


def test_corrupt_stored_raw_fails_closed_instead_of_guessing():
    conn = db()
    seed_chain(conn)
    ingest_outcome_fact(
        conn,
        outcome(
            "outcome-1",
            observed_at="2026-08-26T00:00:30Z",
            values={"retry_interval_ms": 1000},
        ),
        received_at="r3",
    )
    conn.execute("DROP TRIGGER outcome_observation_v0_no_update")
    conn.execute("UPDATE outcome_observation_v0 SET raw = '{broken' WHERE observation_id = 'outcome-1'")
    with pytest.raises(TempoDerivationError, match="invalid"):
        derive_tempo_features(conn, "trace-1")


def test_empty_trace_id_fails_closed():
    conn = db()
    with pytest.raises(TempoDerivationError, match="trace_id"):
        derive_tempo_features(conn, "")
