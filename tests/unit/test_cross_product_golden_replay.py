from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from azazel_knowledge.db.outcome_memory import export_trajectory_bundle, ingest_outcome_fact
from azazel_knowledge.db.outcome_tempo import derive_tempo_features
from azazel_knowledge.db.repository import apply_migrations


FIXTURES = Path(__file__).parents[1] / "fixtures" / "outcome"
TRACE_ID = "trace-golden-redirect-1"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    apply_migrations(conn, "local")
    return conn


def test_edge_to_deception_golden_chain_ingests_and_replays_deterministically():
    conn = db()
    execution = load("cross_product_redirect_execution_v0.json")
    mechanism = load("cross_product_redirection_mechanism_v0.json")
    outcome = load("cross_product_presented_terrain_outcome_v0.json")

    assert ingest_outcome_fact(conn, execution, received_at="2026-08-26T06:11:00Z")
    assert ingest_outcome_fact(conn, mechanism, received_at="2026-08-26T06:11:01Z")
    assert ingest_outcome_fact(conn, outcome, received_at="2026-08-26T06:11:02Z")

    first = export_trajectory_bundle(conn, TRACE_ID)
    second = export_trajectory_bundle(conn, TRACE_ID)
    assert first == second

    replay = json.loads(first)
    assert replay["replay_context"] is True
    assert replay["executable"] is False
    assert [fact["schema_version"] for fact in replay["facts"]] == [
        "outcome-execution/v0.1",
        "outcome-mechanism/v0.1",
        "outcome-observation/v0.1",
    ]
    assert replay["facts"][2]["producer_product"] == "azazel-deception"
    encoded = first.lower()
    assert "tactical-effect-assessment" not in encoded
    assert "attacker_belief" not in encoded
    assert '"success"' not in encoded


def test_presented_terrain_lifecycle_alone_does_not_create_tempo_features():
    conn = db()
    ingest_outcome_fact(conn, load("cross_product_redirect_execution_v0.json"), received_at="r1")
    ingest_outcome_fact(conn, load("cross_product_redirection_mechanism_v0.json"), received_at="r2")
    ingest_outcome_fact(conn, load("cross_product_presented_terrain_outcome_v0.json"), received_at="r3")

    tempo = derive_tempo_features(conn, TRACE_ID)
    assert tempo.status == "insufficient"
    assert tempo.features == {}
    assert "no_explicit_tempo_features" in tempo.limitations


def test_outcome_cannot_ingest_before_edge_mechanism_chain_exists():
    conn = db()
    ingest_outcome_fact(conn, load("cross_product_redirect_execution_v0.json"), received_at="r1")
    try:
        ingest_outcome_fact(conn, load("cross_product_presented_terrain_outcome_v0.json"), received_at="r2")
    except ValueError as exc:
        assert "mechanism fact" in str(exc)
    else:
        raise AssertionError("cross-product outcome must fail without the referenced mechanism")
