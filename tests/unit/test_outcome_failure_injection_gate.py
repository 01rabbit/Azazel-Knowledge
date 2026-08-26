from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import pytest

from azazel_knowledge.db.outcome_memory import (
    OutcomeMemoryError,
    export_trajectory_bundle,
    ingest_outcome_fact,
)
from azazel_knowledge.db.repository import apply_migrations


FIXTURES = Path(__file__).parents[1] / "fixtures" / "outcome"
TRACE_ID = "trace-golden-redirect-1"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    apply_migrations(conn, "local")
    return conn


def test_identical_duplicate_is_idempotent_and_replay_unchanged():
    conn = db()
    execution = load("cross_product_redirect_execution_v0.json")
    assert ingest_outcome_fact(conn, execution, received_at="r1") is True
    before = export_trajectory_bundle(conn, TRACE_ID)
    assert ingest_outcome_fact(conn, execution, received_at="r2") is False
    assert export_trajectory_bundle(conn, TRACE_ID) == before


def test_identity_collision_with_different_canonical_content_is_rejected():
    conn = db()
    execution = load("cross_product_redirect_execution_v0.json")
    ingest_outcome_fact(conn, execution, received_at="r1")
    poisoned = copy.deepcopy(execution)
    poisoned["evidence_refs"] = ["edge:execution:poisoned"]
    with pytest.raises(OutcomeMemoryError, match="identity collision"):
        ingest_outcome_fact(conn, poisoned, received_at="r2")


def test_cross_trace_mechanism_join_is_rejected():
    conn = db()
    ingest_outcome_fact(conn, load("cross_product_redirect_execution_v0.json"), received_at="r1")
    poisoned = load("cross_product_redirection_mechanism_v0.json")
    poisoned["trace_id"] = "trace-poisoned"
    with pytest.raises(OutcomeMemoryError, match="cross-trace/cross-decision execution join rejected"):
        ingest_outcome_fact(conn, poisoned, received_at="r2")


def test_outcome_before_referenced_chain_is_rejected():
    conn = db()
    with pytest.raises(OutcomeMemoryError, match="referenced execution fact is not present"):
        ingest_outcome_fact(conn, load("cross_product_presented_terrain_outcome_v0.json"), received_at="r1")


def test_tactical_claim_smuggling_in_outcome_fact_is_rejected():
    conn = db()
    ingest_outcome_fact(conn, load("cross_product_redirect_execution_v0.json"), received_at="r1")
    ingest_outcome_fact(conn, load("cross_product_redirection_mechanism_v0.json"), received_at="r2")
    poisoned = copy.deepcopy(load("cross_product_presented_terrain_outcome_v0.json"))
    poisoned["observation_values"]["nested"] = {"tactical-effect": "divert"}
    with pytest.raises(OutcomeMemoryError, match="tactical claim"):
        ingest_outcome_fact(conn, poisoned, received_at="r3")


def test_runtime_authority_smuggling_is_rejected():
    conn = db()
    poisoned = copy.deepcopy(load("cross_product_redirect_execution_v0.json"))
    poisoned["provider-command"] = "do-not-execute"
    with pytest.raises(OutcomeMemoryError):
        ingest_outcome_fact(conn, poisoned, received_at="r1")
