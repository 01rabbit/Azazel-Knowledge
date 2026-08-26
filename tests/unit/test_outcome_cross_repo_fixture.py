from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from azazel_knowledge.db.outcome_memory import export_trajectory_bundle, ingest_outcome_fact
from azazel_knowledge.db.repository import apply_migrations


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "outcome" / "gadget_execution_v0.json"


def test_gadget_execution_golden_fixture_ingests_without_authority_upgrade():
    conn = sqlite3.connect(":memory:")
    apply_migrations(conn, "local")
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert ingest_outcome_fact(conn, payload, received_at="2026-08-26T00:01:00Z") is True
    stored = json.loads(conn.execute("SELECT raw FROM outcome_execution_v0").fetchone()[0])
    assert stored == payload
    assert "effect_class" not in stored
    assert "tactical_effect" not in stored
    bundle = json.loads(export_trajectory_bundle(conn, "trace-golden-1"))
    assert bundle["executable"] is False
    assert bundle["facts"] == [payload]
