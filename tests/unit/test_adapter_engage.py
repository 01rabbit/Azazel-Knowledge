from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.feeds.adapters.engage import EngageAdapter, FlattenedEngage

from _feeds_support import make_intel_writer

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "feeds"
NOW = datetime(2026, 7, 6, 0, 0, 0, tzinfo=timezone.utc)


def _make_adapter(tmp_path, fixture_name: str = "engage_catalog.json") -> EngageAdapter:
    intel = make_intel_writer(tmp_path)
    fixture = FIXTURES / fixture_name
    return EngageAdapter(
        "engage",
        {"kind": "engage", "group": "mitre"},
        intel,
        clock=FixedClock(NOW),
        fetch_bytes=fixture.read_bytes,
    )


def _read_activities(adapter: EngageAdapter) -> list[tuple]:
    def query(conn: Any):
        return conn.execute(
            "SELECT activity_id, name, approach, goal, description, engage_version "
            "FROM engage_activity ORDER BY activity_id"
        ).fetchall()

    return adapter._exec_intel(query)


def _read_mappings(adapter: EngageAdapter) -> list[tuple]:
    def query(conn: Any):
        return conn.execute(
            "SELECT technique_id, activity_id, engage_version FROM engage_attack_map "
            "ORDER BY technique_id"
        ).fetchall()

    return adapter._exec_intel(query)


def _read_feed_state_license(adapter: EngageAdapter) -> str | None:
    def query(conn: Any):
        row = conn.execute(
            "SELECT license FROM feed_state WHERE feed_id = ?", (adapter.feed_id,)
        ).fetchone()
        return row[0] if row else None

    return adapter._exec_intel(query)


def test_engage_import_populates_both_tables(tmp_path):
    adapter = _make_adapter(tmp_path)
    outcome = adapter.run()
    assert outcome.status == "applied"
    assert outcome.items_applied == 4  # 2 activities + 2 mappings

    activities = _read_activities(adapter)
    assert [r[0] for r in activities] == ["EAC0010", "EAC0015"]
    assert all(r[5] == "v1.0" for r in activities)
    by_id = {r[0]: r for r in activities}
    assert by_id["EAC0010"][1] == "Decoy Content"
    assert by_id["EAC0010"][2] == "Expose"
    assert by_id["EAC0010"][3] == "Elicit"

    mappings = _read_mappings(adapter)
    assert [r[0] for r in mappings] == ["T1046", "T1595.002"]
    assert all(r[2] == "v1.0" for r in mappings)


def test_engage_full_replace_swaps_engage_version(tmp_path):
    adapter = _make_adapter(tmp_path, "engage_catalog.json")
    adapter.run()

    adapter._fetch_bytes = (FIXTURES / "engage_catalog_v2.json").read_bytes
    outcome = adapter.run()
    assert outcome.status == "applied"

    activities = _read_activities(adapter)
    assert [r[0] for r in activities] == ["EAC0021"]
    assert activities[0][5] == "v2.0"
    assert activities[0][1] == "API Monitoring"

    mappings = _read_mappings(adapter)
    assert [r[0] for r in mappings] == ["T1071.001"]
    assert mappings[0][1] == "EAC0021"
    assert mappings[0][2] == "v2.0"


def test_engage_technique_to_activity_join_lookup(tmp_path):
    adapter = _make_adapter(tmp_path)
    adapter.run()

    def query(conn: Any):
        return conn.execute(
            "SELECT ea.activity_id, ea.name, ea.approach FROM engage_attack_map eam "
            "JOIN engage_activity ea ON ea.activity_id = eam.activity_id "
            "WHERE eam.technique_id = ?",
            ("T1595.002",),
        ).fetchone()

    row = adapter._exec_intel(query)
    assert row == ("EAC0010", "Decoy Content", "Expose")


def test_engage_validate_drops_incomplete_and_oversized_rows(tmp_path):
    adapter = _make_adapter(tmp_path)
    document = {
        "engage_version": "v9.9",
        "license": "MITRE Engage (CC-BY-4.0)",
        "activities": [
            {"activity_id": "EAC0001", "name": "Good", "approach": "Expose", "goal": "Elicit"},
            {"activity_id": "EAC0002", "approach": "Expose"},  # missing name
            {"name": "No id", "approach": "Expose"},  # missing activity_id
            {"activity_id": "EAC0003", "name": "x" * 5000, "approach": "Expose"},  # oversized
            {"id": "EAC0004", "name": "Aliased id", "approach": "Affect"},
        ],
        "mappings": [
            {"technique_id": "T1000", "activity_id": "EAC0001"},
            {"technique_id": "T1001"},  # missing activity_id
            {"activity_id": "EAC0001"},  # missing technique_id
            {"technique_id": "T1002", "activity_id": "EAC0004"},
        ],
    }
    parsed = adapter.parse(json.dumps(document).encode())
    valid = adapter.validate(parsed)
    assert isinstance(valid, FlattenedEngage)
    assert [a.activity_id for a in valid.activities] == ["EAC0001", "EAC0004"]
    assert [(m.technique_id, m.activity_id) for m in valid.mappings] == [
        ("T1000", "EAC0001"),
        ("T1002", "EAC0004"),
    ]


def test_engage_never_touches_ioc_tables(tmp_path):
    adapter = _make_adapter(tmp_path)
    adapter.run()

    def query(conn: Any):
        return (
            conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM ioc_source").fetchone()[0],
        )

    ioc_count, source_count = adapter._exec_intel(query)
    assert (ioc_count, source_count) == (0, 0)


def test_engage_feed_state_records_license(tmp_path):
    adapter = _make_adapter(tmp_path)
    adapter.run()

    assert _read_feed_state_license(adapter) == "MITRE Engage (CC-BY-4.0)"


def test_engage_import_is_deterministic(tmp_path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    adapter1 = _make_adapter(dir_a)
    adapter1.run()
    adapter2 = _make_adapter(dir_b)
    adapter2.run()

    assert _read_activities(adapter1) == _read_activities(adapter2)
    assert _read_mappings(adapter1) == _read_mappings(adapter2)
