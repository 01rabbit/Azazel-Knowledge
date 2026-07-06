from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from azazel_cti.ingest.validators import (
    MAX_LINE_BYTES,
    validate_event_line,
    validate_flow_line,
    validate_reaction_line,
)

NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)


def _line(**fields) -> str:
    return json.dumps(fields)


def test_validate_event_line_accepts_well_formed_line():
    line = _line(
        event_id="ev-1",
        edge_id="edge-1",
        kind="eve_alert",
        observed_at="2026-07-06T11:00:00Z",
        src_ip="203.0.113.7",
        domain="Example.COM",
    )
    ok, result = validate_event_line(line, now=NOW)
    assert ok is True
    assert result["event_id"] == "ev-1"
    assert result["kind"] == "eve_alert"
    types = {e["type"] for e in result["entities"]}
    assert "ip" in types
    assert "domain" in types
    for entity in result["entities"]:
        assert len(entity["entity_key"]) == 32


def test_validate_event_line_rejects_missing_field():
    line = _line(edge_id="edge-1", kind="eve_alert", observed_at="2026-07-06T11:00:00Z")
    ok, error = validate_event_line(line, now=NOW)
    assert ok is False
    assert "event_id" in error


def test_validate_event_line_rejects_unknown_kind():
    line = _line(
        event_id="ev-1", edge_id="edge-1", kind="not_a_kind",
        observed_at="2026-07-06T11:00:00Z",
    )
    ok, error = validate_event_line(line, now=NOW)
    assert ok is False
    assert "kind" in error


def test_validate_event_line_rejects_stale_skew():
    stale = (NOW - timedelta(hours=49)).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = _line(event_id="ev-1", edge_id="edge-1", kind="dns", observed_at=stale)
    ok, error = validate_event_line(line, now=NOW)
    assert ok is False
    assert "skew" in error


def test_validate_event_line_rejects_future_skew():
    future = (NOW + timedelta(hours=49)).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = _line(event_id="ev-1", edge_id="edge-1", kind="dns", observed_at=future)
    ok, error = validate_event_line(line, now=NOW)
    assert ok is False
    assert "skew" in error


def test_validate_event_line_rejects_oversized_line():
    line = _line(
        event_id="ev-1", edge_id="edge-1", kind="dns",
        observed_at="2026-07-06T11:00:00Z", padding="x" * (MAX_LINE_BYTES + 10),
    )
    ok, error = validate_event_line(line, now=NOW)
    assert ok is False
    assert "exceeds" in error


def test_validate_event_line_rejects_invalid_json():
    ok, error = validate_event_line("{not json", now=NOW)
    assert ok is False
    assert "json" in error


def test_validate_event_line_drops_invalid_entity_without_failing_line():
    line = _line(
        event_id="ev-1", edge_id="edge-1", kind="eve_alert",
        observed_at="2026-07-06T11:00:00Z", src_ip="not-an-ip",
    )
    ok, result = validate_event_line(line, now=NOW)
    assert ok is True
    assert result["entities"] == []


def test_validate_flow_line_accepts_five_tuple():
    line = _line(
        event_id="fl-1", edge_id="edge-1", observed_at="2026-07-06T11:00:00Z",
        src_ip="10.0.0.1", src_port=51000, dst_ip="10.0.0.2", dst_port=443,
        proto="tcp", bytes=1500, packets=10,
    )
    ok, result = validate_flow_line(line, now=NOW)
    assert ok is True
    assert result["src_port"] == 51000
    assert result["kind"] == "flow"
    assert len(result["entities"]) == 2


def test_validate_flow_line_rejects_bad_port():
    line = _line(
        event_id="fl-1", edge_id="edge-1", observed_at="2026-07-06T11:00:00Z",
        src_ip="10.0.0.1", src_port=99999, dst_ip="10.0.0.2", dst_port=443,
        proto="tcp", bytes=1500, packets=10,
    )
    ok, error = validate_flow_line(line, now=NOW)
    assert ok is False
    assert "port" in error


def test_validate_flow_line_rejects_negative_counters():
    line = _line(
        event_id="fl-1", edge_id="edge-1", observed_at="2026-07-06T11:00:00Z",
        src_ip="10.0.0.1", src_port=1000, dst_ip="10.0.0.2", dst_port=443,
        proto="tcp", bytes=-1, packets=10,
    )
    ok, error = validate_flow_line(line, now=NOW)
    assert ok is False
    assert "counter" in error


def test_validate_reaction_line_accepts_well_formed_line():
    line = _line(
        edge_id="edge-1", actor_key="203.0.113.9", action_applied="throttle",
        applied_at="2026-07-06T11:00:00Z", reaction="continued_scanning",
        reaction_window_s=120, evidence_refs=["ev-1", "ev-2"],
    )
    ok, result = validate_reaction_line(line, now=NOW)
    assert ok is True
    assert result["reaction_window_s"] == 120
    assert result["evidence_refs"] == ["ev-1", "ev-2"]
    assert result["advisory_id"] is None


def test_validate_reaction_line_accepts_optional_advisory_id():
    line = _line(
        edge_id="edge-1", actor_key="203.0.113.9", action_applied="delay",
        applied_at="2026-07-06T11:00:00Z", reaction="disengaged",
        reaction_window_s=60, evidence_refs=["ev-1"], advisory_id="adv-1",
    )
    ok, result = validate_reaction_line(line, now=NOW)
    assert ok is True
    assert result["advisory_id"] == "adv-1"


def test_validate_reaction_line_rejects_bad_action_applied():
    line = _line(
        edge_id="edge-1", actor_key="203.0.113.9", action_applied="nuke",
        applied_at="2026-07-06T11:00:00Z", reaction="disengaged",
        reaction_window_s=60, evidence_refs=["ev-1"],
    )
    ok, error = validate_reaction_line(line, now=NOW)
    assert ok is False
    assert "action_applied" in error


def test_validate_reaction_line_rejects_bad_reaction_enum():
    line = _line(
        edge_id="edge-1", actor_key="203.0.113.9", action_applied="delay",
        applied_at="2026-07-06T11:00:00Z", reaction="teleported",
        reaction_window_s=60, evidence_refs=["ev-1"],
    )
    ok, error = validate_reaction_line(line, now=NOW)
    assert ok is False
    assert "reaction" in error


def test_validate_reaction_line_rejects_non_positive_window():
    line = _line(
        edge_id="edge-1", actor_key="203.0.113.9", action_applied="delay",
        applied_at="2026-07-06T11:00:00Z", reaction="disengaged",
        reaction_window_s=0, evidence_refs=["ev-1"],
    )
    ok, error = validate_reaction_line(line, now=NOW)
    assert ok is False
    assert "reaction_window_s" in error


def test_validate_reaction_line_rejects_empty_evidence_refs():
    line = _line(
        edge_id="edge-1", actor_key="203.0.113.9", action_applied="delay",
        applied_at="2026-07-06T11:00:00Z", reaction="disengaged",
        reaction_window_s=60, evidence_refs=[],
    )
    ok, error = validate_reaction_line(line, now=NOW)
    assert ok is False
    assert "evidence_refs" in error
