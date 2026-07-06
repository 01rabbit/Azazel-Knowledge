from __future__ import annotations

import pytest

from azazel_cti.bundle.stix_map import (
    ioc_to_indicator,
    indicator_to_ioc,
    native_to_stix,
    observed_data_to_reaction,
    reaction_to_observed_data,
    rule_draft_to_course_of_action,
    stix_to_native,
)


def test_ioc_to_indicator_shape():
    row = {
        "type": "ip",
        "value": "1.2.3.4",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
        "tags": ["botnet"],
        "agg_raw_confidence": 72.5,
    }
    indicator = native_to_stix("ioc", row)
    assert indicator["type"] == "indicator"
    assert indicator["spec_version"] == "2.1"
    assert indicator["id"].startswith("indicator--")
    assert indicator["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert indicator["created"] == "2026-01-01T00:00:00Z"
    assert indicator["modified"] == "2026-01-02T00:00:00Z"


def test_ioc_indicator_id_is_deterministic():
    row = {"type": "domain", "value": "evil.example", "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-01-01T00:00:00Z"}
    a = native_to_stix("ioc", row)
    b = native_to_stix("ioc", dict(row))
    assert a["id"] == b["id"]


@pytest.mark.parametrize(
    "type_,value,pattern",
    [
        ("ip", "1.2.3.4", "[ipv4-addr:value = '1.2.3.4']"),
        ("domain", "evil.example", "[domain-name:value = 'evil.example']"),
        ("url", "http://evil.example/x", "[url:value = 'http://evil.example/x']"),
        ("hash_sha256", "a" * 64, "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"),
        ("email", "bad@evil.example", "[email-addr:value = 'bad@evil.example']"),
        ("asn", "64512", "[autonomous-system:number = '64512']"),
        ("ja3", "abc123", "[x-azazel-ja3:value = 'abc123']"),
    ],
)
def test_ioc_pattern_round_trips(type_, value, pattern):
    row = {"type": type_, "value": value, "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-01-01T00:00:00Z"}
    indicator = native_to_stix("ioc", row)
    assert indicator["pattern"] == pattern
    back = stix_to_native(indicator)
    assert back["type"] == type_
    assert back["value"] == value


def test_indicator_round_trip_preserves_semantic_fields():
    row = {
        "type": "ip",
        "value": "10.0.0.1",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-05T00:00:00Z",
        "tags": ["c2"],
    }
    indicator = ioc_to_indicator(row)
    native = indicator_to_ioc(indicator)
    assert native["type"] == row["type"]
    assert native["value"] == row["value"]
    assert native["first_seen"] == row["first_seen"]
    assert native["last_seen"] == row["last_seen"]
    assert native["tags"] == row["tags"]


def test_reaction_to_observed_data_shape():
    row = {
        "edge_id": "edge-1",
        "actor_key": "1.2.3.4",
        "action_applied": "throttle",
        "applied_at": "2026-07-06T00:00:00Z",
        "reaction": "disengaged",
        "reaction_window_s": 300,
        "events_in_window": 4,
        "classifier": "heuristic-v1",
        "classifier_version": "1",
        "evidence_refs": ["obs-1"],
        "evidence_modality_count": 2,
        "trust_tier": "provisional",
        "advisory_id": "adv-1",
        "advisory_linkage": "echoed_pending",
    }
    observed_data = native_to_stix("reaction", row)
    assert observed_data["type"] == "observed-data"
    assert observed_data["spec_version"] == "2.1"
    extension = observed_data["extensions"]["x-azazel-reaction"]
    assert extension["action_applied"] == "throttle"
    assert extension["reaction"] == "disengaged"
    assert extension["advisory_id"] == "adv-1"


def test_reaction_round_trip_preserves_semantic_fields():
    row = {
        "edge_id": "edge-1",
        "actor_key": "1.2.3.4",
        "action_applied": "isolate",
        "applied_at": "2026-07-06T00:00:00Z",
        "reaction": "shifted_port",
        "reaction_window_s": 120,
        "events_in_window": 1,
        "classifier": "heuristic-v1",
        "classifier_version": "1",
        "evidence_refs": [],
        "evidence_modality_count": 1,
        "trust_tier": "provisional",
        "advisory_id": None,
        "advisory_linkage": "none",
    }
    observed_data = reaction_to_observed_data(row)
    native = observed_data_to_reaction(observed_data)
    for key in ("edge_id", "actor_key", "action_applied", "reaction", "reaction_window_s", "classifier"):
        assert native[key] == row[key]
    assert native["applied_at"] == row["applied_at"]


def test_rule_draft_to_course_of_action_shape():
    row = {
        "sid": "1000001",
        "format": "suricata",
        "status": "draft",
        "content": "alert ip any any -> any any (msg:\"x\"; sid:1000001;)",
        "confidence": 55.0,
        "created_at": "2026-07-06T00:00:00Z",
    }
    coa = native_to_stix("rule_draft", row)
    assert coa["type"] == "course-of-action"
    assert coa["name"] == "1000001"
    assert coa["x_azazel_status"] == "draft"
    assert coa["description"] == row["content"]


def test_native_to_stix_unknown_kind_raises():
    with pytest.raises(ValueError):
        native_to_stix("nonexistent", {})


def test_stix_to_native_unknown_type_raises():
    with pytest.raises(ValueError):
        stix_to_native({"type": "campaign"})


def test_stix_to_native_indicator_missing_extension_raises():
    with pytest.raises(ValueError):
        observed_data_to_reaction({"type": "observed-data", "extensions": {}})
