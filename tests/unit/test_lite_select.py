"""Knowledge Lite selection (ADR-0015 D2/D3, Azazel-Knowledge#73).

These tests verify the stated guarantees: a pinned tuple determines the
content byte-for-byte, nothing reads the clock, ceilings fail closed instead of
truncating, and freshness is a selection rule rather than a limit.
"""

from __future__ import annotations

import dataclasses

import pytest

from azazel_knowledge.bundle.lite_policy import parse_export_policy
from azazel_knowledge.bundle.lite_select import (
    PROFILES,
    LiteSelectionError,
    SelectionInputs,
    select_lite_content,
)

AS_OF = "2026-09-19T00:00:00Z"
FRESH = "2026-09-18T00:00:00Z"
STALE = "2026-01-01T00:00:00Z"

#: Provenance satisfied per row where the data varies, per dataset where it does
#: not. Every dataset must cover all eight D4 roles or the policy is rejected.
_ROW_PROV = {"freshness": "last_seen", "expiry": "expires_at", "confidence_ceiling": "confidence"}
_DATASET_PROV = {
    "citation": "test citation",
    "source": "test source",
    "generation": "test generation",
    "decay": "test decay",
    "limitations": "advisory only",
}
_STATIC_PROV = {
    "row": {},
    "dataset": {
        **_DATASET_PROV,
        "freshness": "static reference content; revised with the ATT&CK version",
        "expiry": "does not expire independently of its ATT&CK version",
        "confidence_ceiling": "not confidence-scored",
    },
}

POLICY_DOC = {
    "version": "lite-export-v1",
    "datasets": {
        "ioc": {
            "provenance": {"row": _ROW_PROV, "dataset": _DATASET_PROV},
            "fields": [
                {"name": "value", "mode": "alias"},
                {"name": "kind"},
                {"name": "last_seen"},
                {"name": "expires_at"},
                {"name": "confidence"},
            ],
        },
        "attack_technique": {
            "provenance": _STATIC_PROV,
            "fields": [{"name": "technique_id"}, {"name": "name"}],
        },
    },
}


@pytest.fixture
def policy():
    return parse_export_policy(POLICY_DOC)


@pytest.fixture
def inputs(policy):
    return SelectionInputs(
        intel_generation=7,
        stats_generation=3,
        attack_version="v15.1",
        config_hash="cfg-abc",
        profile_id="knowledge-lite-16g",
        export_policy_digest=policy.digest,
        as_of=AS_OF,
    )


def _rows(count: int = 2, *, seen: str = FRESH):
    return {
        "ioc": [
            {
                "value": f"10.0.0.{i}",
                "kind": "ip",
                "last_seen": seen,
                "expires_at": "2027-01-01T00:00:00Z",
                "confidence": 60,
            }
            for i in range(count)
        ]
    }


def _select(rows, inputs, policy, **kwargs):
    kwargs.setdefault("freshness_fields", {"ioc": "last_seen"})
    return select_lite_content(
        rows, inputs=inputs, policy=policy, alias_key=b"alias-key", scope="mission-1", **kwargs
    )


# --- determinism -----------------------------------------------------------


def test_same_tuple_produces_byte_identical_content(policy, inputs):
    rows = _rows(50)
    assert _select(rows, inputs, policy).content_bytes() == _select(rows, inputs, policy).content_bytes()


def test_content_is_independent_of_the_order_rows_arrive_in(policy, inputs):
    forward = _rows(20)
    reversed_rows = {"ioc": list(reversed(forward["ioc"]))}
    assert _select(forward, inputs, policy).content_bytes() == _select(
        reversed_rows, inputs, policy
    ).content_bytes()


@pytest.mark.parametrize(
    "field,value",
    [
        ("intel_generation", 8),
        ("stats_generation", 4),
        ("attack_version", "v15.2"),
        ("config_hash", "cfg-def"),
        ("as_of", "2026-09-20T00:00:00Z"),
    ],
)
def test_changing_any_tuple_element_changes_the_artifact(policy, inputs, field, value):
    """Every element of the pinned tuple must be visible in the artifact.

    An element that changed nothing would be a lie in the manifest: a rebuild
    from a different input would claim to be the same artifact.
    """
    base = _select(_rows(), inputs, policy)
    changed = _select(_rows(), dataclasses.replace(inputs, **{field: value}), policy)
    assert changed.profile_block != base.profile_block


def test_changing_the_profile_changes_the_artifact(policy, inputs):
    base = _select(_rows(), inputs, policy)
    other = _select(_rows(), dataclasses.replace(inputs, profile_id="knowledge-lite-32g"), policy)
    assert other.profile_block != base.profile_block


# --- the clock is never read ----------------------------------------------


def test_freshness_is_measured_against_as_of_not_the_current_time(policy, inputs):
    """A row 8 months old is stale relative to as_of and is dropped.

    The same row would be *fresh* if the window were measured against an as_of
    near its own timestamp, which the next assertion shows -- so the window
    genuinely follows as_of rather than whatever today happens to be.
    """
    rows = {"ioc": [{"value": "10.0.0.1", "kind": "ip", "last_seen": STALE,
                     "expires_at": "2027-01-01T00:00:00Z", "confidence": 60}]}
    assert _select(rows, inputs, policy).profile_block["counts"]["rows"] == 0

    near = dataclasses.replace(inputs, as_of="2026-01-05T00:00:00Z")
    assert _select(rows, near, policy).profile_block["counts"]["rows"] == 1


def test_an_as_of_far_in_the_past_still_selects_deterministically(policy, inputs):
    rows = {"ioc": [{"value": "10.0.0.1", "kind": "ip", "last_seen": "1999-01-02T00:00:00Z",
                     "expires_at": "2027-01-01T00:00:00Z", "confidence": 60}]}
    past = dataclasses.replace(inputs, as_of="1999-01-03T00:00:00Z")
    assert _select(rows, past, policy).profile_block["counts"]["rows"] == 1


def test_naive_timestamp_is_refused_rather_than_assumed_utc(policy, inputs):
    rows = {"ioc": [{"value": "10.0.0.1", "kind": "ip", "last_seen": "2026-09-18T00:00:00",
                     "expires_at": "2027-01-01T00:00:00Z", "confidence": 60}]}
    with pytest.raises(LiteSelectionError) as exc:
        _select(rows, inputs, policy)
    assert exc.value.code == "LITE_TIMESTAMP_INVALID"


def test_dataset_without_a_freshness_field_is_exempt(policy, inputs):
    """Static reference material does not expire on a 30-day clock."""
    rows = {"attack_technique": [{"technique_id": "T1110", "name": "Brute Force"}]}
    selection = _select(rows, inputs, policy, freshness_fields={})
    assert selection.profile_block["counts"]["rows"] == 1


def test_declared_freshness_field_missing_from_a_row_is_refused(policy, inputs):
    rows = {"ioc": [{"value": "10.0.0.1", "kind": "ip",
                     "expires_at": "2027-01-01T00:00:00Z", "confidence": 60}]}
    with pytest.raises(LiteSelectionError) as exc:
        _select(rows, inputs, policy)
    assert exc.value.code == "LITE_FRESHNESS_FIELD_MISSING"


# --- ceilings fail closed --------------------------------------------------


def test_per_dataset_row_ceiling_fails_closed_instead_of_truncating(policy, inputs, monkeypatch):
    tight = dataclasses.replace(PROFILES["knowledge-lite-16g"], max_rows_per_dataset=3)
    monkeypatch.setitem(PROFILES, "knowledge-lite-16g", tight)
    with pytest.raises(LiteSelectionError) as exc:
        _select(_rows(4), inputs, policy)
    assert exc.value.code == "LITE_CEILING_EXCEEDED"


def test_total_row_ceiling_fails_closed(policy, inputs, monkeypatch):
    tight = dataclasses.replace(PROFILES["knowledge-lite-16g"], max_rows_total=2)
    monkeypatch.setitem(PROFILES, "knowledge-lite-16g", tight)
    with pytest.raises(LiteSelectionError) as exc:
        _select(_rows(3), inputs, policy)
    assert exc.value.code == "LITE_CEILING_EXCEEDED"


def test_byte_ceiling_fails_closed(policy, inputs, monkeypatch):
    tight = dataclasses.replace(PROFILES["knowledge-lite-16g"], max_uncompressed_bytes=10)
    monkeypatch.setitem(PROFILES, "knowledge-lite-16g", tight)
    with pytest.raises(LiteSelectionError) as exc:
        _select(_rows(3), inputs, policy)
    assert exc.value.code == "LITE_CEILING_EXCEEDED"


def test_dataset_count_ceiling_fails_closed(policy, inputs, monkeypatch):
    tight = dataclasses.replace(PROFILES["knowledge-lite-16g"], max_datasets=1)
    monkeypatch.setitem(PROFILES, "knowledge-lite-16g", tight)
    rows = {
        "ioc": [{"value": "10.0.0.1", "kind": "ip", "last_seen": FRESH,
                 "expires_at": "2027-01-01T00:00:00Z", "confidence": 60}],
        "attack_technique": [{"technique_id": "T1110", "name": "Brute Force"}],
    }
    with pytest.raises(LiteSelectionError) as exc:
        _select(rows, inputs, policy)
    assert exc.value.code == "LITE_CEILING_EXCEEDED"


def test_a_selection_inside_its_ceilings_is_emitted_whole(policy, inputs):
    """Nothing is dropped for capacity reasons on the success path.

    Every row that survived freshness must appear; a bundle that silently
    shipped fewer would be indistinguishable from one where the data was simply
    absent.
    """
    selection = _select(_rows(25), inputs, policy)
    assert selection.profile_block["counts"]["rows"] == 25
    assert len(selection.datasets["ioc"]) == 25


# --- input validation ------------------------------------------------------


def test_unknown_profile_is_refused(policy, inputs):
    with pytest.raises(LiteSelectionError) as exc:
        _select(_rows(), dataclasses.replace(inputs, profile_id="knowledge-lite-99g"), policy)
    assert exc.value.code == "LITE_PROFILE_UNKNOWN"


def test_policy_digest_mismatch_is_refused(policy, inputs):
    """The digest is part of what determines content, so it must match."""
    with pytest.raises(LiteSelectionError) as exc:
        _select(_rows(), dataclasses.replace(inputs, export_policy_digest="0" * 64), policy)
    assert exc.value.code == "LITE_POLICY_DIGEST_MISMATCH"


@pytest.mark.parametrize(
    "field,value",
    [
        ("attack_version", ""),
        ("config_hash", ""),
        ("as_of", ""),
        ("intel_generation", -1),
        ("stats_generation", -1),
    ],
)
def test_incomplete_selection_inputs_are_refused(policy, inputs, field, value):
    changed = dataclasses.replace(inputs, **{field: value})
    with pytest.raises(LiteSelectionError) as exc:
        _select(_rows(), changed, policy)
    assert exc.value.code in {"LITE_INPUTS_INCOMPLETE", "LITE_TIMESTAMP_INVALID"}


# --- manifest block --------------------------------------------------------


def test_profile_block_records_the_tuple_the_ceilings_and_the_counts(policy, inputs):
    block = _select(_rows(4), inputs, policy).profile_block
    assert block["profile_id"] == "knowledge-lite-16g"
    assert block["selection_inputs"]["export_policy_digest"] == policy.digest
    assert block["selection_inputs"]["as_of"] == AS_OF
    assert block["ceilings"]["freshness_window_days"] == 30
    assert block["counts"] == {"datasets": 1, "rows": 4, "uncompressed_bytes": block["counts"]["uncompressed_bytes"]}
    assert block["counts"]["uncompressed_bytes"] > 0


def test_profile_block_carries_dataset_level_provenance(policy, inputs):
    """The half of D4 that is not in the row travels in the manifest.

    A consumer reads per-row provenance from the row and the rest from here, so
    all eight roles are available for any claim without repeating a constant
    sentence on every row.
    """
    block = _select(_rows(), inputs, policy).profile_block
    prov = block["provenance"]["ioc"]
    assert prov["row"]["freshness"] == "last_seen"
    assert prov["dataset"]["limitations"] == "advisory only"
    covered = set(prov["row"]) | set(prov["dataset"])
    assert covered == {
        "citation",
        "source",
        "freshness",
        "generation",
        "expiry",
        "decay",
        "confidence_ceiling",
        "limitations",
    }
