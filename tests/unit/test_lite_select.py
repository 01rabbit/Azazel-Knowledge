"""Knowledge Lite selection (ADR-0015 D2/D3, Azazel-Knowledge#73).

These tests verify the stated guarantees: a pinned tuple determines the
content byte-for-byte, nothing reads the clock, ceilings fail closed instead of
truncating, and freshness is a selection rule rather than a limit.
"""

from __future__ import annotations

import dataclasses

import pytest

from azazel_knowledge.bundle.lite_policy import parse_export_policy
from azazel_knowledge.bundle.verify import DEFAULT_MAX_FILE_BYTES
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


def test_per_dataset_byte_ceiling_fails_closed(policy, inputs, monkeypatch):
    """The total byte ceiling does not stand in for a per-dataset one.

    The tight profile here leaves ``max_uncompressed_bytes`` alone, so a
    selection that trips this must be tripping the per-dataset bound and not
    the total -- otherwise the test would pass with no per-dataset check at all.
    """
    base = PROFILES["knowledge-lite-16g"]
    tight = dataclasses.replace(base, max_bytes_per_dataset=10)
    assert tight.max_uncompressed_bytes > tight.max_bytes_per_dataset
    monkeypatch.setitem(PROFILES, "knowledge-lite-16g", tight)
    with pytest.raises(LiteSelectionError) as exc:
        _select(_rows(3), inputs, policy)
    assert exc.value.code == "LITE_CEILING_EXCEEDED"
    assert "dataset 'ioc'" in exc.value.message


def test_no_profile_can_emit_a_member_the_reader_would_refuse():
    """The builder's per-dataset ceiling is bounded by the reader's per-file cap.

    One dataset is one tar member, and `verify_bundle` refuses any member over
    `DEFAULT_MAX_FILE_BYTES` with BUNDLE_DECOMPRESSION_BOMB. If a profile were
    allowed to exceed that, the builder could sign an artifact that no
    conforming reader accepts -- which is exactly what a 900_000-row selection
    did under the pre-measurement `knowledge-lite-32g` ceilings (1 GiB total,
    no per-dataset bound): it built, signed, and then failed verification at
    534.7 MiB in a single member.

    This is a contract between two modules, so it is asserted against the
    reader's real constant rather than a number copied into this file.
    """
    for profile_id, ceilings in PROFILES.items():
        assert ceilings.max_bytes_per_dataset <= DEFAULT_MAX_FILE_BYTES, (
            f"profile {profile_id!r} allows a {ceilings.max_bytes_per_dataset}-byte dataset, "
            f"but the reader refuses any member over {DEFAULT_MAX_FILE_BYTES} bytes"
        )
        # The total may not be met by one dataset either: with max_datasets
        # datasets the total is reachable, but no single member may exceed the
        # cap, so the per-dataset bound must be the binding one for a member.
        assert ceilings.max_bytes_per_dataset <= ceilings.max_uncompressed_bytes, (
            f"profile {profile_id!r} has a per-dataset ceiling above its total"
        )


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
    assert block["ceilings"]["max_bytes_per_dataset"] == PROFILES["knowledge-lite-16g"].max_bytes_per_dataset
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


# --- the ceilings that actually ship ---------------------------------------
#
# The ceiling tests above monkeypatch `PROFILES` with fabricated values (3 rows,
# 10 bytes, 1 dataset). They prove the *enforcement mechanism* fires, which is
# worth having, but they are blind to the shipped numbers: every one of them
# would still pass if `knowledge-lite-16g` declared `max_rows_total=5` or
# `max_rows_total=5_000_000_000`.
#
# These tests make the declared values load-bearing. Each one fails if a shipped
# constant is wrong, not merely if a check is deleted.


def _prov_dataset(name: str) -> dict:
    """A minimal dataset block covering all eight D4 provenance roles."""
    return {
        "provenance": _STATIC_PROV,
        "fields": [{"name": "technique_id"}, {"name": "name"}],
    }


@pytest.mark.parametrize("profile_id", sorted(PROFILES))
def test_the_dataset_ceiling_is_enforced_at_its_shipped_value(profile_id, inputs):
    """One dataset over the profile's own `max_datasets` fails; exactly at it passes.

    No monkeypatch: this runs against the real `PROFILES` entry, so lowering or
    raising the shipped `max_datasets` breaks it. `max_datasets` is the one
    ceiling reachable without materialising hundreds of thousands of rows, which
    is why the shipped value is pinned here rather than in a volume test.
    """
    limit = PROFILES[profile_id].max_datasets
    profile_inputs = dataclasses.replace(inputs, profile_id=profile_id)

    def build(count: int):
        doc = {
            "version": "lite-export-v1",
            "datasets": {f"attack_technique_{i}": _prov_dataset(f"d{i}") for i in range(count)},
        }
        pol = parse_export_policy(doc)
        rows = {name: [{"technique_id": "T1046", "name": "Network Service Discovery"}] for name in doc["datasets"]}
        return rows, dataclasses.replace(profile_inputs, export_policy_digest=pol.digest), pol

    rows, at_inputs, at_policy = build(limit)
    assert len(select_lite_content(
        rows, inputs=at_inputs, policy=at_policy, alias_key=b"k", scope="s", freshness_fields={}
    ).datasets) == limit

    rows, over_inputs, over_policy = build(limit + 1)
    with pytest.raises(LiteSelectionError) as exc:
        select_lite_content(
            rows, inputs=over_inputs, policy=over_policy, alias_key=b"k", scope="s", freshness_fields={}
        )
    assert exc.value.code == "LITE_CEILING_EXCEEDED"
    assert str(limit) in exc.value.message


def test_the_freshness_window_is_the_one_the_profile_ships(policy, inputs):
    """A 60-day-old row is outside 16g's window and inside 32g's.

    This is what proves a 32g build applies *32g's own* numbers rather than
    silently reusing 16g's: the two profiles differ by their shipped
    `freshness_window_days` (30 vs 90), and a row aged between them is admitted
    by exactly one of them. Changing either shipped constant breaks this.
    """
    sixty_days_old = "2026-07-21T00:00:00Z"  # 60 days before AS_OF
    rows = _rows(3, seen=sixty_days_old)

    on_16g = _select(rows, dataclasses.replace(inputs, profile_id="knowledge-lite-16g"), policy)
    on_32g = _select(rows, dataclasses.replace(inputs, profile_id="knowledge-lite-32g"), policy)

    assert PROFILES["knowledge-lite-16g"].freshness_window_days < 60
    assert PROFILES["knowledge-lite-32g"].freshness_window_days > 60
    assert len(on_16g.datasets.get("ioc", ())) == 0, "a 60-day-old row is outside the 16g window"
    assert len(on_32g.datasets.get("ioc", ())) == 3, "a 60-day-old row is inside the 32g window"


def test_every_profile_admits_the_shipped_default_export_policy():
    """`max_datasets` must not be below what `config/lite-export-policy.yaml` names.

    The shipped policy and the shipped profiles are two constants that have to
    agree: a profile whose dataset ceiling sits below the default policy's
    dataset count cannot build the default artifact at all, and nothing else in
    the suite pairs them.
    """
    from pathlib import Path

    from azazel_knowledge.bundle.lite_policy import load_export_policy

    repo_root = Path(__file__).resolve().parents[2]
    shipped = load_export_policy(repo_root / "config" / "lite-export-policy.yaml")
    for profile_id, ceilings in PROFILES.items():
        assert ceilings.max_datasets >= len(shipped.datasets), (
            f"profile {profile_id!r} allows {ceilings.max_datasets} datasets but the shipped "
            f"default policy names {len(shipped.datasets)}"
        )


def test_no_profile_allows_more_datasets_than_the_schema_can_supply():
    """`max_datasets` is bounded above by the eligible intel tables that exist.

    This is the half that the enforcement test above cannot see. That test reads
    `max_datasets` and builds one dataset more, so it follows the constant
    wherever it goes: raising the shipped 16g ceiling from 8 to 64 leaves it
    green. The ceiling has to be pinned against something outside itself, and
    the schema is that thing -- a profile admitting more datasets than the
    database can ever yield is not a ceiling, it is a number nobody checked.

    Derived from a freshly migrated intel schema rather than a copied count, so
    a migration that adds or removes an exportable table moves the bound with it.

    The bound is deliberately loose and this is not an oversight: the schema
    currently yields 16 exportable tables against shipped ceilings of 8 and 12,
    so it catches a ceiling that has lost contact with reality (8 -> 64) but not
    an off-by-a-few edit (12 -> 13). Tightening it would mean asserting a number
    somebody chose, which is the blindness this test exists to remove.
    """
    import sqlite3
    import tempfile
    from pathlib import Path

    from azazel_knowledge.bundle.verify import LOCAL_TIER_TABLES
    from azazel_knowledge.db.repository import apply_migrations

    with tempfile.TemporaryDirectory() as tmp:
        conn = sqlite3.connect(Path(tmp) / "intel.db")
        apply_migrations(conn, "intel")
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        conn.close()
    eligible = names - set(LOCAL_TIER_TABLES)
    assert eligible, "the intel schema yielded no exportable tables; the bound below is vacuous"
    for profile_id, ceilings in PROFILES.items():
        assert ceilings.max_datasets <= len(eligible), (
            f"profile {profile_id!r} allows {ceilings.max_datasets} datasets but only "
            f"{len(eligible)} exportable tables exist: {sorted(eligible)}"
        )


def test_no_profile_can_exceed_the_readers_total_cap():
    """Companion to the per-dataset bound: the whole artifact must fit too.

    `test_no_profile_can_emit_a_member_the_reader_would_refuse` pins one member
    against `DEFAULT_MAX_FILE_BYTES`. A profile could satisfy that per member and
    still declare a total the reader refuses, so the total is pinned against the
    reader's own `DEFAULT_MAX_TOTAL_BYTES` the same way.
    """
    from azazel_knowledge.bundle.verify import DEFAULT_MAX_TOTAL_BYTES

    for profile_id, ceilings in PROFILES.items():
        assert ceilings.max_uncompressed_bytes <= DEFAULT_MAX_TOTAL_BYTES, (
            f"profile {profile_id!r} allows {ceilings.max_uncompressed_bytes} uncompressed bytes, "
            f"over the reader's total cap {DEFAULT_MAX_TOTAL_BYTES}"
        )
        assert ceilings.max_bytes_per_dataset <= ceilings.max_uncompressed_bytes
        assert ceilings.max_rows_per_dataset <= ceilings.max_rows_total
