"""Knowledge Lite export policy (ADR-0015 D5, Azazel-Knowledge#73).

These tests verify the policy's stated guarantees, not its implementation:
deny-by-default field selection, refusal of any denylist shape, deterministic
keyed aliasing that cannot be correlated across scopes, and a digest that
tracks the policy's meaning rather than its spelling.
"""

from __future__ import annotations

import pytest

from azazel_knowledge.bundle.lite_policy import (
    LitePolicyError,
    alias_value,
    apply_export_policy,
    load_export_policy,
    parse_export_policy,
)

CANARY = "canary-6f3a1c9d-must-never-leave-this-node"

#: A complete provenance block: all eight D4 roles, split between per-row
#: columns and per-dataset literals. Declared once so the validation tests
#: below exercise the property they name rather than tripping over provenance.
_ROW_PROV = {"freshness": "first_seen", "expiry": "expires_at", "confidence_ceiling": "confidence"}
_DATASET_PROV = {
    "citation": "test citation",
    "source": "test source",
    "generation": "test generation",
    "decay": "test decay",
    "limitations": "advisory only",
}
_PROV = {"row": _ROW_PROV, "dataset": _DATASET_PROV}
#: Provenance entirely at dataset level, for policies whose fields are minimal.
_PROV_DATASET_ONLY = {
    "row": {},
    "dataset": {
        **_DATASET_PROV,
        "freshness": "static",
        "expiry": "static",
        "confidence_ceiling": "not scored",
    },
}

_MINIMAL = {
    "version": "lite-export-v1",
    "datasets": {
        "ioc": {
            "provenance": _PROV,
            "fields": [
                {"name": "value", "mode": "alias"},
                {"name": "kind"},
                {"name": "first_seen"},
                {"name": "expires_at"},
                {"name": "confidence"},
                {"name": "note", "optional": True},
            ],
        }
    },
}

#: Every row handed to apply_export_policy needs the provenance columns.
_ROW = {"expires_at": "2027-01-01T00:00:00Z", "confidence": 60, "first_seen": "2026-01-01T00:00:00Z"}


def _policy(document=None):
    return parse_export_policy(document or _MINIMAL)


# --- deny by default -------------------------------------------------------


def test_field_absent_from_the_allowlist_is_dropped():
    exported = apply_export_policy(
        _policy(),
        "ioc",
        {"value": "10.0.0.1", "kind": "ip", "operator_note": "internal only", **_ROW},
        alias_key=b"key",
        scope="mission-1",
    )
    assert set(exported) == {"value", "kind", "first_seen", "expires_at", "confidence"}
    assert "operator_note" not in exported


def test_canary_secret_never_reaches_the_export():
    """The #73 criterion: a default artifact carries no canary secret.

    The canary sits in a column the policy does not list, which is how a column
    added by a later migration behaves too -- it is excluded because it was
    never included, not because anything remembered to exclude it.
    """
    exported = apply_export_policy(
        _policy(),
        "ioc",
        {"value": "10.0.0.1", "kind": "ip", "site_secret": CANARY, **_ROW},
        alias_key=b"key",
        scope="mission-1",
    )
    assert CANARY not in repr(exported)


def test_canary_in_an_aliased_field_is_not_exported_verbatim():
    exported = apply_export_policy(
        _policy(),
        "ioc",
        {"value": CANARY, "kind": "ip", **_ROW},
        alias_key=b"key",
        scope="mission-1",
    )
    assert exported["value"] != CANARY
    assert CANARY not in repr(exported)


def test_dataset_not_named_by_the_policy_is_refused_not_silently_emptied():
    with pytest.raises(LitePolicyError) as exc:
        apply_export_policy(_policy(), "reaction", {"id": 1}, alias_key=b"key", scope="mission-1")
    assert exc.value.code == "LITE_DATASET_NOT_ALLOWED"


# --- no denylist form ------------------------------------------------------


@pytest.mark.parametrize("key", ["deny", "exclude", "blocklist", "all", "EXCEPT"])
def test_denylist_shaped_key_is_rejected(key):
    document = {"version": "v1", "datasets": {"ioc": {"provenance": _PROV_DATASET_ONLY, "fields": [{"name": "kind"}]}}}
    document[key] = ["something"]
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_DENYLIST_SHAPE"


def test_denylist_shape_is_rejected_when_nested_inside_a_dataset():
    document = {
        "version": "v1",
        "datasets": {"ioc": {"provenance": _PROV_DATASET_ONLY, "fields": [{"name": "kind"}], "deny": ["secret"]}},
    }
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_DENYLIST_SHAPE"


# --- structural validation -------------------------------------------------


def test_unknown_key_is_rejected_so_a_typo_cannot_change_behaviour():
    document = {
        "version": "v1",
        "datasets": {"ioc": {"provenance": _PROV_DATASET_ONLY, "fields": [{"name": "kind", "optionl": True}]}},
    }
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_INVALID"


def test_duplicate_field_is_rejected():
    document = {"version": "v1", "datasets": {"ioc": {"provenance": _PROV_DATASET_ONLY, "fields": [{"name": "kind"}, {"name": "kind"}]}}}
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_INVALID"


def test_unknown_mode_is_rejected():
    document = {"version": "v1", "datasets": {"ioc": {"provenance": _PROV_DATASET_ONLY, "fields": [{"name": "kind", "mode": "hash"}]}}}
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_INVALID"


@pytest.mark.parametrize(
    "document",
    [
        {"datasets": {"ioc": {"fields": [{"name": "kind"}]}}},
        {"version": "", "datasets": {"ioc": {"fields": [{"name": "kind"}]}}},
        {"version": "v1", "datasets": {}},
        {"version": "v1", "datasets": {"ioc": {"fields": []}}},
    ],
)
def test_structurally_incomplete_policy_is_rejected(document):
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_INVALID"


def test_required_field_missing_from_the_row_is_refused():
    with pytest.raises(LitePolicyError) as exc:
        apply_export_policy(_policy(), "ioc", {"value": "10.0.0.1", **_ROW}, alias_key=b"key", scope="m")
    assert exc.value.code == "LITE_FIELD_MISSING"


def test_optional_field_missing_from_the_row_is_skipped():
    exported = apply_export_policy(
        _policy(), "ioc", {"value": "10.0.0.1", "kind": "ip", **_ROW}, alias_key=b"key", scope="m"
    )
    assert "note" not in exported


def test_alias_key_and_scope_are_required():
    for kwargs, code in (
        ({"alias_key": b"", "scope": "m"}, "LITE_ALIAS_KEY_MISSING"),
        ({"alias_key": b"key", "scope": ""}, "LITE_SCOPE_MISSING"),
    ):
        with pytest.raises(LitePolicyError) as exc:
            apply_export_policy(_policy(), "ioc", {"value": "v", "kind": "ip", **_ROW}, **kwargs)
        assert exc.value.code == code


# --- digest tracks meaning, not spelling -----------------------------------


def test_digest_is_stable_across_field_ordering():
    a = parse_export_policy(
        {"version": "v1", "datasets": {"ioc": {"provenance": _PROV_DATASET_ONLY, "fields": [{"name": "kind"}, {"name": "value"}]}}}
    )
    b = parse_export_policy(
        {"version": "v1", "datasets": {"ioc": {"provenance": _PROV_DATASET_ONLY, "fields": [{"name": "value"}, {"name": "kind"}]}}}
    )
    assert a.digest == b.digest


def test_digest_changes_when_the_policy_means_something_different():
    base = _policy()
    for changed in (
        {"version": "lite-export-v2", "datasets": _MINIMAL["datasets"]},
        {
            "version": "lite-export-v1",
            "datasets": {"ioc": {"provenance": _PROV, "fields": [{"name": "value", "mode": "allow"}, {"name": "kind"}, {"name": "first_seen"}, {"name": "expires_at"}, {"name": "confidence"}, {"name": "note", "optional": True}]}},
        },
        {
            "version": "lite-export-v1",
            "datasets": {"ioc": {"provenance": _PROV_DATASET_ONLY, "fields": [{"name": "value", "mode": "alias"}]}},
        },
    ):
        assert parse_export_policy(changed).digest != base.digest


def test_digest_is_reproducible():
    assert _policy().digest == _policy().digest


# --- aliasing --------------------------------------------------------------


def test_alias_is_deterministic_for_identical_inputs():
    args = dict(alias_key=b"key", scope="mission-1", dataset="ioc", field="value")
    assert alias_value("10.0.0.1", **args) == alias_value("10.0.0.1", **args)


def test_alias_differs_across_scopes_so_missions_cannot_be_correlated():
    base = dict(alias_key=b"key", dataset="ioc", field="value")
    assert alias_value("10.0.0.1", scope="mission-1", **base) != alias_value(
        "10.0.0.1", scope="mission-2", **base
    )


def test_alias_differs_after_key_rotation():
    base = dict(scope="mission-1", dataset="ioc", field="value")
    assert alias_value("10.0.0.1", alias_key=b"key-a", **base) != alias_value(
        "10.0.0.1", alias_key=b"key-b", **base
    )


def test_alias_differs_across_fields_and_datasets():
    base = dict(alias_key=b"key", scope="mission-1")
    assert alias_value("x", dataset="ioc", field="value", **base) != alias_value(
        "x", dataset="ioc", field="kind", **base
    )
    assert alias_value("x", dataset="ioc", field="value", **base) != alias_value(
        "x", dataset="kev", field="value", **base
    )


def test_alias_components_are_length_prefixed_against_ambiguity():
    """('ab', 'c') and ('a', 'bc') must not collide.

    Plain concatenation would make them the same message, letting one
    dataset/field pair impersonate another's alias space.
    """
    base = dict(alias_key=b"key", scope="s")
    assert alias_value("x", dataset="ab", field="c", **base) != alias_value(
        "x", dataset="a", field="bc", **base
    )


# --- loading ---------------------------------------------------------------


def test_load_export_policy_from_yaml(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: lite-export-v1\n"
        "datasets:\n"
        "  ioc:\n"
        "    provenance:\n"
        "      row: {}\n"
        "      dataset:\n"
        "        citation: c\n"
        "        source: s\n"
        "        freshness: f\n"
        "        generation: g\n"
        "        expiry: e\n"
        "        decay: d\n"
        "        confidence_ceiling: cc\n"
        "        limitations: l\n"
        "    fields:\n"
        "      - name: value\n"
        "        mode: alias\n"
        "      - name: kind\n",
        encoding="utf-8",
    )
    policy = load_export_policy(path)
    assert policy.version == "lite-export-v1"
    assert policy.datasets["ioc"].rule("value").mode == "alias"


def test_load_export_policy_missing_file(tmp_path):
    with pytest.raises(LitePolicyError) as exc:
        load_export_policy(tmp_path / "absent.yaml")
    assert exc.value.code == "LITE_POLICY_MISSING"


def test_load_export_policy_empty_file(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(LitePolicyError) as exc:
        load_export_policy(path)
    assert exc.value.code == "LITE_POLICY_INVALID"


def test_load_export_policy_invalid_yaml(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: [unclosed\n", encoding="utf-8")
    with pytest.raises(LitePolicyError) as exc:
        load_export_policy(path)
    assert exc.value.code == "LITE_POLICY_INVALID"


# --- D4 provenance (ADR-0015, Azazel-Knowledge#73) --------------------------


def _doc(provenance, fields=None):
    return {
        "version": "v1",
        "datasets": {
            "ioc": {
                "provenance": provenance,
                "fields": fields
                or [{"name": "kind"}, {"name": "expires_at"}, {"name": "confidence"}],
            }
        },
    }


def test_policy_without_any_provenance_is_refused():
    """D4: a claim that cannot carry its provenance is not exported.

    Requiring every role, rather than accepting whatever a policy lists, is what
    stops an unprovenanced claim shipping merely because nobody wrote the
    mapping down.
    """
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy({"version": "v1", "datasets": {"ioc": {"fields": [{"name": "kind"}]}}})
    assert exc.value.code == "LITE_PROVENANCE_INCOMPLETE"


def test_policy_missing_one_role_is_refused_and_names_it():
    partial = {"row": {}, "dataset": {k: "x" for k in _DATASET_PROV} | {"freshness": "s", "expiry": "s"}}
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(_doc(partial))
    assert exc.value.code == "LITE_PROVENANCE_INCOMPLETE"
    assert "confidence_ceiling" in exc.value.message


def test_role_satisfied_twice_is_refused():
    both = {
        "row": {"freshness": "kind"},
        "dataset": {**_DATASET_PROV, "freshness": "s", "expiry": "s", "confidence_ceiling": "s"},
    }
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(_doc(both))
    assert exc.value.code == "LITE_PROVENANCE_INVALID"


def test_unknown_provenance_role_is_refused():
    extra = {"row": {}, "dataset": {**_PROV_DATASET_ONLY["dataset"], "vibes": "good"}}
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(_doc(extra))
    assert exc.value.code == "LITE_PROVENANCE_INVALID"


def test_row_provenance_naming_an_unlisted_field_is_refused():
    """Provenance pointing at a field the allowlist drops would never be exported."""
    prov = {
        "row": {"freshness": "not_allowlisted"},
        "dataset": {**_DATASET_PROV, "expiry": "s", "confidence_ceiling": "s"},
    }
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(_doc(prov))
    assert exc.value.code == "LITE_PROVENANCE_INVALID"


def test_row_provenance_naming_an_optional_field_is_refused():
    """Optional provenance is a contradiction: the claim could ship without it."""
    prov = {
        "row": {"freshness": "maybe"},
        "dataset": {**_DATASET_PROV, "expiry": "s", "confidence_ceiling": "s"},
    }
    fields = [{"name": "kind"}, {"name": "maybe", "optional": True}]
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(_doc(prov, fields))
    assert exc.value.code == "LITE_PROVENANCE_INVALID"


def test_aliasing_the_confidence_ceiling_is_refused():
    """Aliasing a confidence destroys the value a consumer must not exceed.

    D4 forbids Lite raising a confidence above the full node's. A pseudonymised
    confidence cannot be compared at all, which is worse than raising it.
    """
    prov = {
        "row": {"confidence_ceiling": "confidence"},
        "dataset": {**_DATASET_PROV, "freshness": "s", "expiry": "s"},
    }
    fields = [{"name": "kind"}, {"name": "confidence", "mode": "alias"}]
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(_doc(prov, fields))
    assert exc.value.code == "LITE_PROVENANCE_INVALID"


def test_empty_dataset_provenance_literal_is_refused():
    prov = {"row": {}, "dataset": {**_PROV_DATASET_ONLY["dataset"], "limitations": "   "}}
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(_doc(prov))
    assert exc.value.code == "LITE_PROVENANCE_INVALID"


def test_null_provenance_value_on_a_row_is_refused():
    """A column that exists but is null carries no provenance.

    This is the case that matters in practice: an indicator that has not been
    through aggregation has no expiry and no confidence, so it cannot be
    exported, however complete the policy looks.
    """
    policy = _policy()
    row = {"value": "10.0.0.1", "kind": "ip", **_ROW, "expires_at": None}
    with pytest.raises(LitePolicyError) as exc:
        apply_export_policy(policy, "ioc", row, alias_key=b"key", scope="m")
    assert exc.value.code == "LITE_PROVENANCE_MISSING"


def test_provenance_is_part_of_the_policy_digest():
    """Changing where provenance comes from changes the artifact it produces."""
    base = _policy().digest
    changed = dict(_MINIMAL)
    changed["datasets"] = {
        "ioc": {
            **_MINIMAL["datasets"]["ioc"],
            "provenance": {
                "row": {"expiry": "expires_at", "confidence_ceiling": "confidence"},
                "dataset": {**_DATASET_PROV, "freshness": "stated per dataset instead"},
            },
        }
    }
    assert parse_export_policy(changed).digest != base
