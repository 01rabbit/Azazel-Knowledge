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

_MINIMAL = {
    "version": "lite-export-v1",
    "datasets": {
        "ioc": {
            "fields": [
                {"name": "value", "mode": "alias"},
                {"name": "kind"},
                {"name": "first_seen", "optional": True},
            ]
        }
    },
}


def _policy(document=None):
    return parse_export_policy(document or _MINIMAL)


# --- deny by default -------------------------------------------------------


def test_field_absent_from_the_allowlist_is_dropped():
    exported = apply_export_policy(
        _policy(),
        "ioc",
        {"value": "10.0.0.1", "kind": "ip", "operator_note": "internal only"},
        alias_key=b"key",
        scope="mission-1",
    )
    assert set(exported) == {"value", "kind"}
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
        {"value": "10.0.0.1", "kind": "ip", "site_secret": CANARY},
        alias_key=b"key",
        scope="mission-1",
    )
    assert CANARY not in repr(exported)


def test_canary_in_an_aliased_field_is_not_exported_verbatim():
    exported = apply_export_policy(
        _policy(),
        "ioc",
        {"value": CANARY, "kind": "ip"},
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
    document = {"version": "v1", "datasets": {"ioc": {"fields": [{"name": "kind"}]}}}
    document[key] = ["something"]
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_DENYLIST_SHAPE"


def test_denylist_shape_is_rejected_when_nested_inside_a_dataset():
    document = {
        "version": "v1",
        "datasets": {"ioc": {"fields": [{"name": "kind"}], "deny": ["secret"]}},
    }
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_DENYLIST_SHAPE"


# --- structural validation -------------------------------------------------


def test_unknown_key_is_rejected_so_a_typo_cannot_change_behaviour():
    document = {
        "version": "v1",
        "datasets": {"ioc": {"fields": [{"name": "kind", "optionl": True}]}},
    }
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_INVALID"


def test_duplicate_field_is_rejected():
    document = {"version": "v1", "datasets": {"ioc": {"fields": [{"name": "kind"}, {"name": "kind"}]}}}
    with pytest.raises(LitePolicyError) as exc:
        parse_export_policy(document)
    assert exc.value.code == "LITE_POLICY_INVALID"


def test_unknown_mode_is_rejected():
    document = {"version": "v1", "datasets": {"ioc": {"fields": [{"name": "kind", "mode": "hash"}]}}}
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
        apply_export_policy(_policy(), "ioc", {"value": "10.0.0.1"}, alias_key=b"key", scope="m")
    assert exc.value.code == "LITE_FIELD_MISSING"


def test_optional_field_missing_from_the_row_is_skipped():
    exported = apply_export_policy(
        _policy(), "ioc", {"value": "10.0.0.1", "kind": "ip"}, alias_key=b"key", scope="m"
    )
    assert "first_seen" not in exported


def test_alias_key_and_scope_are_required():
    for kwargs, code in (
        ({"alias_key": b"", "scope": "m"}, "LITE_ALIAS_KEY_MISSING"),
        ({"alias_key": b"key", "scope": ""}, "LITE_SCOPE_MISSING"),
    ):
        with pytest.raises(LitePolicyError) as exc:
            apply_export_policy(_policy(), "ioc", {"value": "v", "kind": "ip"}, **kwargs)
        assert exc.value.code == code


# --- digest tracks meaning, not spelling -----------------------------------


def test_digest_is_stable_across_field_ordering():
    a = parse_export_policy(
        {"version": "v1", "datasets": {"ioc": {"fields": [{"name": "kind"}, {"name": "value"}]}}}
    )
    b = parse_export_policy(
        {"version": "v1", "datasets": {"ioc": {"fields": [{"name": "value"}, {"name": "kind"}]}}}
    )
    assert a.digest == b.digest


def test_digest_changes_when_the_policy_means_something_different():
    base = _policy()
    for changed in (
        {"version": "lite-export-v2", "datasets": _MINIMAL["datasets"]},
        {
            "version": "lite-export-v1",
            "datasets": {"ioc": {"fields": [{"name": "value", "mode": "allow"}, {"name": "kind"}]}},
        },
        {
            "version": "lite-export-v1",
            "datasets": {"ioc": {"fields": [{"name": "value", "mode": "alias"}]}},
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
