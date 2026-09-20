"""`db/outcome_memory.py` must not drift from Azazel-Fabric's `outcome_contracts`.

`outcome_memory` states the four Outcome-as-Evidence records field-for-field
because it builds their INSERTs, and it cannot import `azazel_fabric` to do
it: the dependency is confined to the `api` extra (Absolute Constraint 7) and
the worker that drains this lane runs without that extra installed.

So there are two statements of one contract. That is the exact arrangement
Azazel-Edge#413 removed on the producer side, where Edge's records had been
"byte-for-byte identical to Fabric's models by coincidence of maintenance
rather than by construction". Edge could fix it by construction -- it builds
Fabric's models. Knowledge cannot, so it is fixed by measurement instead:
this file *is* the thing that makes the second statement safe.

The guard is deliberately asymmetric. Fields and vocabularies must match
exactly; refusals and required fields must be a **superset**, because
Knowledge is legitimately stricter (Fabric defaults `evidence_refs`,
`limitations` and the fact maps; a row reaching storage must carry them). It
pins the direction, so "Knowledge is stricter" cannot quietly become
"Knowledge is looser" -- which is the drift that actually costs something.

Writing this guard found real drift already: Fabric had added `effectiveness`
and `initiative_score` to its tactical-claim refusals and Knowledge had not,
so a producer barred from writing `tactical_effect` into a descriptive fact
map could have written `effectiveness: 0.9` instead and meant the same thing.
"""

from __future__ import annotations

import json
import sqlite3
import typing

import pytest

from azazel_fabric.outcome_contracts import (
    ExecutionRefV0,
    MechanismObservationV0,
    OutcomeObservationV0,
    TacticalEffectAssessmentRefV0,
)
from azazel_fabric.outcome_contracts import validation as fabric_validation
from azazel_knowledge.db import outcome_memory
from azazel_knowledge.db.outcome_memory import (
    OutcomeMemoryError,
    ingest_outcome_fact,
    validate_outcome_fact,
)
from azazel_knowledge.db.repository import apply_migrations

# Written out as a literal rather than derived from `_SPECS` or from Fabric's
# `__all__`. A map built by enumerating one of the two things under test
# cannot see a record deleted from that thing -- it would simply have one
# fewer parametrization and stay green.
CONTRACT_MODELS = {
    "outcome-execution/v0.1": ExecutionRefV0,
    "outcome-mechanism/v0.1": MechanismObservationV0,
    "outcome-observation/v0.1": OutcomeObservationV0,
    "tactical-effect-assessment/v0.1": TacticalEffectAssessmentRefV0,
}

#: Outcome-as-Evidence keeps execution, mechanism, outcome and assessment as
#: four separate facts on purpose -- that separation is what stops any one of
#: them reading as "the action worked". A fifth record, or a missing one, is a
#: change to the doctrine and not something this guard should absorb silently.
EXPECTED_RECORD_COUNT = 4


# --------------------------------------------------------------------------
# builders: every sample is built through Fabric's own model, never by hand
# --------------------------------------------------------------------------

OBSERVED_AT = "2026-08-26T00:00:00Z"


def _execution(**overrides) -> dict:
    fields = {
        "producer_product": "AZ-01",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "exec-1",
        "action": "redirect",
        "status": "applied",
        "observed_at": OBSERVED_AT,
        "evidence_refs": ("edge:nft:1",),
    }
    fields.update(overrides)
    return ExecutionRefV0(**fields).model_dump(mode="json")


def _mechanism(**overrides) -> dict:
    fields = {
        "observation_id": "mech-1",
        "producer_product": "AZ-01",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "exec-1",
        "mechanism_kind": "redirection",
        "status": "observed",
        "observed_parameters": {"target": "decoy-1"},
        "observed_at": OBSERVED_AT,
        "evidence_refs": ("edge:nft:1",),
        "limitations": ("single sample",),
    }
    fields.update(overrides)
    return MechanismObservationV0(**fields).model_dump(mode="json")


def _observation(**overrides) -> dict:
    fields = {
        "observation_id": "obs-1",
        "producer_product": "AZ-01",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "exec-1",
        "mechanism_observation_ref": "mech-1",
        "window_start": OBSERVED_AT,
        "window_end": "2026-08-26T00:05:00Z",
        "phase": "after",
        "observation_class": "session_rate",
        "observation_values": {"sessions": 3},
        "telemetry_coverage": {"source": "conntrack"},
        "confounders": ("concurrent scan",),
        "resource_impact": {"cpu_pct": 2},
        "evidence_refs": ("edge:flow:1",),
        "observed_at": "2026-08-26T00:05:00Z",
    }
    fields.update(overrides)
    return OutcomeObservationV0(**fields).model_dump(mode="json")


def _assessment(**overrides) -> dict:
    fields = {
        "assessment_id": "assess-1",
        "producer_product": "AZ-01",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "execution_ref": "exec-1",
        "mechanism_observation_ref": "mech-1",
        "outcome_observation_refs": ("obs-1",),
        "tactical_effect": "divert",
        "assessment": "supported",
        "evaluator": "edge-policy-v3",
        "policy_ref": "policy-1",
        "evidence_refs": ("edge:flow:1",),
        "limitations": ("one window",),
        "observed_at": "2026-08-26T00:06:00Z",
    }
    fields.update(overrides)
    return TacticalEffectAssessmentRefV0(**fields).model_dump(mode="json")


BUILDERS = {
    "outcome-execution/v0.1": _execution,
    "outcome-mechanism/v0.1": _mechanism,
    "outcome-observation/v0.1": _observation,
    "tactical-effect-assessment/v0.1": _assessment,
}


def _literal_values(model, field: str) -> tuple:
    annotation = model.model_fields[field].annotation
    values = typing.get_args(annotation)
    assert values, f"{model.__name__}.{field} is not a Literal"
    return values


# --------------------------------------------------------------------------
# the guard covers everything it claims to
# --------------------------------------------------------------------------


def test_this_guard_covers_every_record_knowledge_stores():
    assert set(outcome_memory._SPECS) == set(CONTRACT_MODELS)


def test_this_guard_covers_every_record_fabric_publishes():
    import azazel_fabric.outcome_contracts as contracts

    published = {
        getattr(contracts, name)
        for name in contracts.__all__
        if isinstance(getattr(contracts, name), type)
    }
    assert published == set(CONTRACT_MODELS.values())


def test_the_record_count_is_pinned():
    """A literal, so deleting a record from both sides still fails here.

    Four separate facts is the doctrine, not an implementation detail: it is
    what stops execution, mechanism, outcome and assessment collapsing into a
    single "it worked".
    """

    assert len(CONTRACT_MODELS) == EXPECTED_RECORD_COUNT
    assert len(BUILDERS) == EXPECTED_RECORD_COUNT
    assert set(BUILDERS) == set(CONTRACT_MODELS)


# --------------------------------------------------------------------------
# fields and vocabularies: exact match
# --------------------------------------------------------------------------


@pytest.mark.parametrize("schema_version", sorted(CONTRACT_MODELS))
def test_the_field_set_matches_fabric_exactly(schema_version):
    model = CONTRACT_MODELS[schema_version]
    spec = outcome_memory._SPECS[schema_version]
    assert spec["fields"] == set(model.model_fields), (
        f"{model.__name__} and outcome_memory disagree about this record's fields; "
        "one of the two statements of the contract has moved"
    )


@pytest.mark.parametrize("schema_version", sorted(CONTRACT_MODELS))
def test_knowledge_never_requires_less_than_fabric(schema_version):
    model = CONTRACT_MODELS[schema_version]
    spec = outcome_memory._SPECS[schema_version]
    fabric_required = {
        name for name, field in model.model_fields.items() if field.is_required()
    }
    assert fabric_required <= spec["required"], (
        "Knowledge accepts a record missing a field Fabric requires"
    )
    assert spec["required"] <= spec["fields"]


def _store_chain_prefix(conn, schema_version: str) -> None:
    """Store the facts the given record needs before it can be inserted."""

    prefix = {
        "outcome-execution/v0.1": (),
        "outcome-mechanism/v0.1": (_execution,),
        "outcome-observation/v0.1": (_execution, _mechanism),
        "tactical-effect-assessment/v0.1": (_execution, _mechanism, _observation),
    }[schema_version]
    for build in prefix:
        ingest_outcome_fact(conn, build(), received_at=OBSERVED_AT)


@pytest.mark.parametrize("schema_version", sorted(CONTRACT_MODELS))
def test_a_field_knowledge_does_not_require_can_actually_be_absent(schema_version):
    """A field declared optional has to survive actually being omitted.

    The superset rule above pins `required` against Fabric, and Fabric
    defaults several fields the INSERT reads with `payload[...]` rather than
    `.get(...)` -- so `required` can be relaxed down to Fabric's own without
    breaking that rule. Relaxing it alone is harmless today, and this test is
    what establishes that rather than assuming it: `_validate_common_identity`
    and the per-branch field validators demand those fields unconditionally,
    so the row is still quarantined rather than reaching the INSERT.

    That makes `required` a *second*, redundant declaration of the same
    rule -- and the failure this test is really for is the day the two stop
    agreeing: a field dropped from `required` whose per-field validator is
    also gone leaves only the INSERT's bare dereference, and the row dies on
    a `KeyError` inside the write transaction instead of being quarantined as
    a bad line. Nothing here may raise anything but `OutcomeMemoryError`; a
    quarantine is a fine answer, a crash in the writer is not.
    """

    optional = outcome_memory._SPECS[schema_version]["fields"] - outcome_memory._SPECS[schema_version]["required"]
    for field in sorted(optional):
        conn = sqlite3.connect(":memory:")
        apply_migrations(conn, "local")
        _store_chain_prefix(conn, schema_version)
        payload = BUILDERS[schema_version]()
        payload.pop(field, None)
        try:
            ingest_outcome_fact(conn, payload, received_at=OBSERVED_AT)
        except OutcomeMemoryError:
            pass
        except Exception as exc:  # noqa: BLE001 - that is the point
            pytest.fail(
                f"omitting optional field {field!r} from {schema_version} raised "
                f"{type(exc).__name__}: {exc}"
            )
        finally:
            conn.close()


@pytest.mark.parametrize(
    ("schema_version", "field", "knowledge_set"),
    [
        ("outcome-mechanism/v0.1", "mechanism_kind", "_ALLOWED_MECHANISMS"),
        ("tactical-effect-assessment/v0.1", "tactical_effect", "_ALLOWED_TACTICAL_EFFECTS"),
        ("outcome-execution/v0.1", "status", "_ALLOWED_EXECUTION_STATUSES"),
        ("outcome-mechanism/v0.1", "status", "_ALLOWED_MECHANISM_STATUSES"),
        ("outcome-observation/v0.1", "phase", "_ALLOWED_PHASES"),
        ("tactical-effect-assessment/v0.1", "assessment", "_ALLOWED_ASSESSMENTS"),
    ],
)
def test_the_named_vocabularies_match_fabric_exactly(schema_version, field, knowledge_set):
    """Exact equality, not containment.

    A vocabulary that has quietly *gained* a member is the failure the
    value-by-value tests below cannot see: they feed Fabric's values in and
    check they are accepted, which stays green for a set with an extra
    member Fabric never named.
    """

    fabric_values = set(_literal_values(CONTRACT_MODELS[schema_version], field))
    assert getattr(outcome_memory, knowledge_set) == fabric_values


@pytest.mark.parametrize(
    ("schema_version", "field"),
    [
        ("outcome-execution/v0.1", "status"),
        ("outcome-mechanism/v0.1", "status"),
        ("outcome-observation/v0.1", "phase"),
        ("tactical-effect-assessment/v0.1", "tactical_effect"),
        ("tactical-effect-assessment/v0.1", "assessment"),
        ("outcome-mechanism/v0.1", "mechanism_kind"),
    ],
)
def test_every_canonical_value_is_accepted_by_knowledge(schema_version, field):
    """Behavioural, not structural.

    Several of Knowledge's closed sets are written inline inside
    `_validate_shape` rather than as module constants, so there is nothing to
    compare. Feeding each canonical value through instead covers those too,
    and would catch a set that matches on paper but is consulted for the
    wrong field.
    """

    build = BUILDERS[schema_version]
    for value in _literal_values(CONTRACT_MODELS[schema_version], field):
        payload = build(**{field: value})
        assert validate_outcome_fact(payload) == schema_version


@pytest.mark.parametrize(
    ("schema_version", "field"),
    [
        ("outcome-execution/v0.1", "status"),
        ("outcome-mechanism/v0.1", "status"),
        ("outcome-mechanism/v0.1", "mechanism_kind"),
        ("outcome-observation/v0.1", "phase"),
        ("tactical-effect-assessment/v0.1", "tactical_effect"),
        ("tactical-effect-assessment/v0.1", "assessment"),
    ],
)
def test_a_value_outside_the_vocabulary_is_refused_by_both(schema_version, field):
    model = CONTRACT_MODELS[schema_version]
    intruder = "not_in_this_vocabulary"
    assert intruder not in _literal_values(model, field)

    with pytest.raises(Exception):
        model(**{**_valid_kwargs(schema_version), field: intruder})

    payload = BUILDERS[schema_version]()
    payload[field] = intruder
    with pytest.raises(OutcomeMemoryError):
        validate_outcome_fact(payload)


def _valid_kwargs(schema_version: str) -> dict:
    """The builder's payload minus the literals the model pins for itself."""

    payload = BUILDERS[schema_version]()
    for pinned in ("schema_version", "authority_class", "executable"):
        payload.pop(pinned, None)
    return payload


@pytest.mark.parametrize("schema_version", sorted(CONTRACT_MODELS))
def test_the_authority_class_pin_matches_fabric(schema_version):
    """Nothing in this lane may relabel whose fact a record is.

    `authority_class` is the field that says the producer asserted this, not
    Knowledge. Fabric pins it per record as a `Literal`; Knowledge must refuse
    every other value rather than store a fact under an authority its producer
    never claimed.
    """

    model = CONTRACT_MODELS[schema_version]
    (canonical,) = _literal_values(model, "authority_class")
    payload = BUILDERS[schema_version]()
    assert payload["authority_class"] == canonical
    assert validate_outcome_fact(payload) == schema_version

    payload["authority_class"] = "arbiter_decision"
    with pytest.raises(OutcomeMemoryError):
        validate_outcome_fact(payload)


# --------------------------------------------------------------------------
# refusals: superset, checked by behaviour
# --------------------------------------------------------------------------


def test_knowledge_refuses_every_directive_key_fabric_refuses():
    assert fabric_validation._BANNED_KEYS <= outcome_memory._BANNED_KEYS
    for key in sorted(fabric_validation._BANNED_KEYS):
        assert outcome_memory._is_forbidden_key(key), key


def test_knowledge_refuses_every_tactical_claim_key_fabric_refuses():
    assert fabric_validation._TACTICAL_CLAIM_KEYS <= outcome_memory._TACTICAL_CLAIM_KEYS
    for key in sorted(fabric_validation._TACTICAL_CLAIM_KEYS):
        assert outcome_memory._is_tactical_claim_key(key), key


@pytest.mark.parametrize(
    "key",
    [
        "effect_class",
        "tactical_effect",
        "effectiveness",
        "initiative_score",
        "observed_tactical_effect",
        "redirect_effectiveness",
        "initiative_score_v2",
        "Effect Class",
    ],
)
def test_a_tactical_claim_in_a_descriptive_fact_map_is_refused_by_both(key):
    """The affix variants are the point.

    `redirect_effectiveness` is the same claim with a product name glued to
    the front. A guard that only compares whole keys reads it as an ordinary
    descriptive measurement and lets a verdict into a fact-only record.
    """

    assert fabric_validation._is_tactical_claim_key(key)
    assert outcome_memory._is_tactical_claim_key(key)

    with pytest.raises(Exception):
        MechanismObservationV0(
            **{**_valid_kwargs("outcome-mechanism/v0.1"), "observed_parameters": {key: 1}}
        )
    payload = _mechanism()
    payload["observed_parameters"] = {key: 1}
    with pytest.raises(OutcomeMemoryError):
        validate_outcome_fact(payload)


@pytest.mark.parametrize("key", ["execute", "command", "approve", "success", "attacker_belief"])
def test_a_directive_in_a_descriptive_fact_map_is_refused_by_both(key):
    with pytest.raises(Exception):
        MechanismObservationV0(
            **{**_valid_kwargs("outcome-mechanism/v0.1"), "observed_parameters": {key: "x"}}
        )
    payload = _mechanism()
    payload["observed_parameters"] = {key: "x"}
    with pytest.raises(OutcomeMemoryError):
        validate_outcome_fact(payload)


FREE_FORM_FIELDS = {
    "outcome-mechanism/v0.1": ("observed_parameters",),
    "outcome-observation/v0.1": (
        "observation_values",
        "telemetry_coverage",
        "resource_impact",
    ),
}


@pytest.mark.parametrize("schema_version", sorted(CONTRACT_MODELS))
def test_the_contract_walks_its_own_payload_for_directives(schema_version):
    """Fabric's models must keep refusing directives without help.

    `api/contracts.fabric_outcome_evidence_lines` calls
    `assert_no_runtime_directives` on each item before validating it. That
    call is a backstop and is unreachable today, because every model here
    runs the same walk over its own dumped payload in a `model_validator` --
    which is the only reason `extra="forbid"` is enough for records carrying
    free-form `dict[str, Any]` fact maps.

    This is the test that keeps "unreachable" true. If a model lost that
    validator, the backstop would quietly become the only thing between a
    directive and a stored fact, and nothing else in this repo would notice.
    """

    model = CONTRACT_MODELS[schema_version]
    free_form = FREE_FORM_FIELDS.get(schema_version)
    if free_form is None:
        # No free-form field: `extra="forbid"` is what refuses a directive,
        # and that is a structural property rather than a validator call.
        assert model.model_config["extra"] == "forbid"
        for field in model.model_fields.values():
            assert field.annotation is not dict, (
                "this record gained a free-form mapping field; the walk above "
                "is now load-bearing for it and this test must cover it"
            )
        return

    for field in free_form:
        with pytest.raises(Exception):
            model(**{**_valid_kwargs(schema_version), field: {"execute": "rm -rf /"}})


# --------------------------------------------------------------------------
# the round trip the whole guard is for
# --------------------------------------------------------------------------


def test_a_record_fabric_built_is_stored_without_alteration():
    conn = sqlite3.connect(":memory:")
    apply_migrations(conn, "local")
    for payload in (_execution(), _mechanism(), _observation(), _assessment()):
        assert ingest_outcome_fact(conn, payload, received_at=OBSERVED_AT) is True

    for table in (
        "outcome_execution_v0",
        "outcome_mechanism_v0",
        "outcome_observation_v0",
        "outcome_effect_assessment_v0",
    ):
        (raw,) = conn.execute(f"SELECT raw FROM {table}").fetchone()
        stored = json.loads(raw)
        model = CONTRACT_MODELS[stored["schema_version"]]
        # Rebuilding the model from the stored bytes and dumping it again must
        # give back the same bytes: anything Knowledge added, dropped or
        # normalized on the way in shows up here.
        assert model(**{k: v for k, v in stored.items()}).model_dump(mode="json") == stored
