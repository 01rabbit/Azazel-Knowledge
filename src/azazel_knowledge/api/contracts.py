"""Azazel-Fabric `cti_contracts` adoption at the API boundary (ADR-0010).

This module is the *only* place `azazel_fabric` is imported (plus `taxii/`
if a Fabric model ever matches an inbox payload -- today none does). Per
Absolute Constraint 7 the dependency lives in the `api` optional extra and
never leaks into `core/`, `scoring/`, or `correlate/`; importing it at module
scope here mirrors how `api/` already assumes `fastapi`/`pydantic` are present
(the api-extra guarantees all three together).

Two boundary concerns are handled, both **additive** -- Knowledge's existing
hand-rolled pipeline stays authoritative and its wire shapes are unchanged:

1.  **Ingest (request side).** `/v1/events|flows|reactions` accept
    line-oriented JSONL of individual items (fire-and-forget; a single
    malformed line is quarantined at drain, never rejecting the batch -- see
    `docs/api.md` and design S4/F-4). That line-oriented shape is *not* the
    Fabric batch **envelope** (`CtiEventBatch` et al. carry
    `batch_id`/`source_product`/`source_device_id`/`generated_at`/`items`).
    `maybe_fabric_batch_lines` therefore type-enforces Fabric **only when the
    caller opts into the canonical envelope shape**, and flattens its `items`
    back into the same JSONL the spool+drain path already consumes. Legacy
    JSONL callers are untouched (they fall through to the existing splitter);
    an envelope that violates the Fabric contract fails closed with a `422`
    in the repo's error convention.

2.  **Context (response side).** The `/v1/context` response is advisory data.
    `assert_response_advisory_only` walks a *copy* of the assembled advisory
    and rejects any directive-shaped field using Fabric's canonical
    `BANNED_DIRECTIVE_FIELDS` / `assert_advisory_only` -- the single
    series-wide source of truth for "what reads as a command." The original
    response bytes are emitted untouched by the caller, so `/v1/context`
    byte-identical replay is preserved (this function never re-serializes).

Knowledge's `/v1/context` **request** shape (entity + event set) and its
response *scores* (0-100, richer `threat_context`) diverge from Fabric's
`CtiContextRequest` (opaque indicator list) and `IocMatch` (0.0-1.0
confidence). Those models are therefore intentionally **not** forced onto the
request or used to re-validate the full response object -- doing so would
either change the documented wire shapes or reject every valid response. The
shape-agnostic advisory-only invariant is the part that genuinely matches,
and it is the part enforced here.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from pydantic import BaseModel, ValidationError

from azazel_knowledge.api import limits

from azazel_fabric.cti_contracts import (
    BANNED_DIRECTIVE_FIELDS,
    CtiEventBatch,
    CtiFlowBatch,
    CtiReactionBatch,
    assert_advisory_only,
)
from azazel_fabric.deception_contracts import (
    EffectivenessAdvisory,
    InteractionObservation,
    assert_no_effectiveness_verdict,
    assert_no_runtime_directives,
)
from azazel_fabric.effect_contracts import EffectObservation, OutcomeObservationEnvelope
from azazel_fabric.engagement_contracts import EngagementAdvisory, EngagementEvent
from azazel_fabric.outcome_contracts import (
    ExecutionRefV0,
    MechanismObservationV0,
    OutcomeObservationV0,
    TacticalEffectAssessmentRefV0,
)
# Aliased, and deliberately not reusing the `assert_no_runtime_directives`
# already imported above from `deception_contracts`: the two are *different
# functions* over different banned sets, and the outcome contracts' own walk
# is the one that defines what a directive is on an outcome record.
from azazel_fabric.outcome_contracts import (
    assert_no_runtime_directives as assert_no_outcome_runtime_directives,
)
from azazel_fabric.schema.defensive_state import coerce_defensive_state

__all__ = [
    "BANNED_DIRECTIVE_FIELDS",
    "IngestBatchInvalid",
    "AdvisoryInvariantViolation",
    "build_engagement_advisory",
    "classify_reported_defensive_state",
    "maybe_fabric_batch_lines",
    "maybe_fabric_engagement_lines",
    "fabric_outcome_evidence_lines",
    "maybe_fabric_observation_lines",
    "fabric_deception_outcome_lines",
    "build_effectiveness_advisory",
    "assert_response_advisory_only",
]

_BATCH_MODELS: dict[str, type[BaseModel]] = {
    "events": CtiEventBatch,
    "flows": CtiFlowBatch,
    "reactions": CtiReactionBatch,
}

# The keys that mark a body as an *intent* to use the Fabric batch envelope
# rather than legacy per-line JSONL. Both are required by every batch model,
# so their joint presence is an unambiguous opt-in signal that also cannot be
# produced by the existing single-item JSONL callers (which carry neither).
_ENVELOPE_MARKERS = ("items", "source_product")


class IngestBatchInvalid(Exception):
    """A body that declared the Fabric batch envelope violates its contract.

    Envelope-level failure only. Item-level (per-line) data problems are never
    surfaced here -- they stay on the fire-and-forget quarantine path.
    """


class AdvisoryInvariantViolation(Exception):
    """The assembled `/v1/context` advisory carried a directive-shaped field."""


def _looks_like_envelope(obj: object) -> bool:
    return isinstance(obj, dict) and all(k in obj for k in _ENVELOPE_MARKERS)


def maybe_fabric_batch_lines(raw_body: bytes, endpoint: str) -> list[str] | None:
    """Return JSONL lines for a Fabric batch envelope, or `None` for legacy JSONL.

    * `None`  -> body is not a Fabric batch envelope; caller uses its existing
      line splitter (legacy JSONL fire-and-forget, unchanged).
    * `list`  -> body is a valid `Cti<Kind>Batch`; its `items` are returned as
      one canonical JSONL line each, ready for the existing spool/drain path.
    * raises `IngestBatchInvalid` -> body declared the envelope shape but
      violates the Fabric contract (fail closed; caller maps to `422`).
    """
    model = _BATCH_MODELS.get(endpoint)
    if model is None:
        return None

    text = raw_body.decode("utf-8", errors="replace").strip()
    # Legacy JSONL never starts as a single top-level JSON object we can treat
    # as an envelope: multi-line batches, bare non-JSON, and single bare items
    # (which lack the envelope markers) all fall through untouched.
    if not text.startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not _looks_like_envelope(obj):
        return None

    try:
        batch = model.model_validate(obj)
    except ValidationError as exc:
        raise IngestBatchInvalid(str(exc)) from exc

    # Flatten to the same canonical JSONL the drain path already validates
    # item-by-item. sort_keys mirrors every other spool writer in the repo.
    return [json.dumps(item, sort_keys=True) for item in batch.items]


# The keys that mark a body as an *intent* to use the deception-observation
# batch envelope rather than legacy per-line JSONL. A single
# `InteractionObservation` carries `environment_id` but never `items`, so the
# joint presence is an unambiguous opt-in that legacy single-item callers cannot
# produce (mirrors `_ENVELOPE_MARKERS` for the Cti* batches). Azazel-Fabric
# v0.6.0 ships no canonical `InteractionObservationBatch` envelope, so the
# envelope is a thin `{environment_id, items:[...]}` wrapper whose `items` are
# each type-enforced against `InteractionObservation` (ADR-0011).
_OBSERVATION_ENVELOPE_MARKERS = ("items", "environment_id")


def _looks_like_observation_envelope(obj: object) -> bool:
    return isinstance(obj, dict) and all(
        k in obj for k in _OBSERVATION_ENVELOPE_MARKERS
    )


def maybe_fabric_observation_lines(
    raw_body: bytes, endpoint: str
) -> list[str] | None:
    """Return JSONL lines for a deception-observation batch envelope, else None.

    Mirrors `maybe_fabric_batch_lines`: a caller that opts into the batch
    envelope has every item type-enforced against Fabric
    `InteractionObservation` (and the fact-only honesty invariant,
    `assert_no_effectiveness_verdict`) at the boundary, failing closed
    (`IngestBatchInvalid` -> `422`) on any violation. Legacy per-line JSONL
    callers get `None` and keep the unchanged fire-and-forget path, where a
    malformed *line* is quarantined at drain, never rejecting the batch.
    """
    if endpoint != "deception-observations":
        return None

    text = raw_body.decode("utf-8", errors="replace").strip()
    if not text.startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not _looks_like_observation_envelope(obj):
        return None

    items = obj["items"]
    if not isinstance(items, list):
        raise IngestBatchInvalid("envelope 'items' must be a list")

    for item in items:
        if not isinstance(item, dict):
            raise IngestBatchInvalid("envelope item must be an object")
        try:
            # Honesty invariant first: a belief/verdict/effectiveness field is a
            # layer-4 claim that must never ride on a fact-only observation.
            assert_no_effectiveness_verdict(item)
            InteractionObservation.model_validate(item)
        except (ValidationError, ValueError) as exc:
            raise IngestBatchInvalid(str(exc)) from exc

    return [json.dumps(item, sort_keys=True) for item in items]


# The pair a Deception feedback bundle (Azazel-Deception#59) carries under
# `outcome` and `runtime_materialization.effect_observation`. Neither alone is
# enough: the envelope holds coverage / gaps / confounders and has no
# `limitations` field, the effect observation holds `limitations` and has no
# coverage. Isolation state and the objective refs are not Fabric fields at
# all; they are visible only as limitation tokens and `evidence_refs`.
_DECEPTION_OUTCOME_ITEM_KEYS = frozenset({"outcome", "effect_observation"})


def fabric_deception_outcome_lines(raw_body: bytes, endpoint: str) -> list[str] | None:
    """Return JSONL lines for a deception outcome-envelope batch, or `None` off-endpoint.

    Like `/v1/outcome-evidence` this lane is new and has no legacy per-line
    caller, so there is no fall-through: a body that is not a valid envelope of
    Fabric-valid items fails closed (`IngestBatchInvalid` -> `422`).

    Beyond the two Fabric models, the boundary checks that the pair describes
    one thing: the envelope's `environment_ref` is the batch's
    `environment_id`, and the effect observation names the same effect, trace
    and producer as the envelope. A pair assembled from two different traces
    is not a corrupted fact, it is two facts, and storing it as one would put
    one trace's coverage next to another trace's limitations.

    Nothing here judges freshness. A late envelope is the one most worth
    keeping, and age is the reader's to state against its own `query_as_of`.
    """

    if endpoint != "deception-outcome-envelopes":
        return None

    text = raw_body.decode("utf-8", errors="replace").strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IngestBatchInvalid(f"body must be a JSON object: {exc}") from exc
    if not isinstance(obj, dict):
        raise IngestBatchInvalid("body must be a JSON object")
    unknown = set(obj) - {"environment_id", "package_id", "items"}
    if unknown:
        raise IngestBatchInvalid(f"unknown envelope fields: {sorted(unknown)}")
    environment_id = obj.get("environment_id")
    if not isinstance(environment_id, str) or not environment_id.strip():
        raise IngestBatchInvalid("envelope 'environment_id' must be a non-empty string")
    package_id = obj.get("package_id")
    if package_id is not None and (not isinstance(package_id, str) or not package_id.strip()):
        raise IngestBatchInvalid("envelope 'package_id' must be a non-empty string when present")
    items = obj.get("items")
    if not isinstance(items, list):
        raise IngestBatchInvalid("envelope 'items' must be a list")
    if len(items) > limits.INGEST_OUTCOME_ENVELOPE_MAX_ITEMS:
        raise IngestBatchInvalid(
            f"envelope carries {len(items)} items; cap is "
            f"{limits.INGEST_OUTCOME_ENVELOPE_MAX_ITEMS}"
        )

    lines: list[str] = []
    for item in items:
        if not isinstance(item, dict) or set(item) != _DECEPTION_OUTCOME_ITEM_KEYS:
            raise IngestBatchInvalid(
                "envelope item must be an object with exactly 'outcome' and 'effect_observation'"
            )
        try:
            # Honesty invariant first, over the whole item: a verdict-shaped
            # key is a layer-4 claim that must never ride on a fact.
            assert_no_effectiveness_verdict(item)
            envelope = OutcomeObservationEnvelope.model_validate(item["outcome"])
            effect = EffectObservation.model_validate(item["effect_observation"])
        except (ValidationError, ValueError) as exc:
            raise IngestBatchInvalid(str(exc)) from exc

        if envelope.environment_ref != f"environment:{environment_id}":
            raise IngestBatchInvalid("outcome environment_ref is not the batch environment")
        if envelope.effect_ref is None:
            raise IngestBatchInvalid("outcome must name the effect it observed (effect_ref)")
        if effect.effect_ref != envelope.effect_ref:
            raise IngestBatchInvalid("effect_observation belongs to a different effect")
        if effect.trace_id != envelope.trace_id:
            raise IngestBatchInvalid("effect_observation belongs to a different trace")
        if effect.materialization_producer != envelope.producer_product:
            raise IngestBatchInvalid("effect_observation was produced by a different product")

        line = {
            "environment_id": environment_id,
            "package_id": package_id,
            "outcome": envelope.model_dump(mode="json"),
            "effect_observation": effect.model_dump(mode="json"),
        }
        lines.append(json.dumps(line, sort_keys=True))

    return lines


# An `EngagementEvent` records what a product selected and the reaction it
# observed. It carries no actor and no edge identity -- it says what was done,
# not to whom -- so the envelope supplies both. Their joint presence with
# `items` is the opt-in signal, and is a shape no legacy per-line caller
# produces.
_ENGAGEMENT_ENVELOPE_MARKERS = ("items", "edge_id", "actor_key")


def _looks_like_engagement_envelope(obj: object) -> bool:
    return isinstance(obj, dict) and all(
        k in obj for k in _ENGAGEMENT_ENVELOPE_MARKERS
    )


def maybe_fabric_engagement_lines(raw_body: bytes, endpoint: str) -> list[str] | None:
    """Return JSONL lines for an engagement-event batch envelope, else None.

    Azazel-Edge builds a Fabric `EngagementEvent` "for audit / Knowledge
    ingest" (its own words); this is the boundary that reads one. Every item is
    type-enforced against the canonical model and fails closed
    (`IngestBatchInvalid` -> `422`) on a contract violation, mirroring
    `maybe_fabric_observation_lines`.

    An `EngagementEvent` is descriptive by contract — "the product records what
    it selected and the reaction it observed; this contract never re-runs the
    action" — and Knowledge reading one changes nothing about that. Knowledge
    advises; a record of somebody else's selection is not Knowledge's.

    The envelope's `edge_id`/`actor_key` are folded onto each emitted line
    because the contract models neither, and a row that could not be attributed
    to an actor would be unusable for the correlation this lane exists to feed.
    They are written under `_envelope_` names so a reader can tell a field the
    producer sent from one the envelope supplied — and so an item that carried
    those names itself could not be mistaken for the envelope's answer.
    """

    if endpoint != "engagement-events":
        return None

    text = raw_body.decode("utf-8", errors="replace").strip()
    if not text.startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not _looks_like_engagement_envelope(obj):
        return None

    items = obj["items"]
    if not isinstance(items, list):
        raise IngestBatchInvalid("envelope 'items' must be a list")

    edge_id = obj["edge_id"]
    actor_key = obj["actor_key"]
    for name, value in (("edge_id", edge_id), ("actor_key", actor_key)):
        if not isinstance(value, str) or not value.strip():
            raise IngestBatchInvalid(f"envelope {name!r} must be a non-empty string")

    lines: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise IngestBatchInvalid("envelope item must be an object")
        try:
            # A directive has no business on a record of something already
            # done.
            #
            # Today this is unreachable: every model in the `EngagementEvent`
            # tree sets `extra="forbid"` and none has a free-form mapping
            # field, so a directive key is rejected by the model before this
            # sees it -- unlike `EngagementAdvisory`, whose `prior_outcomes`
            # has free-form keys and where the same walk is load-bearing. It
            # is kept as a backstop for this contract gaining such a field,
            # and `test_the_contract_has_no_free_form_field_yet` fails on the
            # day it does, so the backstop cannot be promoted to the only
            # thing standing without anyone noticing.
            assert_no_runtime_directives(item)
            event = EngagementEvent.model_validate(item)
        except (ValidationError, ValueError) as exc:
            raise IngestBatchInvalid(str(exc)) from exc

        line = event.model_dump(mode="json")
        line["_envelope_edge_id"] = edge_id
        line["_envelope_actor_key"] = actor_key
        lines.append(json.dumps(line, sort_keys=True))

    return lines


# Azazel-Fabric's four Outcome-as-Evidence records, keyed by the
# `schema_version` each one pins as a `Literal`. The key is read off the item
# rather than declared by the envelope: a batch is a mixed chain (execution,
# then the mechanism/outcome/assessment facts that reference it), so one
# envelope-level type would either split the chain across four requests or
# force the envelope to lie about three quarters of its contents.
_OUTCOME_MODELS: dict[str, type[BaseModel]] = {
    "outcome-execution/v0.1": ExecutionRefV0,
    "outcome-mechanism/v0.1": MechanismObservationV0,
    "outcome-observation/v0.1": OutcomeObservationV0,
    "tactical-effect-assessment/v0.1": TacticalEffectAssessmentRefV0,
}


def fabric_outcome_evidence_lines(raw_body: bytes, endpoint: str) -> list[str] | None:
    """Return JSONL lines for an outcome-evidence batch, or `None` off-endpoint.

    Azazel-Edge's `outcome/shared_export.py` builds these four Fabric models
    and dumps them, with "deliberately no fallback" -- a record Fabric did not
    validate must not travel as one that it did. This is the reader that holds
    up the other end of that statement.

    **Unlike every other ingest lane, this one has no legacy path.** The
    `Cti<Kind>Batch` and deception endpoints predate Fabric and carry
    documented per-line JSONL callers, so there `None` means "fall through to
    the line splitter". `/v1/outcome-evidence` is new and has no such caller,
    so admitting a non-envelope body would be manufacturing a legacy on
    purpose -- and a lane where the contract is optional is a lane where the
    consumption is optional. A body that is not a valid envelope of
    Fabric-valid items fails closed (`IngestBatchInvalid` -> `422`).

    `None` is returned only for a different endpoint, so the caller's
    fall-through never applies to this one.

    What travels onward is `model_dump(mode="json")`, not the caller's bytes:
    the fields Fabric defaults (`evidence_refs`, `limitations`, the fact maps,
    and the pinned `schema_version`/`authority_class` literals) are then
    present explicitly, which is what the drain's storage rules require.
    """

    if endpoint != "outcome-evidence":
        return None

    text = raw_body.decode("utf-8", errors="replace").strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IngestBatchInvalid(f"body must be a JSON object: {exc}") from exc
    if not isinstance(obj, dict):
        raise IngestBatchInvalid("body must be a JSON object")
    items = obj.get("items")
    if not isinstance(items, list):
        raise IngestBatchInvalid("envelope 'items' must be a list")

    lines: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise IngestBatchInvalid("envelope item must be an object")
        schema_version = item.get("schema_version")
        model = _OUTCOME_MODELS.get(schema_version) if isinstance(schema_version, str) else None
        if model is None:
            # Not "unknown, so pass it through and let the drain judge": an
            # item whose `schema_version` this boundary does not recognize is
            # an item no Fabric model validated, and the whole point of this
            # lane is that nothing else gets in.
            raise IngestBatchInvalid(
                f"unsupported outcome evidence schema_version: {schema_version!r}"
            )
        try:
            # A backstop, and today an unreachable one: every model in this
            # contract runs `assert_no_runtime_directives` over its own dumped
            # payload in a `model_validator`, so a directive is refused below
            # whether or not this line is here -- including one buried in the
            # free-form `dict[str, Any]` fact maps (`observed_parameters`,
            # `observation_values`, `telemetry_coverage`, `resource_impact`)
            # that `extra="forbid"` does not look inside.
            #
            # It is kept because what makes it unreachable is Fabric's
            # decision to walk its own payload, not anything this boundary
            # controls, and a contract that dropped that validator would
            # otherwise start admitting directives here silently.
            # `test_the_contract_walks_its_own_payload_for_directives` fails
            # on the day that changes, so the backstop cannot become the only
            # thing standing without anyone noticing.
            assert_no_outcome_runtime_directives(item)
            record = model.model_validate(item)
        except (ValidationError, ValueError) as exc:
            raise IngestBatchInvalid(str(exc)) from exc
        lines.append(json.dumps(record.model_dump(mode="json"), sort_keys=True))

    return lines


def build_effectiveness_advisory(advisory_fields: Mapping[str, Any]) -> dict[str, Any]:
    """Type-enforce Knowledge's effectiveness output as a Fabric EffectivenessAdvisory.

    The advisory is advisory-only and non-executable by construction:
    `EffectivenessAdvisory` pins `executable=False`, forbids extra fields, and
    is structurally incapable of carrying a belief/verdict field. This also runs
    the runtime-directive invariant over the assembled advisory. Any failure is
    an internal invariant violation -> `AdvisoryInvariantViolation` (the caller
    fails closed `500` and never emits the advisory). Returns a JSON-ready dict.
    """
    try:
        assert_no_runtime_directives(advisory_fields)
        model = EffectivenessAdvisory.model_validate(advisory_fields)
    except (ValidationError, ValueError) as exc:
        raise AdvisoryInvariantViolation(str(exc)) from exc
    return model.model_dump(mode="json")


def classify_reported_defensive_state(reported_state: object) -> tuple[str | None, bool]:
    """Say whether a reported state is in the canonical vocabulary (Knowledge#65 AC-6).

    Returns ``(canonical_state, recognized)``. ``canonical_state`` is the
    Fabric ``DefensiveState`` value when the report is one, and ``None``
    otherwise.

    **It is never the coercion fallback.** `coerce_defensive_state` lands an
    unrecognized value on ``OBSERVE`` so that a *consumer deciding what to do*
    fails safe. Knowledge is not that consumer: it is reporting what a producer
    said. Emitting ``OBSERVE`` here would turn "Edge said something this
    vocabulary does not know" into "Edge said OBSERVE", which is Knowledge
    asserting another product's posture -- the one thing this lane must not do.
    So the fallback is discarded and only the ``recognized`` flag is kept.

    The stored value is never rewritten. `db/defensive_state_memory.py` carries
    `reported_state` exactly as it arrived and enumerates nothing; this
    function lives here because `azazel_fabric` is an `api`-extra dependency
    and must not leak into `db/` (Absolute Constraint 7).
    """

    coerced, recognized = coerce_defensive_state(reported_state)
    return (coerced.value if recognized else None), recognized


def build_engagement_advisory(
    advisory_fields: Mapping[str, Any], *, advisory_id: str, advisor: str
) -> dict[str, Any]:
    """Type-enforce Knowledge's engagement output as a Fabric `EngagementAdvisory`.

    Advisory-only and non-executable **by construction**: the Fabric model pins
    `authority="advisory_only"` and `executable=False` as `Literal` types and
    forbids extra fields, so a suggestion cannot acquire a command, a deadline,
    a handler name, or a firewall rule on the way out -- not because this
    function strips them, but because the model has nowhere to put them.

    `posture_suggestion` is validated as a Fabric `PostureSuggestion`, which
    means its objective, approach and activities must be canonical Engage
    values. Knowledge never widens that vocabulary here.

    Any failure is an internal invariant violation, so the caller fails closed
    with a `500` and never emits the advisory.
    """

    fields = dict(advisory_fields)
    # Knowledge-local context that the Fabric contract does not model. Carried
    # in the response beside the advisory rather than forced into it: widening
    # a shared contract to fit a product-local field is how shared contracts
    # stop being shared.
    fields.pop("repeatability_score", None)
    fields["advisory_id"] = advisory_id
    fields["advisor"] = advisor
    try:
        # The recursive walk is NOT redundant with `extra="forbid"`:
        # `prior_outcomes` is `dict[str, dict[...]]`, so its keys are
        # free-form and a directive could hide one level down where the
        # model's own field validation never looks.
        assert_no_runtime_directives(fields)
        # `posture_suggestion` needs no separate validation here --
        # `EngagementAdvisory` types it as `PostureSuggestion | None` and
        # validates it on the line below. An explicit second call would be
        # dead code wearing a guard's clothes.
        model = EngagementAdvisory.model_validate(fields)
    except (ValidationError, ValueError) as exc:
        raise AdvisoryInvariantViolation(str(exc)) from exc
    return model.model_dump(mode="json")


def assert_response_advisory_only(payload: Any) -> None:
    """Recursively reject directive-shaped fields anywhere in an advisory.

    Uses Fabric's `assert_advisory_only` (and thus `BANNED_DIRECTIVE_FIELDS`)
    as the canonical, series-wide definition of a directive-shaped field, but
    walks every nested mapping/sequence because a banned key could be buried
    inside `recommendation`, `threat_context`, or a behavioral block rather
    than at the top level. Raises `AdvisoryInvariantViolation` on the first
    offending mapping; the caller fails closed and never emits the response.

    Operates on the passed-in structure only (the caller hands it a copy/view
    built from pipeline output) and never mutates or re-serializes it, so the
    emitted response bytes are unaffected.
    """
    try:
        _walk_advisory_only(payload)
    except ValueError as exc:  # raised by Fabric.assert_advisory_only
        raise AdvisoryInvariantViolation(str(exc)) from exc


def _walk_advisory_only(node: Any) -> None:
    if isinstance(node, Mapping):
        assert_advisory_only(node)
        for value in node.values():
            _walk_advisory_only(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            _walk_advisory_only(item)
