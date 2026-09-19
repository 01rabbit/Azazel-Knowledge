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
from azazel_fabric.engagement_contracts import EngagementAdvisory

__all__ = [
    "BANNED_DIRECTIVE_FIELDS",
    "IngestBatchInvalid",
    "AdvisoryInvariantViolation",
    "build_engagement_advisory",
    "maybe_fabric_batch_lines",
    "maybe_fabric_observation_lines",
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
