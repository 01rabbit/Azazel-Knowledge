"""Pure semantic producer adapter: Knowledge `/v1/context` -> Fabric Knowledge Context v1.

Scope and limits (read these before reusing this module):

* **Pure conversion.** No clock, no filesystem, no SQLite, no network, no
  randomness, no route, no signature, no mTLS. Every value that is not derivable
  from the two input models is an explicit argument (ids, timestamps, provider,
  snapshot). Nothing here runs at request time.
* **Not wired.** This module is not connected to any HTTP route, runtime or
  worker. It does not authenticate, sign, or open a live connection to a Fabric
  node. Invoking the existing ``/v1/context`` router can still derive
  ``auth.key_id`` and perform local enrichment; this module does not prevent or
  control that, and it is not a substitute for those controls.
* **Caller-supplied claims.** ``snapshot_*``, ``provider_id``, ``generated_at``
  and ``expires_at`` are caller-supplied claims, not facts this adapter verified.
  The adapter does not check current freshness, the snapshot's age, or any
  maximum TTL. Therefore no live route is permitted by this slice.

Mapping rules this adapter enforces:

* **Entity identity is normalized.** Requested entities and match values are
  compared after the Knowledge ``normalize`` API (``azazel_knowledge.normalize``),
  so domain case and IP canonical form do not cause mis-binding. Two requested
  entities that normalize to the same entity are refused as ambiguous.
* **Exact-only facts.** Only an ``ioc_matches`` entry whose ``match_tier`` is
  exactly ``"exact"`` and whose normalized identity equals a normalized
  requested entity becomes a fact. Any other tier (CIDR containment, domain
  suffix, or anything else) is a non-exact match: it yields no fact and no host
  or range claim, and is recorded as a generic unknown instead.
* **Subject is the original request.** Each fact's subject is the exact
  requested ``entity_type`` and ``value`` as the caller sent them, not the
  canonicalized value, so Fabric correlation holds.
* **Generic provenance.** Every fact carries the fixed provenance
  ``knowledge:intel-index`` only if at least one source group is in the fixed
  external-feed allowlist (``abusech``, ``spamhaus`` or ``geoip``). A local-only
  or unrecognized source group yields no fact. Individual group names are
  validated but never serialized, so no feed name or local-tier marker leaves
  the adapter.
* **Explicit absence.** Every requested entity without an exact representable
  fact gets one deterministic unknown keyed by its request index, stating that
  absence of a fact is not a clean verdict. Caller unknowns are preserved after
  these.
* **Score and advice are not mapped.** ``agg_raw_confidence``, score, confidence,
  reason, recommendation, campaign, attack, pattern, history and engagement
  context are never projected as facts or inferences.
* **Advisory-only is preserved.** A directive-shaped key anywhere in the Knowledge
  response aborts the conversion. The Knowledge response is read, never mutated,
  and never copied wholesale into the output.
* **Fail closed.** Anything that cannot be represented faithfully raises
  :class:`KnowledgeContextAdaptationError`. Nothing is truncated, deduplicated
  silently, or dropped on the way to a successful response. Errors name a rule
  and an index, not input values, where possible.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import ValidationError

from azazel_fabric.cti_contracts import assert_advisory_only
from azazel_fabric.knowledge_context import (
    MAX_FACTS,
    MAX_LIMITATIONS,
    MAX_PROVENANCE_REFS,
    MAX_UNKNOWNS,
    RESPONSE_SCHEMA_VERSION,
    KnowledgeContextRequestV1,
    KnowledgeContextResponseV1,
    assert_response_correlates,
)

from azazel_knowledge.api.models import ContextApiRequest, ContextEntity, ContextResponse
from azazel_knowledge.normalize.ioc import normalize

__all__ = [
    "ABSENT_UNKNOWN",
    "APPROXIMATE_UNKNOWN",
    "KnowledgeContextAdaptationError",
    "MAPPING_LIMITATION",
    "PROVENANCE_REF",
    "from_knowledge_context_request",
    "to_knowledge_context_response",
]

#: The only provenance ref any fact carries. It names the Knowledge index itself,
#: never an individual source group, feed, or local-tier marker.
PROVENANCE_REF = "knowledge:intel-index"

# Groups defined by the current public external IOC feeds in config/feeds.yaml.
# The local `edge_reported` group and unknown/future groups are never sufficient
# provenance for an egress fact until explicitly reviewed and added here.
EGRESSIBLE_SOURCE_GROUPS = frozenset({"abusech", "spamhaus", "geoip"})

#: Aggregated unknown recorded for request entity indices without an exact
#: representable fact. Deliberately echoes no entity values.
ABSENT_UNKNOWN = (
    "requested entities at indices {indices} have no exact representable fact; "
    "absence of a fact is not a clean verdict"
)

#: Unknown recorded for a requested entity that could not be normalized.
UNNORMALIZED_UNKNOWN = (
    "requested entities at indices {indices} could not be normalized; "
    "no fact is asserted and "
    "absence of a fact is not a clean verdict"
)

#: Recorded once if any non-exact match was returned. The match is not
#: represented, and no host or range claim is made from it.
APPROXIMATE_UNKNOWN = (
    "a non-exact ioc match was not represented as a fact; "
    "absence of a fact is not a clean verdict"
)

#: Always appended to ``limitations`` so a consumer can see what this profile
#: deliberately does not carry. Fixed text: deterministic output.
MAPPING_LIMITATION = (
    "knowledge output is mapped exact-only: only exact-tier ioc matches become facts, "
    "and only when backed by an approved external source group; local-only or "
    "unrecognized source groups are withheld; "
    "and CIDR, domain-suffix and other non-exact matches are not represented; "
    "knowledge scoring, confidence, aggregate raw confidence, recommendation, "
    "campaign, attack, pattern, history and engagement context are not mapped "
    "to this semantic profile and carry no score or recommendation"
)

_IOC_REQUIRED_KEYS = frozenset({"type", "value", "sources", "match_tier"})
#: Accepted and deliberately ignored: it is a Knowledge aggregate, not a fact.
_IOC_IGNORED_KEYS = frozenset({"agg_raw_confidence"})
_EXACT_TIER = "exact"
_SOURCE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_MAX_ADVISORY_DEPTH = 16


class KnowledgeContextAdaptationError(ValueError):
    """The input cannot be represented faithfully in the v1 semantic profile.

    Raised instead of returning a lossy or partial payload. The message names
    the rule and an index; it deliberately does not echo input values, source
    names, or entity identifiers.
    """


def _validate(model: type, data: Mapping[str, Any], what: str) -> Any:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ())) or "<root>"
        raise KnowledgeContextAdaptationError(
            f"{what} rejected by Knowledge Context v1 at {location}"
        ) from None


def _assert_advisory_inert(value: Any, depth: int = 0) -> None:
    """Reject any directive-shaped key anywhere in the Knowledge response."""

    if depth > _MAX_ADVISORY_DEPTH:
        raise KnowledgeContextAdaptationError("response exceeds maximum nesting depth")
    if isinstance(value, Mapping):
        try:
            assert_advisory_only(value)
        except ValueError:
            raise KnowledgeContextAdaptationError(
                "response violates the advisory-only invariant"
            ) from None
        for child in value.values():
            _assert_advisory_inert(child, depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_advisory_inert(child, depth + 1)


def from_knowledge_context_request(request: KnowledgeContextRequestV1) -> ContextApiRequest:
    """Map a Fabric Knowledge Context request onto the Knowledge ``/v1/context`` query.

    Only the requested entities are carried over. The Fabric ``request_id`` becomes
    the Knowledge ``event_id`` (an opaque correlation handle); if a future route
    uses the existing handler, that ID will be written in its audit event, so it
    must not contain a secret. Everything that would select local actor, edge,
    event or trace history is left empty: the Fabric ``source_product``,
    ``source_ref`` and ``correlation_id`` describe the caller, not a Knowledge
    lookup, so they are never mapped into those fields.
    """

    if type(request) is not KnowledgeContextRequestV1:
        raise TypeError("request must be a KnowledgeContextRequestV1")

    return ContextApiRequest(
        entities=[
            ContextEntity(type=entity.entity_type, value=entity.value)
            for entity in request.entities
        ],
        event={},
        edge_id="",
        actor_key="",
        event_id=request.request_id,
        trace_id=None,
    )


def _canonical_key(entity_type: str, value: str) -> tuple[str, str]:
    """Normalized identity of one entity, via the Knowledge normalize API.

    Raises ``ValueError`` (``NormalizationError`` or a parse error) when the
    value cannot be normalized.
    """

    return entity_type.strip().lower(), normalize(entity_type, value)


def _index_requested(request: KnowledgeContextRequestV1) -> tuple[dict[tuple[str, str], int], set[int]]:
    """Map normalized identity -> request index; collect un-normalizable indices.

    Two requested entities with the same normalized identity are refused: a
    match could then be bound to either, and any fact would be a conflict.
    """

    by_key: dict[tuple[str, str], int] = {}
    unnormalized: set[int] = set()
    for index, entity in enumerate(request.entities):
        try:
            key = _canonical_key(entity.entity_type, entity.value)
        except ValueError:
            unnormalized.add(index)
            continue
        if key in by_key:
            raise KnowledgeContextAdaptationError(
                f"requested entities {by_key[key]} and {index} normalize to the same entity; "
                "a match cannot be bound unambiguously"
            )
        by_key[key] = index
    return by_key, unnormalized


def _parse_match(index: int, match: Any) -> tuple[str, str, str, bool]:
    """Validate one entry; return type, value, tier and egressable-source flag.

    Structure and provenance are checked for every entry, exact or not, so a
    malformed entry fails closed regardless of its tier.
    """

    if not isinstance(match, Mapping):
        raise KnowledgeContextAdaptationError(f"ioc_matches[{index}] is not an object")
    keys = set(match)
    if not _IOC_REQUIRED_KEYS <= keys:
        raise KnowledgeContextAdaptationError(
            f"ioc_matches[{index}] is missing a required key"
        )
    if keys - _IOC_REQUIRED_KEYS - _IOC_IGNORED_KEYS:
        raise KnowledgeContextAdaptationError(
            f"ioc_matches[{index}] carries an unsupported key"
        )

    entity_type = match["type"]
    value = match["value"]
    tier = match["match_tier"]
    if not isinstance(entity_type, str) or not isinstance(value, str):
        raise KnowledgeContextAdaptationError(
            f"ioc_matches[{index}] type and value must be strings"
        )
    if not isinstance(tier, str):
        raise KnowledgeContextAdaptationError(
            f"ioc_matches[{index}] match_tier must be a string"
        )

    sources = match["sources"]
    if not isinstance(sources, list) or not sources:
        raise KnowledgeContextAdaptationError(
            f"ioc_matches[{index}] has no explicit source provenance"
        )
    for source in sources:
        if not isinstance(source, str) or not _SOURCE_NAME_RE.fullmatch(source):
            raise KnowledgeContextAdaptationError(
                f"ioc_matches[{index}] has a malformed source name"
            )
    if len(set(sources)) != len(sources):
        raise KnowledgeContextAdaptationError(
            f"ioc_matches[{index}] repeats a source name"
        )
    if len(sources) > MAX_PROVENANCE_REFS:
        raise KnowledgeContextAdaptationError(
            f"ioc_matches[{index}] carries more sources than the provenance cap of "
            f"{MAX_PROVENANCE_REFS}"
        )
    has_egressable_source = any(source in EGRESSIBLE_SOURCE_GROUPS for source in sources)
    return entity_type, value, tier, has_egressable_source


def _exact_fact(fact_index: int, entity: Any) -> dict[str, Any]:
    """Fact bound to the original requested entity (not the canonical value)."""

    return {
        "fact_id": f"ioc-match-{fact_index}",
        "subject": {"entity_type": entity.entity_type, "value": entity.value},
        "predicate": "matched_indicator",
        "value": "matched",
        "provenance": [PROVENANCE_REF],
    }


def _string_sequence(name: str, values: Iterable[str]) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be a sequence of strings, not a single string")
    return list(values)


def to_knowledge_context_response(
    api_response: ContextResponse,
    request: KnowledgeContextRequestV1,
    *,
    provider_id: str,
    snapshot_ref: str,
    snapshot_state: str,
    snapshot_as_of: Any,
    generated_at: Any,
    expires_at: Any,
    unknowns: Iterable[str] = (),
    limitations: Iterable[str] = (),
) -> KnowledgeContextResponseV1:
    """Map a Knowledge context answer to the Fabric response profile.

    ``request`` supplies the correlation echo (``request_id``, ``correlation_id``,
    ``source_product``, ``source_ref``) and the entity set every claim is bound
    to. ``snapshot_*``, ``provider_id``, ``generated_at``, ``expires_at``,
    ``unknowns`` and ``limitations`` are caller-supplied claims with no defaults:
    Knowledge's response does not carry them in a form this adapter may infer,
    and this adapter does not verify their freshness or TTL.
    """

    if not isinstance(api_response, ContextResponse):
        raise TypeError("api_response must be a ContextResponse")
    if type(request) is not KnowledgeContextRequestV1:
        raise TypeError("request must be a KnowledgeContextRequestV1")

    _assert_advisory_inert(api_response.model_dump(mode="python"))

    threat_context = api_response.threat_context
    if "ioc_matches" not in threat_context:
        raise KnowledgeContextAdaptationError(
            "threat_context.ioc_matches is required; an absent field is malformed"
        )
    raw_matches = threat_context["ioc_matches"]
    if not isinstance(raw_matches, list):
        raise KnowledgeContextAdaptationError("threat_context.ioc_matches must be a list")
    if len(raw_matches) > MAX_FACTS:
        raise KnowledgeContextAdaptationError(
            f"{len(raw_matches)} ioc matches exceed the fact cap of {MAX_FACTS}"
        )

    by_key, unnormalized = _index_requested(request)

    facts: list[dict[str, Any]] = []
    exact_for: dict[int, int] = {}
    approximate_seen = False
    for match_index, match in enumerate(raw_matches):
        entity_type, value, tier, has_egressable_source = _parse_match(match_index, match)
        if tier != _EXACT_TIER:
            # Non-exact (CIDR containment, domain suffix, anything else): no
            # host or range claim. Recorded once as an unknown below.
            approximate_seen = True
            continue
        if not has_egressable_source:
            # A local-only (or not-yet-reviewed) source is not egressable.
            # The requested entity gets a generic unknown below; source class
            # and entity values are not disclosed.
            continue
        try:
            key = _canonical_key(entity_type, value)
        except ValueError:
            raise KnowledgeContextAdaptationError(
                f"ioc_matches[{match_index}] refers to an entity that was not requested "
                "or cannot be normalized"
            ) from None
        entity_index = by_key.get(key)
        if entity_index is None:
            # A match about something the caller did not ask for cannot be bound to
            # a subject. Dropping it would hide evidence; keeping it would be an
            # unbound claim. Both are refused.
            raise KnowledgeContextAdaptationError(
                f"ioc_matches[{match_index}] refers to an entity that was not requested"
            )
        if entity_index in exact_for:
            raise KnowledgeContextAdaptationError(
                f"ioc_matches[{match_index}] duplicates ioc_matches[{exact_for[entity_index]}] "
                "for one requested entity"
            )
        exact_for[entity_index] = match_index
        facts.append(_exact_fact(match_index, request.entities[entity_index]))

    unmatched = set(range(len(request.entities))) - set(exact_for)
    ordinary_unmatched = sorted(unmatched - unnormalized)
    generated_unknowns: list[str] = []
    if ordinary_unmatched:
        generated_unknowns.append(
            ABSENT_UNKNOWN.format(indices=", ".join(map(str, ordinary_unmatched)))
        )
    if unnormalized:
        generated_unknowns.append(
            UNNORMALIZED_UNKNOWN.format(indices=", ".join(map(str, sorted(unnormalized))))
        )
    if approximate_seen:
        generated_unknowns.append(APPROXIMATE_UNKNOWN)

    caller_unknowns = _string_sequence("unknowns", unknowns)
    if len(generated_unknowns) + len(caller_unknowns) > MAX_UNKNOWNS:
        raise KnowledgeContextAdaptationError(
            f"unknowns exceed the Knowledge Context cap of {MAX_UNKNOWNS}"
        )

    limitation_list = _string_sequence("limitations", limitations)
    if len(limitation_list) + 1 > MAX_LIMITATIONS:
        raise KnowledgeContextAdaptationError(
            f"limitations exceed the cap of {MAX_LIMITATIONS} once the mapping limitation is added"
        )
    limitation_list.append(MAPPING_LIMITATION)

    payload = {
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "request_id": request.request_id,
        "correlation_id": request.correlation_id,
        "source_product": request.source_product,
        "source_ref": request.source_ref,
        "provider_id": provider_id,
        "snapshot": {
            "ref": snapshot_ref,
            "state": snapshot_state,
            "as_of": snapshot_as_of,
        },
        "facts": facts,
        "inferences": [],
        "unknowns": generated_unknowns + caller_unknowns,
        "limitations": limitation_list,
        "generated_at": generated_at,
        "expires_at": expires_at,
    }
    response = _validate(KnowledgeContextResponseV1, payload, "response")

    try:
        assert_response_correlates(request, response)
    except (TypeError, ValueError):
        raise KnowledgeContextAdaptationError("response does not correlate with the request") from None
    return response
