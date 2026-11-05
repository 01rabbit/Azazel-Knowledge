"""Specification tests for the Knowledge -> Fabric Knowledge Context v1 producer adapter.

These pin the adapter's contract, not its implementation:

* deterministic, side-effect-free conversion with explicit inputs only;
* the request direction maps only requested entities and the request id onto a
  Knowledge ``ContextApiRequest``; Fabric source/correlation fields never reach
  local actor/edge/event/trace selectors;
* ``correlation_id`` is the explicit argument, never the Knowledge ``trace_id``;
* facts are exact-only, bound to the original requested entity after
  normalization, and carry the fixed generic provenance;
* absence of an exact fact is an explicit unknown, never a clean verdict;
* source group names and local-tier markers never reach canonical bytes;
* inferences are never invented; snapshot/timestamp claims are never invented;
* anything unrepresentable fails closed rather than being truncated or dropped;
* advisory-only: directive-shaped keys abort the conversion;
* the inputs are never mutated.

The module needs the ``api`` extra (``azazel-fabric``). Without it the whole
file is skipped rather than failing at import.
"""

from __future__ import annotations

import copy
import inspect
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("azazel_fabric.knowledge_context")

from azazel_fabric.knowledge_context import (  # noqa: E402
    MAX_ENTITIES,
    REQUEST_SCHEMA_VERSION,
    KnowledgeContextRequestV1,
    KnowledgeContextResponseV1,
    assert_response_correlates,
    canonical_knowledge_context_bytes,
)

from azazel_knowledge.api import knowledge_context_adapter as adapter  # noqa: E402
from azazel_knowledge.api.knowledge_context_adapter import (  # noqa: E402
    ABSENT_UNKNOWN,
    APPROXIMATE_UNKNOWN,
    MAPPING_LIMITATION,
    PROVENANCE_REF,
    KnowledgeContextAdaptationError,
    from_knowledge_context_request,
    to_knowledge_context_response,
)
from azazel_knowledge.api.models import ContextApiRequest, ContextResponse  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = REPO_ROOT / "src" / "azazel_knowledge" / "api" / "knowledge_context_adapter.py"

IP = "198.51.100.7"
DOMAIN = "example.test"

REQ_KW = {
    "request_id": "req-0001",
    "correlation_id": "corr-0001",
    "source_product": "example-edge",
    "source_ref": "opaque:src-0001",
    "requested_at": "2026-11-04T00:00:00Z",
}
RESP_KW = {
    "provider_id": "example-knowledge",
    "snapshot_ref": "snapshot:2026-11-04-0001",
    "snapshot_state": "complete",
    "snapshot_as_of": "2026-11-04T00:00:00Z",
    "generated_at": "2026-11-04T00:00:05Z",
    "expires_at": "2026-11-04T01:00:00Z",
}


def _fabric_request(
    entities=(("ip", IP), ("domain", DOMAIN)),
    **overrides,
) -> KnowledgeContextRequestV1:
    payload = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        **REQ_KW,
        "entities": [{"entity_type": t, "value": v} for t, v in entities],
        **overrides,
    }
    return KnowledgeContextRequestV1.model_validate(payload)


def _api_response(
    ioc_matches=None,
    *,
    threat_context_extra: dict | None = None,
    recommendation: dict | None = None,
    with_ioc_key: bool = True,
) -> ContextResponse:
    threat_context: dict = {}
    if with_ioc_key:
        threat_context["ioc_matches"] = [] if ioc_matches is None else ioc_matches
    threat_context.update(threat_context_extra or {})
    return ContextResponse(
        threat_context=threat_context,
        threat_score=75.0,
        confidence=65.0,
        reason=[{"component": "ioc_match", "contribution": 29}],
        confidence_reason=[{"driver": "source_count", "contribution": 15}],
        recommendation=recommendation or {"action": "throttle"},
        source_freshness={"oldest_feed_days": 12},
        advisory_id="01JZB2Q8D6NNM2KX4Y7P3A5R9C",
        multi_ioc_scope={"matched_count": len(ioc_matches or [])},
    )


def _match(
    value: str = IP,
    type_: str = "ip",
    sources=("abusech",),
    tier: str = "exact",
) -> dict:
    return {
        "type": type_,
        "value": value,
        "match_tier": tier,
        "agg_raw_confidence": 0.8,
        "sources": list(sources),
    }


def _request(request: KnowledgeContextRequestV1 | None = None) -> KnowledgeContextRequestV1:
    return request or _fabric_request()


def _response(api_response: ContextResponse, request: KnowledgeContextRequestV1 | None = None):
    return to_knowledge_context_response(api_response, request or _request(), **RESP_KW)


def _absent(*indices: int) -> str:
    return ABSENT_UNKNOWN.format(indices=", ".join(map(str, indices)))


# --- determinism and side effects -----------------------------------------


def test_request_mapping_is_deterministic():
    first = from_knowledge_context_request(_request()).model_dump(mode="python")
    second = from_knowledge_context_request(_request()).model_dump(mode="python")
    assert first == second


def test_response_conversion_is_deterministic():
    api_response = _api_response([_match(), _match(DOMAIN, "domain", ("spamhaus",))])
    first = canonical_knowledge_context_bytes(_response(api_response))
    second = canonical_knowledge_context_bytes(_response(api_response))
    assert first == second


def test_output_is_a_validated_fabric_model():
    response = _response(_api_response([_match()]))
    assert type(response) is KnowledgeContextResponseV1
    assert response.schema_version == "knowledge-context-response/v1"
    assert response.authority == "advisory_only"


def test_adapter_module_reads_no_clock_no_randomness_no_io():
    text = ADAPTER_PATH.read_text(encoding="utf-8")
    forbidden = (
        r"datetime\.now",
        r"datetime\.utcnow",
        r"time\.time",
        r"\bimport random\b",
        r"\bimport secrets\b",
        r"\buuid\b",
        r"\bsqlite3\b",
        r"\bsocket\b",
        r"\burllib\b",
        r"\bhttpx\b",
        r"\brequests\b",
        r"\bos\.environ\b",
        r"\bopen\(",
    )
    offenders = [pattern for pattern in forbidden if re.search(pattern, text)]
    assert offenders == []


def test_module_docstring_states_not_wired_and_unverified_freshness():
    doc = " ".join((adapter.__doc__ or "").split())
    assert "Optional route caller" in doc
    assert "candidate-only" in doc
    assert "does not authenticate" in doc
    assert "does not check current freshness" in doc
    assert "enforces" in doc and "maximum response TTL" in doc


def test_snapshot_and_timestamp_claims_have_no_defaults():
    # Explicit claims only: the adapter may never invent a snapshot, provider,
    # freshness or expiry value.
    params = inspect.signature(to_knowledge_context_response).parameters
    for name in (
        "provider_id",
        "snapshot_ref",
        "snapshot_state",
        "snapshot_as_of",
        "generated_at",
        "expires_at",
    ):
        assert params[name].default is inspect.Parameter.empty, name


def test_claims_are_carried_verbatim_not_silently_replaced():
    kwargs = {**RESP_KW, "generated_at": "2026-11-04T00:00:02Z"}
    response = to_knowledge_context_response(_api_response([_match()]), _request(), **kwargs)
    assert response.generated_at == datetime(2026, 11, 4, 0, 0, 2, tzinfo=timezone.utc)


# --- request direction: Fabric request -> Knowledge ContextApiRequest ------


def test_request_mapping_returns_a_knowledge_context_api_request():
    mapped = from_knowledge_context_request(_request())
    assert type(mapped) is ContextApiRequest


def test_request_mapping_preserves_requested_entities_in_order():
    mapped = from_knowledge_context_request(_request())
    assert [(e.type, e.value) for e in mapped.entities] == [("ip", IP), ("domain", DOMAIN)]


def test_request_mapping_uses_request_id_as_event_id():
    mapped = from_knowledge_context_request(_request())
    assert mapped.event_id == REQ_KW["request_id"]


def test_request_mapping_leaves_event_edge_actor_and_trace_empty():
    mapped = from_knowledge_context_request(_request())
    assert mapped.event == {}
    assert mapped.edge_id == ""
    assert mapped.actor_key == ""
    assert mapped.trace_id is None


def test_fabric_source_and_correlation_never_reach_local_selectors():
    request = _fabric_request(
        source_product="SENTINEL-PRODUCT-42",
        source_ref="opaque:SENTINEL-REF-42",
        correlation_id="SENTINEL-CORR-42",
    )
    mapped = from_knowledge_context_request(request)
    dumped = repr(mapped.model_dump(mode="python"))
    for sentinel in ("SENTINEL-PRODUCT-42", "SENTINEL-REF-42", "SENTINEL-CORR-42"):
        assert sentinel not in dumped
    assert mapped.edge_id == ""
    assert mapped.actor_key == ""
    assert mapped.trace_id is None


def test_request_mapping_does_not_copy_fabric_timestamp():
    mapped = from_knowledge_context_request(_request())
    assert "2026-11-04T00:00:00Z" not in repr(mapped.model_dump(mode="python"))


@pytest.mark.parametrize(
    "not_a_request",
    [
        {"entities": [{"entity_type": "ip", "value": IP}]},
        ContextApiRequest(entities=[{"type": "ip", "value": IP}]),
        SimpleNamespace(entities=[], request_id="req-0001"),
        None,
    ],
    ids=["dict", "knowledge-api-request", "duck-typed-namespace", "none"],
)
def test_request_mapping_refuses_anything_but_the_exact_fabric_request_type(not_a_request):
    with pytest.raises(TypeError):
        from_knowledge_context_request(not_a_request)  # type: ignore[arg-type]


def test_request_mapping_does_not_mutate_its_input():
    request = _fabric_request()
    before = copy.deepcopy(request.model_dump(mode="python"))
    from_knowledge_context_request(request)
    assert request.model_dump(mode="python") == before


def test_request_mapping_carries_the_full_entity_cap():
    at_cap = tuple(("ip", f"198.51.100.{i}") for i in range(MAX_ENTITIES))
    request = _fabric_request(entities=at_cap)
    mapped = from_knowledge_context_request(request)
    assert len(mapped.entities) == MAX_ENTITIES
    response = _response(_api_response([]), request)
    assert response.unknowns == (_absent(*range(MAX_ENTITIES)),)


# --- correlation echo and identity -----------------------------------------


def test_correlation_id_is_the_explicit_argument_not_trace_id():
    request = _request()
    assert request.correlation_id == REQ_KW["correlation_id"]
    mapped = from_knowledge_context_request(request)
    assert mapped.trace_id is None
    response = _response(_api_response([_match()]), request)
    assert response.correlation_id == REQ_KW["correlation_id"]
    assert b"trace-SENTINEL-77" not in canonical_knowledge_context_bytes(response)


def test_request_and_response_pass_fabric_correlation():
    request = _request()
    response = _response(_api_response([_match()]), request)
    assert_response_correlates(request, response)


def test_explicit_snapshot_and_provider_are_carried_verbatim():
    response = _response(_api_response([_match()]))
    assert response.provider_id == RESP_KW["provider_id"]
    assert response.snapshot.ref == RESP_KW["snapshot_ref"]
    assert response.snapshot.state == "complete"


# --- normalization and exact-only binding -----------------------------------


def test_domain_case_difference_binds_exact_match_to_original_requested_value():
    request = _fabric_request(entities=(("domain", "Example.TEST"),))
    response = _response(_api_response([_match("example.test", "domain")]), request)
    assert len(response.facts) == 1
    subject = response.facts[0].subject
    assert (subject.entity_type, subject.value) == ("domain", "Example.TEST")
    assert response.unknowns == ()


def test_ipv6_canonical_form_binds_exact_match_to_original_requested_value():
    raw = "2001:DB8:0:0:0:0:0:1"
    request = _fabric_request(entities=(("ip", raw),))
    response = _response(_api_response([_match("2001:db8::1", "ip")]), request)
    assert len(response.facts) == 1
    assert response.facts[0].subject.value == raw
    assert_response_correlates(request, response)


def test_cidr_containment_match_is_an_unknown_and_produces_no_fact():
    api_response = _api_response(
        [_match("198.51.100.0/24", "cidr", tier="cidr_/24")]
    )
    response = _response(api_response)
    assert response.facts == ()
    assert APPROXIMATE_UNKNOWN in response.unknowns
    assert _absent(0, 1) in response.unknowns
    assert b"198.51.100.0/24" not in canonical_knowledge_context_bytes(response)


def test_domain_suffix_match_makes_no_host_claim():
    request = _fabric_request(entities=(("domain", "host.example.test"),))
    api_response = _api_response(
        [_match("example.test", "domain", tier="domain_suffix")]
    )
    response = _response(api_response, request)
    assert response.facts == ()
    assert APPROXIMATE_UNKNOWN in response.unknowns
    assert _absent(0) in response.unknowns


@pytest.mark.parametrize("tier", ["", "EXACT", "intel", "cidr_/24", "domain_suffix"])
def test_only_exactly_exact_tier_becomes_a_fact(tier):
    response = _response(_api_response([_match(IP, "ip", tier=tier)]))
    assert response.facts == ()
    assert APPROXIMATE_UNKNOWN in response.unknowns


def test_match_about_an_unrequested_entity_fails_closed():
    api_response = _api_response([_match("203.0.113.9")])
    with pytest.raises(KnowledgeContextAdaptationError, match="not requested"):
        _response(api_response)


def test_refusal_error_does_not_echo_the_offending_value():
    api_response = _api_response([_match("203.0.113.9")])
    with pytest.raises(KnowledgeContextAdaptationError) as info:
        _response(api_response)
    assert "203.0.113.9" not in str(info.value)


def test_match_with_a_mismatched_type_is_unbound_and_refused():
    api_response = _api_response([_match(IP, "domain")])
    with pytest.raises(KnowledgeContextAdaptationError, match="not requested"):
        _response(api_response)


def test_duplicate_normalized_requests_are_refused_not_bound_twice():
    request = _fabric_request(entities=(("domain", "Example.test"), ("domain", "example.TEST")))
    with pytest.raises(KnowledgeContextAdaptationError, match="normalize to the same entity"):
        _response(_api_response([_match("example.test", "domain")]), request)


def test_duplicate_exact_matches_for_one_entity_are_refused():
    with pytest.raises(KnowledgeContextAdaptationError, match="duplicates"):
        _response(_api_response([_match(IP), _match(IP)]))


def test_unnormalizable_requested_entity_yields_unknown_without_echo():
    request = _fabric_request(entities=(("ip", "not-an-ip-SENTINEL"), ("domain", DOMAIN)))
    response = _response(_api_response([]), request)
    assert response.facts == ()
    assert _absent(1) in response.unknowns
    assert any("could not be normalized" in u and "0" in u for u in response.unknowns)
    assert not any("SENTINEL" in u for u in response.unknowns)
    assert b"not-an-ip-SENTINEL" not in canonical_knowledge_context_bytes(response)


def test_unrequested_entity_without_exact_match_is_unknown_not_clean():
    response = _response(_api_response([]))
    assert response.facts == ()
    assert response.unknowns == (_absent(0, 1),)


def test_inferences_are_never_invented():
    response = _response(_api_response([_match()]))
    assert response.inferences == ()


def test_recommendation_and_scores_never_leak_into_the_profile():
    api_response = _api_response([_match()], recommendation={"action": "SENTINEL-ACTION-42"})
    payload = canonical_knowledge_context_bytes(_response(api_response))
    assert b"SENTINEL-ACTION-42" not in payload
    assert b"threat_score" not in payload
    assert b"advisory_id" not in payload


def test_aggregate_raw_confidence_is_never_projected_as_a_fact():
    api_response = _api_response([{**_match(), "agg_raw_confidence": 0.9137}])
    payload = canonical_knowledge_context_bytes(_response(api_response))
    assert b"0.9137" not in payload
    assert b"agg_raw_confidence" not in payload


def test_mapping_limitation_states_exact_only_and_no_score_or_recommendation():
    response = _response(_api_response([_match()]))
    assert MAPPING_LIMITATION in response.limitations
    assert "exact-only" in MAPPING_LIMITATION
    assert "score" in MAPPING_LIMITATION
    assert "recommendation" in MAPPING_LIMITATION


# --- provenance: generic, never source names --------------------------------


def test_provenance_is_the_fixed_generic_index_ref():
    response = _response(_api_response([_match(sources=("abusech",))]))
    assert response.facts[0].provenance == (PROVENANCE_REF,)
    assert PROVENANCE_REF == "knowledge:intel-index"


@pytest.mark.parametrize(
    "sentinel",
    ["SENTINEL-PUBLIC-FEED", "edge_reported", "local_edge"],
)
def test_source_group_and_local_tier_names_never_enter_canonical_bytes(sentinel):
    api_response = _api_response(
        [_match(sources=("abusech", "SENTINEL-PUBLIC-FEED", "edge_reported", "local_edge"))]
    )
    payload = canonical_knowledge_context_bytes(_response(api_response))
    assert sentinel.encode() not in payload
    if sentinel == "edge_reported":
        for source_group in ("edge_reported", "future_unreviewed_group"):
            response = _response(_api_response([_match(sources=(source_group,))]))
            assert response.facts == ()
            assert response.unknowns == (_absent(0, 1),)
            payload = canonical_knowledge_context_bytes(response)
            assert source_group.encode() not in payload
            assert IP.encode() not in payload


def test_source_names_are_validated_but_not_serialized():
    response = _response(_api_response([_match(sources=("spamhaus", "abusech"))]))
    assert response.facts[0].provenance == (PROVENANCE_REF,)
    assert b"spamhaus" not in canonical_knowledge_context_bytes(response)


@pytest.mark.parametrize(
    "sources",
    [("http://evil.example/x",), ("bad name",), ("",), ("line\nbreak",)],
    ids=["url", "whitespace", "empty", "newline"],
)
def test_malformed_source_names_are_refused(sources):
    with pytest.raises(KnowledgeContextAdaptationError):
        _response(_api_response([_match(sources=sources)]))


# --- empty, absent and unmatched results -------------------------------------


def test_missing_ioc_matches_key_fails_closed():
    with pytest.raises(KnowledgeContextAdaptationError, match="ioc_matches"):
        _response(_api_response(with_ioc_key=False))


def test_empty_ioc_list_yields_one_absence_unknown_per_entity():
    response = _response(_api_response([]))
    assert response.facts == ()
    assert response.inferences == ()
    assert response.unknowns == (_absent(0, 1),)
    assert response.limitations == (MAPPING_LIMITATION,)
    assert canonical_knowledge_context_bytes(response) == canonical_knowledge_context_bytes(
        _response(_api_response([]))
    )


def test_partial_match_leaves_only_the_unmatched_entity_unknown():
    response = _response(_api_response([_match(IP)]))
    assert [f.subject.value for f in response.facts] == [IP]
    assert response.unknowns == (_absent(1),)


def test_unmapped_threat_context_keys_are_not_turned_into_facts():
    api_response = _api_response(
        [],
        threat_context_extra={
            "campaign": {"name": "Coastal Ember", "actor": "UNC-EXAMPLE"},
            "history": {"prior_observations": 14},
        },
    )
    response = _response(api_response)
    assert response.facts == ()
    assert b"Coastal Ember" not in canonical_knowledge_context_bytes(response)


@pytest.mark.parametrize(
    "bad_match, message",
    [
        ({"type": "ip", "value": IP, "match_tier": "exact"}, "missing a required key"),
        ({"type": "ip", "value": IP, "sources": ["x"]}, "missing a required key"),
        ({"type": "ip", "value": IP, "sources": [], "match_tier": "exact"}, "no explicit source"),
        (_match(sources=()), "no explicit source"),
        ({**_match(), "campaign": {"name": "x"}}, "unsupported key"),
        ({**_match(), "confidence": 0.9}, "unsupported key"),
        ("not-an-object", "not an object"),
        ({**_match(), "type": 7}, "must be strings"),
        ({**_match(), "match_tier": None}, "match_tier must be a string"),
        ({**_match(tier="x"), "sources": ["bad name"]}, "malformed source name"),
    ],
    ids=[
        "missing-sources",
        "missing-tier",
        "empty-sources",
        "explicit-empty-sources",
        "unknown-key-campaign",
        "unknown-key-confidence",
        "non-object-match",
        "non-string-type",
        "non-string-tier",
        "malformed-source-even-if-not-exact",
    ],
)
def test_unsupported_or_unprovenanced_matches_fail_closed(bad_match, message):
    with pytest.raises(KnowledgeContextAdaptationError, match=message):
        _response(_api_response([bad_match]))


def test_non_list_ioc_matches_fail_closed():
    with pytest.raises(KnowledgeContextAdaptationError, match="must be a list"):
        _response(_api_response({"not": "a list"}))


def test_duplicate_source_names_fail_closed_not_silently_deduped():
    with pytest.raises(KnowledgeContextAdaptationError, match="repeats"):
        _response(_api_response([_match(sources=("abusech", "abusech"))]))


# --- caller unknowns ----------------------------------------------------------


def test_caller_unknowns_and_limitations_are_preserved_after_generated_ones():
    response = to_knowledge_context_response(
        _api_response([_match()]),
        _request(),
        **RESP_KW,
        unknowns=["Operator note: feed coverage is partial"],
        limitations=["Coverage limited to one feed"],
    )
    assert response.unknowns == (
        _absent(1),
        "Operator note: feed coverage is partial",
    )
    assert response.limitations == ("Coverage limited to one feed", MAPPING_LIMITATION)


def test_limitation_string_is_refused_rather_than_split_into_characters():
    with pytest.raises(TypeError):
        to_knowledge_context_response(
            _api_response([_match()]), _request(), **RESP_KW, limitations="abc"
        )


def test_unknowns_string_is_refused_rather_than_split_into_characters():
    with pytest.raises(TypeError):
        to_knowledge_context_response(
            _api_response([_match()]), _request(), **RESP_KW, unknowns="abc"
        )


def test_wrong_input_types_are_refused():
    with pytest.raises(TypeError):
        to_knowledge_context_response({"ioc": []}, _request(), **RESP_KW)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        to_knowledge_context_response(_api_response([]), {"raw": True}, **RESP_KW)  # type: ignore[arg-type]


# --- advisory-only -------------------------------------------------------------


@pytest.mark.parametrize("field", ["directive", "must_execute", "override", "required_action"])
def test_directive_shaped_key_anywhere_in_response_aborts_conversion(field):
    api_response = _api_response(
        [_match()], threat_context_extra={"campaign": {field: "block"}}
    )
    with pytest.raises(KnowledgeContextAdaptationError, match="advisory-only"):
        _response(api_response)


def test_directive_key_in_recommendation_aborts_conversion():
    api_response = _api_response([_match()], recommendation={"override": True})
    with pytest.raises(KnowledgeContextAdaptationError):
        _response(api_response)


# --- no input mutation --------------------------------------------------------


def test_inputs_are_not_mutated():
    api_response = _api_response(
        [_match(sources=("abusech", "edge_reported"))],
        threat_context_extra={"campaign": {"name": "x"}},
    )
    before_response = copy.deepcopy(api_response.model_dump(mode="python"))
    request = _request()
    before_request = copy.deepcopy(request.model_dump(mode="python"))

    from_knowledge_context_request(request)
    to_knowledge_context_response(api_response, request, **RESP_KW)

    assert request.model_dump(mode="python") == before_request
    assert api_response.model_dump(mode="python") == before_response


def test_failed_conversion_also_leaves_inputs_untouched():
    api_response = _api_response([_match("203.0.113.9")])
    before = copy.deepcopy(api_response.model_dump(mode="python"))
    with pytest.raises(KnowledgeContextAdaptationError):
        _response(api_response)
    assert api_response.model_dump(mode="python") == before


# --- contract-size bounds: fail closed, never truncate ----------------------------


def test_too_many_ioc_matches_fail_closed_not_truncated():
    matches = [_match(IP) for _ in range(adapter.MAX_FACTS + 1)]
    with pytest.raises(KnowledgeContextAdaptationError, match="fact cap"):
        _response(_api_response(matches))


def test_too_many_sources_for_one_match_fail_closed_not_truncated():
    sources = tuple(f"feed{i}" for i in range(adapter.MAX_PROVENANCE_REFS + 1))
    with pytest.raises(KnowledgeContextAdaptationError):
        _response(_api_response([_match(sources=sources)]))


def test_limitations_over_cap_fail_closed_once_mapping_limitation_is_added():
    full = [f"limitation {i}" for i in range(adapter.MAX_LIMITATIONS)]
    with pytest.raises(KnowledgeContextAdaptationError, match="limitations"):
        to_knowledge_context_response(
            _api_response([_match()]), _request(), **RESP_KW, limitations=full
        )


def test_unknowns_over_bound_fail_closed_not_truncated():
    flood = [f"caller unknown {i}" for i in range(10_000)]
    with pytest.raises(KnowledgeContextAdaptationError, match="unknowns exceed"):
        to_knowledge_context_response(
            _api_response([_match()]), _request(), **RESP_KW, unknowns=flood
        )


def test_maximum_profile_stays_within_the_shared_size_bound():
    entities = tuple(("ip", f"198.51.100.{i}") for i in range(MAX_ENTITIES))
    request = _fabric_request(entities=entities)
    count = min(MAX_ENTITIES, adapter.MAX_FACTS)
    matches = [
        _match(entities[i][1], "ip", ("abusech", *(f"group{j}" for j in range(7))))
        for i in range(count)
    ]
    response = _response(_api_response(matches), request)
    assert len(response.facts) == count
    assert len(canonical_knowledge_context_bytes(response)) <= 128 * 1024
