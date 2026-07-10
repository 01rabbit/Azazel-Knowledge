from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_knowledge.core.config import TrackedConfigLoader
from azazel_knowledge.scoring import confidence as conf
from azazel_knowledge.scoring.compute import (
    HistoryInput,
    IocMatchInput,
    ScoringContext,
    SourceRef,
    score_event,
)

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"
SCORING = TrackedConfigLoader(REPO_CONFIG).scoring()

QUERY_AS_OF = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)


def _source(feed_id: str, group: str, last_seen: datetime) -> SourceRef:
    return SourceRef(
        feed_id=feed_id,
        group=group,
        base_confidence=85.0,
        first_seen=last_seen - timedelta(days=10),
        last_seen=last_seen,
    )


def _ioc(
    type_: str = "ip",
    agg: float = 80.0,
    sources: tuple[SourceRef, ...] = (),
    last_seen: datetime | None = None,
) -> IocMatchInput:
    seen = last_seen or QUERY_AS_OF
    return IocMatchInput(
        entity_key="ab" * 16,
        type=type_,
        value="203.0.113.7",
        ioc_id=1,
        agg_raw_confidence=agg,
        first_seen=seen - timedelta(days=30),
        last_seen=seen,
        sources=sources or (_source("urlhaus", "abusech", seen),),
        match_tier="exact",
    )


def make_ctx(**overrides) -> ScoringContext:
    base = dict(
        query_as_of=QUERY_AS_OF,
        intel_generation=1,
        local_generation=1,
        stats_generation=1,
        attack_version="15.1",
        config_hash="deadbeef",
        config=SCORING,
        event={},
    )
    base.update(overrides)
    return ScoringContext(**base)


def test_exactly_four_drivers_in_fixed_order_with_zero_lines():
    result = conf.score_confidence(make_ctx())
    components = [line["component"] for line in result.confidence_reason]
    assert components == list(conf.DRIVER_ORDER)
    assert len(components) == 4
    for line in result.confidence_reason:
        assert set(line) == {
            "component",
            "config_weight",
            "effective_weight",
            "freshness",
            "contribution",
            "detail",
            "applicable",
        }
    assert all(line["contribution"] == 0 for line in result.confidence_reason)


def test_confidence_is_weighted_sum_of_drivers():
    sources = (
        _source("urlhaus", "abusech", QUERY_AS_OF),
        _source("spamhaus_asndrop", "spamhaus", QUERY_AS_OF),
    )
    ctx = make_ctx(
        ioc_matches=(_ioc(sources=sources),),
        primary_index=0,
        reputation_score=60.0,
    )
    result = conf.score_confidence(ctx)
    total = sum(line["contribution"] for line in result.confidence_reason)
    assert result.raw_confidence == pytest.approx(total, abs=1e-6)
    assert result.confidence == max(0.0, min(100.0, result.raw_confidence))

    by_name = {l["component"]: l for l in result.confidence_reason}
    # 2 distinct groups of max 4 -> 0.5 driver at weight 0.30
    assert by_name["source_count"]["contribution"] == pytest.approx(
        0.30 * 0.5 * 100.0
    )
    # even split -> independence 1 - 0.5 = 0.5 at weight 0.30
    assert by_name["source_independence"]["contribution"] == pytest.approx(
        0.30 * 0.5 * 100.0
    )
    # fresh sources -> freshness 1.0 at weight 0.25
    assert by_name["source_freshness"]["contribution"] == pytest.approx(
        0.25 * 1.0 * 100.0
    )
    # reputation 60 -> driver 0.6 at weight 0.15
    assert by_name["local_corroboration"]["contribution"] == pytest.approx(
        0.15 * 0.6 * 100.0
    )


def test_source_count_driver_saturates_at_four_groups():
    sources = tuple(
        _source(f"feed{i}", f"group{i}", QUERY_AS_OF) for i in range(6)
    )
    ctx = make_ctx(ioc_matches=(_ioc(sources=sources),), primary_index=0)
    result = conf.score_confidence(ctx)
    line = next(
        l for l in result.confidence_reason if l["component"] == "source_count"
    )
    assert line["contribution"] == pytest.approx(0.30 * 1.0 * 100.0)


def test_source_independence_zero_for_single_group():
    sources = (
        _source("urlhaus", "abusech", QUERY_AS_OF),
        _source("threatfox", "abusech", QUERY_AS_OF),
    )
    ctx = make_ctx(ioc_matches=(_ioc(sources=sources),), primary_index=0)
    result = conf.score_confidence(ctx)
    line = next(
        l
        for l in result.confidence_reason
        if l["component"] == "source_independence"
    )
    assert line["contribution"] == 0


def test_source_freshness_uses_oldest_contributing_source():
    sources = (
        _source("urlhaus", "abusech", QUERY_AS_OF),
        _source("spamhaus_asndrop", "spamhaus", QUERY_AS_OF - timedelta(days=30)),
    )
    ctx = make_ctx(ioc_matches=(_ioc(sources=sources),), primary_index=0)
    result = conf.score_confidence(ctx)
    line = next(
        l for l in result.confidence_reason if l["component"] == "source_freshness"
    )
    assert line["contribution"] == pytest.approx(0.25 * 0.5 * 100.0)


def test_local_corroboration_floor_applies_when_corroboration_exists():
    ctx = make_ctx(
        ioc_matches=(_ioc(),),
        primary_index=0,
        reputation_score=5.0,  # below floor 0.3
    )
    result = conf.score_confidence(ctx)
    line = next(
        l
        for l in result.confidence_reason
        if l["component"] == "local_corroboration"
    )
    assert line["contribution"] == pytest.approx(0.15 * 0.3 * 100.0)


def test_stale_stats_force_local_corroboration_to_zero():
    ctx = make_ctx(
        ioc_matches=(_ioc(),),
        primary_index=0,
        reputation_score=90.0,
        history=HistoryInput(total_events=80, effective_events=80, windows=1),
        stats_stale=True,
    )
    result = conf.score_confidence(ctx)
    line = next(
        l
        for l in result.confidence_reason
        if l["component"] == "local_corroboration"
    )
    assert line["contribution"] == 0
    assert "max_staleness_s" in line["detail"]


def test_is_stats_stale_threshold():
    updated = QUERY_AS_OF - timedelta(seconds=121)
    assert conf.is_stats_stale(QUERY_AS_OF, updated, 120) is True
    updated = QUERY_AS_OF - timedelta(seconds=60)
    assert conf.is_stats_stale(QUERY_AS_OF, updated, 120) is False


def test_noisy_or_formula():
    assert conf.agg_raw_confidence([]) == 0.0
    assert conf.agg_raw_confidence([50.0]) == pytest.approx(50.0)
    assert conf.agg_raw_confidence([50.0, 50.0]) == pytest.approx(75.0)
    assert conf.agg_raw_confidence([100.0, 10.0]) == pytest.approx(100.0)
    assert conf.noisy_or([80.0, 60.0]) == pytest.approx(92.0)


def test_noisy_or_is_not_a_confidence_term():
    sources = (
        _source("urlhaus", "abusech", QUERY_AS_OF),
        _source("spamhaus_asndrop", "spamhaus", QUERY_AS_OF),
    )
    ctx = make_ctx(
        ioc_matches=(_ioc(sources=sources, agg=99.9),),
        primary_index=0,
    )
    result = conf.score_confidence(ctx)
    noisy = conf.agg_raw_confidence(
        [s.base_confidence for s in sources]
    )
    contributions = [l["contribution"] for l in result.confidence_reason]
    assert all(abs(c - noisy) > 1e-9 for c in contributions if c > 0)
    assert result.confidence != pytest.approx(noisy)


def test_ja3_and_ja4_type_caps_applied_with_disclosure():
    seen = QUERY_AS_OF
    sources = tuple(_source(f"f{i}", f"g{i}", seen) for i in range(3))

    cases = [
        ("ja3", False, 0.6),
        ("ja3", True, 0.9),
        ("ja4", False, 0.7),
        ("ja4", True, 1.0),
    ]
    for type_, corroborated, cap in cases:
        ctx = make_ctx(
            ioc_matches=(_ioc(type_=type_, agg=100.0, sources=sources),),
            primary_index=0,
            corroborated=corroborated,
            cve_applicable=False,
        )
        result = score_event(ctx)
        line = next(l for l in result.reason if l["component"] == "ioc_match")
        expected_value = min(100.0, cap * 100.0)
        expected = (0.30 / 0.85) * expected_value
        assert line["contribution"] == pytest.approx(expected, abs=1e-4), (
            type_,
            corroborated,
        )
        assert "type cap" in line["detail"]


def test_ip_type_has_no_cap():
    assert conf.ja_type_cap("ip", False, SCORING["components"]["ioc_match"]) is None
    assert conf.ja_type_cap("ja3", False, SCORING["components"]["ioc_match"]) == 0.6


def test_confidence_reason_deterministic_across_runs():
    sources = (
        _source("urlhaus", "abusech", QUERY_AS_OF - timedelta(days=3)),
    )
    outputs = []
    for _ in range(3):
        ctx = make_ctx(
            ioc_matches=(_ioc(sources=sources),),
            primary_index=0,
            reputation_score=42.0,
        )
        result = conf.score_confidence(ctx)
        outputs.append(
            json.dumps(
                {
                    "confidence": result.confidence,
                    "lines": list(result.confidence_reason),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    assert outputs[0] == outputs[1] == outputs[2]
