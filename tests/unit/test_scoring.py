from __future__ import annotations

import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from azazel_cti.core.config import TrackedConfigLoader
from azazel_cti.scoring.compute import (
    AttackMapInput,
    CampaignInput,
    GeoAsnInput,
    HistoryInput,
    IocMatchInput,
    REASON_ORDER,
    ScoringContext,
    SourceRef,
    score_event,
)

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"
LOADER = TrackedConfigLoader(REPO_CONFIG)
SCORING = LOADER.scoring()

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
    value: str = "203.0.113.7",
    agg: float = 80.0,
    sources: tuple[SourceRef, ...] | None = None,
    last_seen: datetime | None = None,
    entity_key: str = "aa" * 16,
) -> IocMatchInput:
    seen = last_seen or (QUERY_AS_OF - timedelta(days=4))
    if sources is None:
        sources = (_source("urlhaus", "abusech", seen),)
    return IocMatchInput(
        entity_key=entity_key,
        type=type_,
        value=value,
        ioc_id=1,
        agg_raw_confidence=agg,
        first_seen=seen - timedelta(days=30),
        last_seen=seen,
        sources=sources,
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
        event={"kind": "eve_alert", "event_types": ["eve_alert"]},
        cve_applicable=True,
    )
    base.update(overrides)
    return ScoringContext(**base)


def _canonical(result) -> str:
    return json.dumps(
        {
            "reason": list(result.reason),
            "threat_score": result.threat_score,
            "confidence": result.confidence,
            "confidence_reason": list(result.confidence_reason),
            "content_hash": result.content_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def test_reason_is_complete_and_ordered_with_zero_contributions():
    result = score_event(make_ctx())
    components = [line["component"] for line in result.reason]
    assert components == list(REASON_ORDER)
    for line in result.reason:
        assert set(line) == {
            "component",
            "config_weight",
            "effective_weight",
            "freshness",
            "contribution",
            "detail",
            "applicable",
        }
    zero_lines = [line for line in result.reason if line["contribution"] == 0]
    assert zero_lines, "zero-contribution components must still appear"


def test_sum_contribution_equals_raw_score_and_clamp_invariant():
    ctx = make_ctx(
        ioc_matches=(_ioc(),),
        primary_index=0,
        history=HistoryInput(
            total_events=14,
            effective_events=14,
            trend=0.2,
            freshest_window_end=QUERY_AS_OF - timedelta(days=1),
            windows=2,
        ),
        attack=AttackMapInput(
            techniques=("T1595.002",), rules_scanned=6, rules_total=6
        ),
        cve_kev_hits=("CVE-2024-0001",),
        cve_added=QUERY_AS_OF - timedelta(days=90),
    )
    result = score_event(ctx)
    total = math.fsum(line["contribution"] for line in result.reason)
    assert abs(total - result.raw_score) < 1e-6
    assert result.threat_score == max(0.0, min(100.0, result.raw_score))


def test_cve_inapplicable_renormalizes_remaining_weights():
    result = score_event(make_ctx(cve_applicable=False))
    by_name = {line["component"]: line for line in result.reason}
    cve = by_name["cve_exploited"]
    assert cve["applicable"] is False
    assert cve["contribution"] == 0
    assert cve["effective_weight"] == 0
    assert cve["config_weight"] == pytest.approx(0.15)

    effective_sum = sum(
        line["effective_weight"] for line in result.reason if line["applicable"]
    )
    assert effective_sum == pytest.approx(1.0, abs=1e-6)
    assert by_name["ioc_match"]["effective_weight"] == pytest.approx(0.30 / 0.85)


def test_cve_applicable_uses_config_weights_unrenormalized():
    result = score_event(make_ctx(cve_applicable=True))
    for line in result.reason:
        assert line["applicable"] is True
        assert line["effective_weight"] == pytest.approx(line["config_weight"])


def test_cve_exploited_is_100_iff_kev_hit():
    hit = score_event(
        make_ctx(cve_kev_hits=("CVE-2024-0001",), cve_added=QUERY_AS_OF)
    )
    cve_line = next(l for l in hit.reason if l["component"] == "cve_exploited")
    assert cve_line["contribution"] == pytest.approx(0.15 * 100.0 * 1.0)
    assert "CVE-2024-0001" in cve_line["detail"]

    miss = score_event(make_ctx(cve_kev_hits=()))
    cve_line = next(l for l in miss.reason if l["component"] == "cve_exploited")
    assert cve_line["contribution"] == 0
    assert cve_line["applicable"] is True


def test_cve_freshness_floor_is_0_7():
    result = score_event(
        make_ctx(
            cve_kev_hits=("CVE-2020-0001",),
            cve_added=QUERY_AS_OF - timedelta(days=3650),
        )
    )
    cve_line = next(l for l in result.reason if l["component"] == "cve_exploited")
    assert cve_line["freshness"] == pytest.approx(0.7)


def test_ioc_match_source_count_curve():
    seen = QUERY_AS_OF
    curves = {1: 0.4, 2: 0.7, 3: 1.0, 5: 1.0}
    for count, expected_curve in curves.items():
        sources = tuple(
            _source(f"feed{i}", f"group{i}", seen) for i in range(count)
        )
        ctx = make_ctx(
            ioc_matches=(_ioc(agg=80.0, sources=sources, last_seen=seen),),
            primary_index=0,
        )
        result = score_event(ctx)
        line = next(l for l in result.reason if l["component"] == "ioc_match")
        assert line["contribution"] == pytest.approx(
            0.30 * expected_curve * 80.0 * 1.0
        ), f"source count {count}"


def test_freshness_decay_reduces_contribution():
    fresh = score_event(
        make_ctx(ioc_matches=(_ioc(last_seen=QUERY_AS_OF),), primary_index=0)
    )
    stale = score_event(
        make_ctx(
            ioc_matches=(_ioc(last_seen=QUERY_AS_OF - timedelta(days=30)),),
            primary_index=0,
        )
    )
    fresh_line = next(l for l in fresh.reason if l["component"] == "ioc_match")
    stale_line = next(l for l in stale.reason if l["component"] == "ioc_match")
    assert fresh_line["freshness"] == pytest.approx(1.0)
    assert stale_line["freshness"] == pytest.approx(0.5)
    assert stale_line["contribution"] < fresh_line["contribution"]


def test_freshness_floor_0_2():
    result = score_event(
        make_ctx(
            ioc_matches=(_ioc(last_seen=QUERY_AS_OF - timedelta(days=3650)),),
            primary_index=0,
        )
    )
    line = next(l for l in result.reason if l["component"] == "ioc_match")
    assert line["freshness"] == pytest.approx(0.2)


def test_history_burst_guard_disclosed_in_detail():
    ctx = make_ctx(
        history=HistoryInput(
            total_events=700,
            burst_excluded=200,
            effective_events=500,
            trend=0.1,
            freshest_window_end=QUERY_AS_OF,
            windows=1,
        )
    )
    result = score_event(ctx)
    line = next(l for l in result.reason if l["component"] == "history")
    assert "burst_excluded 200" in line["detail"]
    assert line["contribution"] > 0


def test_stale_stats_force_history_to_zero_with_detail():
    ctx = make_ctx(
        stats_stale=True,
        history=HistoryInput(
            total_events=100, effective_events=100, windows=1,
            freshest_window_end=QUERY_AS_OF,
        ),
    )
    result = score_event(ctx)
    line = next(l for l in result.reason if l["component"] == "history")
    assert line["contribution"] == 0
    assert "max_staleness_s" in line["detail"]


def test_attack_map_single_basis_cap_and_disclosure():
    single = score_event(
        make_ctx(
            attack=AttackMapInput(
                techniques=("T1110",), rules_scanned=6, rules_total=6
            )
        )
    )
    line = next(l for l in single.reason if l["component"] == "attack_map")
    assert line["contribution"] == pytest.approx(0.15 * 60.0)
    assert "rules_scanned 6/6" in line["detail"]
    assert "truncated False" in line["detail"]

    multi = score_event(
        make_ctx(
            attack=AttackMapInput(
                techniques=("T1110", "T1595.002"),
                rules_scanned=6,
                rules_total=6,
                truncated=True,
            )
        )
    )
    line = next(l for l in multi.reason if l["component"] == "attack_map")
    assert line["contribution"] == pytest.approx(0.15 * 100.0)
    assert "truncated True" in line["detail"]


def test_campaign_component_formula_caps_and_bonus():
    base = CampaignInput(
        matched=True,
        name="c1",
        ioc_overlap=1.0,
        technique_overlap=1.0,
        ref_count=1,
        distinct_ref_types=1,
        last_seen=QUERY_AS_OF,
    )
    result = score_event(make_ctx(campaign=base))
    line = next(l for l in result.reason if l["component"] == "campaign")
    assert line["contribution"] == pytest.approx(0.10 * 40.0)  # single_ref_cap

    rich = CampaignInput(
        matched=True,
        name="c1",
        ioc_overlap=0.5,
        technique_overlap=0.5,
        ref_count=4,
        distinct_ref_types=2,
        last_seen=QUERY_AS_OF,
    )
    result = score_event(make_ctx(campaign=rich))
    line = next(l for l in result.reason if l["component"] == "campaign")
    expected = 100.0 * (0.7 * 0.5 + 0.3 * 0.5) + 10.0
    assert line["contribution"] == pytest.approx(0.10 * expected)


def test_geo_asn_untagged_yields_zero():
    result = score_event(
        make_ctx(geo_asn=GeoAsnInput(asn="AS65001", tagged=False))
    )
    line = next(l for l in result.reason if l["component"] == "geo_asn")
    assert line["contribution"] == 0
    assert line["applicable"] is True
    assert "AS65001" in line["detail"]


def test_geo_asn_tagged_contributes():
    result = score_event(
        make_ctx(
            geo_asn=GeoAsnInput(
                asn="AS64500",
                tagged=True,
                reputation_score=80.0,
                updated_at=QUERY_AS_OF,
            )
        )
    )
    line = next(l for l in result.reason if l["component"] == "geo_asn")
    assert line["contribution"] == pytest.approx(0.10 * 80.0)


def test_determinism_three_runs_byte_identical():
    def build():
        return make_ctx(
            ioc_matches=(_ioc(),),
            primary_index=0,
            history=HistoryInput(
                total_events=14,
                effective_events=14,
                trend=0.2,
                freshest_window_end=QUERY_AS_OF - timedelta(days=1),
                windows=2,
            ),
            cve_kev_hits=("CVE-2024-0001",),
            cve_added=QUERY_AS_OF - timedelta(days=90),
        )

    outputs = [_canonical(score_event(build())) for _ in range(3)]
    assert outputs[0] == outputs[1] == outputs[2]


def test_different_query_as_of_changes_freshness_and_content_hash():
    ctx_a = make_ctx(ioc_matches=(_ioc(),), primary_index=0)
    ctx_b = make_ctx(
        ioc_matches=(_ioc(),),
        primary_index=0,
        query_as_of=QUERY_AS_OF + timedelta(days=20),
    )
    a = score_event(ctx_a)
    b = score_event(ctx_b)
    line_a = next(l for l in a.reason if l["component"] == "ioc_match")
    line_b = next(l for l in b.reason if l["component"] == "ioc_match")
    assert line_a["freshness"] != line_b["freshness"]
    assert a.content_hash != b.content_hash


def test_content_hash_changes_with_determinism_tuple_members():
    baseline = score_event(make_ctx(ioc_matches=(_ioc(),), primary_index=0))
    for override in (
        {"intel_generation": 2},
        {"local_generation": 2},
        {"stats_generation": 2},
        {"attack_version": "16.0"},
        {"config_hash": "cafebabe"},
        {"event": {"kind": "eve_alert", "event_types": ["eve_alert"], "x": 1}},
    ):
        varied = score_event(
            make_ctx(ioc_matches=(_ioc(),), primary_index=0, **override)
        )
        assert varied.content_hash != baseline.content_hash, override


def test_threat_score_and_confidence_are_separate_numbers():
    result = score_event(
        make_ctx(
            ioc_matches=(_ioc(),),
            primary_index=0,
            cve_kev_hits=("CVE-2024-0001",),
            cve_added=QUERY_AS_OF,
        )
    )
    assert 0.0 <= result.threat_score <= 100.0
    assert 0.0 <= result.confidence <= 100.0
    assert result.threat_score != result.confidence
