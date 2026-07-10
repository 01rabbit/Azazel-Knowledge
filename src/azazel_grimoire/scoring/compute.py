"""Deterministic threat-score pipeline (design S5).

`score_event(ctx)` runs the fixed-order component pipeline
`ioc_match -> history -> attack_map -> campaign -> geo_asn -> cve_exploited`,
emits a complete `reason[]` (zero-contribution and inapplicable
components always appear), computes the separate `threat_score` and
`confidence`, and folds everything except `advisory_id` into a
`content_hash`. Same determinism tuple + event + query_as_of yields a
byte-identical result.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence

from azazel_grimoire.core.clock import to_rfc3339
from azazel_grimoire.scoring import confidence as conf

REASON_ORDER: tuple[str, ...] = (
    "ioc_match",
    "history",
    "attack_map",
    "campaign",
    "geo_asn",
    "cve_exploited",
)

_INVARIANT_TOLERANCE = 1e-6


def _r(value: float) -> float:
    return round(float(value), 6)


@dataclass(frozen=True)
class SourceRef:
    feed_id: str
    group: str
    base_confidence: float
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True)
class IocMatchInput:
    entity_key: str
    type: str
    value: str
    ioc_id: int
    agg_raw_confidence: float
    first_seen: datetime
    last_seen: datetime
    sources: tuple[SourceRef, ...]
    match_tier: str
    history_count: int = 0


@dataclass(frozen=True)
class HistoryInput:
    total_events: int = 0
    burst_excluded: int = 0
    effective_events: int = 0
    trend: float = 0.0
    freshest_window_end: datetime | None = None
    updated_at: datetime | None = None
    windows: int = 0


@dataclass(frozen=True)
class AttackMapInput:
    techniques: tuple[str, ...] = ()
    rules_scanned: int = 0
    rules_total: int = 0
    truncated: bool = False


@dataclass(frozen=True)
class CampaignInput:
    matched: bool = False
    name: str | None = None
    actor: str | None = None
    ioc_overlap: float = 0.0
    technique_overlap: float = 0.0
    ref_count: int = 0
    distinct_ref_types: int = 0
    last_seen: datetime | None = None


@dataclass(frozen=True)
class GeoAsnInput:
    asn: str | None = None
    tagged: bool = False
    reputation_score: float = 0.0
    updated_at: datetime | None = None


@dataclass(frozen=True)
class ScoringContext:
    query_as_of: datetime
    intel_generation: int
    local_generation: int
    stats_generation: int
    attack_version: str
    config_hash: str
    config: Mapping[str, Any]
    event: Mapping[str, Any]
    ioc_matches: tuple[IocMatchInput, ...] = ()
    primary_index: int | None = None
    corroborated: bool = False
    history: HistoryInput = field(default_factory=HistoryInput)
    stats_stale: bool = False
    attack: AttackMapInput = field(default_factory=AttackMapInput)
    campaign: CampaignInput = field(default_factory=CampaignInput)
    geo_asn: GeoAsnInput = field(default_factory=GeoAsnInput)
    cve_applicable: bool = False
    cve_kev_hits: tuple[str, ...] = ()
    cve_added: datetime | None = None
    reputation_score: float | None = None
    max_staleness_s: int = 120


@dataclass(frozen=True)
class ScoreResult:
    threat_score: float
    raw_score: float
    reason: tuple[dict[str, Any], ...]
    confidence: float
    confidence_reason: tuple[dict[str, Any], ...]
    content_hash: str


@dataclass(frozen=True)
class _Component:
    value: float
    freshness: float
    applicable: bool
    detail: str


def _curve_multiplier(source_count: int, curve: Mapping[str, Any]) -> float:
    if source_count <= 0:
        return 0.0
    if source_count == 1:
        return float(curve["1"])
    if source_count == 2:
        return float(curve["2"])
    return float(curve["3+"])


def _component_ioc_match(ctx: ScoringContext) -> _Component:
    cfg = ctx.config["components"]["ioc_match"]
    fresh_cfg = ctx.config.get("freshness", {})
    half_life = float(fresh_cfg.get("half_life_days", 30.0))
    floor = float(fresh_cfg.get("floor", 0.2))
    if not ctx.ioc_matches or ctx.primary_index is None:
        return _Component(0.0, 1.0, True, "no indicator match")
    primary = ctx.ioc_matches[ctx.primary_index]
    distinct_feeds = len({src.feed_id for src in primary.sources})
    curve = _curve_multiplier(distinct_feeds, cfg["source_count_curve"])
    value = curve * float(primary.agg_raw_confidence)
    detail = (
        f"{primary.type} match ({primary.match_tier}), {distinct_feeds} source(s), "
        f"curve {curve}, agg_confidence {primary.agg_raw_confidence}"
    )
    cap = conf.ja_type_cap(primary.type, ctx.corroborated, cfg)
    if cap is not None:
        capped = min(value, cap * 100.0)
        detail += (
            f", {primary.type} type cap "
            f"{'corroborated ' if ctx.corroborated else ''}{cap} -> max {cap * 100.0}"
        )
        value = capped
    freshness = conf.freshness_decay(
        conf.age_days(ctx.query_as_of, primary.last_seen), half_life, floor
    )
    return _Component(_r(value), freshness, True, detail)


def _component_history(ctx: ScoringContext) -> _Component:
    cfg = ctx.config["components"]["history"]
    fresh_cfg = ctx.config.get("freshness", {})
    half_life = float(fresh_cfg.get("half_life_days", 30.0))
    floor = float(fresh_cfg.get("floor", 0.2))
    hist = ctx.history
    if ctx.stats_stale:
        return _Component(
            0.0, 1.0, True, "forced 0: observation_stats past max_staleness_s"
        )
    if hist.effective_events <= 0:
        return _Component(
            0.0,
            1.0,
            True,
            f"no in-window observations (burst_excluded={hist.burst_excluded})",
        )
    k = float(cfg.get("half_saturation_count", 10))
    base = 100.0 * hist.effective_events / (hist.effective_events + k)
    bonus = float(cfg.get("trend_bonus", 10)) if hist.trend > 0 else 0.0
    value = min(100.0, base + bonus)
    freshness = conf.freshness_decay(
        conf.age_days(ctx.query_as_of, hist.freshest_window_end), half_life, floor
    )
    detail = (
        f"{hist.effective_events} in-window events over {hist.windows} window(s), "
        f"trend {hist.trend}, burst_excluded {hist.burst_excluded}"
    )
    return _Component(_r(value), freshness, True, detail)


def _component_attack_map(ctx: ScoringContext) -> _Component:
    cfg = ctx.config["components"]["attack_map"]
    single_cap = float(cfg.get("single_basis_cap", 60))
    atk = ctx.attack
    matched = len(atk.techniques)
    if matched == 0:
        value = 0.0
    elif matched == 1:
        value = single_cap
    else:
        value = 100.0
    detail = (
        f"techniques {list(atk.techniques)}; rules_scanned {atk.rules_scanned}/"
        f"{atk.rules_total}; truncated {atk.truncated}"
    )
    return _Component(_r(value), 1.0, True, detail)


def _component_campaign(ctx: ScoringContext) -> _Component:
    cfg = ctx.config["components"]["campaign"]
    fresh_cfg = ctx.config.get("freshness", {})
    half_life = float(fresh_cfg.get("half_life_days", 30.0))
    floor = float(fresh_cfg.get("floor", 0.2))
    camp = ctx.campaign
    if not camp.matched:
        return _Component(0.0, 1.0, True, "no campaign association")
    io_w = float(cfg.get("ioc_overlap_weight", 0.7))
    tech_w = float(cfg.get("technique_overlap_weight", 0.3))
    single_ref_cap = float(cfg.get("single_ref_cap", 40))
    diversity_bonus = float(cfg.get("type_diversity_bonus", 10))
    value = 100.0 * (io_w * camp.ioc_overlap + tech_w * camp.technique_overlap)
    if camp.ref_count <= 1:
        value = min(value, single_ref_cap)
    if camp.distinct_ref_types > 1:
        value = min(100.0, value + diversity_bonus)
    freshness = conf.freshness_decay(
        conf.age_days(ctx.query_as_of, camp.last_seen), half_life, floor
    )
    detail = (
        f"{camp.name or 'campaign'} ioc_overlap {camp.ioc_overlap} "
        f"technique_overlap {camp.technique_overlap} refs {camp.ref_count} "
        f"ref_types {camp.distinct_ref_types}"
    )
    return _Component(_r(value), freshness, True, detail)


def _component_geo_asn(ctx: ScoringContext) -> _Component:
    fresh_cfg = ctx.config.get("freshness", {})
    half_life = float(fresh_cfg.get("half_life_days", 30.0))
    floor = float(fresh_cfg.get("floor", 0.2))
    geo = ctx.geo_asn
    if not geo.tagged or geo.asn is None:
        return _Component(
            0.0, 1.0, True, f"ASN {geo.asn or 'unknown'} untagged in reputation tables"
        )
    freshness = conf.freshness_decay(
        conf.age_days(ctx.query_as_of, geo.updated_at), half_life, floor
    )
    detail = f"ASN {geo.asn} reputation {geo.reputation_score}"
    return _Component(_r(geo.reputation_score), freshness, True, detail)


def _component_cve_exploited(ctx: ScoringContext) -> _Component:
    cfg = ctx.config["components"]["cve_exploited"]
    fresh_cfg = ctx.config.get("freshness", {})
    half_life = float(fresh_cfg.get("half_life_days", 30.0))
    cve_floor = float(cfg.get("freshness_floor", 0.7))
    if not ctx.cve_applicable:
        return _Component(
            0.0, 1.0, False, "inapplicable: applies_when eve_alert, none present"
        )
    if not ctx.cve_kev_hits:
        return _Component(0.0, 1.0, True, "no event CVE present in KEV catalog")
    freshness = conf.freshness_decay(
        conf.age_days(ctx.query_as_of, ctx.cve_added), half_life, cve_floor
    )
    detail = f"KEV hit: {list(ctx.cve_kev_hits)}"
    return _Component(100.0, freshness, True, detail)


_COMPONENT_FUNCS = {
    "ioc_match": _component_ioc_match,
    "history": _component_history,
    "attack_map": _component_attack_map,
    "campaign": _component_campaign,
    "geo_asn": _component_geo_asn,
    "cve_exploited": _component_cve_exploited,
}


def _content_hash(
    reason: Sequence[dict[str, Any]],
    threat_score: float,
    confidence: float,
    ctx: ScoringContext,
) -> str:
    payload = {
        "reason": list(reason),
        "threat_score": threat_score,
        "confidence": confidence,
        "determinism": {
            "intel_generation": ctx.intel_generation,
            "local_generation": ctx.local_generation,
            "stats_generation": ctx.stats_generation,
            "attack_version": ctx.attack_version,
            "config_hash": ctx.config_hash,
            "event": ctx.event,
            "query_as_of": to_rfc3339(ctx.query_as_of),
        },
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def score_event(ctx: ScoringContext) -> ScoreResult:
    weights = ctx.config["weights"]
    components = {name: _COMPONENT_FUNCS[name](ctx) for name in REASON_ORDER}

    applicable_weight = sum(
        float(weights[name]) for name in REASON_ORDER if components[name].applicable
    )
    if applicable_weight <= 0:
        raise ValueError("no applicable scoring components")

    reason: list[dict[str, Any]] = []
    contributions: list[float] = []
    for name in REASON_ORDER:
        comp = components[name]
        config_weight = float(weights[name])
        effective_weight = (
            config_weight / applicable_weight if comp.applicable else 0.0
        )
        contribution = _r(effective_weight * comp.value * comp.freshness)
        contributions.append(contribution)
        reason.append(
            {
                "component": name,
                "config_weight": _r(config_weight),
                "effective_weight": _r(effective_weight),
                "freshness": _r(comp.freshness),
                "contribution": contribution,
                "detail": comp.detail,
                "applicable": comp.applicable,
            }
        )

    raw_score = _r(math.fsum(contributions))
    if abs(math.fsum(c["contribution"] for c in reason) - raw_score) > _INVARIANT_TOLERANCE:
        raise AssertionError("sum(contribution) != raw_score")
    threat_score = conf.clamp_0_100(raw_score)

    confidence_result = conf.score_confidence(ctx)
    content_hash = _content_hash(
        reason, threat_score, confidence_result.confidence, ctx
    )

    return ScoreResult(
        threat_score=threat_score,
        raw_score=raw_score,
        reason=tuple(reason),
        confidence=confidence_result.confidence,
        confidence_reason=confidence_result.confidence_reason,
        content_hash=content_hash,
    )
