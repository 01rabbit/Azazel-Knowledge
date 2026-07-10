"""Canonical confidence formula and shared scoring numerics (design S5/F-8).

`confidence` is one canonical weighted sum over exactly four drivers from
`confidence_weights`; the noisy-OR lives here only as
`agg_raw_confidence`, used for primary-IOC selection and `ioc.agg`
materialization, never as a confidence term. This module is the lowest
layer of the scoring package: `compute.py` imports its helpers and
delegates to `score_confidence`, so nothing here may import `compute`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence

DRIVER_ORDER: tuple[str, ...] = (
    "source_count",
    "source_independence",
    "source_freshness",
    "local_corroboration",
)

_DEFAULT_HALF_LIFE_DAYS = 30.0
_DEFAULT_FRESHNESS_FLOOR = 0.2
_DEFAULT_MAX_DISTINCT_GROUPS = 4
_DEFAULT_LOCAL_FLOOR = 0.3
_LOCAL_HISTORY_FULL = 50.0


def _r(value: float) -> float:
    return round(float(value), 6)


def clamp_0_100(value: float) -> float:
    return _r(max(0.0, min(100.0, float(value))))


def age_days(query_as_of: datetime, ts: datetime | None) -> float:
    if ts is None:
        return 0.0
    delta = (query_as_of - ts).total_seconds() / 86400.0
    return max(0.0, delta)


def freshness_decay(
    age: float,
    half_life_days: float = _DEFAULT_HALF_LIFE_DAYS,
    floor: float = _DEFAULT_FRESHNESS_FLOOR,
) -> float:
    if age <= 0:
        return 1.0
    return _r(max(floor, 0.5 ** (age / half_life_days)))


def is_stats_stale(
    query_as_of: datetime, updated_at: datetime | None, max_staleness_s: int
) -> bool:
    if updated_at is None:
        return False
    return (query_as_of - updated_at).total_seconds() > max_staleness_s


def agg_raw_confidence(group_confidences: Sequence[float]) -> float:
    product = 1.0
    for g in group_confidences:
        clamped = max(0.0, min(100.0, float(g)))
        product *= 1.0 - clamped / 100.0
    return clamp_0_100(100.0 * (1.0 - product))


def noisy_or(group_confidences: Sequence[float]) -> float:
    return agg_raw_confidence(group_confidences)


def ja_type_cap(
    ioc_type: str, corroborated: bool, ioc_match_config: Mapping[str, Any]
) -> float | None:
    caps = ioc_match_config.get("type_caps", {})
    if ioc_type == "ja3":
        return float(caps["ja3_corroborated"]) if corroborated else float(caps["ja3"])
    if ioc_type == "ja4":
        return float(caps["ja4_corroborated"]) if corroborated else float(caps["ja4"])
    return None


@dataclass(frozen=True)
class ConfidenceResult:
    confidence: float
    raw_confidence: float
    confidence_reason: tuple[dict[str, Any], ...] = field(default_factory=tuple)


def _confidence_line(
    component: str, weight: float, driver: float, freshness: float, detail: str
) -> dict[str, Any]:
    return {
        "component": component,
        "config_weight": _r(weight),
        "effective_weight": _r(weight),
        "freshness": _r(freshness),
        "contribution": _r(weight * driver * 100.0),
        "detail": detail,
        "applicable": True,
    }


def _primary_sources(ctx: "Any") -> tuple[Any, ...]:
    if not ctx.ioc_matches or ctx.primary_index is None:
        return ()
    return tuple(ctx.ioc_matches[ctx.primary_index].sources)


def score_confidence(ctx: "Any") -> ConfidenceResult:
    config = ctx.config
    weights = config["confidence_weights"]
    freshness_cfg = config.get("freshness", {})
    half_life = float(freshness_cfg.get("half_life_days", _DEFAULT_HALF_LIFE_DAYS))
    fresh_floor = float(freshness_cfg.get("floor", _DEFAULT_FRESHNESS_FLOOR))
    confidence_cfg = config.get("confidence", {})
    max_distinct = int(
        confidence_cfg.get("source_count", {}).get(
            "max_distinct_groups", _DEFAULT_MAX_DISTINCT_GROUPS
        )
    )
    local_floor = float(
        confidence_cfg.get("local_corroboration", {}).get("floor", _DEFAULT_LOCAL_FLOOR)
    )

    sources = _primary_sources(ctx)
    total_sources = len(sources)
    group_counts: dict[str, int] = {}
    for src in sources:
        group_counts[src.group] = group_counts.get(src.group, 0) + 1
    distinct_groups = len(group_counts)

    source_count_driver = (
        min(distinct_groups, max_distinct) / max_distinct if max_distinct else 0.0
    )

    if total_sources > 0:
        max_share = max(group_counts.values()) / total_sources
        independence_driver = 1.0 - max_share
    else:
        independence_driver = 0.0

    if sources:
        oldest = min(src.last_seen for src in sources)
        freshness_driver = freshness_decay(
            age_days(ctx.query_as_of, oldest), half_life, fresh_floor
        )
        oldest_detail = f"oldest source last_seen decayed to {freshness_driver}"
    else:
        freshness_driver = 0.0
        oldest_detail = "no contributing source"

    reputation = ctx.reputation_score
    history_events = ctx.history.effective_events if ctx.history else 0
    if ctx.stats_stale:
        local_driver = 0.0
        local_detail = "forced 0: observation_stats past max_staleness_s"
    elif reputation is None and history_events == 0:
        local_driver = 0.0
        local_detail = "no local reputation or observation corroboration"
    else:
        rep_fraction = (reputation / 100.0) if reputation is not None else 0.0
        hist_fraction = min(1.0, history_events / _LOCAL_HISTORY_FULL)
        local_driver = min(1.0, max(local_floor, rep_fraction, hist_fraction))
        local_detail = (
            f"reputation={rep_fraction:.4f} history={hist_fraction:.4f} "
            f"floor={local_floor}"
        )

    drivers = {
        "source_count": (
            source_count_driver,
            1.0,
            f"{distinct_groups} distinct source group(s), cap {max_distinct}",
        ),
        "source_independence": (
            independence_driver,
            1.0,
            f"1 - max single-group share over {total_sources} source(s)",
        ),
        "source_freshness": (freshness_driver, freshness_driver, oldest_detail),
        "local_corroboration": (local_driver, 1.0, local_detail),
    }

    lines: list[dict[str, Any]] = []
    raw = 0.0
    for name in DRIVER_ORDER:
        driver, freshness, detail = drivers[name]
        weight = float(weights[name])
        line = _confidence_line(name, weight, driver, freshness, detail)
        raw += line["contribution"]
        lines.append(line)

    raw = _r(raw)
    return ConfidenceResult(
        confidence=clamp_0_100(raw),
        raw_confidence=raw,
        confidence_reason=tuple(lines),
    )
