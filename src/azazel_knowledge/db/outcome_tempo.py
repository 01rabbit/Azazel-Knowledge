from __future__ import annotations

import json
import sqlite3
import statistics
from dataclasses import asdict, dataclass
from typing import Any, Mapping


class TempoDerivationError(ValueError):
    pass


@dataclass(frozen=True)
class TempoFeatureSummary:
    trace_id: str
    status: str
    features: dict[str, Any]
    coverage: dict[str, Any]
    confounders: tuple[str, ...]
    source_observation_refs: tuple[str, ...]
    limitations: tuple[str, ...]
    schema_version: str = "outcome-tempo-features/v0.1"
    authority_class: str = "derived_analysis"
    executable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_INTERVAL_KEYS = (
    "retry_interval_ms",
    "probe_interval_ms",
    "event_interval_ms",
)
_COUNT_KEYS = (
    "port_switch_count",
    "protocol_switch_count",
    "interaction_depth",
)
_SEVERE_CONFOUNDERS = {
    "missing_post_telemetry",
    "telemetry_loss",
    "capture_gap",
    "observer_unavailable",
}


def _finite_nonnegative(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if number < 0 or number != number or number in (float("inf"), float("-inf")):
        return None
    return number


def _flatten_candidate_maps(values: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    maps: list[Mapping[str, Any]] = [values]
    for key in ("adversary_response", "after", "metrics", "cadence"):
        nested = values.get(key)
        if isinstance(nested, Mapping):
            maps.append(nested)
    return maps


def _extract_features(values: Mapping[str, Any]) -> tuple[dict[str, list[float]], dict[str, list[float]]]:
    intervals: dict[str, list[float]] = {key: [] for key in _INTERVAL_KEYS}
    counts: dict[str, list[float]] = {key: [] for key in _COUNT_KEYS}
    for candidate in _flatten_candidate_maps(values):
        for key in _INTERVAL_KEYS:
            number = _finite_nonnegative(candidate.get(key))
            if number is not None:
                intervals[key].append(number)
        for key in _COUNT_KEYS:
            number = _finite_nonnegative(candidate.get(key))
            if number is not None:
                counts[key].append(number)
    return intervals, counts


def _coverage_score(coverage: Mapping[str, Any]) -> float | None:
    ratio = _finite_nonnegative(coverage.get("sample_ratio"))
    if ratio is not None:
        return min(1.0, ratio)
    baseline = coverage.get("baseline")
    post = coverage.get("post")
    if isinstance(baseline, (int, float)) and not isinstance(baseline, bool) and isinstance(post, (int, float)) and not isinstance(post, bool):
        return min(1.0, max(0.0, min(float(baseline), float(post))))
    before_present = coverage.get("before_present")
    after_present = coverage.get("after_present")
    if isinstance(before_present, bool) and isinstance(after_present, bool):
        return 1.0 if before_present and after_present else 0.5 if before_present or after_present else 0.0
    return None


def derive_tempo_features(conn: sqlite3.Connection, trace_id: str) -> TempoFeatureSummary:
    """Derive conservative Tempo features from immutable OutcomeObservation facts.

    No universal Tempo score is produced. Missing telemetry is never interpreted
    as slowdown. Only explicitly observed interval/switch/depth fields are
    aggregated, and coverage/confounders travel with the result.
    """

    if not isinstance(trace_id, str) or not trace_id.strip():
        raise TempoDerivationError("trace_id must be a non-empty string")
    rows = conn.execute(
        "SELECT observation_id, raw FROM outcome_observation_v0 WHERE trace_id = ? "
        "ORDER BY observed_at ASC, observation_id ASC",
        (trace_id,),
    ).fetchall()

    interval_samples: dict[str, list[float]] = {key: [] for key in _INTERVAL_KEYS}
    count_samples: dict[str, list[float]] = {key: [] for key in _COUNT_KEYS}
    confounders: list[str] = []
    coverage_samples: list[float] = []
    coverage_unknown = 0
    refs: list[str] = []

    for observation_id, raw in rows:
        try:
            payload = json.loads(str(raw))
        except json.JSONDecodeError as exc:
            raise TempoDerivationError("stored outcome raw JSON is invalid") from exc
        if not isinstance(payload, Mapping):
            raise TempoDerivationError("stored outcome raw payload must be a map")
        values = payload.get("observation_values")
        coverage = payload.get("telemetry_coverage")
        raw_confounders = payload.get("confounders")
        if not isinstance(values, Mapping) or not isinstance(coverage, Mapping) or not isinstance(raw_confounders, list):
            raise TempoDerivationError("stored outcome is missing required fact containers")

        intervals, counts = _extract_features(values)
        for key, samples in intervals.items():
            interval_samples[key].extend(samples)
        for key, samples in counts.items():
            count_samples[key].extend(samples)
        refs.append(str(observation_id))

        score = _coverage_score(coverage)
        if score is None:
            coverage_unknown += 1
        else:
            coverage_samples.append(score)
        for item in raw_confounders:
            if isinstance(item, str) and item.strip():
                confounders.append(item.strip())

    features: dict[str, Any] = {}
    for key, samples in interval_samples.items():
        if samples:
            features[key] = {
                "sample_count": len(samples),
                "median": statistics.median(samples),
                "minimum": min(samples),
                "maximum": max(samples),
                "latest": samples[-1],
            }
    for key, samples in count_samples.items():
        if samples:
            features[key] = {
                "sample_count": len(samples),
                "latest": samples[-1],
                "maximum": max(samples),
            }

    unique_confounders = tuple(dict.fromkeys(confounders))
    limitations: list[str] = []
    if not rows:
        limitations.append("no_outcome_observations")
    if not features:
        limitations.append("no_explicit_tempo_features")
    if coverage_unknown:
        limitations.append("telemetry_coverage_unknown_for_some_observations")
    severe = sorted(set(unique_confounders) & _SEVERE_CONFOUNDERS)
    if severe:
        limitations.append("tempo_interpretation_blocked_by_telemetry_confounder")

    if not features:
        status = "insufficient"
    elif severe or coverage_unknown or not coverage_samples:
        status = "partial"
    elif min(coverage_samples) <= 0.0:
        status = "partial"
        limitations.append("zero_telemetry_coverage_present")
    else:
        status = "usable"

    coverage_summary = {
        "observation_count": len(rows),
        "known_coverage_count": len(coverage_samples),
        "unknown_coverage_count": coverage_unknown,
        "minimum_known_coverage": min(coverage_samples) if coverage_samples else None,
    }
    return TempoFeatureSummary(
        trace_id=trace_id,
        status=status,
        features=features,
        coverage=coverage_summary,
        confounders=unique_confounders,
        source_observation_refs=tuple(refs),
        limitations=tuple(dict.fromkeys(limitations)),
    )
