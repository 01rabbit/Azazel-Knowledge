"""Advisory recommendation selection (design S5) — pure data, no side effects.

Ordered `action_bands`, first match wins, default `observe`.
`rejected_alternatives[]` is a pure function of `(score, confidence,
config)`: every stronger band that was evaluated and failed is reported
with the exact predicate that failed and the actual numbers. It reads no
reaction data (F-19 boundary).
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

DEFAULT_ACTION = "observe"


def _band_matches(band: Mapping[str, Any], score: float, confidence: float) -> bool:
    if band.get("default"):
        return True
    condition = band.get("condition", {}) or {}
    score_gte = condition.get("score_gte")
    confidence_gte = condition.get("confidence_gte")
    if score_gte is not None and score < float(score_gte):
        return False
    if confidence_gte is not None and confidence < float(confidence_gte):
        return False
    return True


def _why_not(band: Mapping[str, Any], score: float, confidence: float) -> str:
    condition = band.get("condition", {}) or {}
    fails: list[str] = []
    score_gte = condition.get("score_gte")
    confidence_gte = condition.get("confidence_gte")
    if score_gte is not None and score < float(score_gte):
        fails.append(f"score {score} < required {score_gte}")
    if confidence_gte is not None and confidence < float(confidence_gte):
        fails.append(f"confidence {confidence} < required {confidence_gte}")
    if not fails:
        fails.append("lower-priority band")
    return "; ".join(fails)


def recommend(
    score: float,
    confidence: float,
    action_bands: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    chosen_index: int | None = None
    for index, band in enumerate(action_bands):
        if _band_matches(band, score, confidence):
            chosen_index = index
            break

    if chosen_index is None:
        return {
            "action": DEFAULT_ACTION,
            "rule": None,
            "delay_profile": None,
            "decoy": None,
            "rejected_alternatives": [
                {"action": band.get("name"), "why_not": _why_not(band, score, confidence)}
                for band in action_bands
            ],
        }

    chosen = action_bands[chosen_index]
    rejected = [
        {
            "action": band.get("name"),
            "why_not": _why_not(band, score, confidence),
        }
        for band in action_bands[:chosen_index]
    ]
    return {
        "action": chosen.get("name", DEFAULT_ACTION),
        "rule": chosen.get("rule"),
        "delay_profile": chosen.get("delay_profile"),
        "decoy": chosen.get("decoy"),
        "rejected_alternatives": rejected,
    }
