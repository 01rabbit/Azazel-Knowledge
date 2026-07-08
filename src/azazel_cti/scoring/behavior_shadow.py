from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from azazel_cti.db.behavior import BehaviorPattern


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


@dataclass(frozen=True)
class BehavioralShadowEvaluation:
    enabled: bool
    would_adjust: bool
    shadow_score_delta: int
    rules_hit: tuple[str, ...]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "would_adjust": self.would_adjust,
            "shadow_score_delta": self.shadow_score_delta,
            "rules_hit": list(self.rules_hit),
            "explanation": self.explanation,
        }


def evaluate_behavioral_shadow(
    pattern: BehaviorPattern,
    rules_block: Mapping[str, Any],
) -> BehavioralShadowEvaluation:
    enabled = bool(rules_block.get("enabled", False))
    max_total_delta = int(rules_block.get("max_total_delta", 0))
    hits: list[str] = []
    total_delta = 0

    for rule in rules_block.get("rules", []):
        if not isinstance(rule, Mapping):
            continue
        when = rule.get("when", {})
        if not isinstance(when, Mapping):
            continue
        if not _rule_matches(pattern, when):
            continue
        shadow_effect = rule.get("shadow_effect", {})
        if not isinstance(shadow_effect, Mapping):
            continue
        total_delta += int(shadow_effect.get("delta", 0))
        hits.append(str(rule["id"]))

    total_delta = _clamp(total_delta, -max_total_delta, max_total_delta)
    would_adjust = bool(hits and total_delta != 0)
    explanation = (
        "Shadow-only; production threat_score unchanged."
        if would_adjust
        else "Shadow-only; no qualifying behavioral evidence; production threat_score unchanged."
    )
    return BehavioralShadowEvaluation(
        enabled=enabled,
        would_adjust=would_adjust,
        shadow_score_delta=total_delta if would_adjust else 0,
        rules_hit=tuple(hits),
        explanation=explanation,
    )


def _rule_matches(pattern: BehaviorPattern, when: Mapping[str, Any]) -> bool:
    for key, expected in when.items():
        if key == "behavior_class" and pattern.behavior_class != expected:
            return False
        if key == "action_applied" and pattern.action_applied != expected:
            return False
        if key == "reaction_contains" and str(expected) not in pattern.reaction_sequence:
            return False
        if key not in {"behavior_class", "action_applied", "reaction_contains"}:
            return False
    return True


def build_behavioral_shadow_record(
    pattern: BehaviorPattern,
    evaluation: BehavioralShadowEvaluation,
) -> dict[str, Any]:
    return {
        "actor_key": pattern.actor_key,
        "behavior_config_hash": pattern.behavior_config_hash,
        "behavior_generation": pattern.behavior_generation,
        "edge_id": pattern.edge_id,
        "generator_version": pattern.generator_version,
        "pattern_id": pattern.pattern_id,
        "behavioral_shadow": evaluation.to_dict(),
    }


def emit_behavioral_shadow_record(path: str | Path, record: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(_canonical_json(record))
        handle.write("\n")
