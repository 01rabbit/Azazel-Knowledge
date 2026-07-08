"""Configuration loading and validation for the query path.

`TrackedConfigLoader` reads every YAML file under a config directory and
computes a `config_hash` that folds in the exact set of query-path files
(design S5/F-2): `scoring.yaml`, `attack-map.yaml`,
`own_infrastructure.yaml`, `feeds.yaml`, `research_metrics.yaml`. That
hash is logged on every advisory and enters the determinism replay
tuple, so any edit to those files is visible in `content_hash`.

Numeric invariants are enforced at load time, never at read time:
`weights` and `confidence_weights` must each sum to 1.0 (tolerance
1e-9), and any `reaction_adjustments` block must declare `mode: shadow`
-- the loader has no code path that accepts `mode: active` (F-19).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

QUERY_PATH_FILES: tuple[str, ...] = (
    "scoring.yaml",
    "attack-map.yaml",
    "own_infrastructure.yaml",
    "feeds.yaml",
    "research_metrics.yaml",
)
BEHAVIOR_PATH_FILES: tuple[str, ...] = ("behavior-classify.yaml",)

_WEIGHT_SUM_TOLERANCE = 1e-9


class ConfigError(Exception):
    """Raised when loaded configuration fails structural or numeric validation."""


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


class TrackedConfigLoader:
    """Loads and validates every YAML file under `config_dir`."""

    def __init__(self, config_dir: str | Path) -> None:
        self._config_dir = Path(config_dir)
        if not self._config_dir.is_dir():
            raise ConfigError(f"config directory not found: {self._config_dir}")

        self._documents: dict[str, Any] = {}
        for path in sorted(self._config_dir.glob("*.yaml")):
            with path.open("r", encoding="utf-8") as handle:
                self._documents[path.name] = yaml.safe_load(handle) or {}

        self._validate()
        self._config_hash = self._compute_config_hash()
        self._behavior_documents = {
            name: self._documents.get(name, {})
            for name in BEHAVIOR_PATH_FILES
        }

    @property
    def config_dir(self) -> Path:
        return self._config_dir

    @property
    def config_hash(self) -> str:
        return self._config_hash

    def raw(self, filename: str) -> Mapping[str, Any]:
        if filename not in self._documents:
            raise ConfigError(f"config file not loaded: {filename}")
        return self._documents[filename]

    def scoring(self) -> Mapping[str, Any]:
        return self.raw("scoring.yaml")

    def weights(self) -> Mapping[str, float]:
        return self.scoring()["weights"]

    def confidence_weights(self) -> Mapping[str, float]:
        return self.scoring()["confidence_weights"]

    def action_bands(self) -> Sequence[Mapping[str, Any]]:
        recommendation = _require_mapping(
            self.scoring().get("recommendation", {}), "scoring.yaml:recommendation"
        )
        return recommendation.get("action_bands", [])

    def deadline_ms(self) -> int:
        context = _require_mapping(
            self.scoring().get("context", {}), "scoring.yaml:context"
        )
        return int(context.get("deadline_ms", 220))

    def max_staleness_s(self) -> int:
        stats = _require_mapping(self.scoring().get("stats", {}), "scoring.yaml:stats")
        return int(stats.get("max_staleness_s", 120))

    def shadow_scoring(self) -> Mapping[str, Any]:
        research = _require_mapping(
            self.scoring().get("research", {}), "scoring.yaml:research"
        )
        return _require_mapping(
            research.get("shadow_scoring", {}), "scoring.yaml:research.shadow_scoring"
        )

    def feeds(self) -> Mapping[str, Any]:
        return self.raw("feeds.yaml")

    def attack_map(self) -> Sequence[Mapping[str, Any]]:
        document = self.raw("attack-map.yaml")
        rules = document.get("rules", document) if isinstance(document, Mapping) else document
        return rules or []

    def own_infrastructure(self) -> Mapping[str, Any]:
        return self.raw("own_infrastructure.yaml")

    def research_metrics(self) -> Mapping[str, Any]:
        return self.raw("research_metrics.yaml")

    def behavior_classify(self) -> Mapping[str, Any]:
        if "behavior-classify.yaml" not in self._documents:
            raise ConfigError("behavior-classify.yaml is required for behavior generation")
        return _require_mapping(
            self.raw("behavior-classify.yaml"), "behavior-classify.yaml"
        )

    def behavior_config_hash(
        self, *, behavior_generation: int, generator_version: str
    ) -> str:
        digest = hashlib.sha256()
        for name in BEHAVIOR_PATH_FILES:
            document = self._behavior_documents.get(name, {})
            digest.update(name.encode("utf-8"))
            digest.update(b"\x00")
            digest.update(_canonical_json_bytes(document))
            digest.update(b"\x00")
        digest.update(str(int(behavior_generation)).encode("utf-8"))
        digest.update(b"\x00")
        digest.update(generator_version.encode("utf-8"))
        return digest.hexdigest()

    def _compute_config_hash(self) -> str:
        digest = hashlib.sha256()
        for name in QUERY_PATH_FILES:
            document = self._documents.get(name, {})
            digest.update(name.encode("utf-8"))
            digest.update(b"\x00")
            digest.update(_canonical_json_bytes(document))
            digest.update(b"\x00")
        return digest.hexdigest()

    def _validate(self) -> None:
        if "scoring.yaml" not in self._documents:
            raise ConfigError("scoring.yaml is required")
        scoring = _require_mapping(self._documents["scoring.yaml"], "scoring.yaml")
        self._validate_weight_sum(scoring, "weights")
        self._validate_weight_sum(scoring, "confidence_weights")
        self._validate_reaction_adjustments(scoring)
        self._validate_behavior_classify()

    def _validate_weight_sum(self, scoring: Mapping[str, Any], key: str) -> None:
        block = scoring.get(key)
        if not isinstance(block, Mapping) or not block:
            raise ConfigError(f"scoring.yaml '{key}' must be a non-empty mapping")
        total = 0.0
        for name, value in block.items():
            try:
                total += float(value)
            except (TypeError, ValueError) as exc:
                raise ConfigError(
                    f"scoring.yaml '{key}.{name}' is not numeric: {value!r}"
                ) from exc
        if abs(total - 1.0) > _WEIGHT_SUM_TOLERANCE:
            raise ConfigError(
                f"scoring.yaml '{key}' must sum to 1.0, got {total!r}"
            )

    def _validate_reaction_adjustments(self, scoring: Mapping[str, Any]) -> None:
        research = scoring.get("research", {}) or {}
        if not isinstance(research, Mapping):
            raise ConfigError("scoring.yaml 'research' must be a mapping")
        shadow_scoring = research.get("shadow_scoring", {}) or {}
        if not isinstance(shadow_scoring, Mapping):
            raise ConfigError("scoring.yaml 'research.shadow_scoring' must be a mapping")

        adjustments = shadow_scoring.get("reaction_adjustments")
        if adjustments is None:
            return
        if not isinstance(adjustments, Mapping):
            raise ConfigError("'reaction_adjustments' must be a mapping")

        mode = adjustments.get("mode")
        if mode != "shadow":
            raise ConfigError(
                f"reaction_adjustments.mode must be 'shadow', got {mode!r} (F-19: "
                "the loader never accepts 'active')"
            )

        enabled = bool(shadow_scoring.get("enabled", False))
        if enabled and mode != "shadow":
            raise ConfigError(
                "research.shadow_scoring.enabled=true requires reaction_adjustments.mode == 'shadow'"
            )

    def _validate_behavior_classify(self) -> None:
        if "behavior-classify.yaml" not in self._documents:
            return
        document = _require_mapping(
            self._documents.get("behavior-classify.yaml"), "behavior-classify.yaml"
        )
        if "version" not in document:
            raise ConfigError("behavior-classify.yaml 'version' is required")
        rules = document.get("rules")
        if not isinstance(rules, list) or not rules:
            raise ConfigError("behavior-classify.yaml 'rules' must be a non-empty list")
        for index, rule in enumerate(rules):
            if not isinstance(rule, Mapping):
                raise ConfigError(f"behavior-classify.yaml 'rules[{index}]' must be a mapping")
            if "class" not in rule:
                raise ConfigError(f"behavior-classify.yaml 'rules[{index}].class' is required")
            when_all = rule.get("when_all")
            if not isinstance(when_all, list) or not when_all:
                raise ConfigError(
                    f"behavior-classify.yaml 'rules[{index}].when_all' must be a non-empty list"
                )
