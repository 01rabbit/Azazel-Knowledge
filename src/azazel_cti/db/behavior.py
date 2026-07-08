from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any


def canonical_behavior_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def behavior_pattern_id(
    edge_id: str,
    actor_key: str,
    observation_start: str,
    observation_end: str,
    generator_version: str,
) -> str:
    digest = hashlib.sha256(
        edge_id.encode("utf-8")
        + b"\x00"
        + actor_key.encode("utf-8")
        + b"\x00"
        + observation_start.encode("utf-8")
        + b"\x00"
        + observation_end.encode("utf-8")
        + b"\x00"
        + generator_version.encode("utf-8")
    ).hexdigest()
    return f"bp-{digest[:16]}"


@dataclass(frozen=True)
class BehaviorPatternEvidence:
    pattern_id: str
    behavior_generation: int
    evidence_type: str
    evidence_id: str
    role: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> BehaviorPatternEvidence:
        return cls(
            pattern_id=str(row["pattern_id"]),
            behavior_generation=int(row["behavior_generation"]),
            evidence_type=str(row["evidence_type"]),
            evidence_id=str(row["evidence_id"]),
            role=str(row["role"]),
        )


@dataclass(frozen=True)
class BehaviorPatternSimilarity:
    pattern_id: str
    behavior_generation: int
    other_pattern_id: str
    similarity: float
    repeatability: int
    shared_features: list[str]
    differences: list[str]
    evidence_refs: list[str]

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> BehaviorPatternSimilarity:
        return cls(
            pattern_id=str(row["pattern_id"]),
            behavior_generation=int(row["behavior_generation"]),
            other_pattern_id=str(row["other_pattern_id"]),
            similarity=float(row["similarity"]),
            repeatability=int(row["repeatability"]),
            shared_features=list(json.loads(row["shared_features"])),
            differences=list(json.loads(row["differences"])),
            evidence_refs=list(json.loads(row["evidence_refs"])),
        )


@dataclass(frozen=True)
class BehaviorPattern:
    pattern_id: str
    behavior_generation: int
    version: int
    actor_key: str
    actor_cluster_key: str | None
    edge_id: str
    observation_start: str
    observation_end: str
    action_applied: str
    reaction_sequence: list[str]
    reaction_window_s: int | None
    behavior_class: str
    confidence: int
    novelty_score: int
    repeatability_score: int
    suspected_stage: str | None
    related_iocs: list[str]
    related_ttps: list[str]
    generated_at: str
    generator_version: str
    behavior_config_hash: str
    provenance: dict[str, Any]

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> BehaviorPattern:
        return cls(
            pattern_id=str(row["pattern_id"]),
            behavior_generation=int(row["behavior_generation"]),
            version=int(row["version"]),
            actor_key=str(row["actor_key"]),
            actor_cluster_key=row["actor_cluster_key"],
            edge_id=str(row["edge_id"]),
            observation_start=str(row["observation_start"]),
            observation_end=str(row["observation_end"]),
            action_applied=str(row["action_applied"]),
            reaction_sequence=list(json.loads(row["reaction_sequence"])),
            reaction_window_s=row["reaction_window_s"],
            behavior_class=str(row["behavior_class"]),
            confidence=int(row["confidence"]),
            novelty_score=int(row["novelty_score"]),
            repeatability_score=int(row["repeatability_score"]),
            suspected_stage=row["suspected_stage"],
            related_iocs=list(json.loads(row["related_iocs"])),
            related_ttps=list(json.loads(row["related_ttps"])),
            generated_at=str(row["generated_at"]),
            generator_version=str(row["generator_version"]),
            behavior_config_hash=str(row["behavior_config_hash"]),
            provenance=dict(json.loads(row["provenance"])),
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "behavior_generation": self.behavior_generation,
            "version": self.version,
            "actor_key": self.actor_key,
            "actor_cluster_key": self.actor_cluster_key,
            "edge_id": self.edge_id,
            "observation_start": self.observation_start,
            "observation_end": self.observation_end,
            "action_applied": self.action_applied,
            "reaction_sequence": canonical_behavior_json(self.reaction_sequence),
            "reaction_window_s": self.reaction_window_s,
            "behavior_class": self.behavior_class,
            "confidence": self.confidence,
            "novelty_score": self.novelty_score,
            "repeatability_score": self.repeatability_score,
            "suspected_stage": self.suspected_stage,
            "related_iocs": canonical_behavior_json(self.related_iocs),
            "related_ttps": canonical_behavior_json(self.related_ttps),
            "generated_at": self.generated_at,
            "generator_version": self.generator_version,
            "behavior_config_hash": self.behavior_config_hash,
            "provenance": canonical_behavior_json(self.provenance),
        }


@dataclass(frozen=True)
class ResolvedBehaviorEvidence:
    evidence: BehaviorPatternEvidence
    payload: dict[str, Any]


def require_behavior_evidence(evidence_rows: list[BehaviorPatternEvidence]) -> None:
    if not evidence_rows:
        raise ValueError("behavior_pattern requires at least one evidence link")
