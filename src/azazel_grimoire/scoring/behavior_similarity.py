"""Deterministic behavioral similarity and repeatability; this is not attribution."""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from azazel_grimoire.core.clock import parse_rfc3339
from azazel_grimoire.core.config import TrackedConfigLoader
from azazel_grimoire.db.behavior import BehaviorPattern, canonical_behavior_json

_PATTERNS_PER_MS = 40


@dataclass(frozen=True)
class SimilarityMatch:
    pattern_id: str
    similarity: float
    repeatability: int
    shared_features: list[str]
    differences: list[str]
    evidence_refs: list[str]

    def to_record(self, *, query_pattern_id: str, behavior_generation: int) -> tuple[Any, ...]:
        return (
            query_pattern_id,
            behavior_generation,
            self.pattern_id,
            self.similarity,
            self.repeatability,
            canonical_behavior_json(self.shared_features),
            canonical_behavior_json(self.differences),
            canonical_behavior_json(self.evidence_refs),
        )


@dataclass(frozen=True)
class SimilarityResult:
    query_pattern_id: str
    matches: list[SimilarityMatch]


@dataclass(frozen=True)
class PatternContext:
    pattern: BehaviorPattern
    source_reaction_ids: tuple[int, ...]
    source_observation_ids: tuple[int, ...]
    retry_bucket: str | None
    decoy_engaged: bool | None


def _round_similarity(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 6)


def _normalize_text_list(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted({str(value) for value in values if str(value)}))


def _sequence_similarity(left: Sequence[str], right: Sequence[str]) -> float:
    if not left and not right:
        return 1.0
    max_len = max(len(left), len(right))
    if max_len == 0:
        return 1.0
    exact = sum(1 for lval, rval in zip(left, right) if lval == rval)
    return exact / max_len


def _overlap_score(left: Sequence[str], right: Sequence[str]) -> float | None:
    left_set = set(_normalize_text_list(left))
    right_set = set(_normalize_text_list(right))
    union = left_set | right_set
    if not union:
        return None
    return len(left_set & right_set) / len(union)


def _retry_bucket(value: int | None) -> str | None:
    if value is None:
        return None
    if value < 1_000:
        return "fast"
    if value < 5_000:
        return "medium"
    return "slow"


def _budgeted_prior_limit(config: Mapping[str, Any]) -> int:
    max_patterns_compared = int(config.get("max_patterns_compared", 200))
    max_eval_ms = int(config.get("max_eval_ms", 5))
    return max(
        1,
        min(
            max_patterns_compared,
            max_eval_ms * _PATTERNS_PER_MS,
        ),
    )


def _load_pattern_contexts(
    conn: sqlite3.Connection, *, behavior_generation: int
) -> list[PatternContext]:
    conn.row_factory = sqlite3.Row
    pattern_rows = conn.execute(
        "SELECT pattern_id, behavior_generation, version, actor_key, actor_cluster_key, "
        "edge_id, observation_start, observation_end, action_applied, reaction_sequence, "
        "reaction_window_s, behavior_class, confidence, novelty_score, repeatability_score, "
        "suspected_stage, related_iocs, related_ttps, generated_at, generator_version, "
        "behavior_config_hash, provenance "
        "FROM behavior_pattern WHERE behavior_generation = ? "
        "ORDER BY observation_start ASC, pattern_id ASC",
        (behavior_generation,),
    ).fetchall()
    evidence_rows = conn.execute(
        "SELECT pattern_id, evidence_type, evidence_id, role "
        "FROM behavior_pattern_evidence WHERE behavior_generation = ? "
        "ORDER BY pattern_id ASC, evidence_type ASC, evidence_id ASC, role ASC",
        (behavior_generation,),
    ).fetchall()
    evidence_by_pattern: dict[str, dict[str, list[int]]] = defaultdict(
        lambda: {"reaction": [], "observation": []}
    )
    for row in evidence_rows:
        if row["role"] != "source" and row["evidence_type"] == "reaction":
            continue
        if row["evidence_type"] == "reaction":
            evidence_by_pattern[str(row["pattern_id"])]["reaction"].append(int(row["evidence_id"]))
        elif row["evidence_type"] == "observation":
            evidence_by_pattern[str(row["pattern_id"])]["observation"].append(int(row["evidence_id"]))

    reaction_ids = sorted(
        {
            reaction_id
            for evidence in evidence_by_pattern.values()
            for reaction_id in evidence["reaction"]
        }
    )
    retry_by_reaction_id: dict[int, str | None] = {}
    if reaction_ids:
        placeholders = ",".join("?" for _ in reaction_ids)
        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(reaction)").fetchall()
        }
        retry_sql = (
            "retry_interval_ms"
            if "retry_interval_ms" in columns
            else "NULL AS retry_interval_ms"
        )
        decoy_sql = "decoy_touched" if "decoy_touched" in columns else "NULL AS decoy_touched"
        reaction_rows = conn.execute(
            "SELECT reaction_id, "
            f"{retry_sql}, {decoy_sql} "
            f"FROM reaction WHERE reaction_id IN ({placeholders}) "
            "ORDER BY reaction_id ASC",
            tuple(reaction_ids),
        ).fetchall()
        decoy_by_reaction_id: dict[int, int | None] = {}
        for row in reaction_rows:
            reaction_id = int(row[0])
            retry_by_reaction_id[reaction_id] = _retry_bucket(
                None if row[1] is None else int(row[1])
            )
            decoy_by_reaction_id[reaction_id] = None if row[2] is None else int(row[2])
    else:
        decoy_by_reaction_id = {}

    contexts: list[PatternContext] = []
    for row in pattern_rows:
        pattern = BehaviorPattern.from_row(row)
        evidence = evidence_by_pattern.get(pattern.pattern_id, {"reaction": [], "observation": []})
        reaction_source_ids = tuple(sorted(evidence["reaction"]))
        observation_source_ids = tuple(sorted(evidence["observation"]))
        retry_values = sorted(
            {
                retry_by_reaction_id[reaction_id]
                for reaction_id in reaction_source_ids
                if reaction_id in retry_by_reaction_id and retry_by_reaction_id[reaction_id] is not None
            }
        )
        retry_bucket = retry_values[0] if retry_values else None
        decoy_engaged = None
        if pattern.behavior_class == "decoy_engaged" or "followed_decoy" in pattern.reaction_sequence:
            decoy_engaged = True
        elif reaction_source_ids:
            if any(decoy_by_reaction_id.get(reaction_id) == 1 for reaction_id in reaction_source_ids):
                decoy_engaged = True
            elif all(
                decoy_by_reaction_id.get(reaction_id) == 0
                for reaction_id in reaction_source_ids
                if decoy_by_reaction_id.get(reaction_id) is not None
            ):
                decoy_engaged = False
        contexts.append(
            PatternContext(
                pattern=pattern,
                source_reaction_ids=reaction_source_ids,
                source_observation_ids=observation_source_ids,
                retry_bucket=retry_bucket,
                decoy_engaged=decoy_engaged,
            )
        )
    return contexts


def _score_feature(
    *,
    name: str,
    weight: float,
    score: float | None,
    shared_features: list[str],
    differences: list[str],
    shared_label: str,
    difference_label: str,
) -> tuple[float, float]:
    if score is None:
        return 0.0, 0.0
    if score > 0.0:
        shared_features.append(shared_label)
    else:
        differences.append(difference_label)
    return weight * score, weight


def _describe_overlap(name: str, left: Sequence[str], right: Sequence[str]) -> tuple[str, str]:
    shared = sorted(set(left) & set(right))
    missing = sorted((set(left) | set(right)) - set(shared))
    return (
        f"{name}:shared={','.join(shared)}" if shared else f"{name}:shared=none",
        f"{name}:different={','.join(missing)}" if missing else f"{name}:different=none",
    )


def _build_evidence_refs(context: PatternContext) -> list[str]:
    refs = [f"observation:{value}" for value in context.source_observation_ids]
    refs.extend(f"reaction:{value}" for value in context.source_reaction_ids)
    return refs


def _compute_similarity_match(
    query: PatternContext,
    prior: PatternContext,
    *,
    weights: Mapping[str, float],
) -> SimilarityMatch:
    shared_features: list[str] = []
    differences: list[str] = []
    weighted_total = 0.0
    applied_weight = 0.0

    seq_score = _sequence_similarity(
        query.pattern.reaction_sequence,
        prior.pattern.reaction_sequence,
    )
    weighted_total += float(weights["reaction_sequence"]) * seq_score
    applied_weight += float(weights["reaction_sequence"])
    if seq_score == 1.0:
        shared_features.append("reaction_sequence:exact")
    elif seq_score > 0.0:
        shared_features.append(f"reaction_sequence:partial={seq_score:.3f}")
        differences.append("reaction_sequence:order_differs")
    else:
        differences.append("reaction_sequence:no_overlap")

    weighted, applied = _score_feature(
        name="behavior_class",
        weight=float(weights["behavior_class"]),
        score=1.0 if query.pattern.behavior_class == prior.pattern.behavior_class else 0.0,
        shared_features=shared_features,
        differences=differences,
        shared_label=f"behavior_class:{query.pattern.behavior_class}",
        difference_label=(
            f"behavior_class:{query.pattern.behavior_class}!={prior.pattern.behavior_class}"
        ),
    )
    weighted_total += weighted
    applied_weight += applied

    decoy_score: float | None = None
    if query.decoy_engaged is True or prior.decoy_engaged is True:
        decoy_score = 1.0 if query.decoy_engaged == prior.decoy_engaged else 0.0
    weighted, applied = _score_feature(
        name="decoy_engaged",
        weight=float(weights["decoy_engaged"]),
        score=decoy_score,
        shared_features=shared_features,
        differences=differences,
        shared_label=f"decoy_engaged:{bool(query.decoy_engaged)}",
        difference_label=(
            f"decoy_engaged:{query.decoy_engaged}!={prior.decoy_engaged}"
        ),
    )
    weighted_total += weighted
    applied_weight += applied

    weighted, applied = _score_feature(
        name="action_applied",
        weight=float(weights["action_applied"]),
        score=1.0 if query.pattern.action_applied == prior.pattern.action_applied else 0.0,
        shared_features=shared_features,
        differences=differences,
        shared_label=f"action_applied:{query.pattern.action_applied}",
        difference_label=(
            f"action_applied:{query.pattern.action_applied}!={prior.pattern.action_applied}"
        ),
    )
    weighted_total += weighted
    applied_weight += applied

    retry_score: float | None = None
    if query.retry_bucket is not None and prior.retry_bucket is not None:
        retry_score = 1.0 if query.retry_bucket == prior.retry_bucket else 0.0
    weighted, applied = _score_feature(
        name="retry_interval",
        weight=float(weights["retry_interval"]),
        score=retry_score,
        shared_features=shared_features,
        differences=differences,
        shared_label=f"retry_interval:{query.retry_bucket}",
        difference_label=f"retry_interval:{query.retry_bucket}!={prior.retry_bucket}",
    )
    weighted_total += weighted
    applied_weight += applied

    ioc_score = _overlap_score(query.pattern.related_iocs, prior.pattern.related_iocs)
    if ioc_score is not None:
        shared, different = _describe_overlap(
            "ioc_overlap", query.pattern.related_iocs, prior.pattern.related_iocs
        )
    else:
        shared = different = ""
    weighted, applied = _score_feature(
        name="ioc_overlap",
        weight=float(weights["ioc_overlap"]),
        score=ioc_score,
        shared_features=shared_features,
        differences=differences,
        shared_label=shared,
        difference_label=different,
    )
    weighted_total += weighted
    applied_weight += applied

    actor_score = 0.0
    actor_shared: str
    actor_diff: str
    if (
        query.pattern.actor_cluster_key
        and prior.pattern.actor_cluster_key
        and query.pattern.actor_cluster_key == prior.pattern.actor_cluster_key
    ):
        actor_score = 1.0
        actor_shared = f"actor_cluster_key:{query.pattern.actor_cluster_key}"
        actor_diff = ""
    elif query.pattern.actor_key == prior.pattern.actor_key:
        actor_score = 1.0
        actor_shared = f"actor_key:{query.pattern.actor_key}"
        actor_diff = ""
    else:
        actor_shared = ""
        actor_diff = (
            f"actor_identity:{query.pattern.actor_key}/{query.pattern.actor_cluster_key}"
            f"!={prior.pattern.actor_key}/{prior.pattern.actor_cluster_key}"
        )
    weighted, applied = _score_feature(
        name="actor_identity",
        weight=float(weights["actor_identity"]),
        score=actor_score,
        shared_features=shared_features,
        differences=differences,
        shared_label=actor_shared,
        difference_label=actor_diff,
    )
    weighted_total += weighted
    applied_weight += applied

    ttp_score = _overlap_score(query.pattern.related_ttps, prior.pattern.related_ttps)
    if ttp_score is not None:
        shared, different = _describe_overlap(
            "ttp_overlap", query.pattern.related_ttps, prior.pattern.related_ttps
        )
    else:
        shared = different = ""
    weighted, applied = _score_feature(
        name="ttp_overlap",
        weight=float(weights["ttp_overlap"]),
        score=ttp_score,
        shared_features=shared_features,
        differences=differences,
        shared_label=shared,
        difference_label=different,
    )
    weighted_total += weighted
    applied_weight += applied

    similarity = 0.0 if applied_weight == 0.0 else weighted_total / applied_weight
    match = SimilarityMatch(
        pattern_id=prior.pattern.pattern_id,
        similarity=_round_similarity(similarity),
        repeatability=0,
        shared_features=sorted(shared_features),
        differences=sorted(value for value in differences if value),
        evidence_refs=_build_evidence_refs(prior),
    )
    return match


def _time_window_bucket(pattern: BehaviorPattern) -> str:
    return parse_rfc3339(pattern.observation_start).strftime("%Y-%m-%d")


def _compute_repeatability(
    query: PatternContext,
    matches: Sequence[tuple[PatternContext, SimilarityMatch]],
) -> int:
    if not matches:
        return 0
    similar = [item for item in matches if item[1].similarity >= 0.5]
    if not similar:
        return 0
    count_score = min(len(similar), 5) / 5.0 * 30.0
    time_buckets = {_time_window_bucket(item[0].pattern) for item in similar}
    time_score = min(len(time_buckets), 3) / 3.0 * 20.0
    cross_edge_score = (
        15.0 if len({item[0].pattern.edge_id for item in similar}) > 1 else 0.0
    )
    cross_cluster_score = (
        15.0
        if len(
            {
                item[0].pattern.actor_cluster_key
                for item in similar
                if item[0].pattern.actor_cluster_key
            }
        )
        > 1
        else 0.0
    )
    sequence_score = (
        sum(item[1].similarity for item in similar) / len(similar)
    ) * 10.0
    actor_score = 10.0 if any(
        item[0].pattern.actor_key == query.pattern.actor_key
        or (
            query.pattern.actor_cluster_key is not None
            and item[0].pattern.actor_cluster_key == query.pattern.actor_cluster_key
        )
        for item in similar
    ) else 0.0
    return max(
        0,
        min(
            100,
            int(
                round(
                    count_score
                    + time_score
                    + cross_edge_score
                    + cross_cluster_score
                    + sequence_score
                    + actor_score
                )
            ),
        ),
    )


def compare_pattern_to_priors(
    query: PatternContext,
    priors: Sequence[PatternContext],
    *,
    config: Mapping[str, Any],
) -> SimilarityResult:
    weights = config["weights"]
    candidate_pairs = [
        (prior, _compute_similarity_match(query, prior, weights=weights))
        for prior in priors[: _budgeted_prior_limit(config)]
    ]
    candidate_pairs.sort(
        key=lambda item: (-item[1].similarity, item[0].pattern.observation_start, item[0].pattern.pattern_id)
    )
    top_pairs = candidate_pairs[: int(config.get("max_patterns_compared", 200))]
    repeatability = _compute_repeatability(query, top_pairs)
    matches = [
        SimilarityMatch(
            pattern_id=match.pattern_id,
            similarity=match.similarity,
            repeatability=repeatability,
            shared_features=match.shared_features,
            differences=match.differences,
            evidence_refs=match.evidence_refs,
        )
        for _, match in top_pairs
        if match.similarity > 0.0
    ]
    return SimilarityResult(query_pattern_id=query.pattern.pattern_id, matches=matches)


def run_similarity(
    conn: sqlite3.Connection,
    loader: TrackedConfigLoader,
    behavior_generation: int,
) -> list[SimilarityResult]:
    config = loader.behavior_similarity()
    current_patterns = _load_pattern_contexts(conn, behavior_generation=behavior_generation)
    prior_generation = behavior_generation - 1
    prior_patterns = (
        _load_pattern_contexts(conn, behavior_generation=prior_generation)
        if prior_generation > 0
        else []
    )
    results: list[SimilarityResult] = []
    pattern_by_id = {pattern.pattern.pattern_id: pattern for pattern in prior_patterns}
    similarity_rows: list[tuple[Any, ...]] = []
    repeatability_updates: list[tuple[int, str, int]] = []
    for query in current_patterns:
        result = compare_pattern_to_priors(query, prior_patterns, config=config)
        results.append(result)
        repeatability = result.matches[0].repeatability if result.matches else 0
        repeatability_updates.append(
            (repeatability, query.pattern.pattern_id, behavior_generation)
        )
        for match in result.matches:
            similarity_rows.append(
                match.to_record(
                    query_pattern_id=result.query_pattern_id,
                    behavior_generation=behavior_generation,
                )
            )
            pattern_by_id.get(match.pattern_id)
    if similarity_rows:
        conn.executemany(
            "INSERT OR REPLACE INTO behavior_pattern_similarity "
            "(pattern_id, behavior_generation, other_pattern_id, similarity, repeatability, "
            "shared_features, differences, evidence_refs) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            similarity_rows,
        )
    if repeatability_updates:
        conn.executemany(
            "UPDATE behavior_pattern SET repeatability_score = ? "
            "WHERE pattern_id = ? AND behavior_generation = ?",
            repeatability_updates,
        )
    return results


def find_similar_by_pattern_id(
    conn: sqlite3.Connection, *, pattern_id: str, behavior_generation: int
) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT pattern_id, behavior_generation, other_pattern_id, similarity, repeatability, "
        "shared_features, differences, evidence_refs "
        "FROM behavior_pattern_similarity WHERE pattern_id = ? AND behavior_generation = ? "
        "ORDER BY similarity DESC, other_pattern_id ASC",
        (pattern_id, behavior_generation),
    ).fetchall()
    return [
        {
            "pattern_id": str(row["pattern_id"]),
            "behavior_generation": int(row["behavior_generation"]),
            "other_pattern_id": str(row["other_pattern_id"]),
            "similarity": float(row["similarity"]),
            "repeatability": int(row["repeatability"]),
            "shared_features": list(json.loads(row["shared_features"])),
            "differences": list(json.loads(row["differences"])),
            "evidence_refs": list(json.loads(row["evidence_refs"])),
        }
        for row in rows
    ]


def find_similar_by_actor_or_time_window(
    conn: sqlite3.Connection,
    *,
    actor_key: str | None = None,
    observation_start: str | None = None,
    observation_end: str | None = None,
    behavior_generation: int,
) -> list[dict[str, Any]]:
    clauses = ["p.behavior_generation = ?"]
    params: list[Any] = [behavior_generation]
    if actor_key is not None:
        clauses.append("p.actor_key = ?")
        params.append(actor_key)
    if observation_start is not None:
        clauses.append("p.observation_start >= ?")
        params.append(observation_start)
    if observation_end is not None:
        clauses.append("p.observation_end <= ?")
        params.append(observation_end)
    where = " AND ".join(clauses)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT s.pattern_id, s.other_pattern_id, s.similarity, s.repeatability, "
        "s.shared_features, s.differences, s.evidence_refs "
        "FROM behavior_pattern_similarity AS s "
        "JOIN behavior_pattern AS p "
        "ON p.pattern_id = s.pattern_id AND p.behavior_generation = s.behavior_generation "
        f"WHERE {where} "
        "ORDER BY s.similarity DESC, s.pattern_id ASC, s.other_pattern_id ASC",
        tuple(params),
    ).fetchall()
    return [
        {
            "pattern_id": str(row["pattern_id"]),
            "other_pattern_id": str(row["other_pattern_id"]),
            "similarity": float(row["similarity"]),
            "repeatability": int(row["repeatability"]),
            "shared_features": list(json.loads(row["shared_features"])),
            "differences": list(json.loads(row["differences"])),
            "evidence_refs": list(json.loads(row["evidence_refs"])),
        }
        for row in rows
    ]
