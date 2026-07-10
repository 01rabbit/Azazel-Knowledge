"""Deterministic behavior pattern generation per phase2 §3.1/§3.2/§3.3."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from azazel_knowledge.core.clock import parse_rfc3339, to_rfc3339
from azazel_knowledge.core.config import TrackedConfigLoader
from azazel_knowledge.db.behavior import (
    BehaviorPattern,
    BehaviorPatternEvidence,
    behavior_pattern_id,
    require_behavior_evidence,
)

GENERATOR_VERSION = "bpg-1"
PATTERN_VERSION = 1
SOURCE_ROLE = "source"
SUPPORTING_ROLE = "supporting"
CLASS_VOCABULARY = frozenset(
    {
        "simple_scanner",
        "scripted_automation",
        "adaptive_probe",
        "decoy_engaged",
        "disengaged_after_friction",
        "unknown",
    }
)


@dataclass(frozen=True)
class ReactionRow:
    reaction_id: int
    edge_id: str
    actor_key: str
    action_applied: str
    applied_at: str
    reaction: str
    reaction_window_s: int
    evidence_refs: tuple[str, ...]
    evidence_modality_count: int
    actor_cluster_key: str | None
    decoy_touched: int | None

    @property
    def partition_key(self) -> tuple[str, str]:
        return (self.edge_id, self.actor_key)


@dataclass(frozen=True)
class SupportingObservation:
    observation_id: int
    event_id: str


@dataclass(frozen=True)
class Episode:
    edge_id: str
    actor_key: str
    actor_cluster_key: str | None
    reactions: tuple[ReactionRow, ...]
    reaction_sequence: tuple[str, ...]
    observation_start: str
    observation_end: str
    action_applied: str
    supporting_observations: tuple[SupportingObservation, ...]
    evidence_modality_count: int
    action_diversity: int
    decoy_seen: bool
    feature_flags: Mapping[str, bool]


@dataclass(frozen=True)
class PersistedPattern:
    pattern: BehaviorPattern
    evidence_rows: tuple[BehaviorPatternEvidence, ...]
    source_reaction_ids: tuple[int, ...]


@dataclass(frozen=True)
class GenerationPlan:
    mode: str
    behavior_generation: int
    query_as_of: str
    generated_at: str
    behavior_config_hash: str
    patterns: tuple[PersistedPattern, ...]
    carried_forward: int
    rebuilt_tail_partitions: tuple[tuple[str, str], ...]

    def to_debug_rows(self) -> list[dict[str, Any]]:
        return [
            {
                **item.pattern.to_record(),
                "evidence_rows": [
                    {
                        "pattern_id": evidence.pattern_id,
                        "behavior_generation": evidence.behavior_generation,
                        "evidence_type": evidence.evidence_type,
                        "evidence_id": evidence.evidence_id,
                        "role": evidence.role,
                    }
                    for evidence in item.evidence_rows
                ],
                "source_reaction_ids": list(item.source_reaction_ids),
            }
            for item in self.patterns
        ]


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _behavior_meta_generation(conn: sqlite3.Connection) -> int | None:
    row = conn.execute(
        "SELECT value FROM behavior_meta WHERE key = 'current_behavior_generation'"
    ).fetchone()
    if row is None:
        return None
    return int(row[0])


def _load_reactions(conn: sqlite3.Connection) -> list[ReactionRow]:
    columns = _table_columns(conn, "reaction")
    actor_cluster_sql = "actor_cluster_key" if "actor_cluster_key" in columns else "NULL AS actor_cluster_key"
    decoy_touched_sql = "decoy_touched" if "decoy_touched" in columns else "NULL AS decoy_touched"
    rows = conn.execute(
        "SELECT reaction_id, edge_id, actor_key, action_applied, applied_at, reaction, "
        "reaction_window_s, evidence_refs, evidence_modality_count, "
        f"{actor_cluster_sql}, {decoy_touched_sql} "
        "FROM reaction ORDER BY edge_id ASC, actor_key ASC, applied_at ASC, reaction_id ASC"
    ).fetchall()
    loaded: list[ReactionRow] = []
    for row in rows:
        loaded.append(
            ReactionRow(
                reaction_id=int(row[0]),
                edge_id=str(row[1]),
                actor_key=str(row[2]),
                action_applied=str(row[3]),
                applied_at=str(row[4]),
                reaction=str(row[5]),
                reaction_window_s=int(row[6]),
                evidence_refs=tuple(str(ref) for ref in json.loads(row[7] or "[]")),
                evidence_modality_count=int(row[8]),
                actor_cluster_key=row[9],
                decoy_touched=None if row[10] is None else int(row[10]),
            )
        )
    return loaded


def _resolve_supporting_observations(
    conn: sqlite3.Connection, evidence_refs: Sequence[str]
) -> tuple[SupportingObservation, ...]:
    if not evidence_refs:
        return ()
    placeholders = ",".join("?" for _ in evidence_refs)
    rows = conn.execute(
        "SELECT observation_id, event_id FROM observation "
        f"WHERE event_id IN ({placeholders}) "
        "ORDER BY observation_id ASC",
        tuple(evidence_refs),
    ).fetchall()
    return tuple(
        SupportingObservation(observation_id=int(row[0]), event_id=str(row[1]))
        for row in rows
    )


def _load_current_generation_patterns(
    conn: sqlite3.Connection, generation: int
) -> dict[tuple[str, str], list[PersistedPattern]]:
    original_factory = conn.row_factory
    conn.row_factory = sqlite3.Row
    try:
        pattern_rows = conn.execute(
        "SELECT pattern_id, behavior_generation, version, actor_key, actor_cluster_key, "
        "edge_id, observation_start, observation_end, action_applied, reaction_sequence, "
        "reaction_window_s, behavior_class, confidence, novelty_score, repeatability_score, "
        "suspected_stage, related_iocs, related_ttps, generated_at, generator_version, "
        "behavior_config_hash, provenance "
        "FROM behavior_pattern WHERE behavior_generation = ? "
        "ORDER BY edge_id ASC, actor_key ASC, observation_start ASC, pattern_id ASC",
        (generation,),
        ).fetchall()
        evidence_rows = conn.execute(
        "SELECT pattern_id, behavior_generation, evidence_type, evidence_id, role "
        "FROM behavior_pattern_evidence WHERE behavior_generation = ? "
        "ORDER BY pattern_id ASC, evidence_type ASC, evidence_id ASC, role ASC",
        (generation,),
        ).fetchall()
    finally:
        conn.row_factory = original_factory
    evidence_by_pattern: dict[str, list[BehaviorPatternEvidence]] = defaultdict(list)
    source_ids_by_pattern: dict[str, list[int]] = defaultdict(list)
    for row in evidence_rows:
        evidence = BehaviorPatternEvidence.from_row(row)
        evidence_by_pattern[evidence.pattern_id].append(evidence)
        if evidence.evidence_type == "reaction" and evidence.role == SOURCE_ROLE:
            source_ids_by_pattern[evidence.pattern_id].append(int(evidence.evidence_id))

    grouped: dict[tuple[str, str], list[PersistedPattern]] = defaultdict(list)
    for row in pattern_rows:
        pattern = BehaviorPattern.from_row(row)
        grouped[(pattern.edge_id, pattern.actor_key)].append(
            PersistedPattern(
                pattern=pattern,
                evidence_rows=tuple(evidence_by_pattern.get(pattern.pattern_id, [])),
                source_reaction_ids=tuple(sorted(source_ids_by_pattern.get(pattern.pattern_id, []))),
            )
        )
    return grouped


def _feature_flags(episode_reactions: Sequence[ReactionRow], min_modality_count: int) -> dict[str, bool]:
    flags = {
        "continued_scanning_after_friction": False,
        "shifted_port_after_friction": False,
        "shifted_protocol_after_friction": False,
        "shifted_target_after_decoy_or_delay": False,
        "followed_decoy": False,
        "auth_pattern_changed": False,
        "disengaged_after_friction": False,
        "sparse_evidence": False,
        "pure_repetitive_scan": False,
    }
    actions_before: list[str] = []
    seen_reactions = {reaction.reaction for reaction in episode_reactions}
    total_modalities = sum(reaction.evidence_modality_count for reaction in episode_reactions)
    flags["sparse_evidence"] = total_modalities < min_modality_count
    flags["pure_repetitive_scan"] = seen_reactions == {"continued_scanning"}

    for reaction in episode_reactions:
        prior_actions = tuple(actions_before)
        if (
            reaction.reaction == "continued_scanning"
            and any(action in {"delay", "throttle"} for action in prior_actions)
        ):
            flags["continued_scanning_after_friction"] = True
        if (
            reaction.reaction == "shifted_port"
            and any(action in {"delay", "throttle"} for action in prior_actions)
        ):
            flags["shifted_port_after_friction"] = True
        if (
            reaction.reaction == "shifted_protocol"
            and any(action in {"delay", "throttle"} for action in prior_actions)
        ):
            flags["shifted_protocol_after_friction"] = True
        if (
            reaction.reaction == "shifted_target"
            and any(action in {"deception", "delay"} for action in prior_actions)
        ):
            flags["shifted_target_after_decoy_or_delay"] = True
        if reaction.reaction == "followed_decoy" or reaction.decoy_touched == 1:
            flags["followed_decoy"] = True
        if reaction.reaction == "auth_pattern_changed":
            flags["auth_pattern_changed"] = True
        if (
            reaction.reaction == "disengaged"
            and any(action in {"deception", "delay"} for action in prior_actions)
        ):
            flags["disengaged_after_friction"] = True
        actions_before.append(reaction.action_applied)
    return flags


def _select_action(actions: Sequence[str], mode: str) -> str:
    if not actions:
        raise ValueError("episode must contain at least one action")
    if len(set(actions)) == 1:
        return actions[0]
    if mode != "dominant_then_first":
        raise ValueError(f"unsupported action selection mode: {mode}")
    counts = Counter(actions)
    winner = max(counts.values())
    for action in actions:
        if counts[action] == winner:
            return action
    return actions[0]


def _build_episodes(
    conn: sqlite3.Connection,
    reactions: Sequence[ReactionRow],
    classify_config: Mapping[str, Any],
) -> list[Episode]:
    session_gap_s = int(classify_config.get("session_gap_s", 3600))
    min_modality_count = int(
        classify_config.get("unknown_thresholds", {}).get("min_total_evidence_modality_count", 2)
    )
    action_mode = str(classify_config.get("action_selection", "dominant_then_first"))
    by_partition: dict[tuple[str, str], list[ReactionRow]] = defaultdict(list)
    for reaction in reactions:
        by_partition[reaction.partition_key].append(reaction)

    episodes: list[Episode] = []
    for partition in sorted(by_partition):
        ordered = sorted(
            by_partition[partition],
            key=lambda row: (row.applied_at, row.reaction_id),
        )
        current: list[ReactionRow] = []
        previous_dt: datetime | None = None
        for reaction in ordered:
            applied_dt = parse_rfc3339(reaction.applied_at)
            if previous_dt is not None:
                gap = int((applied_dt - previous_dt).total_seconds())
                if gap > session_gap_s:
                    episode = _finalize_episode(
                        conn, current, action_mode=action_mode, min_modality_count=min_modality_count
                    )
                    if episode is not None:
                        episodes.append(episode)
                    current = []
            current.append(reaction)
            previous_dt = applied_dt
        episode = _finalize_episode(
            conn, current, action_mode=action_mode, min_modality_count=min_modality_count
        )
        if episode is not None:
            episodes.append(episode)
    return episodes


def _finalize_episode(
    conn: sqlite3.Connection,
    reactions: Sequence[ReactionRow],
    *,
    action_mode: str,
    min_modality_count: int,
) -> Episode | None:
    if not reactions:
        return None
    evidence_refs = tuple(ref for reaction in reactions for ref in reaction.evidence_refs)
    supporting = _resolve_supporting_observations(conn, evidence_refs)
    if not supporting:
        return None
    flags = _feature_flags(reactions, min_modality_count)
    return Episode(
        edge_id=reactions[0].edge_id,
        actor_key=reactions[0].actor_key,
        actor_cluster_key=next(
            (reaction.actor_cluster_key for reaction in reactions if reaction.actor_cluster_key),
            None,
        ),
        reactions=tuple(reactions),
        reaction_sequence=tuple(reaction.reaction for reaction in reactions),
        observation_start=reactions[0].applied_at,
        observation_end=reactions[-1].applied_at,
        action_applied=_select_action([reaction.action_applied for reaction in reactions], action_mode),
        supporting_observations=supporting,
        evidence_modality_count=sum(reaction.evidence_modality_count for reaction in reactions),
        action_diversity=len({reaction.action_applied for reaction in reactions}),
        decoy_seen=flags["followed_decoy"],
        feature_flags=flags,
    )


def _classify_episode(episode: Episode, classify_config: Mapping[str, Any]) -> str:
    rules = classify_config.get("rules", [])
    for rule in rules:
        required = tuple(str(name) for name in rule.get("when_all", []))
        if required and all(bool(episode.feature_flags.get(name, False)) for name in required):
            behavior_class = str(rule["class"])
            if behavior_class not in CLASS_VOCABULARY:
                raise ValueError(f"unsupported behavior_class in config: {behavior_class}")
            return behavior_class
    fallback = str(classify_config.get("fallback_class", "unknown"))
    if fallback not in CLASS_VOCABULARY:
        raise ValueError(f"unsupported fallback behavior_class: {fallback}")
    return fallback


def _score_episode(episode: Episode, classify_config: Mapping[str, Any]) -> tuple[int, int]:
    scoring = classify_config.get("scoring", {})
    confidence_weights = scoring.get("confidence", {})
    novelty_weights = scoring.get("novelty", {})
    confidence = (
        int(confidence_weights.get("base", 0))
        + episode.evidence_modality_count * int(confidence_weights.get("modality_weight", 0))
        + len(episode.reaction_sequence) * int(confidence_weights.get("sequence_weight", 0))
        + episode.action_diversity * int(confidence_weights.get("action_diversity_weight", 0))
        + (int(confidence_weights.get("decoy_bonus", 0)) if episode.decoy_seen else 0)
    )
    novelty = (
        int(novelty_weights.get("base", 0))
        + len(set(episode.reaction_sequence)) * int(novelty_weights.get("unique_reaction_weight", 0))
        + episode.action_diversity * int(novelty_weights.get("action_diversity_weight", 0))
        + (int(novelty_weights.get("decoy_bonus", 0)) if episode.decoy_seen else 0)
    )
    return max(0, min(confidence, 100)), max(0, min(novelty, 100))


def _build_persisted_pattern(
    episode: Episode,
    *,
    behavior_generation: int,
    generated_at: str,
    generator_version: str,
    behavior_config_hash: str,
    classify_config: Mapping[str, Any],
) -> PersistedPattern:
    behavior_class = _classify_episode(episode, classify_config)
    confidence, novelty_score = _score_episode(episode, classify_config)
    pattern_id = behavior_pattern_id(
        episode.edge_id,
        episode.actor_key,
        episode.observation_start,
        episode.observation_end,
        generator_version,
    )
    evidence_rows: list[BehaviorPatternEvidence] = []
    for reaction in episode.reactions:
        evidence_rows.append(
            BehaviorPatternEvidence(
                pattern_id=pattern_id,
                behavior_generation=behavior_generation,
                evidence_type="reaction",
                evidence_id=str(reaction.reaction_id),
                role=SOURCE_ROLE,
            )
        )
    for observation in episode.supporting_observations:
        evidence_rows.append(
            BehaviorPatternEvidence(
                pattern_id=pattern_id,
                behavior_generation=behavior_generation,
                evidence_type="observation",
                evidence_id=str(observation.observation_id),
                role=SUPPORTING_ROLE,
            )
        )
    require_behavior_evidence(evidence_rows)
    provenance = {
        "mode": "derived",
        "query_as_of": generated_at,
        "source_reaction_ids": [reaction.reaction_id for reaction in episode.reactions],
        "supporting_observation_ids": [
            observation.observation_id for observation in episode.supporting_observations
        ],
        "feature_flags": {
            name: bool(value) for name, value in sorted(episode.feature_flags.items())
        },
    }
    pattern = BehaviorPattern(
        pattern_id=pattern_id,
        behavior_generation=behavior_generation,
        version=PATTERN_VERSION,
        actor_key=episode.actor_key,
        actor_cluster_key=episode.actor_cluster_key,
        edge_id=episode.edge_id,
        observation_start=episode.observation_start,
        observation_end=episode.observation_end,
        action_applied=episode.action_applied,
        reaction_sequence=list(episode.reaction_sequence),
        reaction_window_s=None,
        behavior_class=behavior_class,
        confidence=confidence,
        novelty_score=novelty_score,
        repeatability_score=0,
        suspected_stage=None,
        related_iocs=[],
        related_ttps=[],
        generated_at=generated_at,
        generator_version=generator_version,
        behavior_config_hash=behavior_config_hash,
        provenance=provenance,
    )
    return PersistedPattern(
        pattern=pattern,
        evidence_rows=tuple(
            sorted(
                evidence_rows,
                key=lambda row: (row.evidence_type, row.evidence_id, row.role),
            )
        ),
        source_reaction_ids=tuple(reaction.reaction_id for reaction in episode.reactions),
    )


def _copy_forward_pattern(
    persisted: PersistedPattern,
    *,
    behavior_generation: int,
    generated_at: str,
    behavior_config_hash: str,
    query_as_of: str,
) -> PersistedPattern:
    provenance = dict(persisted.pattern.provenance)
    provenance["query_as_of"] = query_as_of
    provenance["carried_forward_from_generation"] = persisted.pattern.behavior_generation
    pattern = BehaviorPattern(
        pattern_id=persisted.pattern.pattern_id,
        behavior_generation=behavior_generation,
        version=persisted.pattern.version,
        actor_key=persisted.pattern.actor_key,
        actor_cluster_key=persisted.pattern.actor_cluster_key,
        edge_id=persisted.pattern.edge_id,
        observation_start=persisted.pattern.observation_start,
        observation_end=persisted.pattern.observation_end,
        action_applied=persisted.pattern.action_applied,
        reaction_sequence=list(persisted.pattern.reaction_sequence),
        reaction_window_s=persisted.pattern.reaction_window_s,
        behavior_class=persisted.pattern.behavior_class,
        confidence=persisted.pattern.confidence,
        novelty_score=persisted.pattern.novelty_score,
        repeatability_score=0,
        suspected_stage=persisted.pattern.suspected_stage,
        related_iocs=list(persisted.pattern.related_iocs),
        related_ttps=list(persisted.pattern.related_ttps),
        generated_at=generated_at,
        generator_version=persisted.pattern.generator_version,
        behavior_config_hash=behavior_config_hash,
        provenance=provenance,
    )
    copied_evidence = tuple(
        BehaviorPatternEvidence(
            pattern_id=pattern.pattern_id,
            behavior_generation=behavior_generation,
            evidence_type=evidence.evidence_type,
            evidence_id=evidence.evidence_id,
            role=evidence.role,
        )
        for evidence in persisted.evidence_rows
    )
    return PersistedPattern(
        pattern=pattern,
        evidence_rows=copied_evidence,
        source_reaction_ids=persisted.source_reaction_ids,
    )


def plan_generation(
    conn: sqlite3.Connection,
    config_loader: TrackedConfigLoader,
    *,
    query_as_of: datetime,
    mode: str,
    generator_version: str = GENERATOR_VERSION,
) -> GenerationPlan:
    if mode not in {"incremental", "rebuild"}:
        raise ValueError(f"unsupported generation mode: {mode}")
    classify_config = config_loader.behavior_classify()
    reactions = _load_reactions(conn)
    current_generation = _behavior_meta_generation(conn) or 0
    query_as_of_rfc3339 = to_rfc3339(query_as_of)

    if mode == "incremental" and current_generation > 0:
        current_patterns = _load_current_generation_patterns(conn, current_generation)
        processed_reaction_ids = {
            reaction_id
            for patterns in current_patterns.values()
            for pattern in patterns
            for reaction_id in pattern.source_reaction_ids
        }
        new_reactions = [reaction for reaction in reactions if reaction.reaction_id not in processed_reaction_ids]
        if not new_reactions:
            return GenerationPlan(
                mode=mode,
                behavior_generation=current_generation,
                query_as_of=query_as_of_rfc3339,
                generated_at=query_as_of_rfc3339,
                behavior_config_hash=config_loader.behavior_config_hash(
                    behavior_generation=current_generation,
                    generator_version=generator_version,
                ),
                patterns=(),
                carried_forward=0,
                rebuilt_tail_partitions=(),
            )
        next_generation = current_generation + 1
        behavior_config_hash = config_loader.behavior_config_hash(
            behavior_generation=next_generation,
            generator_version=generator_version,
        )
        new_by_partition: dict[tuple[str, str], list[ReactionRow]] = defaultdict(list)
        for reaction in new_reactions:
            new_by_partition[reaction.partition_key].append(reaction)

        all_reactions_by_id = {reaction.reaction_id: reaction for reaction in reactions}
        planned: list[PersistedPattern] = []
        carried_forward = 0
        rebuilt_tail_partitions: list[tuple[str, str]] = []
        session_gap_s = int(classify_config.get("session_gap_s", 3600))
        for partition in sorted(
            set(current_patterns.keys()) | set(new_by_partition.keys())
        ):
            existing_patterns = current_patterns.get(partition, [])
            pending_new = sorted(
                new_by_partition.get(partition, []),
                key=lambda row: (row.applied_at, row.reaction_id),
            )
            if not pending_new:
                for persisted in existing_patterns:
                    planned.append(
                        _copy_forward_pattern(
                            persisted,
                            behavior_generation=next_generation,
                            generated_at=query_as_of_rfc3339,
                            behavior_config_hash=behavior_config_hash,
                            query_as_of=query_as_of_rfc3339,
                        )
                    )
                    carried_forward += 1
                continue

            carry = list(existing_patterns)
            tail_seed: list[ReactionRow] = []
            if existing_patterns:
                last_pattern = existing_patterns[-1]
                last_reaction = max(
                    (
                        all_reactions_by_id[reaction_id]
                        for reaction_id in last_pattern.source_reaction_ids
                        if reaction_id in all_reactions_by_id
                    ),
                    key=lambda row: (row.applied_at, row.reaction_id),
                    default=None,
                )
                if last_reaction is not None:
                    first_new = pending_new[0]
                    gap = int(
                        (
                            parse_rfc3339(first_new.applied_at)
                            - parse_rfc3339(last_reaction.applied_at)
                        ).total_seconds()
                    )
                    if gap <= session_gap_s:
                        rebuilt_tail_partitions.append(partition)
                        carry = existing_patterns[:-1]
                        tail_seed = [
                            all_reactions_by_id[reaction_id]
                            for reaction_id in last_pattern.source_reaction_ids
                            if reaction_id in all_reactions_by_id
                        ]
            for persisted in carry:
                planned.append(
                    _copy_forward_pattern(
                        persisted,
                        behavior_generation=next_generation,
                        generated_at=query_as_of_rfc3339,
                        behavior_config_hash=behavior_config_hash,
                        query_as_of=query_as_of_rfc3339,
                    )
                )
                carried_forward += 1
            episodes = _build_episodes(
                conn,
                sorted(
                    [*tail_seed, *pending_new],
                    key=lambda row: (row.applied_at, row.reaction_id),
                ),
                classify_config,
            )
            for episode in episodes:
                planned.append(
                    _build_persisted_pattern(
                        episode,
                        behavior_generation=next_generation,
                        generated_at=query_as_of_rfc3339,
                        generator_version=generator_version,
                        behavior_config_hash=behavior_config_hash,
                        classify_config=classify_config,
                    )
                )
        return GenerationPlan(
            mode=mode,
            behavior_generation=next_generation,
            query_as_of=query_as_of_rfc3339,
            generated_at=query_as_of_rfc3339,
            behavior_config_hash=behavior_config_hash,
            patterns=tuple(
                sorted(
                    planned,
                    key=lambda item: (
                        item.pattern.edge_id,
                        item.pattern.actor_key,
                        item.pattern.observation_start,
                        item.pattern.pattern_id,
                    ),
                )
            ),
            carried_forward=carried_forward,
            rebuilt_tail_partitions=tuple(sorted(rebuilt_tail_partitions)),
        )

    next_generation = current_generation + 1
    behavior_config_hash = config_loader.behavior_config_hash(
        behavior_generation=next_generation,
        generator_version=generator_version,
    )
    episodes = _build_episodes(conn, reactions, classify_config)
    patterns = tuple(
        _build_persisted_pattern(
            episode,
            behavior_generation=next_generation,
            generated_at=query_as_of_rfc3339,
            generator_version=generator_version,
            behavior_config_hash=behavior_config_hash,
            classify_config=classify_config,
        )
        for episode in episodes
    )
    return GenerationPlan(
        mode=mode,
        behavior_generation=next_generation,
        query_as_of=query_as_of_rfc3339,
        generated_at=query_as_of_rfc3339,
        behavior_config_hash=behavior_config_hash,
        patterns=patterns,
        carried_forward=0,
        rebuilt_tail_partitions=(),
    )


def _persist_plan(
    conn: sqlite3.Connection,
    plan: GenerationPlan,
    *,
    before_meta_swap: Callable[[int], None] | None = None,
) -> None:
    if not plan.patterns:
        return
    conn.executemany(
        """
        INSERT OR REPLACE INTO behavior_pattern (
            pattern_id, behavior_generation, version, actor_key, actor_cluster_key,
            edge_id, observation_start, observation_end, action_applied,
            reaction_sequence, reaction_window_s, behavior_class, confidence,
            novelty_score, repeatability_score, suspected_stage, related_iocs,
            related_ttps, generated_at, generator_version, behavior_config_hash, provenance
        ) VALUES (
            :pattern_id, :behavior_generation, :version, :actor_key, :actor_cluster_key,
            :edge_id, :observation_start, :observation_end, :action_applied,
            :reaction_sequence, :reaction_window_s, :behavior_class, :confidence,
            :novelty_score, :repeatability_score, :suspected_stage, :related_iocs,
            :related_ttps, :generated_at, :generator_version, :behavior_config_hash, :provenance
        )
        """,
        [item.pattern.to_record() for item in plan.patterns],
    )
    conn.executemany(
        """
        INSERT OR REPLACE INTO behavior_pattern_evidence (
            pattern_id, behavior_generation, evidence_type, evidence_id, role
        ) VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                evidence.pattern_id,
                evidence.behavior_generation,
                evidence.evidence_type,
                evidence.evidence_id,
                evidence.role,
            )
            for item in plan.patterns
            for evidence in item.evidence_rows
        ],
    )
    conn.execute(
        "DELETE FROM behavior_pattern_similarity WHERE behavior_generation = ?",
        (plan.behavior_generation,),
    )
    if before_meta_swap is not None:
        before_meta_swap(plan.behavior_generation)
    conn.executemany(
        "INSERT OR REPLACE INTO behavior_meta (key, value) VALUES (?, ?)",
        [
            ("current_behavior_generation", str(plan.behavior_generation)),
            ("generator_version", GENERATOR_VERSION),
            ("built_at", plan.generated_at),
        ],
    )


def apply_generation_plan(
    conn: sqlite3.Connection,
    config_loader: TrackedConfigLoader,
    *,
    query_as_of: datetime,
    mode: str,
    before_meta_swap: Callable[[int], None] | None = None,
) -> GenerationPlan:
    plan = plan_generation(conn, config_loader, query_as_of=query_as_of, mode=mode)
    _persist_plan(conn, plan, before_meta_swap=before_meta_swap)
    return plan
