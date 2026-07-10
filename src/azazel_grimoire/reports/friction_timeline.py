from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from typing import Any

from azazel_grimoire.core.clock import to_rfc3339
from azazel_grimoire.correlate.pipeline import ADVISORY_NOTICE
from azazel_grimoire.db.behavior import BehaviorPattern
from azazel_grimoire.db.repository import Repository

_FORBIDDEN_LANGUAGE = (
    "AI attacker confirmed",
    "LLM identified",
    "autonomous intrusion proven",
)

_POSTURE_BY_CLASS = {
    "simple_scanner": "observe",
    "scripted_automation": "delay",
    "adaptive_probe": "delay",
    "decoy_engaged": "decoy",
    "disengaged_after_friction": "no_change",
    "unknown": "unknown",
}


def _current_generation(
    repo: Repository,
    conn: sqlite3.Connection,
    behavior_generation: int | None,
) -> int | None:
    if behavior_generation is not None:
        return behavior_generation
    return repo.get_current_behavior_generation(conn)


def _load_pattern(
    repo: Repository,
    conn: sqlite3.Connection,
    *,
    pattern_id: str,
    behavior_generation: int | None = None,
) -> BehaviorPattern | None:
    generation = _current_generation(repo, conn, behavior_generation)
    if generation is None:
        return None
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT pattern_id, behavior_generation, version, actor_key, actor_cluster_key, "
        "edge_id, observation_start, observation_end, action_applied, reaction_sequence, "
        "reaction_window_s, behavior_class, confidence, novelty_score, "
        "repeatability_score, suspected_stage, related_iocs, related_ttps, "
        "generated_at, generator_version, behavior_config_hash, provenance "
        "FROM behavior_pattern WHERE pattern_id = ? AND behavior_generation = ? "
        "ORDER BY pattern_id ASC",
        (pattern_id, generation),
    ).fetchone()
    if row is None:
        return None
    return BehaviorPattern.from_row(row)


def _select_report_pattern(
    repo: Repository,
    conn: sqlite3.Connection,
    *,
    pattern_id: str | None,
    actor_key: str | None,
    edge_id: str | None,
    behavior_generation: int | None = None,
) -> BehaviorPattern | None:
    if pattern_id is not None:
        return _load_pattern(repo, conn, pattern_id=pattern_id, behavior_generation=behavior_generation)

    generation = _current_generation(repo, conn, behavior_generation)
    if generation is None:
        return None

    clauses = ["behavior_generation = ?"]
    params: list[Any] = [generation]
    if actor_key is not None:
        clauses.append("actor_key = ?")
        params.append(actor_key)
    if edge_id is not None:
        clauses.append("edge_id = ?")
        params.append(edge_id)

    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT pattern_id, behavior_generation, version, actor_key, actor_cluster_key, "
        "edge_id, observation_start, observation_end, action_applied, reaction_sequence, "
        "reaction_window_s, behavior_class, confidence, novelty_score, "
        "repeatability_score, suspected_stage, related_iocs, related_ttps, "
        "generated_at, generator_version, behavior_config_hash, provenance "
        f"FROM behavior_pattern WHERE {' AND '.join(clauses)} "
        "ORDER BY observation_end DESC, pattern_id ASC LIMIT 1",
        tuple(params),
    ).fetchone()
    if row is None:
        return None
    return BehaviorPattern.from_row(row)


def _pattern_to_dict(pattern: BehaviorPattern) -> dict[str, Any]:
    return {
        "pattern_id": pattern.pattern_id,
        "behavior_generation": pattern.behavior_generation,
        "version": pattern.version,
        "actor_key": pattern.actor_key,
        "actor_cluster_key": pattern.actor_cluster_key,
        "edge_id": pattern.edge_id,
        "observation_start": pattern.observation_start,
        "observation_end": pattern.observation_end,
        "action_applied": pattern.action_applied,
        "reaction_sequence": list(pattern.reaction_sequence),
        "reaction_window_s": pattern.reaction_window_s,
        "behavior_class": pattern.behavior_class,
        "confidence": pattern.confidence,
        "novelty_score": pattern.novelty_score,
        "repeatability_score": pattern.repeatability_score,
        "suspected_stage": pattern.suspected_stage,
        "related_iocs": list(pattern.related_iocs),
        "related_ttps": list(pattern.related_ttps),
        "generated_at": pattern.generated_at,
        "generator_version": pattern.generator_version,
        "behavior_config_hash": pattern.behavior_config_hash,
        "provenance": dict(pattern.provenance),
    }


def _evidence_ref(evidence_type: str, evidence_id: str, payload: dict[str, Any] | None = None) -> str:
    if evidence_type == "observation":
        event_id = None if payload is None else payload.get("event_id")
        return f"observation:{event_id or evidence_id}"
    if evidence_type == "reaction":
        return f"reaction:{evidence_id}"
    if evidence_type == "pattern":
        return f"pattern:{evidence_id}"
    return f"{evidence_type}:{evidence_id}"


def _resolved_evidence_rows(
    repo: Repository, conn: sqlite3.Connection, pattern: BehaviorPattern
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for evidence in repo.get_behavior_pattern_evidence(conn, pattern.pattern_id, pattern.behavior_generation):
        resolved = repo.resolve_behavior_evidence(conn, evidence)
        payload = None if resolved is None else dict(resolved.payload)
        rows.append(
            {
                "evidence_type": evidence.evidence_type,
                "evidence_id": evidence.evidence_id,
                "role": evidence.role,
                "evidence_ref": _evidence_ref(evidence.evidence_type, evidence.evidence_id, payload),
                "resolved": payload,
            }
        )
    return rows


def _similarity_rows(repo: Repository, conn: sqlite3.Connection, pattern: BehaviorPattern) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for similarity in repo.get_behavior_pattern_similarities(conn, pattern.pattern_id, pattern.behavior_generation):
        rows.append(
            {
                "other_pattern_id": similarity.other_pattern_id,
                "similarity": similarity.similarity,
                "repeatability": similarity.repeatability,
                "shared_features": list(similarity.shared_features),
                "differences": list(similarity.differences),
                "evidence_refs": list(similarity.evidence_refs),
            }
        )
    return rows


def _unique_refs(rows: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for row in rows:
        ref = str(row["evidence_ref"])
        if ref in seen:
            continue
        seen.add(ref)
        ordered.append(ref)
    return ordered


def _source_reaction_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if row["evidence_type"] == "reaction" and row["role"] == "source" and row["resolved"] is not None
    ]


def _observation_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if row["evidence_type"] == "observation" and row["resolved"] is not None
    ]


def _pattern_source_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if row["evidence_type"] == "pattern" and row["resolved"] is not None
    ]


def _advisory_summary(
    pattern: BehaviorPattern,
    evidence_rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    linked_patterns = _pattern_source_rows(evidence_rows)
    advisory_texts: list[str] = []
    source_pattern_ids: list[str] = []
    for row in linked_patterns:
        resolved = row["resolved"]
        if resolved is None:
            continue
        source_pattern_ids.append(str(resolved["pattern_id"]))
        advisory = resolved.get("advisory")
        if isinstance(advisory, str) and advisory.strip():
            advisory_texts.append(advisory.strip())
    if advisory_texts:
        return {
            "status": "linked_pattern_advisory",
            "suggested_posture": _POSTURE_BY_CLASS[pattern.behavior_class],
            "source_pattern_ids": source_pattern_ids,
            "texts": advisory_texts,
        }
    return None


def _timeline(
    pattern: BehaviorPattern,
    evidence_rows: list[dict[str, Any]],
    advisory_summary: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    observation_rows = _observation_rows(evidence_rows)
    source_reactions = _source_reaction_rows(evidence_rows)
    observation_refs = [row["evidence_ref"] for row in observation_rows]
    reaction_refs = [row["evidence_ref"] for row in source_reactions]
    all_refs = _unique_refs(evidence_rows)
    first_observed_at = (
        str(observation_rows[0]["resolved"]["observed_at"])
        if observation_rows
        else pattern.observation_start
    )
    first_applied_at = (
        str(source_reactions[0]["resolved"]["applied_at"])
        if source_reactions
        else pattern.observation_start
    )
    reaction_names = [
        str(row["resolved"]["reaction"])
        for row in source_reactions
        if row["resolved"] is not None and row["resolved"].get("reaction") is not None
    ]
    reaction_phrase = ", ".join(reaction_names) if reaction_names else ", ".join(pattern.reaction_sequence)
    posture = _POSTURE_BY_CLASS[pattern.behavior_class]
    advisory_text = (
        "behavioral CTI generated from defensive friction suggests posture review with linked advisory context."
        if advisory_summary is not None
        else "behavioral CTI generated from defensive friction suggests posture review; linked advisory context is unavailable."
    )
    return [
        {
            "timestamp": first_observed_at,
            "event_type": "initial_observation",
            "evidence_refs": observation_refs or all_refs,
            "explanation_short": "Initial observation captured before defensive friction was applied.",
        },
        {
            "timestamp": first_applied_at,
            "event_type": "edge_action_applied",
            "action_applied": pattern.action_applied,
            "evidence_refs": reaction_refs or all_refs,
            "explanation_short": f"Edge applied {pattern.action_applied} as a defensive friction step.",
        },
        {
            "timestamp": pattern.observation_end,
            "event_type": "reaction_window",
            "action_applied": pattern.action_applied,
            "evidence_refs": reaction_refs or all_refs,
            "explanation_short": (
                f"Reaction window closed after {pattern.reaction_window_s or 0} seconds with linked source reactions."
            ),
        },
        {
            "timestamp": pattern.observation_end,
            "event_type": "reaction_classification",
            "reaction": reaction_phrase,
            "evidence_refs": reaction_refs or all_refs,
            "explanation_short": f"Reaction classification shows {reaction_phrase}; adaptive behavior observed.",
        },
        {
            "timestamp": pattern.generated_at,
            "event_type": "generated_behavior_pattern",
            "reaction": pattern.behavior_class,
            "evidence_refs": all_refs,
            "explanation_short": (
                f"Behavioral CTI generated from defensive friction classified this sequence as {pattern.behavior_class}."
            ),
        },
        {
            "timestamp": pattern.generated_at,
            "event_type": "evidence_references",
            "evidence_refs": all_refs,
            "explanation_short": "Evidence references are preserved for operator review and traceability.",
        },
        {
            "timestamp": pattern.generated_at,
            "event_type": "advisory_implication",
            "reaction": posture,
            "evidence_refs": all_refs,
            "explanation_short": advisory_text,
        },
        {
            "timestamp": pattern.generated_at,
            "event_type": "cti_advisory_disclaimer",
            "evidence_refs": [],
            "explanation_short": ADVISORY_NOTICE,
        },
    ]


def _limitations(
    similarities: list[dict[str, Any]],
    advisory_summary: dict[str, Any] | None,
) -> list[str]:
    values = [ADVISORY_NOTICE]
    if not similarities:
        values.append("Behavior pattern similarity data is unavailable for this report generation.")
    if advisory_summary is None:
        values.append(
            "Related advisory data was unavailable; behavioral CTI generated from defensive friction remains advisory-only."
        )
    return values


def _assert_language_guardrails(value: Any) -> None:
    text = str(value)
    for phrase in _FORBIDDEN_LANGUAGE:
        if phrase in text:
            raise ValueError(f"forbidden attribution language in report output: {phrase}")


def get_behavior_pattern_detail(
    repo: Repository,
    *,
    pattern_id: str,
    behavior_generation: int | None = None,
) -> dict[str, Any]:
    with repo.connection() as conn:
        pattern = _load_pattern(repo, conn, pattern_id=pattern_id, behavior_generation=behavior_generation)
        if pattern is None:
            raise KeyError(pattern_id)
        evidence_rows = _resolved_evidence_rows(repo, conn, pattern)
        similarities = _similarity_rows(repo, conn, pattern)
    advisory_summary = _advisory_summary(pattern, evidence_rows)
    result = {
        "pattern": _pattern_to_dict(pattern),
        "evidence": evidence_rows,
        "similarity": similarities,
        "limitations": _limitations(similarities, advisory_summary),
        "advisory_notice": ADVISORY_NOTICE,
    }
    _assert_language_guardrails(result)
    return result


def get_behavior_patterns_summary(
    repo: Repository,
    *,
    query_as_of: datetime,
    behavior_class: str | None = None,
    edge_id: str | None = None,
    window_hours: int = 168,
    limit: int = 20,
    behavior_generation: int | None = None,
) -> dict[str, Any]:
    with repo.connection() as conn:
        generation = _current_generation(repo, conn, behavior_generation)
        if generation is None:
            result = {
                "behavior_generation": None,
                "time_window": {
                    "start": to_rfc3339(query_as_of - timedelta(hours=window_hours)),
                    "end": to_rfc3339(query_as_of),
                },
                "filters": {
                    "behavior_class": behavior_class,
                    "edge_id": edge_id,
                    "window_hours": window_hours,
                    "limit": limit,
                },
                "patterns": [],
                "limitations": [ADVISORY_NOTICE],
            }
            _assert_language_guardrails(result)
            return result

        clauses = ["behavior_generation = ?", "observation_end >= ?"]
        params: list[Any] = [generation, to_rfc3339(query_as_of - timedelta(hours=window_hours))]
        if behavior_class is not None:
            clauses.append("behavior_class = ?")
            params.append(behavior_class)
        if edge_id is not None:
            clauses.append("edge_id = ?")
            params.append(edge_id)

        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT pattern_id, behavior_generation, version, actor_key, actor_cluster_key, "
            "edge_id, observation_start, observation_end, action_applied, reaction_sequence, "
            "reaction_window_s, behavior_class, confidence, novelty_score, "
            "repeatability_score, suspected_stage, related_iocs, related_ttps, "
            "generated_at, generator_version, behavior_config_hash, provenance "
            f"FROM behavior_pattern WHERE {' AND '.join(clauses)} "
            "ORDER BY observation_end DESC, pattern_id ASC LIMIT ?",
            tuple([*params, limit]),
        ).fetchall()
    patterns = [_pattern_to_dict(BehaviorPattern.from_row(row)) for row in rows]
    result = {
        "behavior_generation": generation,
        "time_window": {
            "start": to_rfc3339(query_as_of - timedelta(hours=window_hours)),
            "end": to_rfc3339(query_as_of),
        },
        "filters": {
            "behavior_class": behavior_class,
            "edge_id": edge_id,
            "window_hours": window_hours,
            "limit": limit,
        },
        "patterns": patterns,
        "limitations": [ADVISORY_NOTICE],
    }
    _assert_language_guardrails(result)
    return result


def build_friction_timeline_report(
    repo: Repository,
    *,
    query_as_of: datetime,
    pattern_id: str | None = None,
    actor_key: str | None = None,
    edge_id: str | None = None,
    behavior_generation: int | None = None,
) -> dict[str, Any]:
    with repo.connection() as conn:
        pattern = _select_report_pattern(
            repo,
            conn,
            pattern_id=pattern_id,
            actor_key=actor_key,
            edge_id=edge_id,
            behavior_generation=behavior_generation,
        )
        if pattern is None:
            raise KeyError(pattern_id or actor_key or edge_id or "friction_timeline")
        evidence_rows = _resolved_evidence_rows(repo, conn, pattern)
        similarities = _similarity_rows(repo, conn, pattern)
    advisory_summary = _advisory_summary(pattern, evidence_rows)
    result = {
        "report_id": f"friction-{pattern.pattern_id}",
        "actor_key": pattern.actor_key,
        "edge_id": pattern.edge_id,
        "time_window": {
            "start": pattern.observation_start,
            "end": pattern.observation_end,
        },
        "timeline": _timeline(pattern, evidence_rows, advisory_summary),
        "behavior_patterns": [_pattern_to_dict(pattern)],
        "advisory_summary": advisory_summary,
        "limitations": _limitations(similarities, advisory_summary),
    }
    _assert_language_guardrails(result)
    return result
