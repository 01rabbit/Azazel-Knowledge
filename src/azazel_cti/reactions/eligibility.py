"""Trust tiering and metrics eligibility (design S8).

`reaction.trust_tier` is written once at insert time and is a
non-authoritative cache -- `reaction` rows are immutable, so the
authoritative tier is always recomputed here from the append-only
`reaction_trust_event` log. Ladder: `provisional` ->
`same_edge_corroborated` (>= 2 evidence modalities, informational) ->
`human_confirmed` (an admin confirm event) | `corroborated` (a distinct
`edge_id` other than the reaction's own has appended a trust event --
inert in the Phase 1 single-edge deployment, never mutated for it).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from azazel_cti.core.clock import to_rfc3339

TRUST_TIERS: tuple[str, ...] = (
    "provisional",
    "same_edge_corroborated",
    "human_confirmed",
    "corroborated",
)

_FALLBACK_METRICS_CONFIG: dict[str, Any] = {
    "min_trust_tier": "same_edge_corroborated",
    "min_evidence_modality_count": 2,
    "exclude_linkage": ["none"],
}

_DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parents[3] / "config" / "research_metrics.yaml"
)


def _load_default_metrics_config() -> dict[str, Any]:
    try:
        document = yaml.safe_load(_DEFAULT_CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except OSError:
        return dict(_FALLBACK_METRICS_CONFIG)
    return document.get("metrics_eligible_strict", _FALLBACK_METRICS_CONFIG)


DEFAULT_METRICS_CONFIG: dict[str, Any] = _load_default_metrics_config()


def append_trust_event(
    conn: sqlite3.Connection,
    *,
    reaction_id: int,
    edge_id: str,
    actor_key: str,
    event_type: str,
    detail: Mapping[str, Any] | None,
    now: datetime,
) -> int:
    cursor = conn.execute(
        "INSERT INTO reaction_trust_event "
        "(reaction_id, edge_id, actor_key, event_type, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            reaction_id,
            edge_id,
            actor_key,
            event_type,
            json.dumps(detail, sort_keys=True) if detail is not None else None,
            to_rfc3339(now),
        ),
    )
    return int(cursor.lastrowid)


def recompute_trust_tier(
    reaction: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> str:
    """Pure recomputation from a reaction row and its trust events.

    `reaction` needs `edge_id` and `evidence_modality_count`; each event
    needs `event_type` and, when present, `edge_id`.
    """
    if any(event.get("event_type") == "human_confirmed" for event in events):
        return "human_confirmed"

    distinct_edges = {reaction["edge_id"]}
    for event in events:
        edge = event.get("edge_id")
        if edge:
            distinct_edges.add(edge)
    if len(distinct_edges) > 1:
        return "corroborated"

    if int(reaction.get("evidence_modality_count", 0) or 0) >= 2:
        return "same_edge_corroborated"

    return "provisional"


def recompute_trust_tier_for_reaction(conn: sqlite3.Connection, reaction_id: int) -> str:
    row = conn.execute(
        "SELECT edge_id, evidence_modality_count FROM reaction WHERE reaction_id = ?",
        (reaction_id,),
    ).fetchone()
    if row is None:
        raise KeyError(reaction_id)
    reaction = {"edge_id": row[0], "evidence_modality_count": row[1]}
    events = [
        {"event_type": r[0], "edge_id": r[1]}
        for r in conn.execute(
            "SELECT event_type, edge_id FROM reaction_trust_event WHERE reaction_id = ?",
            (reaction_id,),
        ).fetchall()
    ]
    return recompute_trust_tier(reaction, events)


def metrics_eligible_strict(
    reaction: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    *,
    config: Mapping[str, Any] | None = None,
) -> bool:
    cfg = config if config is not None else DEFAULT_METRICS_CONFIG
    tier = recompute_trust_tier(reaction, events)
    min_tier = cfg.get("min_trust_tier", "same_edge_corroborated")
    if TRUST_TIERS.index(tier) < TRUST_TIERS.index(min_tier):
        return False

    min_modality = int(cfg.get("min_evidence_modality_count", 0))
    if int(reaction.get("evidence_modality_count", 0) or 0) < min_modality:
        return False

    excluded_linkage = set(cfg.get("exclude_linkage", []))
    if reaction.get("advisory_linkage") in excluded_linkage:
        return False

    return True
