"""Background reaction classification (design S8, P1 priority).

Input is a reaction row already validated by
`ingest.validators.validate_reaction_line`. Phase 1 trusts the
Edge-supplied `reaction` label as the stored, authoritative value --
`reaction` rows are core immutable research data -- but a first-match
ladder over the reaction enum still recomputes an independent verdict
from the resolvable evidence (`evidence_refs` count and distinct
`observation.kind` modalities). That verdict is recorded as a
`reaction_trust_event` (`event_type='classifier_verdict'`) for research
auditability; it never overrides the stored `reaction` value. Insertion
is INSERT-only: the table's `unique(edge_id, actor_key, action_applied,
applied_at, classifier)` makes replays of the same batch a no-op via
`INSERT OR IGNORE`.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from azazel_knowledge.core.clock import to_rfc3339
from azazel_knowledge.reactions import linkage, quarantine
from azazel_knowledge.reactions.eligibility import append_trust_event

CLASSIFIER_NAME = "reaction_ladder"
CLASSIFIER_VERSION = "1"


def _resolve_evidence(
    conn: sqlite3.Connection, evidence_refs: Sequence[str]
) -> tuple[int, int]:
    """Return `(events_in_window, evidence_modality_count)`.

    Modality is the count of distinct `observation.kind` values among
    observations referenced by `evidence_refs` (their `event_id`s). When
    none resolve (evidence arrived before/without a matching observation),
    fall back to the number of distinct evidence references supplied, so
    the count is never silently zero when the Edge did send evidence.
    """
    if not evidence_refs:
        return 0, 0
    placeholders = ",".join("?" for _ in evidence_refs)
    rows = conn.execute(
        f"SELECT kind FROM observation WHERE event_id IN ({placeholders})",
        list(evidence_refs),
    ).fetchall()
    events_in_window = len(rows)
    if rows:
        modality_count = len({row[0] for row in rows})
    else:
        modality_count = len(set(evidence_refs))
    return events_in_window, modality_count


def classify_verdict(*, events_in_window: int, evidence_modality_count: int) -> str:
    """First-match ladder producing a research verdict (never authoritative)."""
    if events_in_window <= 0:
        return "disengaged"
    if evidence_modality_count >= 3:
        return "shifted_protocol"
    if evidence_modality_count == 2:
        return "shifted_port"
    if evidence_modality_count == 1:
        return "continued_scanning"
    return "unknown"


def ingest_reaction(
    conn: sqlite3.Connection, validated: Mapping[str, Any], *, now: datetime
) -> int | None:
    """Classify and immutably insert one already-validated reaction row.

    Returns the new `reaction_id`, or `None` if this was a dedupe no-op
    (an identical row already exists per the table's unique constraint).
    """
    evidence_refs = list(validated["evidence_refs"])
    events_in_window, modality_count = _resolve_evidence(conn, evidence_refs)
    verdict = classify_verdict(
        events_in_window=events_in_window, evidence_modality_count=modality_count
    )

    advisory_linkage = linkage.initial_linkage_state(
        conn,
        advisory_id=validated.get("advisory_id"),
        actor_key=validated["actor_key"],
        edge_id=validated["edge_id"],
        applied_at=validated["applied_at"],
    )

    cursor = conn.execute(
        "INSERT OR IGNORE INTO reaction "
        "(edge_id, actor_key, action_applied, applied_at, reaction, reaction_window_s, "
        "events_in_window, classifier, classifier_version, evidence_refs, "
        "evidence_modality_count, trust_tier, advisory_id, advisory_linkage, created_at, "
        "actor_cluster_key, action_profile, decoy_touched, decoy_profile, "
        "retry_interval_ms, timeout_adaptation, payload_ext) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            validated["edge_id"],
            validated["actor_key"],
            validated["action_applied"],
            validated["applied_at"],
            validated["reaction"],
            validated["reaction_window_s"],
            events_in_window,
            CLASSIFIER_NAME,
            CLASSIFIER_VERSION,
            json.dumps(evidence_refs),
            modality_count,
            "provisional",
            validated.get("advisory_id"),
            advisory_linkage,
            to_rfc3339(now),
            validated.get("actor_cluster_key"),
            validated.get("action_profile"),
            validated.get("decoy_touched"),
            validated.get("decoy_profile"),
            validated.get("retry_interval_ms"),
            validated.get("timeout_adaptation"),
            json.dumps(validated.get("payload_ext", {}), sort_keys=True),
        ),
    )
    if cursor.rowcount == 0:
        return None

    reaction_id = int(cursor.lastrowid)
    append_trust_event(
        conn,
        reaction_id=reaction_id,
        edge_id=validated["edge_id"],
        actor_key=validated["actor_key"],
        event_type="classifier_verdict",
        detail={
            "verdict": verdict,
            "classifier": CLASSIFIER_NAME,
            "classifier_version": CLASSIFIER_VERSION,
        },
        now=now,
    )
    quarantine.maybe_flag_reaction(
        conn,
        reaction_id=reaction_id,
        edge_id=validated["edge_id"],
        actor_key=validated["actor_key"],
        now=now,
    )
    return reaction_id
