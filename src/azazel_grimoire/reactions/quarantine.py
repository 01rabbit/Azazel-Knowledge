"""Reaction-source quarantine bookkeeping (research-integrity ruling).

A quarantined edge's future reactions are still recorded in full --
never dropped -- and neither the `reaction` row nor its `trust_tier`
cache is ever mutated because of quarantine (rows are immutable by
design and Phase 1 review found mutating confidence for quarantine to be
a research-integrity risk). Quarantine is surfaced only via an
append-only `reaction_trust_event` marker so downstream export/analysis
can filter it in.

There is no dedicated quarantine table for edges in the local schema;
`feed_quarantine` (keyed on `feed_id`) is reused with the convention
`feed_id = "edge:<edge_id>"`.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime

from azazel_grimoire.core.clock import to_rfc3339
from azazel_grimoire.reactions.eligibility import append_trust_event

_EDGE_PREFIX = "edge:"


def _feed_id(edge_id: str) -> str:
    return f"{_EDGE_PREFIX}{edge_id}"


def quarantine_edge(
    conn: sqlite3.Connection,
    edge_id: str,
    reason: str,
    *,
    now: datetime,
    detail: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO feed_quarantine (feed_id, quarantined_at, reason, detail, resolved_at) "
        "VALUES (?, ?, ?, ?, NULL)",
        (_feed_id(edge_id), to_rfc3339(now), reason, detail),
    )


def release_edge(conn: sqlite3.Connection, edge_id: str, *, now: datetime) -> None:
    conn.execute(
        "UPDATE feed_quarantine SET resolved_at = ? WHERE feed_id = ? AND resolved_at IS NULL",
        (to_rfc3339(now), _feed_id(edge_id)),
    )


def is_edge_quarantined(conn: sqlite3.Connection, edge_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM feed_quarantine WHERE feed_id = ? AND resolved_at IS NULL LIMIT 1",
        (_feed_id(edge_id),),
    ).fetchone()
    return row is not None


def maybe_flag_reaction(
    conn: sqlite3.Connection,
    *,
    reaction_id: int,
    edge_id: str,
    actor_key: str,
    now: datetime,
) -> bool:
    """Append a quarantine marker for `reaction_id` if its edge is quarantined.

    Never mutates the reaction row or its cached trust tier. Returns True
    if a marker was appended.
    """
    if not is_edge_quarantined(conn, edge_id):
        return False
    append_trust_event(
        conn,
        reaction_id=reaction_id,
        edge_id=edge_id,
        actor_key=actor_key,
        event_type="edge_quarantined_source",
        detail={"edge_id": edge_id},
        now=now,
    )
    return True
