"""Advisory linkage state machine (design S3/S8, F-6).

`reaction.advisory_linkage` is a `CHECK`-constrained column, but `reaction`
rows are immutable (UPDATE-rejecting triggers) -- so the column can only
ever hold the value it was given at INSERT time. This module resolves that
by treating the column as a frozen *initial* state
(`echoed_pending`/`temporal`/`none`, decided once when the row is
inserted) and recording every later transition as an append-only
`reaction_trust_event` row with `event_type='linkage'`; the *effective*
current state is the latest such event if one exists, else the frozen
column value.

Resolver rules: an echoed `advisory_id` starts `echoed_pending`; once the
matching `advisory_log` row exists it becomes `echoed_resolved`; after 24h
without one it becomes `echoed_unresolved`. No `advisory_id` at all tries
a temporal match against `advisory_log` by `(actor_key, edge_id)` within
`linkage_window_s` (default 3600s) -> `temporal`, else `none`.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta

from azazel_cti.core.clock import parse_rfc3339, to_rfc3339
from azazel_cti.reactions.eligibility import append_trust_event

LINKAGE_STATES: tuple[str, ...] = (
    "echoed_resolved",
    "echoed_pending",
    "echoed_unresolved",
    "temporal",
    "none",
)

DEFAULT_LINKAGE_WINDOW_S = 3600
UNRESOLVED_AFTER_S = 24 * 3600

_AMBIGUOUS_STATES = frozenset({"echoed_pending", "echoed_unresolved", "temporal"})


def _temporal_match_exists(
    conn: sqlite3.Connection,
    *,
    actor_key: str,
    edge_id: str,
    applied_at: str,
    linkage_window_s: int,
) -> bool:
    applied_dt = parse_rfc3339(applied_at)
    lo = to_rfc3339(applied_dt - timedelta(seconds=linkage_window_s))
    hi = to_rfc3339(applied_dt + timedelta(seconds=linkage_window_s))
    row = conn.execute(
        "SELECT 1 FROM advisory_log WHERE actor_key = ? AND edge_id = ? "
        "AND created_at BETWEEN ? AND ? LIMIT 1",
        (actor_key, edge_id, lo, hi),
    ).fetchone()
    return row is not None


def initial_linkage_state(
    conn: sqlite3.Connection,
    *,
    advisory_id: str | None,
    actor_key: str,
    edge_id: str,
    applied_at: str,
    linkage_window_s: int = DEFAULT_LINKAGE_WINDOW_S,
) -> str:
    if advisory_id:
        return "echoed_pending"
    if _temporal_match_exists(
        conn,
        actor_key=actor_key,
        edge_id=edge_id,
        applied_at=applied_at,
        linkage_window_s=linkage_window_s,
    ):
        return "temporal"
    return "none"


def _append_linkage_event(
    conn: sqlite3.Connection,
    *,
    reaction_id: int,
    edge_id: str,
    actor_key: str,
    state: str,
    now: datetime,
) -> None:
    append_trust_event(
        conn,
        reaction_id=reaction_id,
        edge_id=edge_id,
        actor_key=actor_key,
        event_type="linkage",
        detail={"state": state},
        now=now,
    )


def resolve_pending(conn: sqlite3.Connection, now: datetime) -> int:
    """P0 worker entry point: advance every still-`echoed_pending` reaction."""
    rows = conn.execute(
        "SELECT reaction_id, advisory_id, actor_key, edge_id, created_at FROM reaction "
        "WHERE advisory_linkage = 'echoed_pending' AND advisory_id IS NOT NULL "
        "AND reaction_id NOT IN "
        "(SELECT reaction_id FROM reaction_trust_event WHERE event_type = 'linkage')"
    ).fetchall()

    resolved = 0
    for reaction_id, advisory_id, actor_key, edge_id, created_at in rows:
        landed = conn.execute(
            "SELECT 1 FROM advisory_log WHERE advisory_id = ?", (advisory_id,)
        ).fetchone()
        if landed is not None:
            _append_linkage_event(
                conn,
                reaction_id=reaction_id,
                edge_id=edge_id,
                actor_key=actor_key,
                state="echoed_resolved",
                now=now,
            )
            resolved += 1
            continue

        created_dt = parse_rfc3339(created_at)
        if (now - created_dt).total_seconds() >= UNRESOLVED_AFTER_S:
            _append_linkage_event(
                conn,
                reaction_id=reaction_id,
                edge_id=edge_id,
                actor_key=actor_key,
                state="echoed_unresolved",
                now=now,
            )
            resolved += 1

    return resolved


def linkage_state(conn: sqlite3.Connection, reaction_id: int) -> str:
    row = conn.execute(
        "SELECT detail FROM reaction_trust_event "
        "WHERE reaction_id = ? AND event_type = 'linkage' ORDER BY event_id DESC LIMIT 1",
        (reaction_id,),
    ).fetchone()
    if row is not None:
        return json.loads(row[0])["state"]

    column = conn.execute(
        "SELECT advisory_linkage FROM reaction WHERE reaction_id = ?", (reaction_id,)
    ).fetchone()
    if column is None:
        raise KeyError(reaction_id)
    return column[0]


def ambiguous_linkage_rate(conn: sqlite3.Connection) -> float:
    reaction_ids = [
        row[0] for row in conn.execute("SELECT reaction_id FROM reaction").fetchall()
    ]
    if not reaction_ids:
        return 0.0
    ambiguous = sum(
        1 for rid in reaction_ids if linkage_state(conn, rid) in _AMBIGUOUS_STATES
    )
    return ambiguous / len(reaction_ids)
