"""Worker-side spool drain (design S2/S4/S8, P1 priority).

`drain_endpoint` reads a spool endpoint's pending batches idempotently:
each batch is validated line-by-line, valid `events`/`flows` lines become
`observation` rows plus a windowed `observation_stats` bump (bumping
`local_meta.stats_generation`), valid `reactions` lines are handed to
`reactions.classifier` for immutable insertion, and every line's outcome
(quarantined or accepted) is recorded in the batch's `.status.json` with
`drained=True` so a crash-and-replay of the same batch never reprocesses
it and never duplicates rows. `observation` has no unique constraint on
`(event_id, edge_id)`, so duplicate suppression is done by pre-querying
the batch's `event_id`s before inserting rather than relying on
`INSERT OR IGNORE`.

The `entities` JSON column on `observation` stores
`{"items": [...], "excluded_from_stats": bool}` -- the burst-guard verdict
travels with the row itself since the schema has no dedicated column for
it.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from azazel_grimoire.core.clock import Clock, parse_rfc3339, to_rfc3339
from azazel_grimoire.db.writer import P1, PrioritySingleWriterQueue
from azazel_grimoire.ingest.burst_guard import BurstGuard
from azazel_grimoire.ingest.spool import BatchStatus, SpoolWriter
from azazel_grimoire.ingest.validators import (
    Result,
    validate_event_line,
    validate_flow_line,
    validate_reaction_line,
)
from azazel_grimoire.reactions import classifier as reaction_classifier

_VALIDATORS: dict[str, Callable[..., Result]] = {
    "events": validate_event_line,
    "flows": validate_flow_line,
    "reactions": validate_reaction_line,
}

_STATS_WINDOW_S = 3600


@dataclass
class DrainStats:
    batches_drained: int = 0
    lines_valid: int = 0
    lines_invalid: int = 0
    duplicates_skipped: int = 0


def _split_lines(raw_text: str) -> list[str]:
    lines = raw_text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    return lines


def _window_bounds(now: datetime) -> tuple[str, str]:
    epoch = int(now.timestamp())
    start_epoch = (epoch // _STATS_WINDOW_S) * _STATS_WINDOW_S
    end_epoch = start_epoch + _STATS_WINDOW_S
    start = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
    end = datetime.fromtimestamp(end_epoch, tz=timezone.utc)
    return to_rfc3339(start), to_rfc3339(end)


def _next_stats_generation(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT value FROM local_meta WHERE key = 'stats_generation'"
    ).fetchone()
    current = int(row[0]) if row else 0
    return current + 1


def _bump_observation_stats(
    conn: sqlite3.Connection, deltas: dict[bytes, int], now: datetime
) -> None:
    if not deltas:
        return
    window_start, window_end = _window_bounds(now)
    next_gen = _next_stats_generation(conn)
    for key, delta in deltas.items():
        if delta <= 0:
            continue
        row = conn.execute(
            "SELECT event_count FROM observation_stats "
            "WHERE entity_key = ? AND window_start = ?",
            (key, window_start),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO observation_stats "
                "(entity_key, window_start, window_end, event_count, trend, "
                "stats_generation, updated_at) VALUES (?, ?, ?, ?, NULL, ?, ?)",
                (key, window_start, window_end, delta, next_gen, to_rfc3339(now)),
            )
        else:
            conn.execute(
                "UPDATE observation_stats SET event_count = ?, stats_generation = ?, "
                "updated_at = ? WHERE entity_key = ? AND window_start = ?",
                (row[0] + delta, next_gen, to_rfc3339(now), key, window_start),
            )
    conn.execute(
        "INSERT INTO local_meta (key, value) VALUES ('stats_generation', ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (str(next_gen),),
    )


def _insert_observations(
    conn: sqlite3.Connection,
    rows: list[dict[str, Any]],
    now: datetime,
    guard: BurstGuard,
) -> int:
    if not rows:
        return 0
    event_ids = [r["event_id"] for r in rows]
    placeholders = ",".join("?" for _ in event_ids)
    existing = {
        (row[0], row[1])
        for row in conn.execute(
            f"SELECT event_id, edge_id FROM observation WHERE event_id IN ({placeholders})",
            event_ids,
        ).fetchall()
    }

    duplicates = 0
    stats_deltas: dict[bytes, int] = {}
    for r in rows:
        key = (r["event_id"], r["edge_id"])
        if key in existing:
            duplicates += 1
            continue
        existing.add(key)

        entities = r["entities"]
        observed_at = parse_rfc3339(r["observed_at"])
        excluded = False
        for ent in entities:
            ek = bytes.fromhex(ent["entity_key"])
            if not guard.check_and_record(ek, observed_at):
                excluded = True

        primary_key = bytes.fromhex(entities[0]["entity_key"]) if entities else None
        conn.execute(
            "INSERT INTO observation "
            "(event_id, edge_id, kind, observed_at, entity_key, entities, raw, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r["event_id"],
                r["edge_id"],
                r["kind"],
                r["observed_at"],
                primary_key,
                json.dumps({"items": entities, "excluded_from_stats": excluded}),
                json.dumps(r["raw"], sort_keys=True),
                to_rfc3339(now),
            ),
        )
        if not excluded:
            for ent in entities:
                ek = bytes.fromhex(ent["entity_key"])
                stats_deltas[ek] = stats_deltas.get(ek, 0) + 1

    _bump_observation_stats(conn, stats_deltas, now)
    return duplicates


def _drain_reaction_rows(
    writer_queue: PrioritySingleWriterQueue,
    rows: list[dict[str, Any]],
    now: datetime,
) -> int:
    duplicates = {"count": 0}

    def _txn(conn: sqlite3.Connection) -> None:
        for r in rows:
            reaction_id = reaction_classifier.ingest_reaction(conn, r, now=now)
            if reaction_id is None:
                duplicates["count"] += 1

    if rows:
        writer_queue.submit(P1, _txn)
        writer_queue.process_pending()
    return duplicates["count"]


def drain_endpoint(
    endpoint: str,
    spool: SpoolWriter,
    writer_queue: PrioritySingleWriterQueue,
    *,
    clock: Clock,
    burst_guard: BurstGuard | None = None,
) -> DrainStats:
    validator = _VALIDATORS.get(endpoint)
    if validator is None:
        raise ValueError(f"no validator registered for endpoint {endpoint!r}")
    guard = burst_guard if burst_guard is not None else BurstGuard()
    stats = DrainStats()

    for pending in spool.pending_batches(endpoint):
        now = clock.query_as_of()
        raw_text = pending.path.read_text(encoding="utf-8")
        lines = _split_lines(raw_text)

        valid_rows: list[dict[str, Any]] = []
        invalid: list[dict[str, Any]] = []
        for line_no, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            ok, result = validator(line, now=now)
            if ok:
                valid_rows.append(result)  # type: ignore[arg-type]
            else:
                invalid.append({"line_no": line_no, "error": str(result)})

        if endpoint == "reactions":
            duplicates = _drain_reaction_rows(writer_queue, valid_rows, now)
        else:
            duplicates = 0
            if valid_rows:
                def _txn(conn: sqlite3.Connection, _rows=valid_rows) -> None:
                    nonlocal duplicates
                    duplicates = _insert_observations(conn, _rows, now, guard)

                writer_queue.submit(P1, _txn)
                writer_queue.process_pending()

        status = BatchStatus(
            batch_id=pending.batch_id,
            accepted=to_rfc3339(now),
            line_count=len([ln for ln in lines if ln.strip()]),
            valid=len(valid_rows),
            invalid=invalid,
            drained=True,
        )
        spool.write_status(endpoint, pending.batch_id, status)

        stats.batches_drained += 1
        stats.lines_valid += len(valid_rows)
        stats.lines_invalid += len(invalid)
        stats.duplicates_skipped += duplicates

    return stats
