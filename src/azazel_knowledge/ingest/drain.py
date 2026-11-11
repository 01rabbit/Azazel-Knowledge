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

from azazel_knowledge.core.clock import Clock, parse_rfc3339, to_rfc3339
from azazel_knowledge.db.outcome_memory import OutcomeMemoryError, ingest_outcome_fact
from azazel_knowledge.db.writer import P1, PrioritySingleWriterQueue
from azazel_knowledge.ingest.burst_guard import BurstGuard
from azazel_knowledge.ingest.spool import BatchStatus, SpoolWriter
from azazel_knowledge.ingest.validators import (
    Result,
    validate_deception_observation_line,
    validate_deception_outcome_envelope_line,
    validate_engagement_event_line,
    validate_event_line,
    validate_outcome_evidence_line,
    validate_flow_line,
    validate_reaction_line,
)
from azazel_knowledge.reactions import classifier as reaction_classifier

_VALIDATORS: dict[str, Callable[..., Result]] = {
    "events": validate_event_line,
    "flows": validate_flow_line,
    "reactions": validate_reaction_line,
    "engagement-events": validate_engagement_event_line,
    "outcome-evidence": validate_outcome_evidence_line,
    "deception-observations": validate_deception_observation_line,
    "deception-outcome-envelopes": validate_deception_outcome_envelope_line,
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


def _insert_deception_observations(
    conn: sqlite3.Connection, rows: list[tuple[int, dict[str, Any]]], now: datetime
) -> tuple[int, list[tuple[int, str]]]:
    """INSERT-only store of AZ-06 deception observations (F-1, ADR-0011).

    Identical canonical raw content is a duplicate. Reusing an observation ID
    with different content is quarantined against its original batch line;
    the first immutable fact is never overwritten or reported as that conflict.
    """
    duplicates = 0
    rejected: list[tuple[int, str]] = []
    for line_no, r in rows:
        raw = json.dumps(r["raw"], sort_keys=True)
        existing = conn.execute(
            "SELECT raw FROM deception_observation WHERE observation_uid = ?",
            (r["observation_uid"],),
        ).fetchone()
        if existing is not None:
            if existing[0] == raw:
                duplicates += 1
            else:
                rejected.append((line_no, "observation_id already stored with different content"))
            continue
        conn.execute(
            "INSERT INTO deception_observation "
            "(observation_uid, environment_id, package_id, node_id, edge_id, actor_key, "
            "observed_at, observation_class, surface, reaction_kind, lure_id, "
            "first_contact_latency_ms, dwell_ms, attempt_count, confounder_tags, "
            "runtime_context, evidence_refs, raw, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r["observation_uid"],
                r["environment_id"],
                r["package_id"],
                r["node_id"],
                r["edge_id"],
                r["actor_key"],
                r["observed_at"],
                r["observation_class"],
                r["surface"],
                r["reaction_kind"],
                r["lure_id"],
                r["first_contact_latency_ms"],
                r["dwell_ms"],
                r["attempt_count"],
                json.dumps(r["confounder_tags"], sort_keys=True),
                json.dumps(r["runtime_context"], sort_keys=True) if r["runtime_context"] is not None else None,
                json.dumps(r["evidence_refs"], sort_keys=True),
                raw,
                to_rfc3339(now),
            ),
        )
    return duplicates, rejected


def _insert_engagement_events(
    conn: sqlite3.Connection, rows: list[dict[str, Any]], now: datetime
) -> int:
    """INSERT-only store of Azazel-Edge engagement events (Fabric#23 R1c).

    Idempotent via `event_ref UNIQUE` + INSERT OR IGNORE: transport is
    at-least-once, and counting one engagement twice would distort every
    summary built over this table. Returns the number of dedupe no-ops.

    The Engage vocabulary is written through unchanged. Knowledge stores what
    the producer selected; mapping it onto Knowledge's own action vocabulary
    would invent a correspondence that does not exist for five of the eight
    values.
    """

    duplicates = 0
    for r in rows:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO engagement_event_v0 "
            "(event_ref, product, edge_id, actor_key, objective, approach, activity, "
            "attacker_reaction, reaction_window_s, started_at, ended_at, "
            "termination_reason, evidence_refs, schema_version, raw, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r["event_ref"],
                r["product"],
                r["edge_id"],
                r["actor_key"],
                r["objective"],
                r["approach"],
                r["activity"],
                r["attacker_reaction"],
                r["reaction_window_s"],
                r["started_at"],
                r["ended_at"],
                r["termination_reason"],
                json.dumps(r["evidence_refs"], sort_keys=True),
                r["schema_version"],
                json.dumps(r["raw"], sort_keys=True),
                to_rfc3339(now),
            ),
        )
        if cursor.rowcount == 0:
            duplicates += 1
    return duplicates


def _drain_engagement_event_rows(
    writer_queue: PrioritySingleWriterQueue,
    rows: list[dict[str, Any]],
    now: datetime,
) -> int:
    duplicates = {"count": 0}

    def _txn(conn: sqlite3.Connection) -> None:
        duplicates["count"] = _insert_engagement_events(conn, rows, now)

    if rows:
        writer_queue.submit(P1, _txn)
        writer_queue.process_pending()
    return duplicates["count"]


# Dependency order of the four Outcome-as-Evidence records. A mechanism,
# outcome or assessment fact is refused by `ingest_outcome_fact` until the
# execution it names is stored, so a batch carrying a whole chain must be
# inserted in this order.
#
# The facts themselves are an order-independent set joined by reference, so
# sorting is not rewriting the producer's meaning -- it is satisfying a
# storage precondition that has nothing to do with the order bytes happened
# to arrive in. The sort is stable, so facts of equal rank keep their arrival
# order and the insert sequence stays deterministic for a given batch.
_OUTCOME_CHAIN_ORDER: dict[str, int] = {
    "outcome-execution/v0.1": 0,
    "outcome-mechanism/v0.1": 1,
    "outcome-observation/v0.1": 2,
    "tactical-effect-assessment/v0.1": 3,
}


def _insert_outcome_facts(
    conn: sqlite3.Connection, rows: list[tuple[int, dict[str, Any]]], now: datetime
) -> tuple[int, list[tuple[int, str]]]:
    """Store Outcome-as-Evidence facts, quarantining the ones the chain refuses.

    Takes `(line_no, fact)` pairs and returns `(duplicates, rejected)` where
    `rejected` is `(line_no, error)` for each fact `ingest_outcome_fact`
    refused. Those refusals are chain-level, not shape-level -- a dangling
    `execution_ref`, a cross-trace join, an identity reused with different
    canonical bytes -- so they cannot be decided by the line validator, which
    has no database.

    A refused fact is quarantined like any other bad line and the rest of the
    batch is still stored (design S4: a line error never fails the batch).
    Every refusal is raised before its INSERT runs, so nothing partial is left
    behind in the transaction.
    """

    duplicates = 0
    rejected: list[tuple[int, str]] = []
    ordered = sorted(
        rows, key=lambda item: _OUTCOME_CHAIN_ORDER[str(item[1]["schema_version"])]
    )
    for line_no, fact in ordered:
        try:
            if not ingest_outcome_fact(conn, fact, received_at=to_rfc3339(now)):
                duplicates += 1
        except OutcomeMemoryError as exc:
            rejected.append((line_no, str(exc)))
    rejected.sort()
    return duplicates, rejected


def _drain_outcome_evidence_rows(
    writer_queue: PrioritySingleWriterQueue,
    rows: list[tuple[int, dict[str, Any]]],
    now: datetime,
) -> tuple[int, list[tuple[int, str]]]:
    outcome: dict[str, Any] = {"duplicates": 0, "rejected": []}

    def _txn(conn: sqlite3.Connection) -> None:
        duplicates, rejected = _insert_outcome_facts(conn, rows, now)
        outcome["duplicates"] = duplicates
        outcome["rejected"] = rejected

    if rows:
        writer_queue.submit(P1, _txn)
        writer_queue.process_pending()
    return int(outcome["duplicates"]), list(outcome["rejected"])


def _drain_deception_observation_rows(
    writer_queue: PrioritySingleWriterQueue,
    rows: list[tuple[int, dict[str, Any]]],
    now: datetime,
) -> tuple[int, list[tuple[int, str]]]:
    outcome: dict[str, Any] = {"duplicates": 0, "rejected": []}

    def _txn(conn: sqlite3.Connection) -> None:
        duplicates, rejected = _insert_deception_observations(conn, rows, now)
        outcome["duplicates"] = duplicates
        outcome["rejected"] = rejected

    if rows:
        writer_queue.submit(P1, _txn)
        writer_queue.process_pending()
    return int(outcome["duplicates"]), list(outcome["rejected"])


def _insert_deception_outcome_envelopes(
    conn: sqlite3.Connection, rows: list[tuple[int, dict[str, Any]]], now: datetime
) -> tuple[int, list[tuple[int, str]]]:
    """INSERT-only store of AZ-06 outcome envelopes (Deception#55 / Knowledge#111 G7).

    Returns `(duplicates, rejected)`. A re-delivery of identical bytes is a
    no-op counted as a duplicate. An `envelope_id` that is already stored with
    *different* bytes is not a duplicate: it is a second statement under one
    identity, and silently keeping the first (INSERT OR IGNORE) would report
    the second as accepted. It is quarantined instead, and the stored row is
    left as it was.
    """

    duplicates = 0
    rejected: list[tuple[int, str]] = []
    for line_no, r in rows:
        raw = json.dumps(r["raw"], sort_keys=True)
        existing = conn.execute(
            "SELECT raw FROM deception_outcome_envelope_v0 WHERE envelope_ref = ?",
            (r["envelope_ref"],),
        ).fetchone()
        if existing is not None:
            if existing[0] == raw:
                duplicates += 1
            else:
                rejected.append(
                    (line_no, "envelope_id already stored with different content")
                )
            continue
        conn.execute(
            "INSERT INTO deception_outcome_envelope_v0 "
            "(envelope_ref, environment_id, package_id, producer_product, producer_node, "
            "trace_id, decision_ref, effect_ref, presentation_ref, window_start, window_end, "
            "observation_class, coverage_complete, telemetry_coverage, telemetry_gaps, "
            "confounders, impact_observations, evidence_refs, effect_observation_ref, "
            "effect_status, termination_reason, limitations, entries_dropped, observed_at, "
            "authority_class, schema_version, raw, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r["envelope_ref"], r["environment_id"], r["package_id"],
                r["producer_product"], r["producer_node"], r["trace_id"],
                r["decision_ref"], r["effect_ref"], r["presentation_ref"],
                r["window_start"], r["window_end"], r["observation_class"],
                1 if r["coverage_complete"] else 0,
                json.dumps(r["telemetry_coverage"], sort_keys=True),
                json.dumps(r["telemetry_gaps"]),
                json.dumps(r["confounders"]),
                json.dumps(r["impact_observations"], sort_keys=True),
                json.dumps(r["evidence_refs"]),
                r["effect_observation_ref"], r["effect_status"], r["termination_reason"],
                json.dumps(r["limitations"]),
                r["entries_dropped"],
                r["observed_at"], r["authority_class"], r["schema_version"],
                raw, to_rfc3339(now),
            ),
        )
    return duplicates, rejected


def _drain_deception_outcome_envelope_rows(
    writer_queue: PrioritySingleWriterQueue,
    rows: list[tuple[int, dict[str, Any]]],
    now: datetime,
) -> tuple[int, list[tuple[int, str]]]:
    outcome: dict[str, Any] = {"duplicates": 0, "rejected": []}

    def _txn(conn: sqlite3.Connection) -> None:
        duplicates, rejected = _insert_deception_outcome_envelopes(conn, rows, now)
        outcome["duplicates"] = duplicates
        outcome["rejected"] = rejected

    if rows:
        writer_queue.submit(P1, _txn)
        writer_queue.process_pending()
    return int(outcome["duplicates"]), list(outcome["rejected"])


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
        # Kept alongside `valid_rows` so a row rejected at *write* time can be
        # reported against the line it came from. Identity conflicts and
        # outcome chain checks require stored rows, not just shape validation.
        valid_line_numbers: list[int] = []
        invalid: list[dict[str, Any]] = []
        for line_no, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            ok, result = validator(line, now=now)
            if ok:
                valid_rows.append(result)  # type: ignore[arg-type]
                valid_line_numbers.append(line_no)
            else:
                invalid.append({"line_no": line_no, "error": str(result)})

        if endpoint == "reactions":
            duplicates = _drain_reaction_rows(writer_queue, valid_rows, now)
        elif endpoint == "deception-observations":
            duplicates, rejected = _drain_deception_observation_rows(
                writer_queue, list(zip(valid_line_numbers, valid_rows)), now
            )
            if rejected:
                rejected_lines = {line_no for line_no, _ in rejected}
                invalid.extend(
                    {"line_no": line_no, "error": error} for line_no, error in rejected
                )
                invalid.sort(key=lambda item: int(item["line_no"]))
                valid_rows = [
                    row
                    for line_no, row in zip(valid_line_numbers, valid_rows)
                    if line_no not in rejected_lines
                ]
        elif endpoint == "engagement-events":
            duplicates = _drain_engagement_event_rows(writer_queue, valid_rows, now)
        elif endpoint == "deception-outcome-envelopes":
            duplicates, rejected = _drain_deception_outcome_envelope_rows(
                writer_queue, list(zip(valid_line_numbers, valid_rows)), now
            )
            if rejected:
                rejected_lines = {line_no for line_no, _ in rejected}
                invalid.extend(
                    {"line_no": line_no, "error": error} for line_no, error in rejected
                )
                invalid.sort(key=lambda item: int(item["line_no"]))
                valid_rows = [
                    row
                    for line_no, row in zip(valid_line_numbers, valid_rows)
                    if line_no not in rejected_lines
                ]
        elif endpoint == "outcome-evidence":
            duplicates, rejected = _drain_outcome_evidence_rows(
                writer_queue, list(zip(valid_line_numbers, valid_rows)), now
            )
            if rejected:
                rejected_lines = {line_no for line_no, _ in rejected}
                invalid.extend(
                    {"line_no": line_no, "error": error} for line_no, error in rejected
                )
                invalid.sort(key=lambda item: int(item["line_no"]))
                # `valid` must count what was stored, not what parsed. A batch
                # reporting a chain-refused fact as valid would tell the
                # producer its evidence is in memory when it is not.
                valid_rows = [
                    row
                    for line_no, row in zip(valid_line_numbers, valid_rows)
                    if line_no not in rejected_lines
                ]
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
