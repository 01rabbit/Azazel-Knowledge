"""Worker process main (design S2/S11).

The worker is the sole SQLite writer for the live `local.db` and the
current-generation `intel.db`, each guarded by its own `flock()` (design
F-3: two files, two locks -- matching the pattern already used by the
feed-adapter test fixtures, `tests/unit/_feeds_support.py`). It runs a
fixed priority ladder every cycle:

- **P0** -- drain the advisory spool (`var/ingest/advisory/*.jsonl`,
  written by the API process's context handler) into `advisory_log`
  INSERTs, then resolve any `echoed_pending` reaction linkage
  (`reactions.linkage.resolve_pending`) now that newly-landed
  `advisory_log` rows may satisfy it.
- **P1** -- drain the client-facing ingest spool (`events`, `flows`,
  `reactions`) via `ingest.drain.drain_endpoint`.
- **P2** -- scheduled feed pulls (only with `--online`; always respects
  each feed's own `feed_state.enabled`/`min_interval_s`/
  `min_consecutive_polls` gates inside `FeedAdapter.run`), a TTL sweep
  over `intel.db` (mirrors `tools/ttl_sweep.py:sweep` but runs inside the
  priority queue's own transaction instead of calling `conn.commit()`
  itself), and an `observation_stats` trend aggregation pass.
- **P3** -- retention pruning: `advisory_log` rows older than 90 days
  that no `reaction.advisory_id` references, and garbage collection of
  fully-drained ingest spool batches.

Every stage is a plain function over an already-open
`PrioritySingleWriterQueue`, so `run_once` (and the per-stage functions
it calls) are unit-testable without a subprocess; `main()` is a thin
argument-parsing and signal-handling shell around them.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from azazel_knowledge.core.clock import Clock, SystemClock, parse_rfc3339, to_rfc3339
from azazel_knowledge.core.config import TrackedConfigLoader
from azazel_knowledge.db import generations
from azazel_knowledge.db.repository import apply_migrations
from azazel_knowledge.db.writer import P0, P1, P2, P3, PrioritySingleWriterQueue, WRITER_PRAGMAS
from azazel_knowledge.feeds.adapters.attack import AttackAdapter
from azazel_knowledge.feeds.adapters.geoip_asn import GeoipAsnAdapter
from azazel_knowledge.feeds.adapters.kev import KevAdapter
from azazel_knowledge.feeds.adapters.malwarebazaar import MalwarebazaarAdapter
from azazel_knowledge.feeds.adapters.spamhaus_asndrop import SpamhausAsnDropAdapter
from azazel_knowledge.feeds.adapters.threatfox import ThreatfoxAdapter
from azazel_knowledge.feeds.adapters.urlhaus import UrlhausAdapter
from azazel_knowledge.feeds.base import FeedAdapter, FeedRunOutcome, fetch_https_with_pins, merge_feed_config
from azazel_knowledge.ingest.burst_guard import BurstGuard
from azazel_knowledge.ingest.drain import DrainStats, drain_endpoint
from azazel_knowledge.ingest.spool import BatchStatus, SpoolWriter
from azazel_knowledge.normalize.exclusions import ExclusionPolicy
from azazel_knowledge.patterns.behavior_generate import apply_generation_plan
from azazel_knowledge.scoring.behavior_shadow import (
    build_behavioral_shadow_record,
    emit_behavioral_shadow_record,
    evaluate_behavioral_shadow,
)
from azazel_knowledge.scoring.behavior_similarity import run_similarity
from azazel_knowledge.reactions import linkage
from azazel_knowledge.scoring.confidence import noisy_or

ADVISORY_ENDPOINT = "advisory"
INGEST_ENDPOINTS: tuple[str, ...] = (
    "events",
    "flows",
    "reactions",
    "deception-observations",
)

ADVISORY_LOG_FIELDS: tuple[str, ...] = (
    "advisory_id",
    "actor_key",
    "edge_id",
    "content_hash",
    "intel_generation",
    "local_generation",
    "stats_generation",
    "attack_version",
    "config_hash",
    "created_at",
)

DEFAULT_ADVISORY_RETENTION_DAYS = 90
DEFAULT_SPOOL_RETENTION_DAYS = 7

FEED_ADAPTER_REGISTRY: dict[str, type[FeedAdapter]] = {
    "attack_stix": AttackAdapter,
    "cisa_kev": KevAdapter,
    "urlhaus": UrlhausAdapter,
    "malwarebazaar": MalwarebazaarAdapter,
    "threatfox": ThreatfoxAdapter,
    "spamhaus_asndrop": SpamhausAsnDropAdapter,
    "geoip_asn": GeoipAsnAdapter,
}
_NEEDS_EXCLUSION_POLICY = frozenset({"urlhaus", "threatfox"})

# Phase-1 fixed endpoint table for online scheduled pulls (design S6/S11):
# `feeds.yaml` carries `pin_spki_sha256` per feed but no URL, so the worker
# is the single place that knows where each feed lives. `geoip_asn` is
# intentionally absent -- it is a local MaxMind-style file feed, never
# fetched over the network (see its adapter docstring).
FEED_ENDPOINTS: dict[str, str] = {
    "attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "malwarebazaar": "https://bazaar.abuse.ch/export/csv/recent/",
    "threatfox": "https://threatfox.abuse.ch/export/json/recent/",
    "spamhaus_asndrop": "https://www.spamhaus.org/drop/asndrop.json",
}


@dataclass(frozen=True)
class WorkerPaths:
    root: Path
    config_dir: Path
    var_dir: Path
    data_dir: Path
    secrets_dir: Path

    @classmethod
    def from_root(cls, root: str | Path, *, config_dir: str | Path | None = None) -> "WorkerPaths":
        root = Path(root)
        return cls(
            root=root,
            config_dir=Path(config_dir) if config_dir is not None else root / "config",
            var_dir=root / "var",
            data_dir=root / "data",
            secrets_dir=root / "secrets",
        )

    @property
    def data_db_dir(self) -> Path:
        return self.data_dir / "db"

    @property
    def local_db_path(self) -> Path:
        return self.data_db_dir / "local.db"

    @property
    def run_dir(self) -> Path:
        return self.var_dir / "run"

    @property
    def local_lock_path(self) -> Path:
        return self.run_dir / "local.lock"

    @property
    def intel_lock_path(self) -> Path:
        return self.run_dir / "intel.lock"

    @property
    def ingest_root(self) -> Path:
        return self.var_dir / "ingest"

    @property
    def audit_dir(self) -> Path:
        return self.var_dir / "audit"

    @property
    def research_dir(self) -> Path:
        return self.var_dir / "research"

    @property
    def behavior_shadow_log_path(self) -> Path:
        return self.research_dir / "behavioral_shadow.jsonl"

    @property
    def trust_dir(self) -> Path:
        return self.secrets_dir / "trust"

    @property
    def anchors_path(self) -> Path:
        return self.trust_dir / "anchors.toml"

    @property
    def state_path(self) -> Path:
        return self.trust_dir / "state.toml"

    @property
    def node_signing_key_path(self) -> Path:
        return self.secrets_dir / "node_signing_key"

    def ensure_dirs(self) -> None:
        for endpoint in (*INGEST_ENDPOINTS, ADVISORY_ENDPOINT):
            (self.ingest_root / endpoint).mkdir(parents=True, exist_ok=True)
        for d in (
            self.run_dir,
            self.audit_dir,
            self.data_db_dir,
            self.trust_dir,
            self.secrets_dir,
            self.research_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)


@dataclass
class RunStats:
    p0: dict[str, Any] = field(default_factory=dict)
    p1: dict[str, Any] = field(default_factory=dict)
    p2: dict[str, Any] = field(default_factory=dict)
    p3: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# P0: advisory spool drain + reaction linkage resolution
# --------------------------------------------------------------------------


def _validate_advisory_line(line: str) -> tuple[bool, dict[str, Any] | str]:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        return False, f"invalid json: {exc}"
    if not isinstance(obj, dict):
        return False, "line is not a JSON object"
    for name in ADVISORY_LOG_FIELDS:
        if name not in obj or obj[name] in (None, ""):
            return False, f"missing field: {name}"
    return True, obj


def _insert_advisory_rows(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> int:
    inserted = 0
    for row in rows:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO advisory_log "
            "(advisory_id, event_id, actor_key, edge_id, content_hash, intel_generation, "
            "local_generation, stats_generation, attack_version, config_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row["advisory_id"],
                row.get("event_id"),
                row["actor_key"],
                row["edge_id"],
                row["content_hash"],
                int(row["intel_generation"]),
                int(row["local_generation"]),
                int(row["stats_generation"]),
                row["attack_version"],
                row["config_hash"],
                row["created_at"],
            ),
        )
        if cursor.rowcount:
            inserted += 1
    return inserted


def drain_advisory_spool(
    spool: SpoolWriter, writer_queue: PrioritySingleWriterQueue, *, clock: Clock
) -> DrainStats:
    stats = DrainStats()
    for pending in spool.pending_batches(ADVISORY_ENDPOINT):
        now = clock.query_as_of()
        raw_text = pending.path.read_text(encoding="utf-8")
        lines = [ln for ln in raw_text.split("\n") if ln.strip()]

        valid_rows: list[dict[str, Any]] = []
        invalid: list[dict[str, Any]] = []
        for line_no, line in enumerate(lines, start=1):
            ok, result = _validate_advisory_line(line)
            if ok:
                valid_rows.append(result)  # type: ignore[arg-type]
            else:
                invalid.append({"line_no": line_no, "error": str(result)})

        inserted = {"n": 0}
        if valid_rows:
            def _txn(conn: sqlite3.Connection, _rows: list[dict[str, Any]] = valid_rows) -> None:
                inserted["n"] = _insert_advisory_rows(conn, _rows)

            writer_queue.submit(P0, _txn)
            writer_queue.process_pending()

        status = BatchStatus(
            batch_id=pending.batch_id,
            accepted=to_rfc3339(now),
            line_count=len(lines),
            valid=len(valid_rows),
            invalid=invalid,
            drained=True,
        )
        spool.write_status(ADVISORY_ENDPOINT, pending.batch_id, status)

        stats.batches_drained += 1
        stats.lines_valid += len(valid_rows)
        stats.lines_invalid += len(invalid)
        stats.duplicates_skipped += len(valid_rows) - inserted["n"]

    return stats


def resolve_reaction_linkage(
    local_writer: PrioritySingleWriterQueue, *, clock: Clock
) -> int:
    now = clock.query_as_of()
    resolved = {"n": 0}

    def _txn(conn: sqlite3.Connection) -> None:
        resolved["n"] = linkage.resolve_pending(conn, now)

    local_writer.submit(P0, _txn)
    local_writer.process_pending()
    return resolved["n"]


def run_p0(
    local_writer: PrioritySingleWriterQueue, spool: SpoolWriter, *, clock: Clock
) -> dict[str, Any]:
    advisory_stats = drain_advisory_spool(spool, local_writer, clock=clock)
    resolved = resolve_reaction_linkage(local_writer, clock=clock)
    return {
        "advisory_batches_drained": advisory_stats.batches_drained,
        "advisory_lines_valid": advisory_stats.lines_valid,
        "advisory_lines_invalid": advisory_stats.lines_invalid,
        "linkage_resolved": resolved,
    }


# --------------------------------------------------------------------------
# P1: client-facing ingest spool drain
# --------------------------------------------------------------------------


def run_p1(
    local_writer: PrioritySingleWriterQueue,
    spool: SpoolWriter,
    *,
    clock: Clock,
    burst_guard: BurstGuard | None = None,
) -> dict[str, Any]:
    guard = burst_guard if burst_guard is not None else BurstGuard()
    results: dict[str, Any] = {}
    for endpoint in INGEST_ENDPOINTS:
        stats = drain_endpoint(endpoint, spool, local_writer, clock=clock, burst_guard=guard)
        results[endpoint] = {
            "batches_drained": stats.batches_drained,
            "lines_valid": stats.lines_valid,
            "lines_invalid": stats.lines_invalid,
            "duplicates_skipped": stats.duplicates_skipped,
        }
    return results


# --------------------------------------------------------------------------
# P2: scheduled feed pulls (--online only) + ttl_sweep + stats aggregation
# --------------------------------------------------------------------------


def build_feed_adapter(
    feed_id: str,
    feeds_doc: dict[str, Any],
    intel_writer: PrioritySingleWriterQueue,
    local_writer: PrioritySingleWriterQueue | None,
    *,
    clock: Clock,
    fetch_bytes: Callable[[], bytes],
    exclusion_policy: ExclusionPolicy | None = None,
) -> FeedAdapter:
    merged = merge_feed_config(feeds_doc, feed_id)
    kind = merged.get("kind")
    cls = FEED_ADAPTER_REGISTRY.get(kind)
    if cls is None:
        raise ValueError(f"no adapter registered for feed kind {kind!r} (feed_id={feed_id!r})")
    kwargs: dict[str, Any] = {}
    if kind in _NEEDS_EXCLUSION_POLICY:
        kwargs["exclusion_policy"] = exclusion_policy if exclusion_policy is not None else ExclusionPolicy.empty()
    return cls(
        feed_id, merged, intel_writer, local_writer, clock=clock, fetch_bytes=fetch_bytes, **kwargs
    )


def run_scheduled_feed_pulls(
    config_loader: TrackedConfigLoader,
    intel_writer: PrioritySingleWriterQueue,
    local_writer: PrioritySingleWriterQueue,
    *,
    clock: Clock,
    exclusion_policy: ExclusionPolicy | None = None,
) -> list[FeedRunOutcome]:
    feeds_doc = config_loader.feeds()
    configured = feeds_doc.get("feeds") or {}
    outcomes: list[FeedRunOutcome] = []
    for feed_id, url in FEED_ENDPOINTS.items():
        if feed_id not in configured:
            continue
        merged = merge_feed_config(feeds_doc, feed_id)
        pins = list(merged.get("pin_spki_sha256") or [])

        def _fetch(url: str = url, pins: list[str] = pins) -> bytes:
            return fetch_https_with_pins(url, pins)

        try:
            adapter = build_feed_adapter(
                feed_id, feeds_doc, intel_writer, local_writer,
                clock=clock, fetch_bytes=_fetch, exclusion_policy=exclusion_policy,
            )
            outcomes.append(adapter.run())
        except Exception as exc:  # noqa: BLE001 - one feed's failure must not sink the cycle
            outcomes.append(FeedRunOutcome(feed_id, 0, 0, "error", str(exc)))
    return outcomes


def sweep_ioc_ttl(conn: sqlite3.Connection, now_s: str) -> int:
    """P2 TTL sweep, run inside the writer queue's own transaction.

    Mirrors `tools/ttl_sweep.py:sweep` exactly, minus the standalone
    tool's own `conn.commit()` -- that tool owns its own connection and
    transaction for ad hoc/manual use, while this copy must not commit
    early inside the `PrioritySingleWriterQueue`'s batched transaction.
    """
    due = conn.execute(
        "SELECT ioc_id FROM ioc WHERE agg_next_expiry IS NOT NULL AND agg_next_expiry <= ?",
        (now_s,),
    ).fetchall()

    updated = 0
    for (ioc_id,) in due:
        sources = conn.execute(
            "SELECT source_confidence, expires_at FROM ioc_source WHERE ioc_id = ?",
            (ioc_id,),
        ).fetchall()
        active = [(conf, expires) for conf, expires in sources if expires is None or expires > now_s]
        raw_confidence = noisy_or([conf for conf, _ in active]) if active else 0.0
        future_expiries = [expires for _, expires in active if expires is not None]
        next_expiry = min(future_expiries) if future_expiries else None

        conn.execute(
            "UPDATE ioc SET agg_raw_confidence = ?, agg_next_expiry = ?, agg_computed_at = ? "
            "WHERE ioc_id = ?",
            (raw_confidence, next_expiry, now_s, ioc_id),
        )
        updated += 1
    return updated


def aggregate_observation_stats_trend(conn: sqlite3.Connection) -> int:
    """Compute a simple last-window-vs-prior-window trend per entity."""
    rows = conn.execute(
        "SELECT entity_key, window_start, event_count FROM observation_stats "
        "ORDER BY entity_key, window_start"
    ).fetchall()
    by_entity: dict[bytes, list[tuple[str, int]]] = {}
    for entity_key_, window_start, event_count in rows:
        by_entity.setdefault(entity_key_, []).append((window_start, event_count))

    updated = 0
    for entity_key_, windows in by_entity.items():
        if len(windows) < 2:
            continue
        windows.sort()
        _, prev_count = windows[-2]
        last_start, last_count = windows[-1]
        trend = (last_count - prev_count) / prev_count if prev_count else float(last_count)
        conn.execute(
            "UPDATE observation_stats SET trend = ? WHERE entity_key = ? AND window_start = ?",
            (trend, entity_key_, last_start),
        )
        updated += 1
    return updated


def run_p2(
    intel_writer: PrioritySingleWriterQueue,
    local_writer: PrioritySingleWriterQueue,
    config_loader: TrackedConfigLoader,
    *,
    clock: Clock,
    online: bool,
    behavior_shadow_log_path: Path | None = None,
    exclusion_policy: ExclusionPolicy | None = None,
) -> dict[str, Any]:
    feed_outcomes: list[FeedRunOutcome] = []
    if online:
        feed_outcomes = run_scheduled_feed_pulls(
            config_loader, intel_writer, local_writer, clock=clock, exclusion_policy=exclusion_policy
        )

    now_s = to_rfc3339(clock.query_as_of())
    swept = {"n": 0}

    def _sweep(conn: sqlite3.Connection) -> None:
        swept["n"] = sweep_ioc_ttl(conn, now_s)

    intel_writer.submit(P2, _sweep)
    intel_writer.process_pending()

    trend_updated = {"n": 0}
    behavior_built = {"generation": None, "patterns": 0, "mode": "incremental"}
    shadow_records: list[dict[str, Any]] = []

    def _trend(conn: sqlite3.Connection) -> None:
        trend_updated["n"] = aggregate_observation_stats_trend(conn)
        plan = apply_generation_plan(
            conn,
            config_loader,
            query_as_of=clock.query_as_of(),
            mode="incremental",
            before_meta_swap=lambda generation: run_similarity(
                conn, config_loader, generation
            ),
        )
        behavior_built["generation"] = plan.behavior_generation
        behavior_built["patterns"] = len(plan.patterns)
        rules_block = config_loader.behavior_shadow_rules()
        shadow_records.extend(
            build_behavioral_shadow_record(
                persisted.pattern,
                evaluate_behavioral_shadow(persisted.pattern, rules_block),
            )
            for persisted in sorted(plan.patterns, key=lambda item: item.pattern.pattern_id)
        )

    local_writer.submit(P2, _trend)
    local_writer.process_pending()

    if behavior_shadow_log_path is not None:
        for record in shadow_records:
            emit_behavioral_shadow_record(behavior_shadow_log_path, record)

    return {
        "feeds": [
            {"feed_id": o.feed_id, "status": o.status, "items_applied": o.items_applied, "reason": o.reason}
            for o in feed_outcomes
        ],
        "ttl_swept": swept["n"],
        "stats_trend_updated": trend_updated["n"],
        "behavior_generation": behavior_built["generation"],
        "behavior_patterns_written": behavior_built["patterns"],
        "behavior_shadow_emitted": len(shadow_records),
    }


# --------------------------------------------------------------------------
# P3: retention pruning
# --------------------------------------------------------------------------


def prune_advisory_log(conn: sqlite3.Connection, cutoff_rfc3339: str) -> int:
    cursor = conn.execute(
        "DELETE FROM advisory_log WHERE created_at < ? AND advisory_id NOT IN "
        "(SELECT advisory_id FROM reaction WHERE advisory_id IS NOT NULL)",
        (cutoff_rfc3339,),
    )
    return cursor.rowcount


def gc_ingest_spool(root: Path, cutoff: datetime) -> int:
    removed = 0
    if not root.is_dir():
        return removed
    for endpoint_dir in root.iterdir():
        if not endpoint_dir.is_dir():
            continue
        for status_path in endpoint_dir.glob("*.status.json"):
            batch_id = status_path.name[: -len(".status.json")]
            try:
                status = json.loads(status_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not status.get("drained"):
                continue
            accepted = status.get("accepted")
            try:
                accepted_dt = parse_rfc3339(accepted) if accepted else None
            except ValueError:
                accepted_dt = None
            if accepted_dt is None or accepted_dt >= cutoff:
                continue
            for suffix in (".jsonl", ".client", ".status.json"):
                path = endpoint_dir / f"{batch_id}{suffix}"
                if path.exists():
                    path.unlink()
                    removed += 1
    return removed


def run_p3(
    paths: WorkerPaths,
    local_writer: PrioritySingleWriterQueue,
    *,
    clock: Clock,
    advisory_retention_days: int = DEFAULT_ADVISORY_RETENTION_DAYS,
    spool_retention_days: int = DEFAULT_SPOOL_RETENTION_DAYS,
) -> dict[str, Any]:
    now = clock.query_as_of()
    cutoff_advisory = to_rfc3339(now - timedelta(days=advisory_retention_days))
    pruned = {"n": 0}

    def _prune(conn: sqlite3.Connection) -> None:
        pruned["n"] = prune_advisory_log(conn, cutoff_advisory)

    local_writer.submit(P3, _prune)
    local_writer.process_pending()

    spool_cutoff = now - timedelta(days=spool_retention_days)
    removed_files = gc_ingest_spool(paths.ingest_root, spool_cutoff)
    return {"advisory_pruned": pruned["n"], "spool_files_removed": removed_files}


# --------------------------------------------------------------------------
# One full cycle
# --------------------------------------------------------------------------


def run_once(
    paths: WorkerPaths,
    local_writer: PrioritySingleWriterQueue,
    intel_writer: PrioritySingleWriterQueue,
    config_loader: TrackedConfigLoader,
    *,
    clock: Clock,
    online: bool = False,
    exclusion_policy: ExclusionPolicy | None = None,
    burst_guard: BurstGuard | None = None,
    stage_hook: Callable[[str], None] | None = None,
) -> RunStats:
    spool = SpoolWriter(paths.ingest_root)

    if stage_hook is not None:
        stage_hook("p0")
    p0 = run_p0(local_writer, spool, clock=clock)

    if stage_hook is not None:
        stage_hook("p1")
    p1 = run_p1(local_writer, spool, clock=clock, burst_guard=burst_guard)

    if stage_hook is not None:
        stage_hook("p2")
    p2 = run_p2(
        intel_writer, local_writer, config_loader,
        clock=clock, online=online, behavior_shadow_log_path=paths.behavior_shadow_log_path,
        exclusion_policy=exclusion_policy,
    )

    if stage_hook is not None:
        stage_hook("p3")
    p3 = run_p3(paths, local_writer, clock=clock)

    return RunStats(p0=p0, p1=p1, p2=p2, p3=p3)


# --------------------------------------------------------------------------
# Setup helpers shared with azctl
# --------------------------------------------------------------------------


def ensure_local_db(local_db_path: Path) -> None:
    local_db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(local_db_path)
    try:
        apply_migrations(conn, "local")
    finally:
        conn.close()


def ensure_intel_generation(data_db_dir: Path) -> int:
    """Return the current intel generation, creating `gen-1` if none exists yet."""
    current = generations.current_generation(data_db_dir)
    if current is not None:
        return current
    intel_path = generations.build_next_generation(data_db_dir)
    conn = sqlite3.connect(intel_path)
    try:
        apply_migrations(conn, "intel")
        generations.bump_intel_generation(conn, 1)
        conn.commit()
    finally:
        conn.close()
    generations.swap_current(data_db_dir, 1)
    return 1


def current_intel_db_path(data_db_dir: Path) -> Path:
    n = ensure_intel_generation(data_db_dir)
    return generations.intel_db_path(data_db_dir, n)


def load_exclusion_policy(config_dir: Path) -> ExclusionPolicy:
    path = config_dir / "own_infrastructure.yaml"
    if path.is_file():
        return ExclusionPolicy.from_yaml_file(path)
    return ExclusionPolicy.empty()


def open_writers(paths: WorkerPaths) -> tuple[PrioritySingleWriterQueue, PrioritySingleWriterQueue]:
    paths.ensure_dirs()
    ensure_local_db(paths.local_db_path)
    intel_db_path = current_intel_db_path(paths.data_db_dir)

    local_writer = PrioritySingleWriterQueue(paths.local_db_path, paths.local_lock_path)
    local_writer.open()
    intel_writer = PrioritySingleWriterQueue(intel_db_path, paths.intel_lock_path)
    intel_writer.open()
    return local_writer, intel_writer


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="azazel-worker", description=__doc__)
    parser.add_argument(
        "--root", default=None,
        help="node root containing var/, data/, secrets/ (default: $AZAZEL_ROOT or cwd)",
    )
    parser.add_argument("--config-dir", default=None, help="config directory (default: <root>/config)")
    parser.add_argument("--once", action="store_true", help="run exactly one cycle and exit")
    parser.add_argument(
        "--online", action="store_true",
        help="allow P2 scheduled feed pulls over the network (default: offline)",
    )
    parser.add_argument(
        "--interval-s", type=float, default=5.0,
        help="sleep between cycles in continuous mode (default: 5.0)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    root = Path(args.root) if args.root else Path(os.environ.get("AZAZEL_ROOT", ".")).resolve()
    config_dir = Path(args.config_dir) if args.config_dir else None
    paths = WorkerPaths.from_root(root, config_dir=config_dir)

    config_loader = TrackedConfigLoader(paths.config_dir)
    exclusion_policy = load_exclusion_policy(paths.config_dir)
    local_writer, intel_writer = open_writers(paths)

    clock = SystemClock()
    stop = threading.Event()

    def _handle_signal(signum: int, frame: Any) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        if args.once:
            run_once(
                paths, local_writer, intel_writer, config_loader,
                clock=clock, online=args.online, exclusion_policy=exclusion_policy,
            )
            return 0

        while not stop.is_set():
            run_once(
                paths, local_writer, intel_writer, config_loader,
                clock=clock, online=args.online, exclusion_policy=exclusion_policy,
            )
            stop.wait(args.interval_s)
        return 0
    finally:
        local_writer.close()
        intel_writer.close()


if __name__ == "__main__":
    raise SystemExit(main())
