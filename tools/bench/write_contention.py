"""Write-path measurement harness for ADR-0003's two revisit triggers.

ADR-0003 keeps SQLite unless *measured*: "sustained multi-Edge ingest causes
writer contention (>1 s write queue) or the store outgrows ~10 M indicators
with required indexes". `tools/bench/` covered only the read path
(capacity / availability / cold-read), so neither trigger had a harness.
This is that harness. It produces **evidence for a decision, not a
decision**: nothing here adopts PostgreSQL and nothing here writes an ADR.

Part A -- multi-Edge write queue
    Ingest is single-writer by construction: `api/routers/ingest.py` only
    spools (fsync + atomic rename, `ingest/spool.py`), and `worker.py`'s P1
    stage drains the spool into `local.db` through the single
    `PrioritySingleWriterQueue`. "Write queue" in ADR-0003's sense is
    therefore **spool-to-commit latency**: how long an ingested record waits
    between being accepted (the instant `SpoolWriter.write_batch` returns,
    which is the instant the API returns 202) and being committed by the
    worker. N distinct Edge clients (distinct `client_key_id`) spool
    concurrently at a sustained offered rate while a drain loop runs
    `ingest.drain.drain_endpoint`, and the sweep pushes N and the rate until
    the queue stops draining.

Part B -- store scale
    Grows the `ioc` store through the repository's own feed staging path
    (`feeds.base.FeedAdapter.stage_and_swap_ioc`, i.e. `_stage_ioc` ->
    `INSERT .. ON CONFLICT` into `ioc`/`ioc_source`) over a schema built by
    the repo's own `apply_migrations`, so every index ADR-0003 calls
    "required" is live and maintained during the writes. Reports the write
    throughput trend against store size and, explicitly, the largest store
    size actually reached.

Nothing in `src/` is modified or monkeypatched. Part A observes per-batch
commit instants by *subclassing* `SpoolWriter` and recording the moment
`drain_endpoint` calls `write_status` -- which it does immediately after the
writer queue commits that batch -- so the production write path runs
byte-for-byte as shipped.

Like every bench here, results on a non-Pi-4 host are reference-only and are
marked as such; this harness is additionally **not** an S9 gate at all.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from _common import (
    FIXED_QUERY_AS_OF,
    REFERENCE_ONLY_NOTE,
    authoritative,
    default_root,
    evaluate_gate,
    percentile_summary,
    platform_metadata,
    resolve_paths,
    write_json,
)

from azazel_knowledge.core.clock import FixedClock, to_rfc3339
from azazel_knowledge.db.writer import PrioritySingleWriterQueue
from azazel_knowledge.feeds.base import FeedAdapter, IocRow, IocSourceRow
from azazel_knowledge.ingest.burst_guard import BurstGuard
from azazel_knowledge.ingest.drain import drain_endpoint
from azazel_knowledge.ingest.spool import (
    BatchStatus,
    QuotaExceeded,
    SpoolWriter,
    _atomic_write,
    new_batch_id,
)
from azazel_knowledge.normalize.ioc import normalize
from azazel_knowledge.worker import DEFAULT_SPOOL_RETENTION_DAYS, current_intel_db_path

# --- ADR-0003 constants ----------------------------------------------------

#: "writer contention (>1 s write queue)" -- ADR-0003, Revisit trigger.
WRITE_QUEUE_THRESHOLD_MS = 1000.0
#: "the store outgrows ~10 M indicators with required indexes" -- same.
STORE_SCALE_TARGET_ROWS = 10_000_000

# --- harness defaults (every one of these is a disclosed choice) -----------

DEFAULT_SEED = 20260706
DEFAULT_ENDPOINT = "events"
DEFAULT_BATCH_RECORDS = 50
DEFAULT_DURATION_S = 20.0
DEFAULT_TAIL_BUDGET_S = 60.0
DEFAULT_SAMPLE_INTERVAL_S = 0.1
DEFAULT_DRAIN_INTERVAL_S = 0.05
#: worker.py --interval-s default: the cadence a shipped node actually drains at.
SHIPPED_WORKER_INTERVAL_S = 5.0
DEFAULT_ENTITY_POOL = 4096
DEFAULT_SWEEP = "1x200,4x200,4x1000,8x2000,16x4000"
DEFAULT_ACCEPT_COST_POPULATIONS = "0,100,1000,5000"
DEFAULT_ACCEPT_COST_SAMPLES = 20
DEFAULT_STEPS = "100000,1000000,2500000,5000000,10000000"
DEFAULT_CHUNK_ROWS = 50_000
DEFAULT_DISK_FLOOR_GB = 6.0
DEFAULT_PART_B_BUDGET_S = 3600.0
DEFAULT_PROBE_LOOKUPS = 500
#: Slope below which a queue counts as flat rather than growing (records/s).
DEFAULT_SLOPE_TOLERANCE_RPS = 1.0
#: Fraction of the depth series discarded as warmup before fitting a slope.
DEFAULT_SLOPE_WARMUP_FRACTION = 0.5

IOC_TYPES = ("ip", "domain", "sha256", "ja3", "ja4")
FEED_IDS = ("urlhaus", "malwarebazaar", "threatfox", "edge_reported")


# ===========================================================================
# Deterministic synthetic data (seeded; a re-run is byte-comparable)
# ===========================================================================


def _digest_int(*parts: object) -> int:
    """Seeded, process-independent pseudo-randomness.

    `hash()` is salted per process and `random` carries global state; a
    harness whose re-runs must be comparable can use neither.
    """
    blob = "|".join(str(p) for p in parts).encode("utf-8")
    return int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), "big")


def synthetic_event_line(
    client_index: int,
    record_index: int,
    *,
    seed: int = DEFAULT_SEED,
    entity_pool: int = DEFAULT_ENTITY_POOL,
) -> str:
    """One deterministic `events` JSONL line for Edge `client_index`.

    Identical `(seed, client_index, record_index)` always yields identical
    bytes, and `(client_index, record_index)` is carried into `event_id` so
    the drain's duplicate suppression never collapses the offered load.
    `observed_at` sits inside the validators' +/-48h skew window relative to
    the harness's fixed `query_as_of`, so records take the accepted path
    rather than the quarantine path.
    """
    noise = _digest_int(seed, client_index, record_index)
    host = noise % max(1, entity_pool)
    src_ip = normalize("ip", f"10.{(host >> 16) & 0xFF}.{(host >> 8) & 0xFF}.{host & 0xFF}")
    dst_ip = normalize("ip", f"192.0.2.{(client_index % 254) + 1}")
    observed_at = FIXED_QUERY_AS_OF - timedelta(seconds=(noise >> 20) % 86_400)
    record = {
        "event_id": f"bench-{client_index:04d}-{record_index:012d}",
        "edge_id": f"bench-edge-{client_index:04d}",
        "kind": "eve_alert",
        "observed_at": to_rfc3339(observed_at),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": 1024 + (noise % 64_000),
        "signature": f"BENCH synthetic alert {noise % 997}",
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def synthetic_ioc_rows(
    start_index: int, count: int, *, seed: int, intel_generation: int
) -> tuple[list[IocRow], list[IocSourceRow]]:
    """`count` deterministic, globally unique indicators from `start_index`.

    Values are index-derived so no two chunks collide: the growth curve in
    Part B must come from a store that really got larger, not from an upsert
    that kept overwriting the same rows.
    """
    ioc_rows: list[IocRow] = []
    source_rows: list[IocSourceRow] = []
    for offset in range(count):
        index = start_index + offset
        type_ = IOC_TYPES[index % len(IOC_TYPES)]
        if type_ == "ip":
            value = normalize(
                "ip", f"10.{(index >> 16) & 0xFF}.{(index >> 8) & 0xFF}.{index & 0xFF}"
            )
            # 10.0.0.0/8 holds 2**24 addresses; past that the ip slice would
            # start repeating values, which would silently turn inserts into
            # upserts. Fall back to a unique domain instead of lying.
            if index >= (1 << 24):
                type_, value = "domain", normalize("domain", f"i{index:012x}.bench.example")
        elif type_ == "domain":
            value = normalize("domain", f"d{index:012x}.bench.example")
        elif type_ == "sha256":
            value = normalize("sha256", f"{index:064x}")
        elif type_ == "ja3":
            value = normalize("ja3", f"{index:032x}")
        else:
            value = normalize("ja4", f"t13d{index:08x}h2_{index:05x}")
        day = (index % 28) + 1
        ts = f"2026-07-{day:02d}T00:00:00Z"
        feed_id = FEED_IDS[_digest_int(seed, index) % len(FEED_IDS)]
        ioc_rows.append(IocRow(type=type_, value=value, first_seen=ts, last_seen=ts, tags=[]))
        source_rows.append(
            IocSourceRow(
                type=type_,
                value=value,
                feed_id=feed_id,
                source_confidence=35 if feed_id == "edge_reported" else 80 + (index % 11),
                first_seen=ts,
                last_seen=ts,
                expires_at=None,
                intel_generation=intel_generation,
            )
        )
    return ioc_rows, source_rows


# ===========================================================================
# Latency / queue-depth accounting (pure; unit-tested in tests/unit)
# ===========================================================================


@dataclass(frozen=True)
class BatchAccept:
    """A batch the API accepted: `accepted_s` is when 202 would be returned."""

    batch_id: str
    client_key_id: str
    records: int
    accepted_s: float
    accept_ms: float


@dataclass(frozen=True)
class DepthSample:
    t_s: float
    pending_batches: int
    pending_records: int


@dataclass(frozen=True)
class LatencySet:
    per_batch_ms: list[float]
    per_record_ms: list[float]
    undrained_batches: int
    undrained_records: int


def spool_to_commit_latencies(
    accepts: Sequence[BatchAccept], commit_s: Mapping[str, float]
) -> LatencySet:
    """Spool-to-commit latency per batch and per record.

    Per-record is the primary view: ADR-0003's threshold is about how long an
    *ingested record* waits, so a 50-record batch contributes 50 samples at
    its batch latency. A batch with no commit instant was never drained; it
    is counted, never imputed -- inventing a latency for a record the worker
    never committed would flatter the result exactly where it matters.

    A commit instant preceding its accept instant means the instrumentation
    is wrong, so it raises rather than reporting a negative wait.
    """
    per_batch: list[float] = []
    per_record: list[float] = []
    undrained_batches = 0
    undrained_records = 0
    for accept in accepts:
        committed = commit_s.get(accept.batch_id)
        if committed is None:
            undrained_batches += 1
            undrained_records += accept.records
            continue
        elapsed_ms = (committed - accept.accepted_s) * 1000.0
        if elapsed_ms < 0.0:
            raise ValueError(
                f"batch {accept.batch_id} committed before it was accepted "
                f"({elapsed_ms:.3f} ms); the harness instrumentation is wrong"
            )
        per_batch.append(elapsed_ms)
        per_record.extend([elapsed_ms] * accept.records)
    return LatencySet(
        per_batch_ms=per_batch,
        per_record_ms=per_record,
        undrained_batches=undrained_batches,
        undrained_records=undrained_records,
    )


def depth_slope_records_per_s(
    samples: Sequence[DepthSample],
    *,
    warmup_fraction: float = DEFAULT_SLOPE_WARMUP_FRACTION,
) -> float:
    """Least-squares growth rate of the pending-record queue, in records/s.

    Fitted over the tail of the series only: the head is the ramp in which
    every queue grows, and including it would report growth for a queue that
    has already settled. A flat queue fits to 0.0.
    """
    if len(samples) < 2:
        return 0.0
    cutoff = int(len(samples) * warmup_fraction)
    window = list(samples[cutoff:])
    if len(window) < 2:
        window = list(samples[-2:])
    n = len(window)
    mean_t = sum(s.t_s for s in window) / n
    mean_d = sum(s.pending_records for s in window) / n
    numerator = sum((s.t_s - mean_t) * (s.pending_records - mean_d) for s in window)
    denominator = sum((s.t_s - mean_t) ** 2 for s in window)
    if denominator == 0.0:
        return 0.0
    return numerator / denominator


def samples_during_load(
    samples: Sequence[DepthSample], offer_window_s: float
) -> list[DepthSample]:
    """The depth samples taken while load was still being offered.

    The drain tail is excluded on purpose. After the producers stop, every
    queue drains, so a slope fitted through the whole series reports
    *shrinkage* for a queue that grew without bound the entire time it was
    being fed -- which is the exact configuration the finding is about.

    If no sample falls inside the window the whole series is returned rather
    than nothing: reporting a slope of 0.0 for "we have no data" would be a
    silent claim that the queue was flat.
    """
    during = [sample for sample in samples if sample.t_s <= offer_window_s]
    return during or list(samples)


def classify_queue(
    p99_record_latency_ms: float,
    depth_slope_rps: float,
    drained_within_tail: bool,
    *,
    latency_threshold_ms: float = WRITE_QUEUE_THRESHOLD_MS,
    slope_tolerance_rps: float = DEFAULT_SLOPE_TOLERANCE_RPS,
) -> str:
    """Name what the queue did. The distinction ADR-0003 turns on.

    - `unbounded`  -- the queue never emptied even after the offered load
                      stopped. The finding that matters.
    - `growing`    -- it did empty once load stopped, but grew while load was
                      offered: keep-up is marginal.
    - `saturated_stable` -- latency is over the 1 s threshold but the depth is
                      flat: a high-but-stable wait, a different finding.
    - `stable`     -- under threshold and flat.

    `unbounded` dominates: a queue that never drains is not "stable" however
    pleasant its latency percentiles looked while it was filling.
    """
    if not drained_within_tail:
        return "unbounded"
    if depth_slope_rps > slope_tolerance_rps:
        return "growing"
    if p99_record_latency_ms >= latency_threshold_ms:
        return "saturated_stable"
    return "stable"


def evaluate_write_queue_trigger(
    configs: Sequence[Mapping[str, Any]],
    *,
    threshold_ms: float = WRITE_QUEUE_THRESHOLD_MS,
) -> dict[str, Any]:
    """ADR-0003 trigger A over a completed sweep.

    Met iff at least one swept configuration sustained a p99 spool-to-commit
    wait at or beyond the threshold. An empty sweep is `not_measured`, never
    `not_met`: "we did not look" and "we looked and it was fine" are
    different claims and the caller must be able to tell them apart.
    """
    if not configs:
        return {
            "trigger": "sustained multi-Edge ingest causes writer contention (>1 s write queue)",
            "threshold_ms": threshold_ms,
            "status": "not_measured",
            "breaching_configs": [],
            "unbounded_configs": [],
            "max_p99_record_latency_ms": None,
        }
    breaching = [
        c["config"] for c in configs if float(c["p99_record_latency_ms"]) >= threshold_ms
    ]
    unbounded = [c["config"] for c in configs if c["classification"] == "unbounded"]
    return {
        "trigger": "sustained multi-Edge ingest causes writer contention (>1 s write queue)",
        "threshold_ms": threshold_ms,
        "status": "met" if breaching else "not_met",
        "breaching_configs": breaching,
        "unbounded_configs": unbounded,
        "max_p99_record_latency_ms": max(
            float(c["p99_record_latency_ms"]) for c in configs
        ),
    }


def evaluate_store_scale_trigger(
    max_rows_reached: int,
    *,
    target_rows: int = STORE_SCALE_TARGET_ROWS,
) -> dict[str, Any]:
    """ADR-0003 trigger B: did the run actually reach ~10 M indicators?

    A run that stopped short yields `not_reached` plus the shortfall and
    nothing else. No pass/fail is extrapolated from smaller sizes --
    `verdict_extrapolated` is False unconditionally, and says so in the
    result file so a reader cannot mistake a trend for a verdict.
    """
    reached = max_rows_reached >= target_rows
    return {
        "trigger": "the store outgrows ~10 M indicators with required indexes",
        "target_rows": target_rows,
        "max_rows_reached": max_rows_reached,
        "status": "reached" if reached else "not_reached",
        "shortfall_rows": 0 if reached else target_rows - max_rows_reached,
        "verdict_extrapolated": False,
    }


def stop_reason(
    *,
    rows: int,
    max_rows: int,
    free_bytes: int,
    floor_bytes: int,
    elapsed_s: float,
    budget_s: float,
) -> str | None:
    """Why Part B should stop growing the store, or None to continue.

    Disk is checked before the time budget: running the filesystem dry
    crashes the run and loses the steps already measured, while exceeding the
    time budget merely ends it early with its results intact.
    """
    if rows >= max_rows:
        return "target_reached"
    if free_bytes <= floor_bytes:
        return "disk_floor"
    if elapsed_s >= budget_s:
        return "time_budget"
    return None


def parse_sweep(spec: str) -> list[tuple[int, float]]:
    """`"4x200,8x2000"` -> [(4, 200.0), (8, 2000.0)] (clients x records/s)."""
    out: list[tuple[int, float]] = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        clients_s, _, rate_s = item.partition("x")
        if not rate_s:
            raise ValueError(f"malformed sweep entry {item!r} (expected '<clients>x<rate>')")
        clients = int(clients_s)
        rate = float(rate_s)
        if clients < 1 or rate <= 0:
            raise ValueError(f"malformed sweep entry {item!r} (clients >= 1, rate > 0)")
        out.append((clients, rate))
    if not out:
        raise ValueError("empty sweep specification")
    return out


def parse_steps(spec: str) -> list[int]:
    steps = [int(item) for item in spec.split(",") if item.strip()]
    if not steps:
        raise ValueError("empty step specification")
    if steps != sorted(steps) or steps[0] <= 0:
        raise ValueError("steps must be positive and ascending")
    return steps


def throughput_trend(step_rows_per_s: Sequence[tuple[int, float]]) -> dict[str, Any]:
    """Derived: how throughput at the largest measured size compares to the first.

    Every field here is arithmetic over observed values, not a new
    measurement, which is why the payload files it under `derived`.
    """
    if len(step_rows_per_s) < 2:
        return {"derived": True, "comparable": False}
    first_rows, first_rate = step_rows_per_s[0]
    last_rows, last_rate = step_rows_per_s[-1]
    return {
        "derived": True,
        "comparable": True,
        "first_step_rows": first_rows,
        "first_step_rows_per_s": round(first_rate, 3),
        "last_step_rows": last_rows,
        "last_step_rows_per_s": round(last_rate, 3),
        "retention_ratio": round(last_rate / first_rate, 6) if first_rate else None,
    }


# ===========================================================================
# Part A -- multi-Edge write queue
# ===========================================================================


class _CommitRecordingSpool(SpoolWriter):
    """`SpoolWriter` that timestamps each batch's commit, changing nothing else.

    `drain_endpoint` calls `write_status` immediately after the single-writer
    queue has committed that batch's transaction, so entry to this override is
    the commit instant. The timestamp is taken *before* delegating, so the
    status file's own fsync is not charged to the measured wait. The write
    path (`write_batch`, `pending_batches`) is untouched and inherited.
    """

    def __init__(self, root: Path | str) -> None:
        super().__init__(root)
        self.commit_s: dict[str, float] = {}
        self.committed_records = 0
        self._commit_lock = threading.Lock()

    def write_status(self, endpoint: str, batch_id: str, status: BatchStatus) -> None:
        now = time.perf_counter()
        with self._commit_lock:
            self.commit_s[batch_id] = now
            self.committed_records += status.line_count
        super().write_status(endpoint, batch_id, status)


@dataclass
class _Counter:
    value: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, delta: int) -> None:
        with self._lock:
            self.value += delta


def _producer(
    *,
    client_index: int,
    spool: SpoolWriter,
    endpoint: str,
    records_target: int,
    rate_rps: float,
    batch_records: int,
    seed: int,
    entity_pool: int,
    started_s: float,
    stop_event: threading.Event,
    accepts: list[BatchAccept],
    accepted_records: _Counter,
    quota_rejections: _Counter,
    prebuilt: list[list[str]] | None = None,
) -> None:
    client_key_id = f"bench-edge-{client_index:04d}"
    sent = 0
    batch_no = 0
    while sent < records_target and not stop_event.is_set():
        size = min(batch_records, records_target - sent)
        if prebuilt is not None:
            lines = prebuilt[batch_no]
            size = len(lines)
        else:
            lines = [
                synthetic_event_line(client_index, sent + j, seed=seed, entity_pool=entity_pool)
                for j in range(size)
            ]
        batch_no += 1
        due_s = started_s + (sent / rate_rps)
        delay = due_s - time.perf_counter()
        if delay > 0:
            if stop_event.wait(delay):
                return
        before = time.perf_counter()
        try:
            batch_id = spool.write_batch(endpoint, client_key_id, lines)
        except QuotaExceeded:
            # The spool's own backpressure (503 ingest_quota_exceeded at the
            # API). Counted, not smoothed over: it is how the system bounds
            # its own queue and part of what the trigger is asking about.
            quota_rejections.add(1)
            sent += size
            continue
        accepted_s = time.perf_counter()
        accepts.append(
            BatchAccept(
                batch_id=batch_id,
                client_key_id=client_key_id,
                records=size,
                accepted_s=accepted_s,
                accept_ms=(accepted_s - before) * 1000.0,
            )
        )
        accepted_records.add(size)
        sent += size


def _drain_loop(
    *,
    spool: SpoolWriter,
    writer_queue: PrioritySingleWriterQueue,
    endpoint: str,
    clock: FixedClock,
    guard: BurstGuard,
    stop_event: threading.Event,
    cycles: list[dict[str, float]],
    cycle_interval_s: float,
    on_error: list[BaseException],
) -> None:
    try:
        while not stop_event.is_set():
            began = time.perf_counter()
            stats = drain_endpoint(
                endpoint, spool, writer_queue, clock=clock, burst_guard=guard
            )
            ended = time.perf_counter()
            cycles.append(
                {
                    "began_s": began,
                    "ended_s": ended,
                    "batches": stats.batches_drained,
                    "records": stats.lines_valid,
                    "invalid": stats.lines_invalid,
                }
            )
            if cycle_interval_s > 0:
                stop_event.wait(cycle_interval_s)
    except BaseException as exc:  # surfaced to the caller; never swallowed
        on_error.append(exc)
        stop_event.set()


def run_part_a_config(
    root: Path,
    *,
    clients: int,
    offered_rps: float,
    duration_s: float,
    batch_records: int,
    endpoint: str,
    seed: int,
    entity_pool: int,
    tail_budget_s: float,
    sample_interval_s: float,
    drain_interval_s: float,
    pregenerate: bool = True,
    config_dir: Path | None = None,
) -> dict[str, Any]:
    """One (clients, offered rate) point of the Part A sweep.

    Each configuration gets its own root, so every run starts from an empty
    `local.db` and an empty spool; otherwise later configurations would be
    measured against a store the earlier ones had already grown.
    """
    name = f"{clients}x{offered_rps:g}"
    paths = resolve_paths(root, config_dir=config_dir)
    spool = _CommitRecordingSpool(paths.ingest_root)
    writer_queue = PrioritySingleWriterQueue(paths.local_db_path, paths.local_lock_path)
    writer_queue.open()
    clock = FixedClock(FIXED_QUERY_AS_OF)
    guard = BurstGuard()

    accepted_records = _Counter()
    quota_rejections = _Counter()
    per_thread_accepts: list[list[BatchAccept]] = [[] for _ in range(clients)]
    cycles: list[dict[str, float]] = []
    depth: list[DepthSample] = []
    drain_errors: list[BaseException] = []

    producer_stop = threading.Event()
    drain_stop = threading.Event()
    sampler_stop = threading.Event()

    rate_per_client = offered_rps / clients
    records_target = max(1, int(round(rate_per_client * duration_s)))

    # Building a record costs ~18 us of CPU on this host, which at a high
    # offered rate is a meaningful slice of a core that real Edges would not
    # be spending inside this process. Pre-building every batch keeps the
    # producer threads doing only what an Edge does: spool an already-formed
    # payload. It is memory for honesty about the offered rate.
    prebuilt: list[list[list[str]]] | None = None
    if pregenerate:
        prebuilt = []
        for client_index in range(clients):
            batches: list[list[str]] = []
            sent = 0
            while sent < records_target:
                size = min(batch_records, records_target - sent)
                batches.append(
                    [
                        synthetic_event_line(
                            client_index, sent + j, seed=seed, entity_pool=entity_pool
                        )
                        for j in range(size)
                    ]
                )
                sent += size
            prebuilt.append(batches)

    started_s = time.perf_counter()

    def _sampler() -> None:
        while not sampler_stop.is_set():
            now = time.perf_counter()
            with spool._commit_lock:  # noqa: SLF001 -- same object, same module's contract
                committed = spool.committed_records
                committed_batches = len(spool.commit_s)
            accepted = accepted_records.value
            accepted_batches = sum(len(chunk) for chunk in per_thread_accepts)
            depth.append(
                DepthSample(
                    t_s=now - started_s,
                    pending_batches=accepted_batches - committed_batches,
                    pending_records=accepted - committed,
                )
            )
            sampler_stop.wait(sample_interval_s)

    drain_thread = threading.Thread(
        target=_drain_loop,
        kwargs=dict(
            spool=spool,
            writer_queue=writer_queue,
            endpoint=endpoint,
            clock=clock,
            guard=guard,
            stop_event=drain_stop,
            cycles=cycles,
            cycle_interval_s=drain_interval_s,
            on_error=drain_errors,
        ),
        daemon=True,
    )
    sampler_thread = threading.Thread(target=_sampler, daemon=True)
    producers = [
        threading.Thread(
            target=_producer,
            kwargs=dict(
                client_index=i,
                spool=spool,
                endpoint=endpoint,
                records_target=records_target,
                rate_rps=rate_per_client,
                batch_records=batch_records,
                seed=seed,
                entity_pool=entity_pool,
                started_s=started_s,
                stop_event=producer_stop,
                accepts=per_thread_accepts[i],
                accepted_records=accepted_records,
                quota_rejections=quota_rejections,
                prebuilt=None if prebuilt is None else prebuilt[i],
            ),
            daemon=True,
        )
        for i in range(clients)
    ]

    drain_thread.start()
    sampler_thread.start()
    for thread in producers:
        thread.start()
    for thread in producers:
        thread.join()
    offer_ended_s = time.perf_counter()

    # Tail: keep draining with no offered load and see whether the queue empties.
    tail_deadline = time.perf_counter() + tail_budget_s
    drained_within_tail = False
    while time.perf_counter() < tail_deadline:
        with spool._commit_lock:  # noqa: SLF001
            committed_batches = len(spool.commit_s)
        accepted_batches = sum(len(chunk) for chunk in per_thread_accepts)
        if committed_batches >= accepted_batches:
            drained_within_tail = True
            break
        if drain_errors:
            break
        time.sleep(0.02)
    tail_ended_s = time.perf_counter()

    sampler_stop.set()
    drain_stop.set()
    sampler_thread.join(timeout=5)
    drain_thread.join(timeout=30)
    writer_queue.close()

    if drain_errors:
        raise RuntimeError(f"drain loop failed in config {name}") from drain_errors[0]

    accepts = [a for chunk in per_thread_accepts for a in chunk]
    with spool._commit_lock:  # noqa: SLF001
        commit_s = dict(spool.commit_s)
    latencies = spool_to_commit_latencies(accepts, commit_s)
    offer_window_s = offer_ended_s - started_s
    total_window_s = tail_ended_s - started_s
    drained_records = sum(int(c["records"]) for c in cycles)
    load_depth = samples_during_load(depth, offer_window_s)
    slope = depth_slope_records_per_s(load_depth)
    record_stats = percentile_summary(latencies.per_record_ms)
    p99 = record_stats["p99_ms"]
    classification = classify_queue(p99, slope, drained_within_tail)

    return {
        "config": name,
        "clients": clients,
        "target_offered_rps": offered_rps,
        "records_target_per_client": records_target,
        "observed": {
            "offer_window_s": round(offer_window_s, 6),
            "total_window_s": round(total_window_s, 6),
            "accepted_batches": len(accepts),
            "accepted_records": accepted_records.value,
            "committed_records": drained_records,
            "quota_rejections": quota_rejections.value,
            "undrained_batches": latencies.undrained_batches,
            "undrained_records": latencies.undrained_records,
            "drain_cycles": len(cycles),
            "drained_within_tail": drained_within_tail,
            "max_pending_records": max((s.pending_records for s in depth), default=0),
            "max_pending_batches": max((s.pending_batches for s in depth), default=0),
            "final_pending_records": depth[-1].pending_records if depth else 0,
            "spool_accept_ms": percentile_summary([a.accept_ms for a in accepts]),
            "spool_accept_max_ms": round(max((a.accept_ms for a in accepts), default=0.0), 6),
            "record_latency_ms": record_stats,
            "record_latency_max_ms": round(
                max(latencies.per_record_ms, default=0.0), 6
            ),
            "batch_latency_ms": percentile_summary(latencies.per_batch_ms),
            "depth_samples": [
                {
                    "t_s": round(s.t_s, 4),
                    "pending_batches": s.pending_batches,
                    "pending_records": s.pending_records,
                }
                for s in depth
            ],
        },
        "derived": {
            "derived": True,
            "achieved_offer_rate_rps": round(
                accepted_records.value / offer_window_s, 3
            )
            if offer_window_s > 0
            else 0.0,
            "achieved_drain_rate_rps": round(drained_records / total_window_s, 3)
            if total_window_s > 0
            else 0.0,
            "depth_slope_records_per_s": round(slope, 6),
            "depth_slope_window": "offered-load window only; the drain tail is excluded",
            "depth_samples_during_load": len(load_depth),
        },
        "p99_record_latency_ms": p99,
        "classification": classification,
    }


def run_part_a(
    root: Path,
    *,
    sweep: Sequence[tuple[int, float]],
    duration_s: float,
    batch_records: int,
    endpoint: str,
    seed: int,
    entity_pool: int,
    tail_budget_s: float,
    sample_interval_s: float,
    drain_interval_s: float,
    pregenerate: bool = True,
    config_dir: Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for clients, offered_rps in sweep:
        name = f"{clients}x{offered_rps:g}"
        if progress is not None:
            progress(f"part-a {name}")
        config_root = root / "part-a" / name.replace(".", "_")
        if config_root.exists():
            shutil.rmtree(config_root)
        results.append(
            run_part_a_config(
                config_root,
                clients=clients,
                offered_rps=offered_rps,
                duration_s=duration_s,
                batch_records=batch_records,
                endpoint=endpoint,
                seed=seed,
                entity_pool=entity_pool,
                tail_budget_s=tail_budget_s,
                sample_interval_s=sample_interval_s,
                drain_interval_s=drain_interval_s,
                pregenerate=pregenerate,
                config_dir=config_dir,
            )
        )
        # The spool and local.db of a finished configuration are dead weight
        # on a host whose free disk Part B is about to need.
        shutil.rmtree(config_root, ignore_errors=True)
    return results


def populate_drained_spool(
    spool: SpoolWriter,
    endpoint: str,
    client_key_id: str,
    population: int,
    *,
    batch_records: int,
    seed: int,
    entity_pool: int,
) -> int:
    """Leave `population` **drained** batches in the endpoint directory.

    Drained, not pending: the cost being measured is the one a healthy node
    pays all week, where every batch has long since been committed and is
    only waiting for P3's retention sweep. A pending backlog would measure
    something else entirely -- a node that is already failing.

    The payload and client sidecar are laid down with the spool module's own
    `_atomic_write`, not through `write_batch`, because `write_batch` charges
    the very quota scan being measured: building an N-batch population
    through it would itself cost O(N^2) and take longer than the measurement.
    The resulting files are the same three per batch, with the same names and
    contents, which is what the scan reads.
    """
    endpoint_dir = Path(spool.root) / endpoint
    endpoint_dir.mkdir(parents=True, exist_ok=True)
    for i in range(population):
        lines = [
            synthetic_event_line(0, i * batch_records + j, seed=seed, entity_pool=entity_pool)
            for j in range(batch_records)
        ]
        batch_id = new_batch_id()
        _atomic_write(
            endpoint_dir / f"{batch_id}.jsonl",
            ("\n".join(lines) + "\n").encode("utf-8"),
        )
        _atomic_write(
            endpoint_dir / f"{batch_id}.client", client_key_id.encode("utf-8")
        )
        spool.write_status(
            endpoint,
            batch_id,
            BatchStatus(
                batch_id=batch_id,
                accepted=to_rfc3339(FIXED_QUERY_AS_OF),
                line_count=batch_records,
                valid=batch_records,
                invalid=[],
                drained=True,
            ),
        )
    return population


def measure_accept_cost(
    root: Path,
    *,
    populations: Sequence[int],
    samples: int,
    batch_records: int,
    endpoint: str,
    seed: int,
    entity_pool: int,
    config_dir: Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """What one API accept costs as the spool directory fills up.

    `SpoolWriter.write_batch` charges every accept a per-client quota scan
    that globs the endpoint directory and reads a sidecar for every batch
    it finds, drained or not -- and `worker.py`'s P3 only deletes drained
    batches after `DEFAULT_SPOOL_RETENTION_DAYS` (7). So the population an
    accept scans is a week of ingest, not a queue depth.

    This is measured separately from the sweep because it is *not* database
    writer contention: it is filesystem bookkeeping in front of the
    database, and no storage engine swap would move it. Telling the two
    apart is the whole point of the exercise.
    """
    results: list[dict[str, Any]] = []
    for population in populations:
        if progress is not None:
            progress(f"accept-cost population={population}")
        case_root = root / "accept-cost" / str(population)
        if case_root.exists():
            shutil.rmtree(case_root)
        paths = resolve_paths(case_root, config_dir=config_dir)
        spool = SpoolWriter(paths.ingest_root)
        client_key_id = "bench-edge-0000"
        populate_drained_spool(
            spool,
            endpoint,
            client_key_id,
            population,
            batch_records=batch_records,
            seed=seed,
            entity_pool=entity_pool,
        )
        measured: list[float] = []
        for k in range(samples):
            lines = [
                synthetic_event_line(
                    1, k * batch_records + j, seed=seed, entity_pool=entity_pool
                )
                for j in range(batch_records)
            ]
            began = time.perf_counter()
            spool.write_batch(endpoint, client_key_id, lines)
            measured.append((time.perf_counter() - began) * 1000.0)
        results.append(
            {
                "drained_batches_on_disk": population,
                "observed": {
                    "accept_ms": percentile_summary(measured),
                    "accept_max_ms": round(max(measured, default=0.0), 6),
                },
                "derived": {
                    "derived": True,
                    "max_accepts_per_s_single_client": round(
                        1000.0 / (sum(measured) / len(measured)), 3
                    )
                    if measured
                    else None,
                },
            }
        )
        shutil.rmtree(case_root, ignore_errors=True)
    return results


# ===========================================================================
# Part B -- store scale
# ===========================================================================


class _BenchIocFeed(FeedAdapter):
    """Offline adapter used only to reach `stage_and_swap_ioc`.

    `fetch`/`parse` are never called: the harness stages rows it generated
    itself. Subclassing rather than re-implementing the SQL is the point --
    Part B must measure the repository's real indicator write path, including
    its two-transaction stage-then-swap shape.
    """

    def parse(self, raw: bytes) -> Any:  # pragma: no cover - never called
        raise NotImplementedError("bench adapter never fetches")

    def apply_batch(self, batch: Any) -> int:  # pragma: no cover - never called
        raise NotImplementedError("bench adapter never fetches")


def _db_bytes(db_path: Path) -> dict[str, int]:
    sizes = {}
    total = 0
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(db_path) + suffix)
        size = path.stat().st_size if path.exists() else 0
        sizes[f"bytes{suffix or '_main'}"] = size
        total += size
    sizes["bytes_total"] = total
    return sizes


def _probe_lookups(db_path: Path, rows: int, count: int, seed: int) -> dict[str, float]:
    """Point lookups over `UNIQUE (type, value)` at the current store size.

    Secondary evidence for "with required indexes": a store that has grown
    past the point where its own unique index stops being cheap is the thing
    ADR-0003's second trigger is worried about.
    """
    if rows <= 0 or count <= 0:
        return {"count": 0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA query_only = 1")
        latencies: list[float] = []
        for i in range(count):
            index = _digest_int(seed, "probe", i) % rows
            probe_rows, _ = synthetic_ioc_rows(index, 1, seed=seed, intel_generation=1)
            row = probe_rows[0]
            began = time.perf_counter()
            conn.execute(
                "SELECT ioc_id FROM ioc WHERE type = ? AND value = ?", (row.type, row.value)
            ).fetchone()
            latencies.append((time.perf_counter() - began) * 1000.0)
    finally:
        conn.close()
    return percentile_summary(latencies)


def run_part_b(
    root: Path,
    *,
    steps: Sequence[int],
    chunk_rows: int,
    seed: int,
    disk_floor_bytes: int,
    budget_s: float,
    probe_lookups: int,
    config_dir: Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    paths = resolve_paths(root, config_dir=config_dir)
    intel_db_path = current_intel_db_path(paths.data_db_dir)
    intel_writer = PrioritySingleWriterQueue(intel_db_path, paths.intel_lock_path)
    intel_writer.open()
    adapter = _BenchIocFeed(
        "bench_scale", {}, intel_writer, clock=FixedClock(FIXED_QUERY_AS_OF)
    )

    step_results: list[dict[str, Any]] = []
    chunk_samples: list[dict[str, Any]] = []
    rows = 0
    max_rows = max(steps)
    began_s = time.perf_counter()
    halt: str | None = None
    try:
        for target in steps:
            step_began = time.perf_counter()
            step_rows = 0
            while rows < target:
                free_bytes = shutil.disk_usage(root).free
                halt = stop_reason(
                    rows=rows,
                    max_rows=max_rows,
                    free_bytes=free_bytes,
                    floor_bytes=disk_floor_bytes,
                    elapsed_s=time.perf_counter() - began_s,
                    budget_s=budget_s,
                )
                if halt is not None and halt != "target_reached":
                    break
                size = min(chunk_rows, target - rows)
                ioc_rows, source_rows = synthetic_ioc_rows(
                    rows, size, seed=seed, intel_generation=1
                )
                chunk_began = time.perf_counter()
                adapter.stage_and_swap_ioc(ioc_rows, source_rows)
                chunk_elapsed = time.perf_counter() - chunk_began
                chunk_samples.append(
                    {
                        "rows_before": rows,
                        "chunk_rows": size,
                        "elapsed_s": round(chunk_elapsed, 6),
                        "rows_per_s": round(size / chunk_elapsed, 3) if chunk_elapsed else None,
                    }
                )
                rows += size
                step_rows += size
            step_elapsed = time.perf_counter() - step_began
            if step_rows == 0:
                break
            conn = sqlite3.connect(intel_db_path)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                stored = conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
                stored_sources = conn.execute("SELECT COUNT(*) FROM ioc_source").fetchone()[0]
            finally:
                conn.close()
            sizes = _db_bytes(intel_db_path)
            if progress is not None:
                progress(
                    f"part-b step rows={rows} stored={stored} "
                    f"rows_per_s={step_rows / step_elapsed:.0f} "
                    f"db_mb={sizes['bytes_total'] / 1e6:.0f}"
                )
            step_results.append(
                {
                    "target_rows": target,
                    "observed": {
                        "rows_written_cumulative": rows,
                        "ioc_rows_in_store": stored,
                        "ioc_source_rows_in_store": stored_sources,
                        "step_rows": step_rows,
                        "step_elapsed_s": round(step_elapsed, 6),
                        "db_bytes": sizes,
                        "disk_free_bytes": shutil.disk_usage(root).free,
                        "lookup_ms": _probe_lookups(
                            intel_db_path, rows, probe_lookups, seed
                        ),
                    },
                    "derived": {
                        "derived": True,
                        "step_rows_per_s": round(step_rows / step_elapsed, 3)
                        if step_elapsed
                        else None,
                        "bytes_per_row": round(sizes["bytes_total"] / stored, 3)
                        if stored
                        else None,
                    },
                }
            )
            if halt is not None and halt != "target_reached":
                break
    finally:
        intel_writer.close()

    trend = throughput_trend(
        [
            (s["observed"]["rows_written_cumulative"], float(s["derived"]["step_rows_per_s"]))
            for s in step_results
            if s["derived"]["step_rows_per_s"]
        ]
    )
    return {
        "steps": step_results,
        "chunk_samples": chunk_samples,
        "observed": {
            "max_rows_reached": rows,
            "halt_reason": halt or "target_reached",
            "total_elapsed_s": round(time.perf_counter() - began_s, 6),
            "intel_db_path": str(intel_db_path),
        },
        "derived": trend,
    }


# ===========================================================================
# Driver
# ===========================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=default_root())
    parser.add_argument("--config-dir", type=Path, default=None)
    parser.add_argument("--part", choices=("a", "b", "both"), default="both")
    parser.add_argument("--sweep", default=DEFAULT_SWEEP, help="<clients>x<records/s>, comma separated")
    parser.add_argument("--duration-s", type=float, default=DEFAULT_DURATION_S)
    parser.add_argument("--batch-records", type=int, default=DEFAULT_BATCH_RECORDS)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--entity-pool", type=int, default=DEFAULT_ENTITY_POOL)
    parser.add_argument("--tail-budget-s", type=float, default=DEFAULT_TAIL_BUDGET_S)
    parser.add_argument("--sample-interval-s", type=float, default=DEFAULT_SAMPLE_INTERVAL_S)
    parser.add_argument(
        "--drain-interval-s",
        type=float,
        default=DEFAULT_DRAIN_INTERVAL_S,
        help=f"sleep between drain cycles; worker.py ships with {SHIPPED_WORKER_INTERVAL_S}",
    )
    parser.add_argument(
        "--no-pregenerate",
        action="store_true",
        help="build each batch inside the timed loop instead of before it",
    )
    parser.add_argument("--accept-cost-populations", default=DEFAULT_ACCEPT_COST_POPULATIONS)
    parser.add_argument("--accept-cost-samples", type=int, default=DEFAULT_ACCEPT_COST_SAMPLES)
    parser.add_argument("--steps", default=DEFAULT_STEPS)
    parser.add_argument("--chunk-rows", type=int, default=DEFAULT_CHUNK_ROWS)
    parser.add_argument("--disk-floor-gb", type=float, default=DEFAULT_DISK_FLOOR_GB)
    parser.add_argument("--part-b-budget-s", type=float, default=DEFAULT_PART_B_BUDGET_S)
    parser.add_argument("--probe-lookups", type=int, default=DEFAULT_PROBE_LOOKUPS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--label", default="run")
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--quiet", action="store_true")
    return parser


def _choices(args: argparse.Namespace) -> dict[str, Any]:
    """Every methodology choice the numbers depend on, in the result file.

    A reader who disagrees with one of these can re-run with it changed;
    a reader who cannot see them has to take the numbers on trust.
    """
    return {
        "spool_to_commit_definition": (
            "accept = SpoolWriter.write_batch returns (the instant the API returns 202); "
            "commit = drain_endpoint calls write_status for that batch, which it does "
            "immediately after the single-writer queue commits the batch's transaction"
        ),
        "drained_definition": (
            "a batch is drained when its status is written with drained=True; a batch with "
            "no commit instant is reported as undrained and contributes no latency sample"
        ),
        "latency_weighting": "per record (a batch of N records contributes N samples at its batch latency)",
        "sustained_rate_definition": (
            "each client paces to offered_rps/clients records/s against its own start instant, "
            "for duration_s; a client that cannot keep up falls behind rather than bursting, "
            "so achieved_offer_rate_rps is reported next to the target"
        ),
        "batch_records": args.batch_records,
        "endpoint": args.endpoint,
        "entity_pool": args.entity_pool,
        "drain_cadence_s": args.drain_interval_s,
        "drain_cadence": (
            f"drain_endpoint is called in a loop with a {args.drain_interval_s}s sleep between "
            f"cycles. worker.py ships with --interval-s {SHIPPED_WORKER_INTERVAL_S}, so a run at a "
            "shorter interval measures how fast the spool *can* be drained, not the wait an Edge "
            "sees on a default node; a run at 5.0 measures the latter. Each cycle costs a full "
            "directory scan (SpoolWriter.pending_batches globs the endpoint dir and parses every "
            "status file), so a very short interval is not automatically a better case"
        ),
        "per_config_isolation": "each sweep configuration starts from an empty local.db and empty spool",
        "payload_pregeneration": (
            "batches are built before the timed loop by default (--no-pregenerate to disable), so "
            "the offered rate is not capped by this process's own JSON/hash cost"
        ),
        "producer_model": (
            "producers are threads in one CPython process sharing a GIL with the drain loop; real "
            "Edges are separate hosts, so the offered rate this harness can sustain is a harness "
            "ceiling, not a property of SQLite"
        ),
        "clock": (
            "drain uses FixedClock(FIXED_QUERY_AS_OF); measurement uses time.perf_counter. "
            "All observations therefore land in one observation_stats window"
        ),
        "accept_cost_population_meaning": (
            "drained batches retained on disk, which worker.py's P3 keeps for "
            f"{DEFAULT_SPOOL_RETENTION_DAYS} days. They used to sit in the endpoint directory and "
            "the accept scan read every one; since the drained-directory change they sit in "
            "<endpoint>/drained/ and the accept scan does not see them, so this curve should now "
            "be flat. A curve that rises with the population again is a regression"
        ),
        "part_b_write_path": (
            "feeds.base.FeedAdapter.stage_and_swap_ioc (_stage_ioc -> INSERT .. ON CONFLICT into "
            "ioc/ioc_source) over a schema built by db.repository.apply_migrations"
        ),
        "part_b_cidr": (
            "ioc_cidr rows are NOT populated; the ip-tier expansion would add 4 rows per ip "
            "indicator and change both the disk and the time envelope"
        ),
        "part_b_chunk_rows": args.chunk_rows,
        "part_b_disk_floor_gb": args.disk_floor_gb,
        "part_b_budget_s": args.part_b_budget_s,
        "seed": args.seed,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    progress = None if args.quiet else (lambda msg: print(msg, flush=True))
    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)

    part_a: list[dict[str, Any]] = []
    part_b: dict[str, Any] | None = None

    if args.part in ("a", "both"):
        part_a = run_part_a(
            root,
            sweep=parse_sweep(args.sweep),
            duration_s=args.duration_s,
            batch_records=args.batch_records,
            endpoint=args.endpoint,
            seed=args.seed,
            entity_pool=args.entity_pool,
            tail_budget_s=args.tail_budget_s,
            sample_interval_s=args.sample_interval_s,
            drain_interval_s=args.drain_interval_s,
            pregenerate=not args.no_pregenerate,
            config_dir=args.config_dir,
            progress=progress,
        )
    accept_cost: list[dict[str, Any]] = []
    if args.part in ("a", "both") and args.accept_cost_populations:
        accept_cost = measure_accept_cost(
            root,
            populations=[int(v) for v in args.accept_cost_populations.split(",") if v.strip()],
            samples=args.accept_cost_samples,
            batch_records=args.batch_records,
            endpoint=args.endpoint,
            seed=args.seed,
            entity_pool=args.entity_pool,
            config_dir=args.config_dir,
            progress=progress,
        )
    if args.part in ("b", "both"):
        part_b_root = root / "part-b"
        part_b_root.mkdir(parents=True, exist_ok=True)
        part_b = run_part_b(
            part_b_root,
            steps=parse_steps(args.steps),
            chunk_rows=args.chunk_rows,
            seed=args.seed,
            disk_floor_bytes=int(args.disk_floor_gb * 1e9),
            budget_s=args.part_b_budget_s,
            probe_lookups=args.probe_lookups,
            config_dir=args.config_dir,
            progress=progress,
        )

    write_queue = evaluate_write_queue_trigger(part_a)
    store_scale = (
        evaluate_store_scale_trigger(part_b["observed"]["max_rows_reached"])
        if part_b is not None
        else evaluate_store_scale_trigger(0)
        | {"status": "not_measured", "max_rows_reached": None}
    )
    gates = [
        evaluate_gate(
            "max_p99_spool_to_commit_ms",
            write_queue["max_p99_record_latency_ms"] or 0.0,
            WRITE_QUEUE_THRESHOLD_MS,
            "<",
        )
    ]
    meta = platform_metadata()
    payload = {
        "name": "write-contention",
        "label": args.label,
        "stamp": args.stamp,
        "root": str(root),
        "authoritative": meta["authoritative"],
        "platform": meta,
        "purpose": (
            "evidence for ADR-0003's revisit triggers; NOT a decision, NOT an S9 gate, "
            "and it adopts nothing"
        ),
        "choices": _choices(args),
        "gates": gates,
        "pass": all(gate["pass"] for gate in gates),
        "adr0003_triggers": {"write_queue": write_queue, "store_scale": store_scale},
        "part_a": {"configs": part_a, "accept_cost_vs_spool_population": accept_cost},
        "part_b": part_b,
    }
    if not authoritative():
        payload["note"] = REFERENCE_ONLY_NOTE
    output_path = write_json("write-contention", args.label, payload)
    print(
        json.dumps(
            {
                "output": str(output_path),
                "authoritative": payload["authoritative"],
                "write_queue_trigger": write_queue["status"],
                "store_scale_trigger": store_scale["status"],
            },
            sort_keys=True,
        )
    )
    return payload


def main(argv: list[str] | None = None) -> int:
    run(build_arg_parser().parse_args(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
