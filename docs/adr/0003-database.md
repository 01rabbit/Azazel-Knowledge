# ADR-0003: SQLite (WAL) first; PostgreSQL is a Phase 2 exit criterion

Status: accepted (design phase)

## Context

Choice between SQLite and PostgreSQL on a Pi 4 with SSD boot. Workload:
many small reads (lookups), one writer (importer/worker), periodic bulk
imports.

## Decision

SQLite in WAL mode for Phase 1. Access through a thin repository layer so
the engine can change without touching the correlation engine.

## Rationale

- The workload is SQLite's best case: read-heavy, single-writer,
  local disk. WAL gives concurrent readers during imports.
- One less always-on service on a constrained node; the whole DB is one
  file, which makes the offline bundle and backup story trivial
  (snapshot = file copy of a checkpointed DB).
- Azazel-Edge already operates in this stack style (Python, stdlib-first,
  Flask); operational knowledge transfers.

## Revisit trigger (Phase 2)

Move to PostgreSQL only if measured: sustained multi-Edge ingest causes
writer contention (>1 s write queue) or the store outgrows ~10 M indicators
with required indexes. Migration is a repository-layer swap plus a bundle
re-baseline, not a redesign.

## Measurement (2026-09-19) — reference-only, not a gate

`tools/bench/write_contention.py` measures both triggers against the real
ingest path: API accept via `SpoolWriter.write_batch`, worker P1 drain via
`ingest.drain.drain_endpoint`. "Write queue" is read as **spool-to-commit
latency** — the wait between the API accepting a record and the single writer
committing it — because that is the queue an Edge experiences.

**These numbers are from an x86 Linux VM (4 cores, 16 GB, virtio disk), not a
Pi 4.** Every result file carries `authoritative: false`. They are evidence for
a decision, not the decision, and not an S9 gate. **The Pi 4 run (issue #21)
decides pass/fail.** Expect the Pi 4's slower CPU and fsync to move every
number here, most of all the accept-cost curve.

### Trigger 1 — write queue: crossed, but not by the database

p99 spool-to-commit exceeded 1 000 ms in 5 of 9 measured configurations,
including at the shipped worker cadence with a *single* Edge at 200 rec/s
(p50 2 579 ms, p99 5 029 ms). Two mechanisms in front of SQLite produce it:

- **`worker.py --interval-s` defaults to 5.0**, so P1 drains once per 5 s.
  That alone puts a ~5 s floor under spool-to-commit latency, whatever the
  storage engine is.
- **`SpoolWriter.write_batch` charges every accept an O(N) directory scan**
  (`_pending_bytes_for_client` globs the endpoint directory and reads a
  sidecar per batch found), while P3 retains drained batches for
  `DEFAULT_SPOOL_RETENTION_DAYS = 7`. Measured single-client accept cost:
  2.07 ms at 0 batches on disk, 48.88 ms at 1 000, 232.92 ms at 5 000 —
  ≈ 2.1 ms + 0.046 ms per batch, linear per accept and quadratic over a run.

With the drain loop at 0.1 s the queue **never became unbounded**:
`undrained_records` is 0 in every configuration, and every queue drained to
empty once load stopped. Sustained drain ceiling ≈ **4 200–4 700 records/s**
at batch 500; saturation sits between 2 000 and 5 000 records/s offered.

So the trigger is met on its letter and **not** on its cause. The one figure
that is about the database — sustained drain rate — held, with full recovery.
A storage-engine swap would move neither the 5 s interval nor the spool scan.

### Trigger 2 — store scale: 10 M reached, SQLite held

10 000 000 `ioc` rows (plus 10 000 000 `ioc_source`) written through
`FeedAdapter.stage_and_swap_ioc` with every migration index live. Reached, not
extrapolated (`status: "reached"`, `shortfall_rows: 0`,
`verdict_extrapolated: false`).

| store | write rows/s | DB size | lookup p50 | p99 |
|---|---|---|---|---|
| 1 M | 85 124 | 325 MB | 7.5 µs | 38.7 µs |
| 5 M | 73 657 | 1 594 MB | 8.0 µs | 34.2 µs |
| 10 M | 72 383 | 3 199 MB | 9.0 µs | 36.6 µs |

One step down inside the first 2 M as indexes stop fitting cache, then flat to
10 M. No cliff. Reaching 10 M costs ~15 % of write throughput and ~3 µs of
lookup latency.

### Conclusion

**Neither trigger indicts SQLite on this host, so the decision stands
unchanged.** The 1 s breach is scheduling and filesystem bookkeeping in front
of the database; the 10 M store is handled with a flat, modest cost.

Two findings are worth separate attention and are **not** database problems:
the O(N) spool accept scan against a 7-day retention window is a live ingest
ceiling today, and the 5 s worker interval contradicts any expectation of
sub-second ingest visibility. Both are cheap to change and neither is decided
here.

### Not measured

Pi 4 hardware (issue #21); headroom past 10 M (a 15 M point was observed in a
progress log but its run was stopped before writing a result file, so it is
**not** recorded here); real network ingest (producers were threads in one
CPython process sharing the GIL, so offered rates above ~6 000 rec/s are a
harness ceiling, not a SQLite property); the `flows`, `reactions` and
deception-observation endpoints; P0/P2/P3 running concurrently with P1 on the
same single writer; WAL checkpoint behaviour under multi-hour load.
