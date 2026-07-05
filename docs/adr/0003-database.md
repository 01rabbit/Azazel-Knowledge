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
