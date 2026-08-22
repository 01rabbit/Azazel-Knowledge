# ADR-0014: EPSS exploit-probability ingest as advisory context (design spike)

Status: proposed (design spike, 2026-08-22 — Azazel-Knowledge#55)

## Context

Azazel-Knowledge already scores an alert CVE against **CISA KEV** — the
`cve_exploited` component (`docs/scoring.md`, weight 0.15) contributes 100
iff an alert CVE is in the `kev` intel table, else 0, and only
`applies_when: [eve_alert]`. KEV answers "is this CVE *confirmed*
exploited-in-the-wild right now?" — a binary, certain fact.

The industry-standard complement is **EPSS** (Exploit Prediction Scoring
System, published by FIRST): a per-CVE probability in [0,1] that the CVE will
be observed exploited in the next 30 days, plus a percentile. KEV is
certainty about the present; EPSS is probability about the near future. The
2026-08 technical-reconnaissance report (`docs/reports/ai-landscape-2026-08.md`
§4 P2) flagged EPSS as the single realistic product-enrichment candidate, and
ADR-0013 already names this spike (#55) as its determinism sibling.

#55 asks for a spike on ingesting EPSS **as secondary advisory context, never
as a scoring input**: store the per-CVE probability so a later PR can surface
it on `/v1/context` beside the existing `cve_exploited` reasoning, giving an
operator "confirmed by KEV, and EPSS puts near-term exploitation at 0.87
(99th pct)" instead of KEV alone. This ADR fixes the storage shape, the
generation/replay discipline, the response shape, and the constraints a later
PR must honor; it does **not** wire the block into `/v1/context` (separable,
later, demand-gated PR — see Consequences).

The central risk this ADR exists to foreclose: an "EPSS score" feature is an
obvious, tempting on-ramp to **folding EPSS into `threat_score`** (weighting
it beside `cve_exploited`). That would drag a daily-mutating, ML-derived
probability into the deterministic 7-element replay tuple, break
byte-identical replay (F-2/F-8), and require an ADR-0006 revision. This ADR
draws that line explicitly, before any adapter code exists: **EPSS is
secondary context only.**

## Decision

Add one full-replace feed adapter, `feeds/adapters/epss.py`, that fetches a
pinned EPSS daily snapshot, extracts `(cve, epss, percentile)` plus the
snapshot's model metadata, and stores them in a new intel-tier table. Nothing
in this path runs a model or affects a score.

1. **Adapter follows the ATT&CK/KEV full-replace pattern exactly**
   (`feeds/adapters/attack.py`): `full_replace = True`, one writer
   transaction per run that `DELETE`s and re-`INSERT`s the table, pinned to
   an `epss_generation` resolved at parse time. `fetch()` uses the existing
   `fetch_https_with_pins` SPKI-pinned HTTPS helper (`feeds/base.py`) against
   the FIRST published daily snapshot URL, or a signed offline bundle swap —
   same determinism/offline discipline as every other feed.

2. **One source, published numbers only.** FIRST EPSS daily snapshot
   (`epss_scores-YYYY-MM-DD.csv.gz`): a gzip-compressed CSV whose first line
   is a `#`-comment carrying `model_version` and `score_date`, followed by a
   `cve,epss,percentile` header and rows. We ingest the *published* score; we
   never compute or approximate a probability ourselves (that would be ML —
   ADR-0009). Attribution to FIRST EPSS is recorded per feed.

3. **Parsing is stdlib-only.** `gzip` + `csv` from the standard library parse
   the snapshot; the `#model_version=…,score_date=…` header line is read for
   provenance. No new dependency, no numeric library, no model.

4. **Storage keeps the score and its provenance together** (see Schema) so a
   later `/v1/context` lookup is a single cheap indexed point-read by CVE, and
   every row is traceable to a specific EPSS model version and score date.

## Constraints

1. **Advisory-only, never a scoring input.** EPSS rows are inert context:
   probability + percentile + provenance columns, read-only from the query
   path. No write SQL in `api/` (existing `test_api_static.py` guard); writes
   go through the worker single-writer only. The `/v1/context` EPSS block
   (later PR) is a *suggestion of exploit likelihood*, never a command and
   never a `threat_score`/`reason[]` term.
2. **Deterministic, but out of the scoring tuple.** `epss_generation` is
   pinned once per adapter run (full-replace, like `attack_version`) and is
   **not** added to the scoring 7-tuple (`intel_generation, local_generation,
   stats_generation, attack_version, config_hash, event, query_as_of`). Like
   the corpus spike (ADR-0013) and the behavioral lane (ADR-0009), EPSS is
   secondary context — informational, never a scoring input — so adding,
   dropping, or swapping the EPSS generation cannot change a
   `raw_confidence`/`reason[]` replay. **EPSS is never folded into
   `cve_exploited` or any weight** (that would need an ADR-0006 revision;
   see Alternatives — non-recommended).
3. **Determinism input discipline.** The query path reads EPSS by
   `(cve, epss_generation)` only — no `datetime.now`, no randomness, no
   file-ordering. `epss_generation` is resolved at handler entry (the same
   discipline as `query_as_of`), so the EPSS block is itself reproducible:
   the same `(cve, epss_generation)` yields byte-identical EPSS context.
4. **Offline-first.** The adapter fetches only from `worker.py`'s scheduled
   run (`--online`) or a signed offline bundle swap (`tools/bundle_build`) —
   identical to every existing feed. The query path (`api/routers/context.py`)
   never fetches; a field-deployed node serves the last imported EPSS
   generation from bundle media with no internet.
5. **local.db immutable (F-1) untouched.** The EPSS table lives in the
   **intel-tier** database only (`db/migrations/intel/`), exactly where
   `kev`/`attack_technique`/`ioc` already live. Nothing here touches
   `db/migrations/local/` or the F-1 "rows never decrease" tables. EPSS is
   feed intel, not research data.
6. **Fail-closed on bad data, fail-open on absence.** A row that does not
   parse to `cve:str, epss:float∈[0,1], percentile:float∈[0,1]` is quarantined
   (`insert_quarantine`), not half-inserted — fail-closed, same posture as an
   unparseable STIX object in the ATT&CK adapter. On the query side the EPSS
   block is a best-effort sub-read under its own sub-deadline: its **absence
   never errors an answer** and never emits `503` (same fail-open discipline
   as the `behavioral_cti` block). The scored core keeps its own
   `503 context_timeout` / `503 audit_unavailable` fail-closed behavior
   unchanged (F-12/F-17) — EPSS is strictly additive to it.
7. **Dependency minimal — no new pip dependency.** Parsing reuses stdlib
   `gzip` + `csv`; fetch reuses the existing `fetch_https_with_pins` helper.
   EPSS's ML nature is entirely external (FIRST computes it); we store a
   published number, we run no model — so no numeric/ML dependency enters
   `pyproject.toml`, and ADR-0009's "no ML in generation/scoring" is
   respected (we consume, we do not model).

## Schema (intel-tier, `db/migrations/intel/000X_epss.sql` sketch)

```sql
CREATE TABLE epss_score (
    cve             TEXT NOT NULL,      -- e.g. "CVE-2024-3400"
    epss            REAL NOT NULL,      -- probability in [0,1], as published
    percentile      REAL NOT NULL,      -- percentile in [0,1], as published
    model_version   TEXT NOT NULL,      -- from the snapshot header, e.g. "v2025.03.14"
    score_date      TEXT NOT NULL,      -- snapshot date (UTC), from the header
    epss_generation TEXT NOT NULL,      -- hash(score_date, model_version, source digest)
    feed_id         TEXT NOT NULL DEFAULT 'epss',
    PRIMARY KEY (cve, epss_generation)
) STRICT;

CREATE INDEX idx_epss_score_cve ON epss_score (cve);
```

Full-replace per adapter run, checkpointed through the existing `feed_state`
row (keyed by `feed_id = 'epss'`) — no new bookkeeping table. `epss_generation`
is stored on every row so a later `/v1/context` read can pin a specific
generation and so a past advisory's EPSS context can be reproduced exactly.

## Response shape (later PR — fixed here, not wired here)

`/v1/context` gains an optional, additive block, present only when the event
carries a CVE that resolves in `epss_score` (mirroring `cve_exploited`'s
`applies_when: [eve_alert]`), and omitted entirely otherwise:

```
threat_context.epss  (optional / best-effort):
  cve, epss, percentile, model_version, score_date, epss_as_of
```

It sits beside — never inside — the scoring envelope: no `epss` term appears
in `reason[]`, `threat_score`, or the `content_hash` inputs. Its `epss_as_of`
echoes the `epss_generation`'s `score_date` for freshness discounting, exactly
as `source_freshness` already lets Edge/operators discount stale intel.

## Data source & licensing

| Adapter | Source | Attribution | Notes |
|---|---|---|---|
| `epss` | FIRST EPSS daily snapshot (`epss_scores-YYYY-MM-DD.csv.gz`), pinned by `score_date` | FIRST EPSS, cited per `docs/sync-offline.md` feed table | freely available; gzip CSV, stdlib parse; ~280k CVE rows per snapshot |

The snapshot is pinned by `score_date` (not a moving "latest" alias) so a run
is reproducible; a snapshot whose header `model_version`/`score_date` cannot be
read is rejected wholesale (fail-closed), not partially imported.

## Determinism handling

`epss_generation` is resolved once per adapter run and stored on every row,
exactly like `attack_version` in `attack.py`. It is surfaced in the
`/v1/context` EPSS block (later PR) as provenance but is **excluded** from the
scoring 7-tuple. Consequence: replaying the same `(intel_generation,
local_generation, stats_generation, attack_version, config_hash, event,
query_as_of)` tuple reproduces a byte-identical `raw_confidence`/`reason[]`
regardless of which EPSS generation is loaded — EPSS can be absent, stale, or
mid-swap without perturbing the deterministic core. This is the same
separation ADR-0009 uses for the behavioral lane and ADR-0013 for the rule
corpus.

## Pi 4 budget (spike output — estimate, to be confirmed on hardware per T4/S9)

- A full EPSS snapshot is on the order of **~280,000 CVE rows**; each
  `epss_score` row is small (a CVE id, two REALs, two short provenance
  strings). Estimated **~30–40 MB** for the table + `idx_epss_score_cve`
  index; full-replace, so peak-during-swap is ~2x that.
- Small relative to the existing `ioc`/`attack_*` tables on the documented
  8 GB Pi 4 target (`docs/architecture.md`). RSS impact is adapter-run-only
  (worker process); the query-path API process gains no RSS — it only reads an
  indexed row by CVE.
- Optional narrowing (config-driven, `config/feeds.yaml`): store only CVEs
  already present in `kev`/`ioc`/`attack`-linked intel, or above an
  `epss.min_score` threshold, if real Pi 4 numbers (S9 harness) come in
  worse. The default is the full snapshot for completeness.

## Consequences

- One new intel-tier table and one new feed adapter join the existing
  full-replace family (`attack`, `kev`); `feed_state`/`feed_quarantine`
  bookkeeping is reused as-is, no new plumbing.
- `/v1/context` gains a **future** optional `threat_context.epss` block, but
  this ADR ships no such wiring — deferred to a later, separable PR.
- **Implementation is demand-gated (per #55 assessment).** Because EPSS can
  never touch the score (Constraint 2), its concrete benefit is operator-
  facing enrichment that partly overlaps the KEV signal the node already has,
  and EPSS is known to lag KEV listing. This ADR fixes feasibility — the
  design is sound within all eight Absolute Constraints — but recommends
  scheduling the adapter + wiring PR only when a concrete consumer (Azazel-Edge
  or an operator surface) asks for EPSS context, rather than building it
  speculatively.
- Staleness is acceptable: an adapter that stops running serves the last
  full-replace generation until the next successful worker run — fail-closed
  on parse errors (quarantine), fail-open on absence (Constraint 6).

## Alternatives considered

- **Fold EPSS into `threat_score` / `cve_exploited`.** Rejected. It puts a
  daily-mutating, ML-derived probability into the deterministic 7-tuple,
  breaking byte-identical replay (F-2/F-8), and requires an ADR-0006 revision.
  EPSS's documented lag (its score moves largely *after* a CVE lands in KEV,
  which the node already scores) makes it a weak scoring input anyway. A
  future decision to weight EPSS would be its own ADR-0006 revision, and the
  spike does **not** recommend it.
- **Query the EPSS API live at query time.** Rejected: an online dependency
  in the query path violates offline-first (Constraint 4) and makes the
  answer non-deterministic and latency-coupled to a third party.
- **Store only the latest snapshot, no `epss_generation`.** Rejected: loses
  as-of reproducibility of the EPSS block — a past advisory's EPSS context
  could not be reconstructed, weakening the auditability the rest of the node
  holds itself to.
- **Compute our own exploit-probability model.** Rejected: that is ML in the
  node, directly against ADR-0009, and needlessly re-derives what FIRST
  already publishes.
- **Wire `threat_context.epss` into `/v1/context` in this same PR.** Rejected
  per the spike's own scoping and the demand-gated recommendation: fixing the
  ingest/storage/replay shape first lets it be reviewed without re-litigating
  the `/v1/context` response contract (`docs/api.md`) at the same time.

## Acceptance criteria (for the later, demand-gated implementation PR)

- `feeds/adapters/epss.py` exists, subclasses `FeedAdapter`, sets
  `full_replace = True`, and fetches a `score_date`-pinned FIRST snapshot via
  `fetch_https_with_pins` (or a signed bundle).
- A new intel-tier migration adds `epss_score` per the schema sketch above
  (cve + epss + percentile + model_version + score_date + epss_generation are
  non-negotiable).
- `pyproject.toml` is **unchanged** (no new dependency — stdlib `gzip`/`csv`
  only) — checked directly in diff review.
- `epss_generation` is **not** present in the scoring 7-tuple; a replay test
  asserts `raw_confidence`/`reason[]` are byte-identical with the `epss_score`
  table empty vs. populated for the same event.
- A row failing `epss∈[0,1]`/`percentile∈[0,1]` parse is quarantined via
  `insert_quarantine`, not inserted.
- With the `epss_score` table empty (fresh DB), every existing unit test still
  passes unchanged — the current test baseline does not shrink, and no
  existing response shape changes.
- If the `/v1/context` block is included in the same PR, it is optional/absent
  by default and omitted when no EPSS row matches the event's CVE.

## Non-goals

- No scoring input — EPSS presence/value never enters the 7-element scoring
  tuple, `raw_confidence`, `reason[]`, or `content_hash`.
- No live query-time fetch — ingest is worker/bundle only; the query path
  never reaches the network.
- No self-computed probability model — the node stores FIRST's published
  numbers, never runs a model (ADR-0009).
- No `threat_context.epss` wiring in this ADR's scope — deferred to a later,
  separable, demand-gated PR.
- No EPSS-driven action or recommendation — the block is exploit-likelihood
  context for a human/Edge to weigh, never a directive.
