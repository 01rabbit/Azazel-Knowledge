# ADR-0012: MITRE Engage ingest

Status: **accepted — implemented** (spike proposed 2026-08; shipped and
verified against the code 2026-09-19 — Azazel-Knowledge#60)

## Implementation status (verified 2026-09-19)

This spike is no longer a proposal: the ingest, the schema, and the
`/v1/context` usage seam it deliberately deferred have all shipped. Recorded
here so a reader does not have to infer it from the absence of a later ADR.

| What the spike fixed | Where it lives now |
|---|---|
| Adapter (`full_replace`, `parse`/`validate`/`apply_batch` in the `attack.py` shape) | `src/azazel_knowledge/feeds/adapters/engage.py` (`EngageAdapter`) |
| Schema: `engage_activity`, `engage_attack_map`, `feed_state.license` | `src/azazel_knowledge/db/migrations/intel/0002_engage.sql` |
| Feed configuration (`kind`, `group`, `pin_spki_sha256`) | `config/feeds.yaml`, `engage:` block |
| The deferred usage seam — `engage_refs` on `POST /v1/context` | `correlate/engage_rule_refs.py` (`lookup_engage_refs`), `api/models.py` (`EngageRef`), `api/routers/context.py`; contract in [`docs/api.md`](../api.md) §`engage_refs` / `rule_refs` |
| Tests | `tests/unit/test_adapter_engage.py`, `tests/unit/test_context_engage_rule_refs.py` |

The usage seam was shipped in a separate PR from the ingest, exactly as
"Alternatives considered" required, and it resolved the open question this ADR
left in its Non-goals: `engage_refs` is an always-present, possibly-empty,
top-level array, match-gated on the advisory's own `attack_mapping`, computed
after scoring, outside the 7-element replay tuple and the `content_hash`.
`docs/api.md` is the binding statement of that shape; this ADR does not restate
it.

The constraints held: `pyproject.toml` gained no dependency, `config/scoring.yaml`
has no `engage` weight, and `tests/unit/test_api_static.py`'s write-SQL scan
still passes — Engage reaches the query path read-only.

## Context

MITRE Engage (`github.com/mitre/engage`) catalogs adversary engagement
*approaches* and *activities* (deception, denial, disruption) and publishes an
official mapping from ATT&CK techniques to the Engage activities that counter
them. Azazel-Knowledge already ingests ATT&CK itself (`feeds/adapters/attack.py`,
full-replace into `attack_technique`/`attack_mitigation`/`attack_relation`) and
already runs an effectiveness-advisory lane for AZ-06 deception outcomes
(ADR-0011, `docs/azazel-deception-effectiveness.md`). Engage is a natural third
leg: given a technique the node has already attributed to an event (via
`attack_mapping` in `/v1/context`), which Engage activities exist for
*countering* that technique — as reference material, not as a directive.

This began as a **design spike**: it fixed the shape (schema, adapter contract,
determinism boundary, dependency stance) before implementation splits into
separate PRs, per the discipline used for the EPSS as-of-pin spike
(Azazel-Knowledge#55) and mirroring ADR-0011's format. The exact
`/v1/context` response field/shape for `engage_refs` and how `recommend`
bands cite Engage activities in prose are **not** decided here — both are
"usage, separable, later PRs," gated on this ADR's determinism boundary.

The project's non-negotiable rule applies unchanged: Azazel-Knowledge never
commands. An Engage activity referenced in an advisory is descriptive context
("this technique has a cataloged counter-activity of this kind"), never an
instruction to activate anything. Final authority for any deception/response
action remains the Azazel-Edge Deterministic Arbiter and, for AZ-06 package
activation specifically, AZ-06 itself.

## Decision

Add a full-replace Engage feed adapter and two new intel-tier tables, built to
the same lifecycle every other feed adapter already runs through
(`FeedAdapter.run()`: fetch → parse → validate → apply, checkpointed in
`feed_state`). No query-path code changes ship in this spike; the usage seam
(§ Usage, later PRs) is specified but deferred.

1. **Adapter** `feeds/adapters/engage.py`, `full_replace = True`, matching the
   `AttackAdapter`/`KevAdapter` shape exactly:
   - `parse(raw)` — stdlib `json.loads` over two documents supplied by the
     worker/`azctl feed` invocation: the Engage activity catalog (Engage's
     generated `data/engage-data-v*.json`, the same JSON the public Engage
     site is built from) and the official ATT&CK↔Engage mapping
     (`data/attack-engage-mapping.json` upstream). Both are pinned to one
     Engage release tag (`engage_version`), exactly as `attack.py` resolves
     `attack_version` from the STIX bundle — no independent-cadence merge of
     mismatched catalog/mapping versions.
   - `validate(items)` — length-bounds every string field and drops rows
     missing `activity_id`/`technique_id`, mirroring `KevAdapter.validate`.
   - `apply_batch(batch)` — one writer transaction:
     `DELETE FROM engage_attack_map; DELETE FROM engage_activity;` then
     `INSERT` both tables, tagged with `engage_version`. Atomic by
     construction, identical pattern to `attack.py`'s three-table replace.
   - `feed_state` row `feed_id = "engage"` carries `checksum`/`cursor`/
     `last_success`/`enabled`/`consecutive_polls` like every other feed, plus
     the new `license` column below, recording the upstream license string at
     fetch time.
   - Reuses `FeedAdapter.fetch()`/`fetch_https_with_pins` unchanged — SPKI-
     pinned HTTPS, invoked only from the worker's `--online` path or a signed
     bundle import, never from the query path (Constraint 3).

2. **`feed_state.license` column.** No feed adapter today records the
   license under which its data was pulled; Engage's CC-BY-4.0-style
   attribution requirement makes this a documented obligation. Add
   `license TEXT` to `feed_state` in the same migration that adds the two new
   tables (nullable — existing feeds keep `NULL`; `engage`'s adapter always
   writes the pinned license string). Additive to a shared intel-tier table,
   not a redesign of it.

## Constraints

These six bind every follow-on PR under Azazel-Knowledge#60 (design spike,
implementation, and usage), not just this document; fuller mechanics for 2–6
are in Decision/Determinism handling/Schema below.

1. **Advisory-only.** `engage.py` lives under `feeds/adapters/`, never
   `api/`; every Engage write happens inside `apply_batch`'s single writer
   transaction via `intel_writer.submit()`, never inline SQL in a router —
   `tests/unit/test_api_static.py`'s zero-write-SQL-under-`api/` scan holds.
2. **Deterministic scoring.** `engage_activity`/`engage_attack_map` never
   join `scoring/` or the 7-element replay tuple; if used in advice it is
   SECONDARY context under its own version stamp with an as-of pin, same
   shape as `threat_context.behavioral_cti` and the EPSS spike (#55) — see
   Determinism handling.
3. **Offline-first.** Engage's JSON is fetched only inside `engage.py`'s
   `fetch()`, run by the worker's `--online` pass or a signed bundle import;
   the query path never imports networking code for this feature.
4. **`local.db` immutable (F-1).** Both new tables are intel-tier
   (`db/migrations/intel/`); nothing here touches `db/migrations/local/` or
   any F-1 append-only table, and there is no FK from local-tier rows into
   Engage data.
5. **Dependency minimal.** `engage.py` parses with stdlib `json` only — no
   new pip dependency in this spike; any future one requires a
   `pyproject.toml` change and an ADR update in the same diff.
6. **Fail-closed and additive.** With `engage` never run, both tables are
   empty and `/v1/context` behaves exactly as today — no new required field,
   no new error path; the later usage seam is additive-only per
   `docs/api.md`'s Versioning rule.

## Schema

Both tables are intel-tier (`db/migrations/intel/000N_engage.sql`), created
and dropped only by full-replace, `STRICT`, matching the column-naming and
indexing conventions of `attack_technique`/`attack_relation`:

```sql
CREATE TABLE engage_activity (
    activity_id  TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    approach     TEXT NOT NULL,   -- Engage "approach" facet, e.g. Expose/Affect/Elicit/Understand
    goal         TEXT,            -- Engage "goal" facet, when present upstream
    description  TEXT,
    engage_version TEXT NOT NULL
) STRICT;

CREATE INDEX idx_engage_activity_version ON engage_activity (engage_version);

CREATE TABLE engage_attack_map (
    technique_id TEXT NOT NULL,   -- ATT&CK technique/sub-technique id, e.g. T1595.002
    activity_id  TEXT NOT NULL REFERENCES engage_activity (activity_id),
    engage_version TEXT NOT NULL,
    PRIMARY KEY (technique_id, activity_id)
) STRICT;

CREATE INDEX idx_engage_attack_map_technique ON engage_attack_map (technique_id);

-- same migration:
ALTER TABLE feed_state ADD COLUMN license TEXT;
```

Notes: `engage_attack_map.technique_id` is a bare string, deliberately **not**
a foreign key into `attack_technique.technique_id` — ATT&CK and Engage ship
on independent release cadences, so a hard FK would force lock-step
versioning the way `attack_relation` already avoids by storing
`source_id`/`target_id` as opaque strings; joins at read time are best-effort
string matches, same as `attack_mapping` today. `engage_version` (not a
shared generic `version` column) matches the `attack_version`/
`catalog_version` (KEV) convention. No `source_confidence`/`ioc_id` columns:
Engage is catalog reference data, not an indicator — like KEV it never
appears in `ioc`/`ioc_source` or a lookup's `sources[]`.

## Data source & licensing

**Source**: `github.com/mitre/engage`'s generated JSON data files (not the
docs site HTML) — the activity catalog and the ATT&CK↔Engage mapping file,
both pulled at the same pinned release tag/commit so the two never drift
relative to each other mid-import. **Version pin**: `engage_version` resolves
from the release tag (or a `config/feeds.yaml` override, mirroring
`attack.attack_version`), never from wall-clock or fetch time. **License**:
MITRE Engage content ships under MITRE's standard Attribution (CC-BY-4.0-style)
terms; the exact license string/URL is resolved at fetch time from upstream
release metadata and written to `feed_state.license`, so any exported bundle
or research dataset shows provenance without a hardcoded copy in source —
`tools/export_research_dataset.py` should surface it for every feed it
touches (out of scope here, noted for the follow-on PR). **Fetch transport**:
HTTPS with SPKI pinning via `feeds/base.py:fetch_https_with_pins`,
`pin_spki_sha256` configured under a new `engage:` block in
`config/feeds.yaml`, same shape as `attack:`/`cisa_kev:`.

## Determinism handling

Engage data is reference/catalog material, structurally analogous to ATT&CK
technique metadata, not to a scored signal like an IOC hit or a KEV listing.
It therefore **never** enters `scoring/` at all in this spike — there is no
`engage`-named component in `config/scoring.yaml`'s `weights`, and no
`reason[]` entry references it.

The only place Engage data may ever reach a response is the deferred usage
seam, and there it follows the precedent already shipped for
`threat_context.behavioral_cti` (`docs/api.md`) and specified for the
deception-effectiveness advisory (ADR-0011 item 4) and the EPSS spike (#55):
a **separate generation/version stamp** (not `config_hash`, not the 7-tuple —
candidate: `engage_version` read directly, since the table is full-replace
and already carries its own version column; no new hash construction unless a
later PR finds a reason to); an **as-of pin** taken once at handler entry via
`core/clock.py`, never a fresh `datetime.now()` read inside the lookup;
**match-gated presence** — the block appears only when the request's
`attack_mapping` technique(s) have a row in `engage_attack_map`, otherwise the
key is omitted entirely, never `null`; and **best-effort, never a failure
mode** — a lookup miss, timeout, or the `engage` feed never having run
degrades silently to "block absent," never turning a `200` into a `503`, and
never blocking or delaying the existing `threat_score`/`reason[]`/audit-chain
fail-closed paths (F-12, F-17).

This keeps Phase 1 replay (`test_scoring.py`, `test_confidence.py`) and the
frozen `QUERY_PATH_FILES` set completely untouched by this feature landing.

## Consequences

- Two new intel-tier tables and one additive column join the full-replace
  family already following the `attack.py`/`kev.py` pattern; the "delete +
  insert in one writer transaction" discipline now covers Engage.
- `feed_state.license` becomes available to every feed adapter going
  forward, not just Engage — a small, deliberately generic addition.
- `/v1/context` and `recommend` gain a documented (not yet implemented) seam
  for citing Engage activities; implementing that citation is deferred to a
  later, separable PR gated on this ADR.
- Reverting the full-replace shape, adding Engage to the scored 7-tuple, or
  hard-FK'ing `engage_attack_map.technique_id` into `attack_technique` would
  each require a new ADR.

## Alternatives considered

- **Fold Engage into `attack_relation`.** Rejected: `attack_relation` is
  scoped/versioned to ATT&CK's own `attack_version`; mixing in an
  independently-versioned external catalog would force lock-step versioning,
  breaking the "one source, one version column" convention every adapter
  follows.
- **Score Engage coverage as a scoring component** (e.g. a "counter-activity
  exists" bonus). Rejected per Constraint 2 and core doctrine: Engage
  activities describe *possible counters*, not observed threat evidence —
  letting catalog completeness silently move `threat_score` is exactly the
  scope creep ADR-0006 forecloses.
- **Store the activity catalog only, skip the mapping table.** Rejected:
  without `engage_attack_map` there is no deterministic way to join a
  technique from `attack_mapping` to a candidate activity without runtime
  fuzzy-matching, which is neither deterministic nor offline-cheap.
- **Ship usage (`engage_refs`, `recommend` citations) in this same PR.**
  Rejected for this spike: the schema/adapter/determinism boundary is what
  downstream consumers depend on being stable first; splitting usage into
  later PRs lets the response-shape decision be reviewed independently, as
  EPSS (#55) and behavioral CTI (ADR-0009) were each staged.

## Acceptance criteria

- [x] `feeds/adapters/engage.py` exists, `full_replace = True`, subclassing
      `FeedAdapter`; `parse`/`validate`/`apply_batch` follow the
      `attack.py`/`kev.py` shape exactly (no bespoke writer path).
- [x] `db/migrations/intel/000N_engage.sql` creates `engage_activity` and
      `engage_attack_map` as specified and adds `feed_state.license`, applied
      in the same migration.
- [x] `config/feeds.yaml` gains an `engage:` block (`kind`, `group`,
      `pin_spki_sha256`) matching the shape of `attack:`/`cisa_kev:`.
- [x] `apply_batch` performs `DELETE`+`INSERT` for both tables inside one
      `intel_writer` transaction; a killed process before commit leaves the
      prior generation's rows untouched, verified the same way as
      `attack.py`'s existing test.
- [x] `feed_state` row for `feed_id = "engage"` records `engage_version` (via
      `cursor`/`checksum` as today) and the resolved `license` string.
- [x] `tests/unit/test_api_static.py`'s write-SQL scan passes unchanged — no
      write SQL introduced under `api/`.
- [x] No `engage`/`engage_*` entry appears in `config/scoring.yaml`'s
      `weights`, and no `reason[]` component references Engage; the 7-element
      replay tuple and existing scoring replay tests are unaffected.
- [x] With the `engage` feed never run, every existing `/v1/context` test
      still passes byte-for-byte — no new required field, no response-shape
      change.
- [x] `pyproject.toml` is unchanged by this spike (or a later PR needing a
      new dependency carries both the `pyproject.toml` diff and an ADR
      update, never a silent import) — Absolute Constraint 7.
- [x] `python -m pytest tests/unit -q` stays fully green with no reduction in
      test count (CLAUDE.md's baseline discipline; CLAUDE.md is the single
      source for the number, and `tests/unit/test_claude_md_baseline.py`
      enforces it — no raw count is copied here, to keep this ADR from going
      stale the way the copies in `AGENTS.md` and the development guide did).

## Non-goals

- **No auto-execution of Engage activities.** This ADR adds read-only
  reference data and, later, advisory citations — never a code path that
  activates, schedules, or commands an AZ-06 deception package, a host tier,
  or any Edge action from an Engage row. Final authority for any such action
  remains AZ-06/Azazel-Edge, per the project's core doctrine restated in
  `CLAUDE.md`.
- **Only the official ATT&CK↔Engage mapping is ingested.** No
  similarity-based, ML-inferred, or locally-authored technique→activity
  mapping is in scope; `engage_attack_map` is a straight load of MITRE's
  published mapping file, full-replace, exactly like `attack_relation` loads
  MITRE's own STIX relationships without local reinterpretation.
- **No scoring-component status for Engage**, now or by implication — see
  Constraint 2 and Alternatives considered. A future ADR could propose one,
  but it is out of scope here.
- **No response-shape decision for `engage_refs`.** This spike fixes that
  such a field will be additive, match-gated, best-effort, and outside the
  7-tuple; it does not fix the field's exact name, position, or JSON shape —
  that is decided in the separable usage PR referenced in Consequences.
