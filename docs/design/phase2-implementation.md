# Phase 2 implementation design — Behavioral CTI from tactical delay

Version: design-draft (2026-07). Companion to
[phase1-implementation.md](phase1-implementation.md). Resolves issues
[#29](../../issues/29) (doctrine) / [#30](../../issues/30) (tracker) and the
seven child issues [#31](../../issues/31)–[#37](../../issues/37) to an
implementable state. F2-1…F2-20 below are **binding**; the register in §12
restates each in one line. Where a decision extends or is constrained by a
Phase 1 decision it cites the `F-n` tag verbatim.

Architecture subtitle for this phase (naming per ADR-0001, brand stays
**Azazel**): *Aegis-like cyber defense through tactical delay, deception, and
behavioral CTI.* The Aegis analogy is an explanatory framing (observe → track
→ classify → advise), never a product rename and never an interception claim.

---

## Binding constraints (violating any of these is a CRITICAL revert)

- **The Phase 1 `threat_score` determinism envelope is frozen.** The 7-element
  replay tuple (`intel_generation, local_generation, stats_generation,
  attack_version, config_hash, event, query_as_of`), the `content_hash`, the
  `QUERY_PATH_FILES` set that feeds `config_hash`, and the sum-to-1.0
  `weights`/`confidence_weights` are **not modified by any Phase 2 change**
  **[F2-1]**. All 487 baseline tests keep passing; existing advisories replay
  byte-identical. Behavioral CTI is a *separate, additive lane* with its own
  version stamp.
- **Behavioral CTI never becomes action authority.** It enriches context,
  generates patterns, and *suggests* posture. It must not add a field that
  commands Edge to block/drop/redirect/delay, and must not become a required
  part of a valid `/v1/context` response (#35 guardrail; ADR-0007;
  `advisory_notice` doctrine).
- **Deterministic, declarative, no ML.** Pattern generation, classification,
  similarity, repeatability, and shadow rules are deterministic and
  config-versioned. No embedding model, clustering model, or LLM anywhere in
  generation, similarity, or scoring (ADR-0006; roadmap standing constraint).
  LLM use, if ever introduced, is confined to explanation/report prose and
  marked in output — out of scope here.
- **`local.db` inviolability holds [F-1].** Behavioral patterns derive from
  `reaction`/`observation` (both local-tier) and therefore live in `local.db`.
  Bundles remain intel-tier only; a bundle naming any behavioral table
  hard-aborts (`BUNDLE_TOUCHES_LOCAL_TIER`). Immutable `reaction`/`observation`
  rows are never mutated by generation.
- **No new query-path internet or full-table scan.** Behavioral lookup on the
  `/v1/context` hot path is a single indexed point-read; similarity is
  precomputed offline. The Pi 4 budgets hold: IOC p95 < 50 ms, context p95 <
  250 ms with the F-20 cold-read margin, combined RSS < 2 GB.
- **Fail-closed is preserved but scoped correctly [F-12/F-17].** The
  `threat_score`/`reason[]` verdict and the audit chain keep their fail-closed
  semantics unchanged. The *optional additive* behavioral block is best-effort:
  its absence is never an error and never a 503.
- **No AI attribution.** Output and docs characterize *adaptive / automation-
  like behavior*; they never claim proof of AI usage or attribute to a specific
  model. The `behavior_class` vocabulary excludes attribution terms.

---

## 1. Lane model and the separate determinism envelope [F2-1]

Phase 2 introduces the **Behavioral CTI lane**: a parallel, additive data and
scoring lane that sits beside the Phase 1 verdict path and never mutates it.

- The Phase 1 `threat_score` path (`scoring/compute.py`, `correlate/pipeline.py`)
  is untouched. Its `config_hash` is still computed only over
  `QUERY_PATH_FILES = (scoring.yaml, attack-map.yaml, own_infrastructure.yaml,
  feeds.yaml, research_metrics.yaml)`. **Behavioral config files are
  deliberately kept out of that tuple** so that shipping them does not change
  any existing deployment's `content_hash` and does not break byte-identical
  replay.
- The lane carries its **own** version stamp, the **`behavior_config_hash`**:
  `sha256` over the canonical JSON of the three behavioral config files
  (`behavior-classify.yaml`, `behavior-similarity.yaml`,
  `behavior-shadow-rules.yaml`), plus the active `behavior_generation` and
  `generator_version`. It is exposed via `loader.behavior_config_hash()` and
  reported inside every behavioral artifact (pattern provenance, `behavioral_cti`
  advisory block, report) so behavioral output is independently replayable
  without entangling the Phase 1 envelope.
- Rationale: this single decision is what makes the entire phase additive and
  safe. It preserves F-2/F-8 (determinism tuple, confidence parity) structurally
  — there is no carry-forward step into the verdict path to get wrong.

New ADR **[ADR-0009]** records this lane and its guardrails **[F2-16]**.

## 2. Storage — behavioral tables live in `local.db`, rebuildable by generation

### 2.1 Placement and tier [F2-2]

`behavior_pattern`, `behavior_pattern_evidence`, `behavior_pattern_similarity`,
and `behavior_meta` are **local-tier** tables in a new `local` migration file
(`src/azazel_knowledge/db/migrations/local/0002_behavior.sql`). They derive from
`reaction`/`observation`, which are local-tier and F-1-permanent; intel-tier
bundles must never name them (existing `BUNDLE_TOUCHES_LOCAL_TIER` guard already
covers any local table). The `#36` reaction extension is a second local
migration (`0003_reaction_ext.sql`).

### 2.2 Rebuildable derived artifact — local generation, not directory swap [F2-3]

Behavioral patterns are *derived and rebuildable*, unlike immutable `reaction`
rows. The intel-tier directory+symlink generation machinery (`db/generations.py`)
is **not** reused — it is single-file-incompatible with `local.db`. Instead a
**local-tier generation integer**, `behavior_generation`, governs atomic
rebuild:

1. The generator writes all rows for `behavior_generation = N+1` under the
   single-writer queue.
2. In the **same writer transaction** it bumps
   `behavior_meta['current_behavior_generation'] = N+1`.
3. Readers resolve the current generation once, then read
   `WHERE behavior_generation = <current>` — a stale read only ever sees the
   prior complete generation, never a half-built one.
4. A P3 retention pass sweeps generations older than `keep = 2`.

Behavioral tables are **excluded from the F-1 non-decrease invariant**
(`test_local_rows_never_decrease_across_full_import` names only
`reaction`/`observation`/`advisory_log`/`edge_reported_ioc`) precisely because
they are rebuildable — regeneration may legitimately reduce row counts. They
carry **no immutability triggers**.

### 2.3 DDL (authoritative spec for #31)

```sql
-- migrations/local/0002_behavior.sql
CREATE TABLE behavior_pattern (
    pattern_id           TEXT NOT NULL,
    behavior_generation  INTEGER NOT NULL,
    version              INTEGER NOT NULL DEFAULT 1,   -- generator schema version
    actor_key            TEXT NOT NULL,
    actor_cluster_key    TEXT,
    edge_id              TEXT NOT NULL,                -- source node; source_node_id alias
    observation_start    TEXT NOT NULL,
    observation_end      TEXT NOT NULL,
    action_applied       TEXT NOT NULL,
    reaction_sequence    TEXT NOT NULL DEFAULT '[]',   -- ordered JSON array of reaction classes
    reaction_window_s    INTEGER,
    behavior_class       TEXT NOT NULL CHECK (behavior_class IN (
                             'simple_scanner','scripted_automation','adaptive_probe',
                             'decoy_engaged','disengaged_after_friction','unknown')),
    confidence           INTEGER NOT NULL DEFAULT 0,   -- 0-100
    novelty_score        INTEGER NOT NULL DEFAULT 0,   -- 0-100
    repeatability_score  INTEGER NOT NULL DEFAULT 0,   -- 0-100; 0 = not yet computed / insufficient prior data (#34 fills)
    suspected_stage      TEXT,
    related_iocs         TEXT NOT NULL DEFAULT '[]',
    related_ttps         TEXT NOT NULL DEFAULT '[]',
    generated_at         TEXT NOT NULL,
    generator_version    TEXT NOT NULL,
    behavior_config_hash TEXT NOT NULL,
    provenance           TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (pattern_id, behavior_generation)
) STRICT;
CREATE INDEX idx_behavior_pattern_actor ON behavior_pattern (actor_key, behavior_generation);
CREATE INDEX idx_behavior_pattern_gen   ON behavior_pattern (behavior_generation);
CREATE INDEX idx_behavior_pattern_edge  ON behavior_pattern (edge_id, behavior_generation);

CREATE TABLE behavior_pattern_evidence (
    pattern_id           TEXT NOT NULL,
    behavior_generation  INTEGER NOT NULL,
    evidence_type        TEXT NOT NULL CHECK (evidence_type IN ('observation','reaction','pattern')),
    evidence_id          TEXT NOT NULL,                -- reaction_id / observation_id / event_id as text
    role                 TEXT NOT NULL CHECK (role IN ('source','supporting','derived_from')),
    PRIMARY KEY (pattern_id, behavior_generation, evidence_type, evidence_id, role)
) STRICT;
CREATE INDEX idx_bpe_pattern ON behavior_pattern_evidence (pattern_id, behavior_generation);

-- Precomputed similarity edges (written by #34 during the generation pass).
CREATE TABLE behavior_pattern_similarity (
    pattern_id           TEXT NOT NULL,
    behavior_generation  INTEGER NOT NULL,
    other_pattern_id     TEXT NOT NULL,
    similarity           REAL NOT NULL,                -- 0.0-1.0
    repeatability        INTEGER NOT NULL DEFAULT 0,   -- 0-100
    shared_features      TEXT NOT NULL DEFAULT '[]',
    differences          TEXT NOT NULL DEFAULT '[]',
    evidence_refs        TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (pattern_id, behavior_generation, other_pattern_id)
) STRICT;
CREATE INDEX idx_bps_pattern ON behavior_pattern_similarity (pattern_id, behavior_generation, similarity DESC);

CREATE TABLE behavior_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
) STRICT;   -- rows: current_behavior_generation, generator_version, built_at
```

```sql
-- migrations/local/0003_reaction_ext.sql  (#36; all additive nullable columns,
-- reaction stays INSERT-only/immutable — ADD COLUMN is DDL, triggers are on UPDATE/DELETE)
ALTER TABLE reaction ADD COLUMN actor_cluster_key TEXT;
ALTER TABLE reaction ADD COLUMN action_profile    TEXT;
ALTER TABLE reaction ADD COLUMN decoy_touched     INTEGER;   -- 0/1
ALTER TABLE reaction ADD COLUMN decoy_profile     TEXT;
ALTER TABLE reaction ADD COLUMN retry_interval_ms INTEGER;
ALTER TABLE reaction ADD COLUMN timeout_adaptation TEXT;
ALTER TABLE reaction ADD COLUMN payload_ext       TEXT NOT NULL DEFAULT '{}';  -- pre/post summaries, raw_refs, unknown fields (audit)
```

### 2.4 Deterministic pattern IDs [F2-4]

`pattern_id = "bp-" + sha256(canonical(edge_id \x00 actor_key \x00
observation_start \x00 observation_end \x00 generator_version))[:16]`. Because
the source `reaction` rows are immutable and grouping (§3.1) is deterministic,
the same episode yields the same `pattern_id` in every generation. Cross-
generation stability is what makes similarity/repeatability meaningful.
Uniqueness is `(pattern_id, behavior_generation)`; re-running the generator for
the same generation is idempotent.

### 2.5 Evidence-link integrity [F2-7]

Every `behavior_pattern` row has **≥1** `behavior_pattern_evidence` row. An
episode whose `reaction.evidence_refs` resolve to zero `observation`/`reaction`
rows produces **no** pattern (matches #32's "no pattern without evidence"
test). Evidence rows record `role` (`source` for the seed reactions,
`supporting`/`derived_from` for linked observations/patterns) so every pattern
is traceable to raw evidence — the Azazel doctrine that derived answers must be
walkable back to observations.

## 3. Pattern generation pipeline (#32)

### 3.1 Deterministic grouping into episodes [F2-5]

Input = immutable `reaction` rows with resolvable `evidence_refs`. Grouping is a
pure function of the reaction set + `behavior-classify.yaml`:

- Partition by `(edge_id, actor_key)`.
- Within a partition, order by `(applied_at, reaction_id)` and cut a new
  **episode** whenever the gap to the previous reaction exceeds
  `session_gap_s` (config, default 3600). `reaction_id` is the deterministic
  tie-breaker so ordering never depends on row-insertion or file order.
- `reaction_sequence` = the ordered list of `reaction` classes in the episode;
  `observation_start/end` = min/max `applied_at`; `action_applied` = the
  episode's applied action(s) (single value when uniform, else the dominant/
  first — spelled out in config).

Determinism input discipline mirrors the scoring rule [F-3] **[F2-20]**: the
generator takes `query_as_of` from `core/clock.py` **once** at entry and
threads it as a value; no `datetime.now`, no `random`, no env, no reliance on
directory/query order (every SELECT carries an explicit `ORDER BY`).

### 3.2 Deterministic classification [F2-6]

`behavior-classify.yaml` (versioned, own hash) maps episode features →
`behavior_class`. Seed mapping (from #32/#29, refined in config):

| Episode feature | Candidate class |
|---|---|
| `continued_scanning` after `delay`/`throttle` | `scripted_automation` |
| `shifted_port`/`shifted_protocol` after delayed/failed interaction | `adaptive_probe` |
| `shifted_target` after decoy or delay | `adaptive_probe` |
| `followed_decoy` (or `decoy_touched=1`) | `decoy_engaged` |
| `auth_pattern_changed` | `adaptive_probe` |
| `disengaged` after deception/delay | `disengaged_after_friction` |
| sparse/insufficient evidence | `unknown` |
| pure repetitive scan, no adaptation | `simple_scanner` |

The vocabulary is fixed at six values; it **never** emits `ai_attacker` or any
attribution label — these describe behavior style, not operator identity or
model **[F2-17]**. `confidence` and `novelty_score` are deterministic functions
of evidence richness (`evidence_modality_count`, sequence length, decoy
presence, action diversity); `repeatability_score` is left at its default `0`
here and filled by #34 (§5) **[F2-10]**.

### 3.3 Execution surface — worker P2 + CLI [F2-8]

- **Worker job** at priority **P2**, alongside `aggregate_observation_stats_trend`
  (`worker.py run_p2` → `writer.submit(P2, _txn)`): a periodic pass that reads
  `reaction`/`observation`, builds generation `N+1`, and swaps `behavior_meta`.
  It is an offline aggregation pass, never on a request path.
- **CLI** `azctl behavior generate|rebuild|dry-run`: `generate` processes
  unprocessed reactions incrementally; `rebuild` regenerates the whole
  generation from source; `dry-run` prints the would-be rows without writing
  (tests/debugging).
- Replayability: the same reaction set + same `behavior_config_hash` produce
  identical `pattern_id`s, classes, and reaction sequences (three-run
  byte-identical generation test, mirroring `test_scoring` determinism)
  **[F2-20]**. `generated_at`, `generator_version`, `behavior_config_hash`, and
  `provenance` are recorded on every row.

## 4. Behavioral similarity & repeatability (#34)

### 4.1 Deterministic, explainable similarity [F2-9]

A `scoring`/`correlate`-sibling module `behavior_similarity` (pure functions,
same input discipline [F2-20]) compares a query pattern to prior-generation
patterns using **feature-weighted** scoring configured in
`behavior-similarity.yaml` (versioned, own hash, **not** in `QUERY_PATH_FILES`).
Feature weights are validated to **sum to 1.0** by an added loader check
mirroring `_validate_weight_sum`. Comparison dimensions and seed weights:

| Feature | Weight class |
|---|---|
| `reaction_sequence` similarity (ordered) | high |
| `behavior_class` match | high |
| `decoy_engaged` when present | high |
| `action_applied` match | medium |
| `retry_interval` bucket match | medium |
| IOC overlap | medium |
| `actor_key`/`actor_cluster_key` exact match | high, not required |
| ATT&CK/TTP overlap | low/medium |

Output is `{query_pattern_id, matches:[{pattern_id, similarity, repeatability,
shared_features[], differences[], evidence_refs[]}]}` — every match explains
`shared_features` and `differences`. No embeddings, clustering, or LLM. Ceilings
`max_patterns_compared` (default 200) and `max_eval_ms` (default 5) mirror the
matchspec budget so the pass stays within Pi 4 limits **[F2-19]**.

### 4.2 Repeatability [F2-10]

`repeatability_score` (0-100) is a deterministic function of: count of similar
prior patterns, recurrence across time windows, recurrence across
`edge_id`/`actor_cluster_key`, reaction-sequence stability, same
`actor_key`/`actor_cluster_key`. It is explicitly **not** campaign-attribution
proof. `0` means "not yet computed / insufficient prior data" so #31/#32 can
ship before #34 with no rework.

### 4.3 Integration point

Similarity/repeatability run **inside the P2 generation pass**, after patterns
for generation `N+1` are staged and before the `behavior_meta` swap: they
compare against generation `N`, write `behavior_pattern_similarity` edges, and
backfill `behavior_pattern.repeatability_score` — all in the same atomic build.
`/v1/context` and reports therefore read *precomputed* results as point-reads;
similarity is **never** computed at query time [F2-19]. At least one internal
callable each is provided: compare-pattern-to-priors, find-similar-by-pattern-id,
find-similar-by-actor/time-window. A public API is deferred unless #33/#35 need
it (they read the precomputed tables directly).

## 5. `/v1/context` behavioral advisory (#35)

### 5.1 Additive, optional, best-effort block [F2-11]

When a current-generation `behavior_pattern` matches the request `actor_key`
(indexed point-read on `idx_behavior_pattern_actor`), the response gains an
**additive** `threat_context.behavioral_cti` object; the top `reason[]`,
`threat_score`, `confidence`, and `advisory_notice` are unchanged. Shape:

```json
{
  "threat_context": {
    "behavioral_cti": {
      "behavior_seen_before": true,
      "behavior_class": "adaptive_probe",
      "pattern_id": "bp-9f2c1a77b0e4d135",
      "similarity": 0.84,
      "repeatability_score": 72,
      "novelty_score": 28,
      "suggested_posture": "delay",
      "confidence": 68,
      "evidence_refs": ["obs-...", "rxn-..."],
      "explanation_short": "Actor shifted protocol and retried after delay; similar reaction sequence observed previously.",
      "limitations": [
        "Behavioral similarity is not attribution.",
        "AI usage is not directly proven.",
        "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
      ],
      "behavior_generation": 7,
      "generator_version": "bpg-1",
      "behavior_config_hash": "…"
    }
  }
}
```

- `suggested_posture ∈ {observe, delay, decoy, escalate, no_change, unknown}` —
  a **posture suggestion, not an action command**. No field instructs Edge to
  block/drop/redirect/delay directly **[F2-11]** (guardrail; ADR-0007).
- When no pattern matches, the block is **omitted entirely** (least-disruptive,
  additive-safe choice offered by #35). `limitations[]` is mandatory whenever
  the block is present.
- Backward-compatible per api.md's additive-only versioning rule; existing
  `reason[]`/`confidence_reason[]`/`advisory_notice` contracts preserved.

### 5.2 Best-effort under a sub-deadline — fail-closed correctly scoped [F2-12]

The behavioral lookup runs under a small sub-budget inside the existing 220 ms
deadline, guarded by a `_deadline_check` after scoring. If the sub-budget is
exceeded or the lookup errors, the block is **omitted** and the context response
still succeeds. This does **not** violate F-12/F-17: those govern the
`threat_score`/`reason[]` verdict and the audit-chain append, which keep their
`503 context_timeout` / `503 audit_unavailable` semantics unchanged. The
behavioral block is optional enrichment (#35: "must not be required for a valid
response") — its absence is definitionally not a verdict failure. The lookup is
a single indexed point-read (no full-table scan, no new synchronous round trip
outside a deadline checkpoint), keeping the Pi 4 context budget and the F-20
cold-read margin intact **[F2-19]**.

## 6. Reaction payload contract for Phase 2 (#36)

### 6.1 Additive, backward-compatible ingest [F2-13]

`POST /v1/reactions` stays a raw spool write (no client-time content
validation; S4). `ingest/validators.py:validate_reaction_line` is extended to
**accept and normalize** the Phase 2 optional fields; Phase 1 minimal records
(only the seven required fields) remain valid. The **8-class reaction taxonomy
is unchanged** — new fields enrich the record without changing the enum.

Field routing:

- **Promoted to typed nullable columns** (queryable by the generator):
  `actor_cluster_key, action_profile, decoy_touched, decoy_profile,
  retry_interval_ms, timeout_adaptation`.
- **Preserved in `payload_ext` JSON** (auditability, forward-compat):
  `pre_action_summary, post_action_summary, raw_refs`, and any unknown optional
  fields (preserved, never silently dropped).

Validation behavior (unchanged doctrine): a malformed line is **quarantined**
into the batch's `invalid[]` status, never rejecting the whole batch (S4); valid
lines still insert. `evidence_refs` remains **required non-empty**; unresolved
refs are resolved lazily via the existing linkage state machine [F-6] and simply
excluded from generation until resolvable. All timestamps normalized to UTC.
`reaction` stays INSERT-only/immutable.

### 6.2 Edge companion (cross-repo, flagged not created)

If Azazel-Edge must change its emitted payload (delay-history export, decoy-hit
export, `reaction_window_s` computation, `evidence_refs`↔Edge-audit-id mapping,
fire-and-forget delivery), that is **Edge-side work**. Per the escalation rule,
a companion issue in `01rabbit/Azazel-Edge` is **required but out of this
repo's scope** — it is listed in §13 as a follow-up for owner action, not
opened here. The contract remains fire-and-forget; nothing here introduces an
Edge hot-path dependency on CTI.

## 7. Operator friction timeline / report (#33)

### 7.1 Read surface [F2-14]

New **read-only** endpoints (Scope.READ, `reads.py` pattern — `repo.connection()`
`SELECT`-only, plain dict return, no write SQL so `test_api_static.py` stays
green):

- `GET /v1/behavior-patterns/{pattern_id}` — one pattern + evidence + similarity.
- `GET /v1/behavior-patterns/summary` — recent patterns by class/edge/window.
- `GET /v1/reports/friction-timeline` — the demo narrative surface.

A `azctl behavior report` CLI and a static-JSON generator ride the same
read code for demos.

### 7.2 Required timeline model

Each report renders, when source evidence exists: (1) initial observation →
(2) Edge action applied → (3) reaction window → (4) reaction classification →
(5) generated behavior pattern → (6) evidence references → (7) advisory
implication → (8) explicit CTI-advisory disclaimer. JSON fields:
`report_id, actor_key, edge_id, time_window, timeline[]{timestamp, event_type,
action_applied?, reaction?, evidence_refs, explanation_short},
behavior_patterns[], advisory_summary?, limitations[]`. The report **degrades
gracefully** when advisory data is absent.

### 7.3 Language guardrail [F2-17]

Human-readable output **must not** contain "AI attacker confirmed", "LLM
identified", or "autonomous intrusion proven". Preferred phrasing: "adaptive
behavior observed", "automation-like reaction pattern", "behavioral CTI
generated from defensive friction". Enforced by report tests asserting the
disclaimer is present and attribution terms are absent.

## 8. Shadow reaction-informed scoring (#37)

### 8.1 Reuse F-19 machinery, behavioral variant [F2-15]

Reaction-/behavior-informed scoring stays **research-only, default-off,
shadow-only**, reusing the F-19 pattern (`research.shadow_scoring.enabled:
false`, loader hard-pins `mode: shadow`, rejects `active`). The declarative
`behavioral_shadow_rules` live in a **separate** versioned file
`behavior-shadow-rules.yaml` (own hash, **not** in `QUERY_PATH_FILES` → the
`threat_score` `content_hash` is untouched even when the file ships). A loader
check mirroring `_validate_reaction_adjustments` makes an "active" behavioral
shadow structurally impossible to configure.

Rules are declarative (not learned weights), e.g.:

```yaml
behavioral_shadow_rules:
  enabled: false
  mode: shadow
  max_delta: 30
  max_total_delta: 20
  rules:
    - id: continued-scan-after-delay
      when: { behavior_class: scripted_automation, action_applied: delay, reaction_contains: continued_scanning }
      shadow_effect: { component: history, delta: 5 }
      explanation: Actor continued scanning after delay; shadow-only history adjustment.
```

### 8.2 Output isolation — honors F-19 [F2-15]

A computed `shadow_score_delta` **never** changes `threat_score` and **never**
appears in the Edge-facing `/v1/context` response (F-19: shadow output goes to
the JSONL research log only). It may additionally be surfaced on a
**research-scoped** read/report surface, never the advisory contract. Output
shape (research log / research surface only):

```json
{ "behavioral_shadow": { "enabled": false, "would_adjust": true,
  "shadow_score_delta": 5, "rules_hit": ["continued-scan-after-delay"],
  "explanation": "Shadow-only; production threat_score unchanged." } }
```

Deterministic and versioned; includes `explanation` + `rules_hit`; produces no
adjustment when evidence is insufficient. The Phase 1 `reason[]` completeness
contract is **untouched** — shadow is a separate lane and does not add or remove
`reason[]` lines.

## 9. Performance & Pi 4 budget [F2-19]

- **Query path**: one indexed point-read on `behavior_pattern(actor_key,
  behavior_generation)` + evidence resolution, under the context 250 ms budget
  and the F-20 cold-read margin. No similarity at query time; no full-table
  scan.
- **Offline path**: generation + similarity are P2 worker passes, bounded like
  feed pulls; similarity honors `max_patterns_compared`/`max_eval_ms` ceilings.
- **Memory**: behavioral tables are small (episodes, not raw events); no new
  `GenCache`, no change to the F-11 192 MB cache arithmetic. `azctl
  check-config` continues to print the memory arithmetic.

## 10. Test plan (per issue)

- **#31**: create pattern with evidence links; reject/skip a pattern with zero
  resolvable evidence; JSON round-trips deterministically; rows traceable to
  reaction/observation ids; derived-artifact delete/regenerate semantics;
  schema tolerates multiple `edge_id` without cross-site logic; **baseline
  `test_local_rows_never_decrease_*` still passes** (behavioral tables excluded).
- **#32**: single reaction → one pattern; multi-reaction → ordered
  `reaction_sequence`; evidence preserved; no pattern when evidence unresolved;
  repeated run does not duplicate (idempotent generation); classification
  deterministic; `generated_at/generator_version/provenance` present; class
  never `ai_attacker`; **three-run byte-identical generation replay**.
- **#33**: all timeline stages present when evidence exists; degrades
  gracefully; every stage links `evidence_refs`; disclaimer present;
  attribution terms absent; report renders from #32 fixtures.
- **#34**: exact-sequence match → high similarity; different actor same sequence
  still matches; same actor unrelated behavior does not overmatch; decoy
  materially affects similarity; missing features degrade gracefully;
  `shared_features`/`differences` explained; no ML dependency; weight-sum
  loader validation.
- **#35**: block present on match / valid when absent; `evidence_refs` +
  `limitations` present; `suggested_posture` not treated as command; additive/
  backward-compatible; `reason[]`/`advisory_notice` preserved; sub-deadline
  omission path still returns a valid scored 200; no full-table scan.
- **#36**: valid Phase 2 payload accepted; missing `evidence_refs` handled per
  policy; unknown optional fields preserved; `decoy_touched`/`action_profile`
  available to generator; invalid taxonomy quarantined; UTC normalization;
  Phase 1 minimal record still valid.
- **#37**: disabled by default; production score unchanged when disabled;
  production score unchanged even when shadow computed; rules deterministic +
  versioned; output includes `explanation`+`rules_hit`; insufficient evidence →
  no adjustment; `reason[]` contract intact; loader rejects `active`.

Baseline discipline: the 487-test floor never drops; new tests are added, never
removed.

## 11. Per-issue work breakdown (implementation order = #30 order)

| Issue | Delivers | Binding decisions | Owns (files) |
|---|---|---|---|
| **#31** schema | behavioral DDL + migrations + model | F2-2,3,4,7,10,17,18 | `migrations/local/0002_behavior.sql`, model/repo readers, `data-model.md`, `test_migrations`/model tests |
| **#32** generation | deterministic generator (P2 + CLI) | F2-5,6,8,20 | `patterns/` generator, `behavior-classify.yaml`, `worker.py run_p2`, `azctl`, tests |
| **#33** report | operator friction timeline | F2-14,17 | `api/routers/reads.py` (+report module), `azctl behavior report`, tests |
| **#34** similarity | deterministic similarity + repeatability | F2-9,10,19,20 | `behavior_similarity` module, `behavior-similarity.yaml`, P2 integration, tests |
| **#35** advisory | `/v1/context` behavioral block | F2-11,12,19 | `correlate/pipeline.py` additive block, `api/models.py`, `api.md`, tests |
| **#36** payload | Phase 2 reaction contract | F2-13 | `migrations/local/0003_reaction_ext.sql`, `ingest/validators.py`, `api.md`/`data-model.md`, tests; Edge companion note |
| **#37** shadow | shadow reaction-informed scoring | F2-15 | `behavior-shadow-rules.yaml`, loader guard, research-log emit, `scoring.md`, tests |
| **ADR-0009** | lane doctrine record | F2-1,16 | `docs/adr/0009-behavioral-cti.md`, ADR README row |

Each issue is one worktree / one branch / one draft PR (Codex delegation
protocol). The satellite doc edits for #31/#35/#36/#37 land in the same PR as
their code (design-doc-in-same-PR rule).

## 12. Decision register (F2-1 … F2-20, one line each)

F2-1 Behavioral CTI is a separate additive lane; the Phase 1 `threat_score`
determinism envelope (7-tuple, `content_hash`, `QUERY_PATH_FILES`, weight sums)
is frozen; the lane carries its own `behavior_config_hash`. F2-2 Behavioral
tables live in `local.db` (derive from local-tier `reaction`/`observation`;
F-1 bundle guard covers them). F2-3 Rebuild via a local `behavior_generation`
integer + atomic `behavior_meta` swap + P3 GC, not intel directory-swap, not row
immutability; excluded from the F-1 non-decrease invariant. F2-4 Deterministic
`pattern_id = bp-sha256(edge_id,actor_key,start,end,generator_version)[:16]`,
stable across generations. F2-5 Deterministic episode grouping by
`(edge_id,actor_key)` with `session_gap_s` cut and `(applied_at,reaction_id)`
ordering. F2-6 Deterministic config-versioned classification into six
`behavior_class` values; never an attribution label. F2-7 Every pattern has ≥1
evidence link; zero resolvable evidence ⇒ no pattern. F2-8 Generation runs as a
P2 worker job + `azctl` CLI; replayable, provenance-stamped. F2-9 Deterministic
feature-weighted similarity (own config, sum-to-1.0), explainable, no ML,
budget-ceilinged. F2-10 `repeatability_score` deterministic; default `0` =
not-yet-computed so #31/#32 ship before #34. F2-11 `/v1/context` gains an
additive `behavioral_cti` block on match, omitted otherwise; `suggested_posture`
is a suggestion, never a command. F2-12 The behavioral block is best-effort
under a sub-deadline; its omission is never a 503; verdict/audit fail-closed
[F-12/F-17] unchanged. F2-13 Phase 2 reaction payload is additive/backward-
compatible; generator-critical fields promoted to nullable columns, the rest
preserved in `payload_ext`; taxonomy unchanged; quarantine-not-reject. F2-14
Operator friction-timeline report via read-only endpoints + CLI. F2-15 Shadow
reaction-informed scoring reuses F-19: default-off, shadow-only, separate config
file (outside `QUERY_PATH_FILES`), research-log-only output, never in the Edge
advisory. F2-16 New ADR-0009 records the lane. F2-17 No AI attribution in output
or docs; `behavior_class` vocabulary excludes attribution terms; report tests
enforce it. F2-18 STIX/TAXII boundary unchanged (ADR-0002); behavioral patterns
are internal-relational only; export deferred. F2-19 Pi 4 budgets preserved:
query = one indexed point-read, similarity precomputed offline, no new
`GenCache`. F2-20 Determinism input discipline [F-3] extended to the behavioral
core (clock-once `query_as_of`, no wall-clock/random/env/file-order;
byte-identical generation replay test).

## 13. Deferred / open items

- **S2-1 Edge companion issue** (#36) — Azazel-Edge payload changes are
  required for full end-to-end Phase 2 but are cross-repo and owner-gated;
  filed by the owner in `01rabbit/Azazel-Edge`, not here. Trigger: before
  Phase 2 end-to-end demo.
- **S2-2 Pattern export to Edges** (roadmap Phase 2 line) — exporting compiled
  behavior patterns to Edges rides the existing bundle/sync channel (ADR-0004);
  out of scope for #31–#37. Trigger: multi-Edge deployment.
- **S2-3 Cross-edge correlation** — schema carries `edge_id`/`actor_cluster_key`
  so it is *possible* later, but no cross-site logic is enabled now (#29
  out-of-scope). Trigger: Phase 2 multi-Edge ingest.
- **S2-4 SQLite → PostgreSQL** (ADR-0003 exit criteria) — behavioral write load
  is modest (offline P2 batch); re-evaluate only against measured writer
  contention. Trigger: measured >1 s write queue or >10 M store.
- **S2-5 STIX mapping for behavior patterns** — deferred (F2-18); revisit only
  if behavior patterns must cross a STIX/TAXII boundary. Trigger: external
  behavioral-CTI interchange requirement (would need an ADR-0002 addendum).
- **S2-6 LLM briefing layer** — any LLM use stays confined to explanation/report
  prose, marked in output, excluded from generation/similarity/scoring; not
  built in Phase 2.
