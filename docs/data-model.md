# Data model

Internal storage uses a **native lightweight relational model** tuned for
lookup latency on Pi 4. STIX 2.1 is an interchange format at the boundary
only (import/export), never the query model. See ADR-0002.

## Stores

### ioc

Indicators of compromise, one row per indicator, unique on `(type, value)`.

| Column | Notes |
|---|---|
| type | `ip`, `domain`, `url`, `hash_md5/sha1/sha256`, `email`, `asn`, `certificate`, `ja3`, `ja4` |
| value | normalized (lowercase, A-label punycode for IDN, defanged input re-armed) |
| first_seen / last_seen | UTC |
| sources | JSON array of feed ids |
| tags | JSON array |
| confidence | 0–100, per [scoring.md](scoring.md) |
| expires_at | TTL per feed policy; expired rows excluded from matches, kept for history |

Indexes: `(type, value)` unique; `last_seen`; per-type partial indexes for
the hot types (`ip`, `domain`, `ja3`, `ja4`).

### attack

MITRE ATT&CK snapshot: technique, sub-technique, tactic, mitigations,
detections, data sources. Refreshed from the official STIX bundle; stored
flattened for join-free lookup. Version pinned per import (`attack_version`).

### campaign

| Column | Notes |
|---|---|
| name, actor | |
| industries, regions | JSON arrays |
| confidence | analyst/source confidence, 0–100 |
| ioc_refs | join table `campaign_ioc` |
| technique_refs | join table `campaign_technique` |

### observation — historical evidence from Edge

Every event received from Azazel-Edge, normalized:

| Column | Notes |
|---|---|
| event_id | Edge-side evidence id (correlates with Edge audit trail) |
| edge_id | which Edge sent it (Phase 2+: several) |
| kind | `eve_alert`, `dns`, `http`, `flow`, `canary_hit`, `delay_history`, ... |
| observed_at | |
| entities | extracted IOC candidates (JSON) |
| raw | original JSONL payload |

Aggregates (frequency, trend per entity) are maintained in
`observation_stats` by the background worker, not computed at query time.

### reaction — the Tactical CTI Sensor core (Azazel-Edge #283)

What makes this node more than an IOC cache: structured records of **attacker
behavior under friction**.

| Column | Notes |
|---|---|
| actor_key | source entity (ip / ja3 / session cluster) |
| action_applied | `throttle`, `redirect`, `isolate`, `delay`, `deception` |
| applied_at | |
| reaction | `continued_scanning`, `shifted_port`, `shifted_protocol`, `shifted_target`, `followed_decoy`, `auth_pattern_changed`, `disengaged`, `unknown` |
| reaction_window_s | seconds observed after the action |
| evidence_refs | observation ids backing the classification |

This table is the input to the Pattern Generator and the primary export for
the "CTI value of delaying defense" research theme (ADR-0008).

### pattern — Tactical Pattern Memory

| Column | Notes |
|---|---|
| pattern_id, version | |
| match_spec | declarative predicate over normalized evidence (JSON) |
| attack_refs | ATT&CK technique ids |
| provenance | which CTI sources / reactions produced it |
| advisory | suggested rule / delay / decoy templates |
| confidence | |

Patterns are **compiled artifacts**, regenerated from source data; the store
can be rebuilt at any time. A pattern match is advisory context, never a
verdict.

### reputation

Rolling reputation per ip / domain / hash: score, contributing sources,
decay timestamps. Derived data — rebuildable from `ioc` + `observation`.

### feed_state

Per-feed cursor: last run, last success, item counts, checksum of last
snapshot, enabled flag. Drives both online pulls and offline bundle
version checks.

## Behavioral CTI (Phase 2)

Design source: [phase2-implementation.md](design/phase2-implementation.md) §2,
§6.1, §12; [ADR-0009](adr/0009-behavioral-cti.md). Behavioral CTI is a
**separate, additive lane** beside the Phase 1 verdict path (F2-1): it never
changes the `threat_score` determinism envelope, and it never commands
Azazel-Edge. It only characterizes observed attacker behavior under friction
and offers advisory posture suggestions.

> Behavioral CTI characterizes adaptive or automation-like behavior. It does not prove that an attacker used AI.

Behavior patterns are advisory, rebuildable derived artifacts built from
`reaction` and `observation` evidence, and they are not verdicts.

### Placement — `local.db`, not a bundle table [F2-2]

`behavior_pattern`, `behavior_pattern_evidence`, `behavior_pattern_similarity`,
and `behavior_meta` are **local-tier** tables (migration
`db/migrations/local/0002_behavior.sql`). They derive from `reaction` and
`observation`, which are themselves local-tier and F-1-permanent, so the
derived behavioral tables live in `local.db` alongside them. Intel-tier
bundles are STIX/ATT&CK/campaign data only; a bundle naming any behavioral
table hard-aborts under the existing `BUNDLE_TOUCHES_LOCAL_TIER` guard — the
same guard that already protects `reaction`/`observation`.

### Derived, rebuildable — not a verdict, not F-1-immutable [F2-3]

Unlike `reaction`/`observation` rows, behavior patterns are **compiled,
rebuildable artifacts**, in the same spirit as the `pattern` store above but
with their own rebuild mechanism: a **local-tier generation integer**,
`behavior_generation`, rather than the intel-tier directory+symlink
generation swap (`db/generations.py` is not reused; it is single-file-
incompatible with `local.db`). The generator writes all rows for
`behavior_generation = N+1` and, in the same writer transaction, bumps
`behavior_meta['current_behavior_generation'] = N+1`; readers resolve the
current generation once and read `WHERE behavior_generation = <current>`, so
a stale read only ever sees the prior complete generation, never a
half-built one. A P3 retention pass sweeps generations older than `keep = 2`.

Because regeneration may legitimately reduce row counts, the four behavioral
tables are **excluded from the F-1 non-decrease invariant**
(`test_local_rows_never_decrease_across_full_import` names only
`reaction`/`observation`/`advisory_log`/`edge_reported_ioc`) and carry **no
immutability triggers**. `reaction` and `observation` rows themselves remain
immutable and untouched by generation — the derived lane reads them, never
writes them. The resulting behavior patterns remain advisory/rebuildable
derived artifacts rather than verdicts.

### behavior_pattern

One row per generated episode per generation; primary key
`(pattern_id, behavior_generation)`.

| Column | Notes |
|---|---|
| pattern_id | `"bp-" + sha256(edge_id, actor_key, observation_start, observation_end, generator_version)[:16]`; stable across generations for the same episode |
| behavior_generation | local generation this row belongs to |
| version | generator schema version, default 1 |
| actor_key | source entity (ip / ja3 / session cluster), as in `reaction` |
| actor_cluster_key | optional cross-episode actor grouping key |
| edge_id | source Edge node |
| observation_start / observation_end | episode window (min/max `applied_at` of its reactions) |
| action_applied | the episode's applied Edge action(s) |
| reaction_sequence | ordered JSON array of `reaction` classes in the episode |
| reaction_window_s | seconds observed after the action |
| behavior_class | one of `simple_scanner`, `scripted_automation`, `adaptive_probe`, `decoy_engaged`, `disengaged_after_friction`, `unknown` — never an attribution label |
| confidence | 0–100, deterministic function of evidence richness |
| novelty_score | 0–100, deterministic function of evidence richness |
| repeatability_score | 0–100; `0` = not yet computed / insufficient prior data, filled by the similarity pass |
| suspected_stage | optional |
| related_iocs / related_ttps | JSON arrays |
| generated_at, generator_version, behavior_config_hash | provenance/replay stamp |
| provenance | JSON |

Indexes: `(actor_key, behavior_generation)`, `(behavior_generation)`,
`(edge_id, behavior_generation)`. The `/v1/context` behavioral lookup is a
single indexed point-read on the actor index (§5, F2-19) — never a
full-table scan and never computed at query time.

### behavior_pattern_evidence

Links every `behavior_pattern` back to the raw evidence it was built from —
the same "derived answers must be walkable back to observations" rule the
`pattern` store and `reputation` already follow.

| Column | Notes |
|---|---|
| pattern_id, behavior_generation | FK to `behavior_pattern` |
| evidence_type | `observation`, `reaction`, or `pattern` |
| evidence_id | `reaction_id` / `observation_id` / `event_id` as text |
| role | `source` (seed reactions), `supporting`, or `derived_from` |

Primary key `(pattern_id, behavior_generation, evidence_type, evidence_id,
role)`. Every `behavior_pattern` row has **≥1** evidence row; an episode whose
`reaction.evidence_refs` resolve to zero `observation`/`reaction` rows
produces **no** pattern at all (F2-7).

### behavior_pattern_similarity

Precomputed similarity edges, written during the same P2 generation pass that
stages a new `behavior_generation`, comparing it against the prior
generation. Never computed at query time (F2-9, F2-19).

| Column | Notes |
|---|---|
| pattern_id, behavior_generation | the query pattern |
| other_pattern_id | the matched prior-generation pattern |
| similarity | 0.0–1.0, feature-weighted per `behavior-similarity.yaml` |
| repeatability | 0–100 |
| shared_features / differences | JSON arrays, explain the match |
| evidence_refs | JSON array |

Primary key `(pattern_id, behavior_generation, other_pattern_id)`.

### behavior_meta

Key/value table holding the swap state: `current_behavior_generation`,
`generator_version`, `built_at`. The P2 writer updates
`current_behavior_generation` atomically with the new generation's rows so
readers never observe a half-built generation.

### Reaction extension (Phase 2 payload, #36)

`reaction` gains additive, **nullable** columns (migration
`db/migrations/local/0003_reaction_ext.sql`). `reaction` stays INSERT-only
and immutable — these are `ADD COLUMN` DDL, not a change to the existing
UPDATE/DELETE-rejecting triggers — and Phase 1 minimal records (only the
seven original required fields) remain valid rows.

| Column | Notes |
|---|---|
| actor_cluster_key | optional cross-episode actor grouping key |
| action_profile | optional refinement of `action_applied` |
| decoy_touched | 0/1, whether the actor engaged a decoy |
| decoy_profile | which decoy profile, if touched |
| retry_interval_ms | observed retry timing, if any |
| timeout_adaptation | observed timeout-handling change, if any |
| payload_ext | JSON, default `{}`; holds `pre_action_summary`, `post_action_summary`, `raw_refs`, and any unknown optional fields — preserved, never silently dropped |

`actor_cluster_key, action_profile, decoy_touched, decoy_profile,
retry_interval_ms, timeout_adaptation` are promoted to typed columns because
the pattern generator queries them directly; everything else stays in
`payload_ext` for auditability and forward-compatibility. The 8-class
`reaction` taxonomy itself is unchanged.

Per Phase 2 §6.1 routing, the six promoted context fields above plus
`payload_ext` are the only schema additions. `pre_action_summary` and
`post_action_summary` are not narrowed to strings: they are accepted as any
JSON value and stored verbatim in `payload_ext`, alongside `raw_refs` and any
future unknown optional fields. This keeps `reaction` queryable where needed
without sacrificing auditability or forward compatibility. `reaction`
remains INSERT-only and immutable after these additions.

## Deception effectiveness (AZ-06, ADR-0011)

### deception_observation — `local.db`, F-1 immutable

First-class store of AZ-06 **fact-only** deception observations (Fabric
`InteractionObservation`: honesty ladder layers 1–3). Created by migration
`db/migrations/local/0004_deception_observation.sql`, INSERT-only with
`BEFORE UPDATE`/`BEFORE DELETE` triggers rejecting mutation exactly like
`reaction`/`observation` (F-1). Idempotent replay via `observation_uid UNIQUE`
+ `INSERT OR IGNORE`; **rows never decrease across imports**. It stores the
honesty-ladder **facts only** — there is deliberately **no** belief / verdict /
effectiveness column, because interaction does not prove attacker belief
(Azazel-Deception#6, Azazel-Knowledge#58); that layer-4 inference lives only in
the advisory **output** (`EffectivenessAdvisory`), never in this table.

| Column | Notes |
|---|---|
| observation_uid | Fabric `observation_id`; UNIQUE idempotency/dedupe key |
| environment_id, package_id, node_id | AZ-06 environment / package / node identity |
| edge_id, actor_key | linkage into the reaction/observation model; Edge-stamped in observation `metadata` when available, else `NULL` (never synthesised) |
| observed_at | UTC |
| observation_class | `interaction`, `reaction`, `outcome` (layers 1–3) |
| surface | closed `InteractionSurface` enum (service/port/file/document/credential_lure/…) |
| reaction_kind | closed `ReactionKind` enum; must be absent for a pure `interaction` |
| lure_id | optional decoy-lure id (untrusted string, length-bounded) |
| first_contact_latency_ms, dwell_ms, attempt_count | measured quantities (non-negative) |
| confounder_tags | JSON array of closed `ConfounderTag` enum (scanner_noise, host_capacity, …) |
| runtime_context | JSON: tier / architecture / runtime_adapter / active+omitted components / resource_saturation / capability_drift |
| evidence_refs | JSON array of opaque refs |
| raw | full canonical observation JSON (audit); attacker-authored strings are opaque data |

Every string field is untrusted attacker-authored content — length-bounded,
stored as opaque data, never evaluated or executed. The advisory read path
(`GET /v1/deception-effectiveness`, `correlate/deception_effectiveness.py`)
summarizes these rows deterministically into a Fabric `EffectivenessAdvisory`;
it separates narrative effectiveness from runtime/capacity confounders and never
claims attacker belief.

### deception_outcome_envelope_v0 — `local.db`, F-1 immutable

What the producer could see while it watched (Knowledge#111 G7): a Fabric
`OutcomeObservationEnvelope` and the `EffectObservation` it correlates. Migration
`db/migrations/local/0008_deception_outcome_envelope.sql`; INSERT-only with
`BEFORE UPDATE`/`BEFORE DELETE` triggers; idempotent on `envelope_ref`
(= `envelope_id`). **No verdict column**, and no derived column: isolation state
is read from `limitations` at query time rather than stored a second time.

| Column | Notes |
|---|---|
| envelope_ref | Fabric `envelope_id`; UNIQUE. A re-used id with different `raw` is quarantined at drain, never overwritten |
| environment_id, package_id | from the batch (`package_id` optional); `environment_ref` is checked against `environment_id` |
| producer_product, producer_node, trace_id | identity; `trace_id` and `effect_ref` must match the effect observation |
| decision_ref, effect_ref, presentation_ref | typed refs, as sent |
| window_start, window_end, observed_at | UTC, fixed-width (`…%S.%fZ`) so string order is time order |
| coverage_complete, telemetry_gaps | 0/1 and JSON array; CHECKed against each other in both directions |
| telemetry_coverage, impact_observations, confounders | JSON; bounded fact maps / tokens |
| evidence_refs | JSON; includes the typed `advisory:` objective / hypothesis / frame refs |
| effect_observation_ref, effect_status, termination_reason, limitations | from the `EffectObservation` (`limitations` is JSON, identifier-like tokens) |
| authority_class | CHECK `observed_fact` / `active_materialized` |
| raw | the whole `{outcome, effect_observation}` line as stored |

## Normalization rules

- All timestamps UTC ISO 8601.
- IOC values canonicalized before insert (case normalization, A-label IDN
  normalization, URL normalization). Internationalized domain names are
  stored in A-label (`xn--` punycode) form, not U-label Unicode display form;
  matching is exact-after-normalization, plus CIDR containment for IPs and
  suffix match for domains.
- U-label storage is not a safe canonical form because visually identical
  homoglyph and mixed-script domains can remain distinct byte strings and
  evade exact matching. Canonicalizing IDNs to A-label with IDNA via the
  `idna` library collapses those variants to one stable representation and
  preserves the soundness of exact-after-normalization matching.
- Every derived row (`reputation`, `observation_stats`, `pattern`) records
  its inputs, so any answer can be traced to raw evidence — the same
  auditability rule Azazel-Edge applies to actions.

## STIX 2.1 mapping (boundary only)

| Internal | STIX |
|---|---|
| ioc | `indicator` (pattern) |
| campaign | `campaign` / `intrusion-set` |
| attack | `attack-pattern` (consumed from MITRE bundle) |
| observation | `observed-data` |
| reaction | `observed-data` + custom extension `x-azazel-reaction` |
| pattern advisory | `course-of-action` (advisory semantics preserved) |

Import: STIX feeds and Edge TAXII pushes are flattened into the tables above.
Export: TAXII 2.1 collections serve generated bundles for upstream sharing
(Phase 4 Regional CTI), reusing the exporter design from Azazel-Edge #224/#238.
