# Deterministic scoring

Same doctrine as Azazel-Edge: deterministic, bounded, explainable. No ML in
the verdict path, no opaque numbers (ADR-0006).

## Model

Weighted sum of independent components, weights defined in configuration
(YAML, versioned in git), every answer returns the full breakdown.

```
threat_score = clamp_0_100( Σ  weight_i × component_i × freshness_i )
```

Default components and weights (tunable per deployment):

| Component | Weight | Source |
|---|---|---|
| ioc_match | 0.30 | number/quality of matching indicators |
| history | 0.20 | prior observations of the entity from this site's Edges |
| attack_map | 0.15 | mapped ATT&CK techniques (severity class of tactic) |
| cve_exploited | 0.15 | 100 iff an alert CVE is in `kev`, else 0; `applies_when: [eve_alert]` |
| campaign | 0.10 | campaign/actor association strength |
| geo_asn | 0.10 | ASN/GeoIP reputation |

Weights must sum to 1.0; the config loader rejects anything else.
When `cve_exploited` is not applicable because the advisory was not derived
from an `eve_alert`, the `reason[]` entry still appears with
`contribution: 0` and `applicable: false`, and the remaining applicable
component weights are renormalized to sum to 1.0 using
`effective_weight = config_weight / Σ(applicable config_weight)`.

## Freshness decay

Each component is discounted by the age of its supporting data:

```
freshness = max(floor, 0.5 ^ (age_days / half_life_days))
```

Default half-life 30 days, floor 0.2 (old intel keeps some weight rather
than vanishing — offline deployments must degrade gracefully, per
[sync-offline.md](sync-offline.md#staleness-handling)).

## Confidence vs. threat score

Two separate numbers, never merged:

- **threat_score** (0–100): how bad the entity looks.
- **confidence** (0–100): how much the node trusts its own answer — driven by
  source count, source independence, source freshness, and whether local
  observations corroborate external feeds.

```
confidence = clamp_0_100( Σ w_j × driver_j )
```

| Driver | Weight | Description |
|---|---|---|
| source_count | 0.30 | min(distinct_groups, 4) / 4 |
| source_independence | 0.30 | 1 − max_single_group_share |
| source_freshness | 0.25 | oldest contributing source age |
| local_corroboration | 0.15 | local observation corroboration (floor 0.3) |

The noisy-OR aggregation is only for `ioc.agg_raw_confidence`; it is not the
confidence scoring formula above.

A single stale feed hit → high score is impossible; it yields a moderate
score with low confidence, and the `reason[]` breakdown says exactly why.

## Reaction-informed adjustment (research, Phase 2+)

Attacker reactions recorded under friction (the `reaction` store) may adjust
component values — e.g. `continued_scanning` after throttle raises the
history component; `disengaged` after deception lowers it. Rules for this are
declarative entries in the same YAML config, never learned weights. This is
the scoring-side half of the "CTI optimizes delaying defense" research theme
(ADR-0008).

## Explainability contract

Every scored answer must include:

1. `reason[]` — component, `config_weight`, `effective_weight`,
   contribution, human-readable detail.
2. `source_freshness` — oldest contributing feed age, ATT&CK version.
3. `rejected_alternatives` — when a recommendation is present, why stronger
   and weaker actions were not recommended.

If a component contributed nothing, it appears with contribution 0 — silence
is not allowed to look like omission. The test suite treats a scoring answer
without a complete breakdown as a failing contract.

## Behavioral CTI scoring lane (Phase 2)

Full design: [phase2-implementation.md](design/phase2-implementation.md) §1,
§4, §8; doctrine record: [ADR-0009](adr/0009-behavioral-cti.md). This section
extends, and does not contradict, the "Reaction-informed adjustment (research,
Phase 2+)" note above — it is the concrete lane that note anticipated.

### A separate determinism envelope [F2-1]

Behavioral scoring is a **parallel, additive lane** that never enters the
Phase 1 `threat_score` determinism described earlier in this document. The
7-element replay tuple (`intel_generation, local_generation, stats_generation,
attack_version, config_hash, event, query_as_of`), the production `content_hash`,
the `QUERY_PATH_FILES` set, and the sum-to-1.0 production `weights`/
`confidence_weights` tables above are frozen and untouched by anything in this
section. Existing advisories continue to replay byte-identical.

The behavioral lane instead carries its **own** version stamp,
`behavior_config_hash`: a `sha256` over the canonical JSON of the three
behavioral config files (`behavior-classify.yaml`, `behavior-similarity.yaml`,
`behavior-shadow-rules.yaml`) plus the active `behavior_generation` and
`generator_version`. None of these three files is a member of
`QUERY_PATH_FILES`, so shipping or editing them never changes the production
`config_hash`/`content_hash` and never perturbs Phase 1 replay tests.

### Deterministic similarity & repeatability [F2-9, F2-10]

A `behavior_similarity` module compares a query behavior pattern against
prior-generation patterns using **feature-weighted** scoring, configured in
its own file, `behavior-similarity.yaml`. Like the production weights above,
the behavioral feature weights must sum to 1.0; a loader check mirroring
`_validate_weight_sum` rejects any file that does not. The columns below use a
qualitative weight class, not the numeric production weights, to keep this
table distinct from the weights table earlier in this document:

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

Every match is explainable: the output carries `shared_features[]` and
`differences[]` per comparison, never an opaque number. There is **no**
embedding model, clustering model, or LLM anywhere in generation, similarity,
or scoring (ADR-0006; ADR-0009). Similarity and repeatability are computed
**offline**, inside the P2 worker generation pass, and written to
`behavior_pattern_similarity` / `behavior_pattern.repeatability_score`; the
`/v1/context` hot path and reports only ever perform a **point-read** of the
precomputed result, never a query-time computation. `repeatability_score` is
0-100; `0` means "not yet computed / insufficient prior data" and is explicitly
not campaign-attribution proof.

### Shadow reaction-informed scoring [F2-15, extends F-19]

The "Reaction-informed adjustment" note above names the doctrine; this is its
Phase 2 mechanism. Behavioral reaction-informed scoring reuses the F-19
shadow-scoring machinery and stays **research-only, default-off, shadow-only**:
`behavioral_shadow_rules.enabled: false` ships, and the loader hard-pins
`mode: shadow` — configuring `mode: active` is structurally rejected, mirroring
`_validate_reaction_adjustments`.

The declarative rules live in **`behavior-shadow-rules.yaml`**, a file
deliberately kept **out of `QUERY_PATH_FILES`** so that shipping it, or
changing its rules, never changes the production `threat_score` `content_hash`.
Rules are declarative pattern-matches (never learned weights), e.g. "actor
continued scanning after a delay action" triggers a small shadow-only
adjustment to the `history` component class.

A computed `shadow_score_delta`:

- **Never** changes the production `threat_score`.
- **Never** appears in the Edge-facing `/v1/context` response.
- Goes only to the JSONL research log (honoring F-19), and may optionally be
  surfaced on a research-scoped read/report surface — never the advisory
  contract.

The `reason[]` completeness contract described above is untouched by this:
shadow scoring is a separate lane and neither adds nor removes `reason[]`
entries in the production response.

### No AI attribution

As with the rest of this document's "no opaque numbers, no ML in the verdict
path" doctrine (ADR-0006), the behavioral lane adds no ML/embeddings/LLM in
generation, similarity, or scoring (ADR-0006; ADR-0009). Its output
characterizes *adaptive* or *automation-like* behavior — it never proves AI
usage and never attributes behavior to a specific model or operator.
