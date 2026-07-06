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
