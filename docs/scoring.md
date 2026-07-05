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
| ioc_match | 0.35 | number/quality of matching indicators |
| history | 0.20 | prior observations of the entity from this site's Edges |
| attack_map | 0.15 | mapped ATT&CK techniques (severity class of tactic) |
| campaign | 0.15 | campaign/actor association strength |
| geo_asn | 0.15 | ASN/GeoIP reputation |

Weights must sum to 1.0; the config loader rejects anything else.

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

1. `reason[]` — component, weight, contribution, human-readable detail.
2. `source_freshness` — oldest contributing feed age, ATT&CK version.
3. `rejected_alternatives` — when a recommendation is present, why stronger
   and weaker actions were not recommended.

If a component contributed nothing, it appears with contribution 0 — silence
is not allowed to look like omission. The test suite treats a scoring answer
without a complete breakdown as a failing contract.
