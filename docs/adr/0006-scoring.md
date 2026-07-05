# ADR-0006: Deterministic weighted scoring with mandatory breakdown

Status: accepted (design phase)

## Context

How to weigh IOC matches, ATT&CK mapping, history, geo/ASN, time factors
into a threat score — and whether any learned/opaque scoring is acceptable.

## Decision

Deterministic weighted sum, weights in versioned YAML config, exponential
freshness decay, separate `threat_score` and `confidence`, and a mandatory
per-component `reason[]` breakdown in every answer. Full spec:
[scoring.md](../scoring.md). No ML in the verdict path.

## Rationale

- Mirrors the family doctrine: Azazel-Edge's arbiter is deterministic and
  auditable; its enrichment source must meet the same bar or it poisons the
  audit story ("the decision was deterministic but based on an unexplainable
  score" does not survive scrutiny at an Arsenal booth or in a postmortem).
- Config-as-data makes site tuning reviewable in git, and makes scoring
  reproducible: same DB + same config + same event = same answer, always.

## Consequences

- Scoring quality improves through better config and better data (reactions,
  patterns), not through model training — a deliberate research constraint.
- Contract tests enforce breakdown completeness and weight-sum validation.
