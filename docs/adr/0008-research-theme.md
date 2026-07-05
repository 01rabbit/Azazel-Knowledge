# ADR-0008: Research center of gravity = "CTI-optimized delaying defense"

Status: accepted (design phase)

## Context

The project could be framed as (a) a lightweight on-prem CTI node — useful
but unremarkable, many prior examples — or (b) research on the closed loop
between CTI and delaying action. Azazel-Edge #283 already poses the
questions: *can delaying defense produce reusable CTI observations, and what
schema does attacker-reaction tracking need?*

## Decision

The research center is **(b)**: the friction loop.

```
friction applied → attacker reaction observed → pattern compiled
      ▲                                              │
      └──────── better delay/decoy advice ◀──────────┘
```

The `reaction` store ([data-model.md](../data-model.md)) and
reaction-informed scoring ([scoring.md](../scoring.md)) are therefore core
schema, not extensions. The generic CTI-node function (feeds, IOC lookup,
enrichment) is the supporting infrastructure that makes the loop useful in
the field.

## Rationale

- Novelty and family fit: nobody needs another MISP-lite; "your delaying
  defense is also your intelligence sensor" is a thesis only the Azazel
  doctrine (scapegoat, friction, Go no Sen) is positioned to argue.
- It gives Phase 2–4 a measurable claim: does reaction-informed advice make
  delays and decoys measurably more effective than static config?

## Consequences

- BHUSA 2027-candidate narrative and evaluation design follow this theme
  ([roadmap.md](../roadmap.md)).
- Even Phase 1 must record reactions faithfully, because the research
  dataset starts accumulating from the first deployment.
