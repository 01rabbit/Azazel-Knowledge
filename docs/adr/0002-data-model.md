# ADR-0002: Native lightweight data model; STIX 2.1 at the boundary only

Status: accepted (design phase)

## Context

Options were (a) adopt STIX 2.1 as the internal model, or (b) a lightweight
Azazel-native model with STIX as interchange. The node must answer IOC
lookups in < 50 ms p95 on a Pi 4 and hold ~10 M indicators.

## Decision

Native relational model ([data-model.md](../data-model.md)) for storage and
query. STIX 2.1 is used **only** at boundaries: feed import, TAXII inbox
from Edge (which already ships a STIX exporter and TAXII push client —
Azazel-Edge #238/#248), and export to upstream tiers.

## Rationale

- STIX-as-storage means JSON graph traversal on every lookup — wrong shape
  for a latency budget on SBC hardware.
- Azazel-specific data (delay history, attacker reactions, pattern memory)
  has no clean STIX home; forcing it in costs more than a mapping table.
- Keeping STIX at the boundary preserves full interoperability, including
  the custom `x-azazel-reaction` extension for reaction sharing.

## Consequences

- A mapping layer must be maintained (see data-model.md §STIX mapping).
- Interop claims are tested at the boundary: round-trip tests
  (STIX in → native → STIX out) are part of the contract suite.
