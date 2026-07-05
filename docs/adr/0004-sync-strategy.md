# ADR-0004: Sync = scheduled pull online + signed offline bundles; both first-class

Status: accepted (design phase)

## Context

Feed data must reach the node online (opportunistic connectivity) and fully
offline (air-gapped field sites). Candidates: pull, push, USB offline
update, differential sync — in some combination.

## Decision

Two first-class paths, one format:

1. **Online**: scheduled per-feed pull adapters, checkpointed and resumable.
   No inbound push from the internet, ever.
2. **Offline**: signed bundle (full snapshot or differential against a stated
   base version) imported from USB/SSD/LAN — see
   [sync-offline.md](../sync-offline.md).

Differential sync exists only inside the bundle format (deltas with base
version checks), not as a bespoke network protocol.

## Rationale

- Pull-only online keeps the attack surface at zero listeners on the WAN
  side.
- Making the offline bundle the canonical distribution artifact means the
  air-gapped path is tested constantly, not a degraded afterthought — and
  the same artifact later serves Phase 4 regional distribution.
- Signature + monotonic version checks give tamper and rollback resistance
  matching the node's role as a trust anchor for Edge enrichment.

## Consequences

- A bundle builder tool is part of Phase 1 scope.
- Feed adapters must write through a staging area so a failed pull can never
  half-update live tables.
