# Roadmap

> **Two axes, don't conflate them.** This roadmap's phases are a *scaling*
> ladder (one Edge → several → site → region). The *implementation* milestones
> in [`design/`](design/) are a different axis: `phase1-implementation.md` (the
> full single-site node) and `phase2-implementation.md` (the **Behavioral CTI**
> lane — reaction→pattern→similarity→advisory→shadow). Both implementation
> milestones are **delivered on `main`**; the scaling phases below are largely
> future work layered on top.

## Phase 1 — one Edge, one CTI node (first milestone) — delivered

Scope: everything in [architecture.md](architecture.md) at single-site scale.

- SQLite store, feed importer for a starter feed set (ATT&CK, CISA KEV,
  abuse.ch trio), offline bundle import.
- Ingest endpoints + `ioc/ja3/ja4 search` + `context` with full reason
  breakdown.
- `reaction` recording from Edge delay history.
- Docker Compose deployment on Pi 4, provisioning script.

Exit criteria: Edge queries enrich real events end-to-end on LAN within the
latency budget; pulling the CTI node's power cable changes nothing about
Edge behavior except missing enrichment.

## Phase 2 — several Edges, one CTI node

The Behavioral CTI *mechanism* this phase depends on is already implemented
(see the Behavioral CTI implementation milestone,
[phase2-implementation.md](design/phase2-implementation.md)); what remains here
is the multi-edge *scale-out* around it.

- Pattern Generator is **live**: reactions + observations are compiled into
  Tactical Pattern Memory and evidence-backed behavior patterns, scored for
  similarity/repeatability, and surfaced to Edges as advisory context
  (`threat_context.behavioral_cti`). The schema already carries `edge_id` on
  every behavior pattern.
- **Remaining:** cross-edge correlation (same actor seen at two Edges is itself
  intelligence — the schema tolerates multiple `edge_id` but cross-site logic is
  not yet enabled) and multi-edge ingest scale.
- Evaluate SQLite → PostgreSQL against measured write load (ADR-0003 exit
  criteria).
- ~~Evaluate alignment/adoption of `azazel_fabric.cti_contracts`
  ([Azazel-Fabric](https://github.com/01rabbit/Azazel-Fabric), formerly Azazel-Common) for the
  Edge-facing boundary (requires an ADR + owner decision).~~ **Done** via
  [ADR-0010](adr/0010-adopt-fabric-cti-contracts.md) (2026-07-10): adopted
  tag-pinned `azazel-fabric` v0.3.0 as an `api`-extra-only dependency for
  boundary payload validation; additive, wire shapes unchanged. Edge side
  still defers its own CTI integration to FY2027+ per Azazel-Edge's adapter
  plan (`docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md` in the Azazel-Edge repo).

## Phase 3 — site-wide threat picture

```
        CTI Node
      /    |     \
  Edge1  Edge2  Edge3
```

- Operator-facing site view: campaign activity, reaction statistics,
  friction effectiveness ("which delays actually slowed which actors").
- Advisory rule drafts (Suricata/Sigma) generated from patterns, reviewed by
  humans, distributed to Edges (ADR-0007: never auto-deployed).

## Phase 4 — regional sharing

```
      Regional CTI
           │
       CTI Node
      /    |    \
  Edge   Edge   Edge
```

- STIX/TAXII export of site intelligence (reaction summaries, campaign
  sightings) to a regional tier: municipalities, disaster-response sites,
  event venues, exercise ranges.
- Offline bundle distribution doubles as the regional propagation mechanism
  for disconnected sites ([sync-offline.md](sync-offline.md)).
- Rule of the family: knowledge flows freely between tiers, authority never
  does. A regional tier supplies data; every site's Edge arbiter remains
  sovereign.

## Research direction (BHUSA 2027 candidate)

Theme per ADR-0008: **"CTI-optimized delaying defense"** — the closed loop

```
friction applied → attacker reaction observed → pattern compiled
      ▲                                              │
      └──────── better delay/decoy advice ◀──────────┘
```

This is the concrete continuation of Azazel-Edge #283's long-term questions:

| #283 long-term question | Where it is answered |
|---|---|
| Can delaying defense produce reusable CTI observations? | **Implemented:** `reaction` store → deterministic behavior-pattern generation, similarity, and the `friction-timeline` report |
| What evidence schema is needed for attacker-reaction tracking? | [data-model.md](data-model.md#reaction--the-tactical-cti-sensor-core-azazel-edge-283) + the Behavioral CTI tables; Edge payload contract [Azazel-Edge#305](https://github.com/01rabbit/Azazel-Edge/issues/305) |
| Which parts belong in Azazel-Edge vs. external tooling? | Plane separation: Edge keeps decision, CTI node keeps knowledge |
| Is Agentic Edge SOC/NOC a useful framing? | Out of scope here; this repo stays deterministic-advisory |

The closed loop is now exercisable end to end: friction applied → reaction
recorded → behavior pattern compiled → advisory posture suggested. Turning
reaction evidence back into *better* delay/decoy advice (the upper arrow) is the
open research question, with the default-off shadow-scoring hooks as its
measurement harness.

## Standing constraints (all phases)

- Advisory-only contract is permanent, not a Phase 1 simplification.
- Pi 4-class resource budget holds through Phase 3; scale problems are
  solved by tiering (Phase 4), not by fattening the node.
- LLM use, if introduced, is limited to explanation/report generation and
  is marked in output; verdicts stay deterministic.
