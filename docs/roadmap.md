# Roadmap

## Phase 1 — one Edge, one CTI node (first milestone)

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

- Multi-edge ingest (`edge_id` becomes meaningful), cross-edge correlation:
  same actor seen at two Edges is itself intelligence.
- Pattern Generator goes live: reactions + observations compiled into
  Tactical Pattern Memory; patterns exported to Edges as advisory context.
- Evaluate SQLite → PostgreSQL against measured write load (ADR-0003 exit
  criteria).

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
| Can delaying defense produce reusable CTI observations? | `reaction` store + Phase 2 pattern generation |
| What evidence schema is needed for attacker-reaction tracking? | [data-model.md](data-model.md#reaction--the-tactical-cti-sensor-core-azazel-edge-283) |
| Which parts belong in Azazel-Edge vs. external tooling? | Plane separation: Edge keeps decision, CTI node keeps knowledge |
| Is Agentic Edge SOC/NOC a useful framing? | Out of scope here; this repo stays deterministic-advisory |

## Standing constraints (all phases)

- Advisory-only contract is permanent, not a Phase 1 simplification.
- Pi 4-class resource budget holds through Phase 3; scale problems are
  solved by tiering (Phase 4), not by fattening the node.
- LLM use, if introduced, is limited to explanation/report generation and
  is marked in output; verdicts stay deterministic.
