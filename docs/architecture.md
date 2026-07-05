# Architecture

Azazel-CTI is the **Threat Knowledge Plane** of the Azazel system. It sits
beside — never inside — the Azazel-Edge decision loop.

## Plane separation

| Plane | Device | Responsibility | Authority |
|---|---|---|---|
| Evidence Plane | Azazel-Edge (Pi 5) | Collect Suricata EVE, DNS, HTTP metadata, JA3/JA4, flows, canary hits, delay history | — |
| Decision Plane | Azazel-Edge (Pi 5) | Deterministic evaluators + Action Arbiter select bounded actions | **Final** |
| Knowledge Plane | Azazel-CTI (Pi 4) | IOC management, correlation, campaign analysis, pattern memory, feed ingestion | Advisory only |

The Knowledge Plane enriches evidence and explains context. It never selects,
schedules, or vetoes an action.

## Components (single Pi 4, Docker Compose)

```
┌─ Azazel-CTI ────────────────────────────────────────────────┐
│                                                             │
│  ┌──────────────┐   ┌──────────────────┐   ┌─────────────┐  │
│  │ REST API     │   │ Correlation      │   │ Pattern     │  │
│  │ (FastAPI)    │──▶│ Engine           │──▶│ Generator   │  │
│  │ Edge-facing  │   │ IOC/hist/ATT&CK/ │   │ (Tactical   │  │
│  └──────────────┘   │ campaign match   │   │  Pattern    │  │
│         │           └──────────────────┘   │  Memory)    │  │
│         │                    │             └─────────────┘  │
│         ▼                    ▼                    │         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ SQLite (WAL)  — IOC / ATT&CK / campaign /           │    │
│  │ observations / reputation / patterns / feed state   │    │
│  └─────────────────────────────────────────────────────┘    │
│         ▲                                    ▲              │
│  ┌──────────────┐                    ┌──────────────────┐   │
│  │ Feed         │  online pull       │ Bundle Importer  │   │
│  │ Importer     │◀── (optional) ──   │ (USB/SSD/LAN,    │   │
│  │ (background  │                    │  signed bundles) │   │
│  │  worker)     │                    └──────────────────┘   │
│  └──────────────┘                                           │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ TAXII 2.1 endpoints — inbox (Edge push) + collections│   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ JSON logger — all queries, answers, imports (JSONL)  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

- **REST API** — Edge-facing query/context endpoints ([api.md](api.md)).
- **Correlation Engine** — deterministic pipeline:
  `normalize → IOC match → historical match → ATT&CK mapping → campaign
  match → confidence calculation → recommendation`. Every stage emits its
  contribution to the final reason breakdown ([scoring.md](scoring.md)).
- **Pattern Generator** — compiles CTI + local observations into lightweight
  tactical patterns (Tactical Pattern Memory, per Azazel-Edge #283). Patterns
  accelerate matching and enrich explanations; they never replace evaluators.
- **Feed Importer** — per-feed adapters, online only, rate-limited,
  checkpointed ([sync-offline.md](sync-offline.md)).
- **Bundle Importer** — offline update path; verifies signed bundles from
  USB/SSD/LAN.
- **TAXII 2.1 endpoints** — reuse the boundary already prototyped in
  Azazel-Edge (#238 STIX exporter + TAXII read API, #248 TAXII push client):
  the Edge push client can POST decision/audit bundles into the CTI node's
  inbox unchanged. STIX/TAXII is the *interchange* format only (ADR-0002).

## Data flows

### 1. Evidence in (Edge → CTI)

Edge sends — asynchronously, fire-and-forget — Suricata EVE, DNS queries,
HTTP metadata, JA3/JA4, flow records, alerts, canary hits, and **delay
history** (what friction was applied and how the actor reacted). Transport:
REST JSONL batches; STIX bundles via TAXII push are also accepted.

### 2. Context out (CTI → Edge)

On selective triggers only (critical alert, unknown IOC/JA3/JA4, first
contact, high local score) Edge queries the CTI node and receives:

```
ioc_match, confidence, campaign, attack_mapping (MITRE ATT&CK),
threat_score, reason[] (component breakdown),
recommended_rule, recommended_delay, recommended_decoy,
rejected_alternatives[], source_freshness
```

All advisory. Edge treats the response as one more piece of evidence for its
deterministic evaluators.

### 3. Feed update (Internet → CTI, optional)

Scheduled pulls when a link exists; nothing in the query path depends on it.

### 4. Offline bundle (courier → CTI)

Signed snapshot/differential bundles imported from removable media or LAN.

## Failure model — Edge must not care

- **CTI node down / unreachable:** Edge query times out (default budget
  250 ms, configurable) and proceeds on local logic. No retry in the hot path.
- **CTI node stale:** every answer carries `source_freshness`; Edge and
  operators can discount old intelligence. Staleness never blocks answers.
- **CTI node wrong:** advisory-only contract means a bad answer can worsen
  enrichment, never force an action.
- **Edge absent:** CTI node keeps ingesting feeds and serving operators
  directly (reports, campaign views).

## Security boundary

- Edge ↔ CTI on a dedicated management segment; bearer-token auth minimum,
  mTLS optional.
- CTI node initiates outbound connections only for feed pulls; never accepts
  inbound from the protected network.
- Offline bundles are signed; the importer rejects unsigned or
  version-regressing bundles.
- All queries and answers logged as JSONL for the same auditability standard
  as Azazel-Edge decisions.

## Resource budget

Raspberry Pi 4, 8 GB RAM, SSD boot:

| Item | Budget |
|---|---|
| IOC lookup latency (LAN, p95) | < 50 ms |
| Full context query (LAN, p95) | < 250 ms |
| Resident memory, API + workers | < 2 GB |
| IOC store | ~10 M indicators in SQLite with indexes |
| Feed import | background, nice/ionice, never blocks queries |

These budgets are design constraints, not aspirations: features that break
them belong in Phase 2+ hardware, not in this node.
