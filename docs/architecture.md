# Architecture

Azazel-Knowledge (formerly Azazel-CTI) is the **Threat Knowledge Plane** of the Azazel system. It sits
beside — never inside — the Azazel-Edge decision loop.

## Plane separation

| Plane | Device | Responsibility | Authority |
|---|---|---|---|
| Evidence Plane | Azazel-Edge (Pi 5) | Collect Suricata EVE, DNS, HTTP metadata, JA3/JA4, flows, canary hits, delay history | — |
| Decision Plane | Azazel-Edge (Pi 5) | Deterministic evaluators + Action Arbiter select bounded actions | **Final** |
| Knowledge Plane | Azazel-Knowledge (Pi 4) | IOC management, correlation, campaign analysis, pattern memory, feed ingestion | Advisory only |

The Knowledge Plane enriches evidence and explains context. It never selects,
schedules, or vetoes an action.

[Azazel-Fabric](https://github.com/01rabbit/Azazel-Fabric) (AZ-05, formerly
Azazel-Common) is the Azazel series' shared contracts library (`azazel_fabric`
from its v0.3.0, pydantic v2 as its sole dependency). Its `cti_contracts` module
independently defines request and response shapes for a boundary matching this
repo's `/v1/context` above, and encodes the same advisory-only invariant at the
type level. As of [ADR-0010](adr/0010-adopt-fabric-cti-contracts.md) (ratified
2026-07-10) this repository **adopts** `azazel_fabric.cti_contracts` at
the API boundary, tag-pinned as an `api`-extra-only dependency; the pin in
force is the published pre-release `v0.10.0rc1`
([ADR-0022](adr/0022-fabric-pin-v0-10-0rc1.md), carried in
`pyproject.toml`). The adoption is
additive and the documented wire shapes are unchanged: ingest can now be
type-enforced against the canonical `Cti<Kind>Batch` envelope, and every
`/v1/context` response is checked against Fabric's `BANNED_DIRECTIVE_FIELDS`
before it is emitted. `azazel_fabric` is imported only under
`azazel_knowledge.api`/`taxii` — never in `scoring/`, `correlate/`, or
`core/`, whose dependency set is unchanged (Absolute Constraint 7). What was
"aspirational until ratified by an ADR" is now ratified.

## Aegis-like framing (Phase 2, doctrine unchanged)

Architecture subtitle for Phase 2: *Azazel: Aegis-like cyber defense through
tactical delay, deception, and behavioral CTI.* This is an **explanatory
analogy only** — observe → track → classify → advise — never a product
rename (the brand stays **Azazel**, per ADR-0001) and never an interception
claim. Aegis is interception-centric and physical; Azazel is delay-centric,
deception-aware, CTI-driven, and cyber (issue #29). The analogy names a
posture, not a mechanism swap.

Phase 2 introduces **Behavioral CTI**: reaction records are compiled into
evidence-backed behavior patterns, compared for similarity and
repeatability, and surfaced to Azazel-Edge as advisory context. It stays
entirely inside the Knowledge Plane defined above: it enriches evidence,
generates rebuildable behavior patterns, and *suggests* posture — it never
selects, schedules, or vetoes an action. The deterministic Edge arbiter
remains final. Behavioral CTI never enters the Edge hot decision loop; on the
query path it is a single indexed point-read, and its absence never blocks
or errors an answer (same fail-open discipline as the rest of this plane).

**Non-attribution doctrine:** Azazel does not claim to identify AI usage
directly. It characterizes AI-enabled, adaptive, and automation-like
behavior patterns — never a proof of AI involvement or an attribution to a
specific actor or model.

Full Phase 2 design: [phase2-implementation.md](design/phase2-implementation.md)
and [ADR-0009](adr/0009-behavioral-cti.md).

## Components (single Pi 4, Docker Compose)

```
┌─ Azazel-Knowledge ────────────────────────────────────────────────┐
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
│  │ SQLite (WAL)  — intel.db: IOC / ATT&CK / campaign;  │    │
│  │ local.db: observations / reactions / reputation /   │    │
│  │ patterns / behavior patterns + similarity / feeds   │    │
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
- **Behavioral CTI generator (Phase 2)** — a P2 worker pass compiles immutable
  `reaction` rows into rebuildable `behavior_pattern` rows, classifies them
  deterministically, precomputes similarity/repeatability, and swaps the
  `behavior_generation` atomically. Exposed offline via `azctl behavior
  generate|rebuild|dry-run`; surfaced read-only via
  `GET /v1/behavior-patterns/*` and `/v1/reports/friction-timeline`. A
  research-only, default-off **shadow scoring** hook writes potential
  reaction-informed adjustments to a JSONL research log only — never to the
  production `threat_score`, `/v1/context` response, or `reason[]`.
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
rejected_alternatives[], source_freshness,
threat_context.behavioral_cti  (Phase 2, additive/optional):
  behavior_class, similarity, repeatability_score, suggested_posture,
  evidence_refs, limitations[]  — omitted entirely when no pattern matches
```

All advisory. Edge treats the response as one more piece of evidence for its
deterministic evaluators. The behavioral block is a best-effort, single indexed
point-read under a sub-deadline: its absence is never an error, and its
`suggested_posture` is a suggestion, never an action command.

### 3. Feed update (Internet → CTI, optional)

Scheduled pulls when a link exists; nothing in the query path depends on it.

### 4. Offline bundle (courier → CTI)

Signed snapshot/differential bundles imported from removable media or LAN.

### 5. Knowledge Lite (CTI → Nexus / Boot, offline)

A **Knowledge Lite** artifact is a bounded capacity profile of that same signed
bundle — always full, never differential — built for Azazel-Nexus and
Azazel-Boot, which embed a read-only cache of it. Selection is deterministic
from a pinned tuple, capacity ceilings fail closed rather than truncate, and
export is deny-by-default. Knowledge produces and signs it; the consumer owns
trust and caching, and stays fully operational without it. Contract:
[ADR-0015](adr/0015-knowledge-lite-bundle.md) and
[ADR-0017](adr/0017-lite-is-full-only.md); operator view:
[sync-offline.md](sync-offline.md#knowledge-lite--a-bounded-profile-of-the-same-bundle).

## Failure model — Edge must not care

- **CTI node down / unreachable:** Edge query times out (default budget
  250 ms, configurable) and proceeds on local logic. No retry in the hot path.
- **CTI node stale:** every answer carries `source_freshness`; Edge and
  operators can discount old intelligence. Staleness never blocks answers.
- **CTI node wrong:** advisory-only contract means a bad answer can worsen
  enrichment, never force an action.
- **Edge absent:** CTI node keeps ingesting feeds and serving operators
  directly (reports, campaign views).

> **External corroboration (2026-11).** This advisory-only, auditable failure
> model is what the wider field is converging on, not a local peculiarity.
> MITRE ATT&CK v20 (2026-10-13) now catalogs Direct and Indirect Prompt
> Injection (T1699 / T1698) as adversary techniques — keeping final authority in
> a deterministic arbiter that cannot be steered by model-facing prompts, and
> confining the LLM to explanation, is a direct answer to that attack surface.
> The academic TRACE-CTI work names the gap this node closes by design: there
> was "no explicit, auditable boundary between what a model predicted and what
> the system is prepared to trust." CISA BOD 26-04 requires forensic-ready
> triage for the highest-risk tier, which our byte-identical replay, complete
> `reason[]`, and JSONL audit chain already provide. See
> [`docs/reports/ai-landscape-2026-11.md`](reports/ai-landscape-2026-11.md) §3
> for sources. This is corroboration of the existing design, not a change to it.

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
