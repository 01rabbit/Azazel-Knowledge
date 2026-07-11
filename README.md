# AZ-04 Azazel-Knowledge - On-Premises Tactical Threat Knowledge Advisor

> **Codename:** `GRIMOIRE`

![Azazel-Knowledge Banner](images/Azazel-Knowledge_Banner.svg)

> **Formerly Azazel-CTI.** The formal series name is **Azazel-Knowledge Advisor**
> (**AZ-04**), ratified 2026-07-10; the `Advisor` Role suffix is used in
> formal/external contexts. The repository was renamed
> `01rabbit/Azazel-CTI` → `01rabbit/Azazel-Knowledge` (old URLs redirect).
> The codename `GRIMOIRE` follows the series convention (Edge: `SENTINEL`,
> Gadget: `TACMOD`): the accumulated book of threats — a grimoire never casts
> its own spells. Codenames are for changelogs and release names, never formal
> external naming.
> `Knowledge` is the class that accumulates and correlates IOC, ATT&CK, attacker
> reactions, and behavioral patterns — the series' Threat Knowledge Plane;
> `Advisor` returns evidence, confidence, history, and recommendations, never
> commands, and final authority stays with Azazel-Edge's deterministic arbiter.
> Likewise this node's generated Suricata/Sigma rules are drafts it never
> deploys. See [ADR-0001](docs/adr/0001-repository-naming.md).

**Status: implemented and under active development.** Phase 1 (the full node —
ingest, IOC/JA3/JA4 search, deterministic `/v1/context`, reaction recording,
offline bundles, TAXII) and the Phase 2 **Behavioral CTI** lane
([design](docs/design/phase2-implementation.md)) are merged on `main`. The unit
suite is the baseline gate (currently 583 tests); the advisory-only,
determinism, and offline-first contracts below are enforced by static and
replay tests, not just convention.

Azazel-Knowledge is an independent, on-premises Cyber Threat Intelligence node built
on a portable Raspberry Pi 4. It pairs with
[Azazel-Edge](https://github.com/01rabbit/Azazel-Edge) (AZ-01) but is
deliberately a separate device and a separate repository.

The CTI node does **not** defend anything. It is a *device that understands
threats* — a Threat Knowledge Plane for the Azazel family:

- Operates fully on-premises; internet access is optional, used only to
  refresh threat feeds (MITRE ATT&CK, CVE/NVD, CISA KEV, abuse feeds, ...).
- Operates fully offline in the field; feeds can be updated via USB/SSD/LAN
  bundle transfer.
- Improves Azazel-Edge decision quality without degrading its real-time path.
- Turns delaying defense into a CTI sensor: attacker reactions under friction
  (throttle, redirect, isolate, deception) become structured intelligence.
- **Behavioral CTI (Phase 2):** compiles those reactions into evidence-backed
  behavior patterns, scores their similarity and repeatability, and returns
  them to Edge as *advisory* behavioral context — never a command, never a
  claim of AI attribution.

## The one rule that shapes everything

**The CTI node never commands.** It returns *threat context, confidence,
reasons, and recommendations* — advisory data only. Final authority always
stays with the Azazel-Edge Deterministic Arbiter. Azazel-Edge must remain
fully functional when the CTI node is absent, slow, or wrong.

## System overview

```
              Internet (optional)
                     │
             Threat feed update            offline: USB / SSD / LAN bundle
                     │
      ┌──────────────────────────────┐
      │  Raspberry Pi 4              │
      │  Azazel-Knowledge (AZ-04)     │   Intelligence / Correlation /
      │  Threat Knowledge Plane      │   Campaign analysis / IOC management /
      │                              │   Behavioral CTI (patterns, similarity)
      └──────────────────────────────┘
               ▲            │
   Evidence    │            │  Threat context (advisory)
   (EVE, DNS,  │            │  confidence / reason / ATT&CK /
   JA3/JA4,    │            │  recommended action + alternatives /
   flows,      │            │  behavioral_cti (seen-before, posture suggestion)
   delay hist, │            ▼
   reactions)  │
      ┌──────────────────────────────┐
      │  Raspberry Pi 5              │
      │  Azazel-Edge (AZ-01)         │   Detection / Delay / Deception /
      │  Decision Plane              │   Local decision / Local logging
      └──────────────────────────────┘
                     │
              Protected network
```

## Behavioral CTI (Phase 2)

Behavioral CTI is a **separate, additive lane** beside the Phase 1 scoring
envelope — it never touches the frozen `threat_score` / `reason[]` / replay
contract ([design](docs/design/phase2-implementation.md),
[ADR-0009](docs/adr/0009-behavioral-cti.md)):

- **Patterns** — immutable `reaction` rows (+ linked observations) are compiled
  deterministically into rebuildable `behavior_pattern` rows in `local.db`,
  every one traceable to raw evidence. Regeneration is atomic via a
  `behavior_generation` swap.
- **Classification** — config-versioned mapping into six behavior classes
  (`simple_scanner`, `scripted_automation`, `adaptive_probe`, `decoy_engaged`,
  `disengaged_after_friction`, `unknown`). Never an attribution label.
- **Similarity & repeatability** — deterministic, explainable, precomputed
  offline (no ML, no query-time computation).
- **Advisory** — `/v1/context` gains an optional, best-effort
  `threat_context.behavioral_cti` block (a *posture suggestion*, never a
  command); its absence never blocks or errors an answer.
- **Operator surfaces** — `GET /v1/behavior-patterns/*` and
  `/v1/reports/friction-timeline` plus `azctl behavior report` render the
  observe → track → classify → advise narrative.
- **Shadow scoring** — research-only, default-off, shadow-only hooks whose
  `shadow_score_delta` never reaches `threat_score`, the `/v1/context`
  response, or `reason[]`; output goes to a JSONL research log alone.

**Non-attribution doctrine:** Behavioral CTI characterizes adaptive or
automation-like behavior. It does not prove that an attacker used AI.

## Relationship to Azazel-Edge roadmap

This repository is the concrete home for the post-2026 research items tracked
in [Azazel-Edge #283](https://github.com/01rabbit/Azazel-Edge/issues/283):

| #283 research item | Where it lands here |
|---|---|
| Tactical CTI Sensor extension | Attacker-reaction store ([data model](docs/data-model.md)); Edge payload contract [Azazel-Edge#305](https://github.com/01rabbit/Azazel-Edge/issues/305) |
| Tactical Pattern Memory | Pattern store + deterministic Behavioral CTI generator ([architecture](docs/architecture.md), [Phase 2 design](docs/design/phase2-implementation.md)) |
| Richer correlation / knowledge model | Correlation engine, historical observation DB, behavioral similarity |
| External SOC/SIEM integration | STIX 2.1 / TAXII 2.1 boundary (already prototyped in Azazel-Edge) |

Research framing: **"How does CTI optimize delaying defense?"** — not
"a lightweight CTI platform." See [ADR-0008](docs/adr/0008-research-theme.md).

## Azazel series context

Azazel-Knowledge (**AZ-04**, codename `GRIMOIRE`; formerly Azazel-CTI — formal
series name **Azazel-Knowledge Advisor**, ratified in
[ADR-0001](docs/adr/0001-repository-naming.md)) is one product of the
**Azazel** series ("Cyber Scapegoat Gateway"). The series map, AZ
designations, and naming specification live in the umbrella repository:
[01rabbit/Azazel](https://github.com/01rabbit/Azazel).

Knowledge-local integration note: this repository adopts
[`azazel_fabric.cti_contracts`](https://github.com/01rabbit/Azazel-Fabric)
v0.3.0 at its API boundary
([ADR-0010](docs/adr/0010-adopt-fabric-cti-contracts.md)) — ingest can be
type-enforced against the canonical `Cti<Kind>Batch` envelope, and every
`/v1/context` response is checked against Fabric's directive-field validator
before it is emitted (fail-closed). The adoption is additive, wire shapes are
unchanged, and **there is still no core dependency**: Fabric is imported only
under `azazel_knowledge.api`; the core dependency set (stdlib + PyYAML + idna
+ PyNaCl) is untouched, per this repo's dependency-minimality constraint.

## Documentation

- [Architecture](docs/architecture.md) — planes, components, data flows, failure modes
- [Data model](docs/data-model.md) — IOC, ATT&CK, campaign, observation, pattern, behavioral stores
- [API](docs/api.md) — Edge-facing REST contract, behavioral advisory, query discipline
- [Scoring](docs/scoring.md) — deterministic, explainable confidence; shadow reaction-informed scoring
- [Sync and offline operation](docs/sync-offline.md) — feed adapters, signed offline bundles
- [Operations](docs/operations.md) — provisioning, feeds, connecting an Edge, behavioral generation
- [Roadmap](docs/roadmap.md) — scaling phases and the CTI-optimized-delay research loop
- [Development guide](docs/development-guide.md) — the commander/adversarial-reviewer + Codex delegation loop
- [Design records](docs/design/) — Phase 1 and Phase 2 implementation designs
- [Decision records](docs/adr/) — resolved design questions with rationale
- [Contributing](CONTRIBUTING.md) — branch/commit conventions, PR gate, delegation rules
- [Security policy](SECURITY.md) — vulnerability reporting and scope

## Non-goals

- Not a defense device: no packet forwarding, no blocking, no enforcement.
- Not an autonomous analyst: LLM use (if any) is limited to explanation and
  report generation, never verdicts.
- Not a cloud TIP replacement: single-site, constrained-hardware, offline-first.
- Not authoritative over Azazel-Edge: advisory output only, by contract.
- Not an AI-attribution engine: it names adaptive/automation-like behavior,
  never a proof of AI usage.

## Target hardware

Raspberry Pi 4 (8 GB RAM), SSD boot, Gigabit Ethernet, Docker Compose,
optional UPS. Sized so the full IOC store and correlation workload fit a
single SBC; see [architecture](docs/architecture.md#resource-budget).
