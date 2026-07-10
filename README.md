# Azazel-Grimoire — On-Premises Tactical CTI Node for the Azazel System

> **Formerly Azazel-CTI.** The formal series name is **Azazel-Grimoire Advisor**
> (**AZ-04**), ratified 2026-07-10; the `Advisor` Role suffix is used in
> formal/external contexts. The repository was renamed
> `01rabbit/Azazel-CTI` → `01rabbit/Azazel-Grimoire` (old URLs redirect). A
> grimoire never casts its own spells — the reader (Azazel-Edge's deterministic
> arbiter) decides; likewise this node's generated Suricata/Sigma rules are
> drafts it never deploys. See [ADR-0001](docs/adr/0001-repository-naming.md).

**Status: implemented and under active development.** Phase 1 (the full node —
ingest, IOC/JA3/JA4 search, deterministic `/v1/context`, reaction recording,
offline bundles, TAXII) and the Phase 2 **Behavioral CTI** lane
([design](docs/design/phase2-implementation.md)) are merged on `main`. The unit
suite is the baseline gate (currently 583 tests); the advisory-only,
determinism, and offline-first contracts below are enforced by static and
replay tests, not just convention.

Azazel-Grimoire is an independent, on-premises Cyber Threat Intelligence node built
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
      │  Azazel-Grimoire (AZ-04)     │   Intelligence / Correlation /
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

The Azazel family, as currently assigned:

- **[Azazel](https://01rabbit.github.io/Azazel/)** — the umbrella doctrine
  hub and GitHub Pages site (Apache-2.0).
- **Azazel-Edge (AZ-01)** — resident edge-class gateway (Pi 5), MIT. Pairs
  with this repo as described above.
- **Azazel-Gadget (AZ-02)** — USB-gadget-class portable device, MIT. No CTI
  integration is planned.
- **Azazel-Boot (AZ-03)** — reserved; no repository yet.
- **Azazel-Grimoire (AZ-04)** (this repository, formerly Azazel-CTI) — formal
  series name `Azazel-Grimoire Advisor`; see
  [ADR-0001](docs/adr/0001-repository-naming.md) above. AZ-xx now denotes series
  accession order, no longer appliance-only.
- **[Azazel-Covenant (AZ-05)](https://github.com/01rabbit/Azazel-Covenant)**
  (formerly Azazel-Common) — a shared contracts library for the series
  (distribution name `azazel-covenant`, installed via pinned git tag;
  `azazel_covenant` package from its v0.3.0, pydantic v2 as its sole
  dependency). Its `cti_contracts` module type-enforces the same advisory-only
  invariant this repo's [API contract](docs/api.md) defines — directive-shaped
  fields such as `directive`/`must_execute`/`override`/`required_action` are
  rejected by its validators — and Azazel-Gadget already consumes it. **This
  repository does not depend on Azazel-Covenant today.** Its `cti_contracts`
  shapes mirror this repo's `/v1/context` boundary but were developed
  independently; evaluating adoption is future work that would require a
  `pyproject.toml` change and a new ADR under this repo's
  dependency-minimality constraint. No commitment either way exists yet.

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
