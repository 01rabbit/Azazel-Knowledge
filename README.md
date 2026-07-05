# Azazel-CTI — On-Premises Tactical CTI Node for the Azazel System

> **Working name.** The formal name and AZ-xx designation are deliberately
> deferred (AZ-01 = Azazel-Edge, AZ-02 = Azazel-Gadget, AZ-03 = Azazel-Boot
> are already assigned). See [ADR-0001](docs/adr/0001-repository-naming.md).

**Status: design phase. No implementation yet.**

Azazel-CTI is an independent, on-premises Cyber Threat Intelligence node built
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
  (throttle, redirect, isolate) become structured intelligence.

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
      │  Azazel-CTI (working name)   │   Intelligence / Correlation /
      │  Threat Knowledge Plane      │   Campaign analysis / IOC management
      └──────────────────────────────┘
               ▲            │
   Evidence    │            │  Threat context (advisory)
   (EVE, DNS,  │            │  confidence / reason / ATT&CK /
   JA3/JA4,    │            │  recommended action + alternatives
   flows,      │            ▼
   delay hist) │
      ┌──────────────────────────────┐
      │  Raspberry Pi 5              │
      │  Azazel-Edge (AZ-01)         │   Detection / Delay / Deception /
      │  Decision Plane              │   Local decision / Local logging
      └──────────────────────────────┘
                     │
              Protected network
```

## Relationship to Azazel-Edge roadmap

This repository is the concrete home for the post-2026 research items tracked
in [Azazel-Edge #283](https://github.com/01rabbit/Azazel-Edge/issues/283):

| #283 research item | Where it lands here |
|---|---|
| Tactical CTI Sensor extension | Attacker-reaction observation schema ([data model](docs/data-model.md)) |
| Tactical Pattern Memory | Pattern generator + pattern store ([architecture](docs/architecture.md)) |
| Richer correlation / knowledge model | Correlation engine, historical observation DB |
| External SOC/SIEM integration | STIX 2.1 / TAXII 2.1 boundary (already prototyped in Azazel-Edge) |

Research framing: **"How does CTI optimize delaying defense?"** — not
"a lightweight CTI platform." See [ADR-0008](docs/adr/0008-research-theme.md).

## Documentation

- [Architecture](docs/architecture.md) — planes, components, data flows, failure modes
- [Data model](docs/data-model.md) — IOC, ATT&CK, campaign, observation, pattern stores
- [API](docs/api.md) — Edge-facing REST contract and query discipline
- [Sync and offline operation](docs/sync-offline.md) — feed adapters, signed offline bundles
- [Scoring](docs/scoring.md) — deterministic, explainable confidence calculation
- [Roadmap](docs/roadmap.md) — Phase 1–4, BHUSA research direction
- [Decision records](docs/adr/) — resolved design questions with rationale

## Non-goals

- Not a defense device: no packet forwarding, no blocking, no enforcement.
- Not an autonomous analyst: LLM use (if any) is limited to explanation and
  report generation, never verdicts.
- Not a cloud TIP replacement: single-site, constrained-hardware, offline-first.
- Not authoritative over Azazel-Edge: advisory output only, by contract.

## Target hardware

Raspberry Pi 4 (8 GB RAM), SSD boot, Gigabit Ethernet, Docker Compose,
optional UPS. Sized so the full IOC store and correlation workload fit a
single SBC; see [architecture](docs/architecture.md#resource-budget).
