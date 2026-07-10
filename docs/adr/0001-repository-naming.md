# ADR-0001: Repository naming and family positioning

Status: **Accepted (2026-07-10)** — formal name `Azazel-Knowledge Advisor`, AZ-04,
repository `01rabbit/Azazel-Knowledge` (formerly `Azazel-CTI`). See the
**Resolution** section for the ratified decision; the original deferral context
and decision below are preserved as history.

## Context

The Azazel naming spec (`Azazel/docs/specs/naming.md`) mandates
`Azazel-<Form> <Role>` and explicitly forbids new Form/Role words without
updating the spec first. Current vocabulary:

- Form: `Gadget`, `Edge`, `Boot` — all describe *defense device* classes.
- Role: `Gateway`, `Shield`, `Probe`.

A CTI node fits none of these: it is not in the traffic path, defends
nothing, and is a rear-echelon knowledge service.

AZ-xx designations already assigned: **AZ-01 = Azazel-Edge, AZ-02 =
Azazel-Gadget, AZ-03 = Azazel-Boot.** This node would take the next free
number when formally named.

The physical form is a portable Raspberry Pi 4 — man-packable like the rest
of the family, which may inform the eventual Form word.

## Decision

Naming is **deliberately deferred**. Design and Phase 1 implementation
proceed under the working name `Azazel-CTI`.

Before first public release:

1. Choose the formal `Azazel-<Form> <Role>` name (new Form and/or Role word
   likely required — e.g. a rear/knowledge-tier Form, or a Role such as
   `Oracle`/`Intel`; `Probe`'s "observation focused, minimal control" is the
   closest existing Role in spirit).
2. Update the naming spec and product map in `01rabbit/Azazel`, and take the
   next AZ-xx number.

## Consequences

- Renaming a GitHub repo later is cheap (redirects preserved); the doctrine
  vocabulary decision is the real task and belongs in the Azazel repo.
- Until then, external-facing text must present `Azazel-CTI` as a working
  name.

## Resolution (2026-07-10)

The owner ratified the formal naming on 2026-07-10, superseding the deferral above.

- **Formal series name:** `Azazel-Knowledge Advisor`, series number **AZ-04**.
- **Short name (prose):** `Azazel-Knowledge` — with the `Advisor` Role suffix
  used in formal/external contexts, mirroring `Edge`/`Gadget`.
- **Repository:** `01rabbit/Azazel-CTI` → `01rabbit/Azazel-Knowledge` (old URLs
  redirect); Python import namespace is `azazel_knowledge`.
- **Rationale:** `Knowledge` is the class that accumulates and correlates IOC,
  ATT&CK, attacker reactions, and behavioral patterns — the series' Threat
  Knowledge Plane; `Advisor` returns evidence, confidence, history, and
  recommendations, never commands, and final authority stays with Azazel-Edge's
  deterministic arbiter. Likewise this node's generated Suricata/Sigma rules are
  drafts that it never deploys (ADR-0007). The advisory-only doctrine is
  unchanged.
- **Alternatives considered and superseded before merge:** Azazel-Grimoire
  Advisor, Azazel-Keep Oracle. `Grimoire` was retained as this product's
  development codename (changelogs, release names, milestones — never formal
  external naming).
- **AZ-xx meaning:** accession order (series order), no longer appliance-only —
  which is what frees a rear-echelon knowledge node to take a number.
- **Sibling rename (same sweep):** `Azazel-Common` → `Azazel-Fabric` (AZ-05),
  import namespace `azazel_common` → `azazel_fabric` from its v0.3.0. This
  repository does not depend on it; references in docs are updated accordingly.

Full series after this decision: Azazel (umbrella), AZ-01 Azazel-Edge, AZ-02
Azazel-Gadget, AZ-03 Azazel-Boot (reserved), AZ-04 Azazel-Knowledge (this repo,
formerly Azazel-CTI), AZ-05 Azazel-Fabric (formerly Azazel-Common).
