# ADR-0001: Repository naming and family positioning

Status: **deferred by owner decision (2026-07-05)** — working name `Azazel-CTI`

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
