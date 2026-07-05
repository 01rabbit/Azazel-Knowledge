# ADR-0001: Repository naming and family positioning

Status: **open — needs owner decision + naming spec update**

## Context

The Azazel naming spec (`Azazel/docs/specs/naming.md`) mandates
`Azazel-<Form> <Role>` and explicitly forbids new Form/Role words without
updating the spec first. Current vocabulary:

- Form: `Gadget`, `Edge`, `Boot` — all describe *defense device* classes.
- Role: `Gateway`, `Shield`, `Probe`.

A CTI node fits none of these: it is not in the traffic path, defends
nothing, and is a rear-echelon knowledge service. Azazel-Edge is designated
AZ-01; this node is the natural AZ-02.

## Options

1. New Form word for rear/knowledge-tier devices, e.g. `Azazel-Keep`
   (castle keep — rear stronghold, fits the delaying-action doctrine) with
   Role `Oracle` or `Intel`.
2. `Azazel-CTI` — plain, descriptive, breaks the Form/Role scheme but is
   instantly legible at a conference booth.
3. Reuse `Probe` role semantics ("observation and measurement focused, minimal
   control") under a new Form — closest existing Role in spirit.

## Decision (interim)

Use **Azazel-CTI** as the working repository name so design work is not
blocked. Before first public release: pick the formal name, update the
naming spec in `01rabbit/Azazel`, and add this node to the doctrine repo's
product map and AZ-xx numbering.

## Consequences

- Renaming a GitHub repo later is cheap (redirects preserved); deciding the
  doctrine vocabulary is the real task and belongs in the Azazel repo.
