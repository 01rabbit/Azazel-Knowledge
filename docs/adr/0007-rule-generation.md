# ADR-0007: Rule generation is advisory drafts only — never auto-deploy

Status: accepted (design phase)

## Context

How far should the node go in generating Suricata/Sigma rules from
intelligence and patterns?

## Decision

The node generates **draft** Suricata and Sigma rules from templates filled
with IOC/pattern data, exposed via `GET /v1/recommendations/rules` and in
context answers (`recommendation.rule`). Drafts carry provenance (which
IOCs/patterns/reactions produced them) and confidence. Deployment is always
an explicit human or Edge-side deterministic-policy decision; the CTI node
has no channel to install anything.

## Rationale

- Auto-deployed rules would make the node command the Edge in effect,
  violating the advisory-only contract that defines this architecture.
- A wrong rule in the traffic path is an availability incident on a device
  whose whole purpose is to keep constrained networks operating.
- Template-based generation stays deterministic and explainable; free-form
  (LLM) rule synthesis is excluded from the verdict/enforcement path
  entirely.

## Consequences

- Rule quality feedback (was the draft adopted? did it fire?) returns as
  Edge evidence, closing the loop without closing the authority gap.
