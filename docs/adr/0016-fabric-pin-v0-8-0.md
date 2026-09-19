# ADR-0016: Move the Azazel-Fabric api-extra pin to `v0.8.0`

Status: accepted (2026-09-19 — owner-authorized; evidence below)

## Context

This repository pinned `azazel-fabric` to `v0.3.0` in
[ADR-0010](0010-adopt-fabric-cti-contracts.md) and moved it to `v0.6.0` in
[ADR-0011](0011-deception-observation-ingest.md). Meanwhile the rest of the
series moved on:

| Repository | Observed Fabric pin |
|---|---|
| Azazel-Edge | `v0.8.0` (`requirements/fabric.txt`) |
| Azazel-Deception | `v0.8.0` (`pyproject.toml`) |
| **Azazel-Knowledge** | **`v0.6.0`** (api extra) |

The series' R0 baseline names `v0.8.0` as the reference candidate, and the R0
exit criteria require every consumer to carry an explicit immutable pin. A
series in which one consumer sits two minor versions behind the reference
candidate does not satisfy that in substance, whatever each repository's own
pin says in isolation. [ADR-0015](0015-knowledge-lite-bundle.md) recorded this
as an open question rather than settling it inside an implementation PR.

Both tags are published: `git ls-remote` returns `refs/tags/v0.6.0` and
`refs/tags/v0.8.0`.

## Decision

Move the api-extra pin from `@v0.6.0` to `@v0.8.0`.

Nothing else changes. Fabric remains an **api-extra-only** dependency, imported
solely under `azazel_knowledge/api/` and `taxii/`, never a core dependency
(Absolute Constraint 7). Core dependencies are still stdlib + PyYAML + idna +
PyNaCl. No source file changed to accommodate the move.

## Evidence

Measured on this branch, not inferred:

- `pip install -e ".[api,dev]"` resolves `azazel-fabric 0.8.0` from the tag.
- `python -m pytest tests/unit -q` → **817 passed**, the same count as under
  `v0.6.0`, with no test modified for the bump.
- Every symbol this repository imports resolves against `v0.8.0`:
  `BANNED_DIRECTIVE_FIELDS`, `CtiEventBatch`, `CtiFlowBatch`,
  `CtiReactionBatch`, `assert_advisory_only` from `cti_contracts`; and
  `EffectivenessAdvisory`, `InteractionObservation`,
  `assert_no_effectiveness_verdict`, `assert_no_runtime_directives` from
  `deception_contracts`.
- `azazel_knowledge.api.contracts` and `azazel_knowledge.taxii` both import
  cleanly.

A green suite alone would not have been sufficient: tests need not exercise
every imported name, so the symbols were checked directly rather than assumed
from the absence of failures.

The two references to `azazel_fabric` in `ingest/validators.py` were examined
and are **comments** marking deliberate mirrors of Fabric enums, written that
way precisely because Fabric is api-extra only. The scope rule is being
observed there, not broken.

## Consequences

- ADR-0011's `v0.6.0` decision is superseded for the pin; everything else it
  decided stands.
- ADR-0015's open question on the Fabric baseline is settled by this ADR.
- Consumers of this repository's Lite artifacts (Azazel-Nexus, Azazel-Boot) now
  see one Fabric version across Edge, Deception, and Knowledge.

### What this evidence does not establish

That `v0.8.0` is *better*, only that it is compatible with what this repository
actually uses. Fabric features added between `v0.6.0` and `v0.8.0` are not
adopted here and remain unexercised by this suite; adopting one is a separate
change with its own evidence.
