# ADR-0020: Development-only Fabric commit pin for the Knowledge Context v1 producer adapter

Status: accepted for development only (2026-11-04). Not a release. Not shippable.

## Context

Nexus #395 needs a producer-side semantic adapter that maps Knowledge's
`/v1/context` answer to Fabric's Knowledge Context v1 profile
(`KnowledgeContextRequestV1` / `KnowledgeContextResponseV1`). That profile is
defined in Azazel-Fabric PR #76, a Draft candidate at commit
`50494cf769978abdbad21626a130d6525c83135d`, whose package version is
`0.9.0rc6.dev0`. The candidate is not merged and has no published tag. The
current published pin, `v0.9.0rc5` ([ADR-0019](0019-fabric-pin-v0-9-0rc5.md)),
does not contain the model.

[ADR-0010](0010-adopt-fabric-cti-contracts.md) and
[ADR-0019](0019-fabric-pin-v0-9-0rc5.md) state that the api-extra Fabric pin is
tag-pinned. The owner has explicitly allowed an immutable commit pin for
development, and has prohibited only a floating reference (`main`, a branch, or
a moving tag) in shipping configuration.

## Decision

1. **Release and stable dependencies remain tag-pinned.** Nothing in this ADR
   changes that rule for any release, tag, or shipped artifact.
2. **Scoped exception, development only.** `pyproject.toml`'s `api` extra pins
   `azazel-fabric` to the immutable commit
   `50494cf769978abdbad21626a130d6525c83135d`. This commit is the Draft
   candidate above. It is not a release, and an install from this pin is not a
   shippable install.
3. **Return condition.** Before any release, the pin must return to a published
   Fabric tag that contains the Knowledge Context v1 API. This ADR does not set
   that tag and does not claim one exists.
4. **Scope is not broadened.** The exception covers only this commit pin for
   the `api` extra, which stays the only place Fabric is imported. It does not
   permit `main`, a branch name, a tag that does not exist yet, or any other
   floating or unreviewed reference in config. It does not move Fabric into the
   core dependencies (Absolute Constraint 7).
5. **Product version unchanged.** Knowledge stays at `0.1.0`. No release is
   declared.

The producer adapter itself is a pure module under `azazel_knowledge/api/`:
`knowledge_context_adapter.py`. It reads the two existing models and emits the
Fabric models. It has no clock, no I/O, no route, no signature, and no mTLS.
It maps only `threat_context.ioc_matches` to facts, because that is the only
Knowledge output with explicit source provenance and a requested entity
identity. An exact match is emitted only when at least one source group is in
the fixed allowlist derived from `config/feeds.yaml` (`abusech`, `spamhaus`,
`geoip`). Local-only `edge_reported` and unrecognized or future groups produce
no fact until separately reviewed and added. It emits no inferences, and it
fails closed on anything it cannot represent faithfully. The request ID becomes
the Knowledge event ID; if later wired through the current router, it is written
to the audit event, so it must remain opaque and nonsensitive.

## Additive optional outcome fields (worker mirror)

The pinned candidate (`0.9.0rc6.dev0`) adds four optional fields to
`OutcomeObservationEnvelope`: `observation_objective_ref`, `hypothesis_refs`,
`frame_ref` and `limitations`. The Knowledge worker's framework-free mirror
(`ingest/validators.py`, the deception outcome-envelope lane) rejected them as
unknown fields. That was an observable side effect of the pinned source tree.

Because the pin requires these fields to be accepted, the worker mirror now:

- allows the four names in the envelope field set, so the field-set equality
  test against the pinned Fabric model passes;
- requires `observation_objective_ref` (if present and non-null) to be an
  opaque typed ref of kind `observation_objective`, `frame_ref` of kind
  `frame`, and each `hypothesis_refs` entry of kind `hypothesis`. The list is
  capped at 8 and must be unique, and a non-empty list requires `frame_ref`.
  The grammar is duplicated from Fabric `effect_contracts/refs.py`, not
  imported. A ref whose body carries an imperative command segment (the
  existing C3 word set) is refused;
- validates envelope `limitations` with the existing limitation token grammar
  and counts an invalid entry as dropped. The list is bounded by
  `OUTCOME_ENVELOPE_LIST_MAX` (128). A structural violation quarantines the
  pair, as the other structural checks do;
- keeps absent optional fields backward-compatible. The two optional scalar
  refs accept null as well as omission; `hypothesis_refs` is a list and an
  explicit null is rejected, matching Fabric's model.
- refuses `active_materialized` when objective/hypothesis/frame context is
  present without a `decision_ref`, matching Fabric's distinction between an
  observation objective and an authorized decision.

The full envelope is retained in `raw`, as before. The new fields are not
written to any column, and no advisory or efficacy claim changes. Envelope
`limitations` are validated and retained in `raw` but are not surfaced in the
normalized advisory at this stage; this is recorded in `docs/api.md`. The
mirror checks the new fields so malformed values are refused rather than
stored. **No behavioral integration is claimed**: this decision covers
acceptance by the worker mirror and nothing downstream of it.

## Consequences

- The current-pin statement in the README, API, architecture, roadmap and
  development-guide documents now names this commit as a development-only pin.
  ADR-0019 remains the historical record of the published `v0.9.0rc5` pin.
- The pin-shape regression now permits a version tag or an immutable 40-digit
  commit only when the development-only ADR and `DEVELOPMENT-ONLY` declaration
  are present. Floating refs remain refused.
- The suite baseline was recounted from 1,595 to 1,729 collected unit tests.
  `CLAUDE.md` remains the single source, with `AGENTS.md` and
  `docs/development-guide.md` synchronized; `test_claude_md_baseline.py`
  checks the six statements and prevents a stale low baseline.
- This ADR is superseded by a new ADR when the pin returns to a published tag.
