# ADR-0010: Adopt Azazel-Fabric `cti_contracts` at the API boundary

Status: accepted (2026-07-10, owner-authorized Phase 2 boundary adoption)

> **Pin superseded.** The `v0.3.0` tag recorded below is this ADR's original
> decision and is kept as the historical record. The api-extra pin in force is
> **`v0.10.0rc1`**, moved by [ADR-0011](0011-deception-observation-ingest.md) §
> *Consequences* (to `v0.6.0`) and then by
> [ADR-0016](0016-fabric-pin-v0-8-0.md) (to `v0.8.0`), an interim
> `v0.9.0rc2` pin, and [ADR-0019](0019-fabric-pin-v0-9-0rc5.md) (to the
> published pre-release `v0.9.0rc5`), then by
> [ADR-0020](0020-fabric-pin-v0-9-0rc6.md) (to `v0.9.0rc6`), then by
> [ADR-0021](0021-fabric-pin-v0-9-0.md) (to the stable `v0.9.0`), then by
> [ADR-0022](0022-fabric-pin-v0-10-0rc1.md) (to the published pre-release `v0.10.0rc1`), and carried in
> `pyproject.toml`. Everything else in this ADR —
> api-extra-only scope, `api/`+`taxii/` confinement, never a core dependency —
> remains in force.

## Context

[Azazel-Fabric](https://github.com/01rabbit/Azazel-Fabric) (AZ-05, formerly
Azazel-Common) is the Azazel series' shared contracts library. Its
`azazel_fabric.cti_contracts` module independently defines the Edge/Gadget ↔
CTI wire shapes — `CtiEventBatch`/`CtiFlowBatch`/`CtiReactionBatch` (a shared
ingest envelope keyed by `SourceProduct = Literal["edge","gadget"]`),
`CtiContextRequest`/`CtiContextResponse` (`+ IocMatch`, `BehavioralCtiBlock`),
and the advisory-only invariant primitives `BANNED_DIRECTIVE_FIELDS`,
`is_advisory_only`, `assert_advisory_only`. Until now this repository
re-implemented those shapes by hand and kept alignment "aspirational until
ratified by an ADR" (ADR-0009 era `architecture.md`, `roadmap.md`,
`README.md`).

Adopting Fabric introduces a **new dependency**, which Absolute Constraint 7
(dependency minimality) forbids without a `pyproject.toml` change *and* an
explicit ADR. The owner authorized the Phase 2 boundary adoption on 2026-07-10
and made the Fabric repository public so the tag pin resolves in CI. This ADR
is that ratification.

## Decision

Adopt `azazel-fabric`, **tag-pinned to `v0.3.0`**
(`azazel-fabric @ git+https://github.com/01rabbit/Azazel-Fabric.git@v0.3.0`),
as an **`api`-extra-only** dependency for boundary payload validation.

- **Scope: `api/` and `taxii/` boundary ONLY.** `azazel_fabric` is imported
  exclusively under `azazel_knowledge.api` (today, only `api/contracts.py`).
  It never enters `scoring/`, `correlate/`, or `core/`. The core dependency
  set (stdlib + PyYAML + idna + PyNaCl) is unchanged; Fabric ships in the same
  optional `api` extra as `fastapi`/`pydantic`, which the API layer already
  assumes present together.

- **Additive, shapes unchanged.** Fabric validation layers on top of the
  existing hand-rolled pipeline, which stays authoritative. No documented wire
  shape changes.

  - *Ingest.* `/v1/events|flows|reactions` keep their line-oriented JSONL
    fire-and-forget contract (a malformed **line** is quarantined at drain,
    never rejecting the batch). A caller that opts into the canonical Fabric
    batch **envelope** is now additionally type-enforced against
    `Cti<Kind>Batch`; an envelope-level contract violation fails closed with
    `422 ingest_batch_invalid`. Its `items` are flattened back into the same
    JSONL the drain path already consumes.

  - *Context response.* Every `/v1/context` response is checked — on a copy —
    against Fabric's `BANNED_DIRECTIVE_FIELDS` / `assert_advisory_only`
    (walked recursively). A directive-shaped field fails closed with
    `500 advisory_invariant_violation`; the response is never emitted. The
    **original bytes are emitted unchanged**, so byte-identical replay (F-2)
    is preserved — the check never re-serializes.

- **Not forced where shapes genuinely diverge.** Knowledge's `/v1/context`
  *request* is an entity+event set (not Fabric's opaque indicator-list
  `CtiContextRequest`), and its response *scores* are 0–100 with a richer
  `threat_context` (not Fabric's 0.0–1.0 `IocMatch`). Forcing those models
  would change wire shapes or reject valid traffic, so they are not applied;
  only the shape-agnostic advisory-only invariant — the part that truly
  matches — is enforced. The TAXII inbox carries STIX 2.1 envelopes, which no
  Fabric model matches, and is left untouched.

## Rationale

- **Single source of contract truth across the series.** The advisory-only
  invariant and the ingest/context wire shapes now derive from one library
  every Azazel repo can share, ending hand-maintained per-repo drift.
- **Type-enforced advisory-only invariant.** Directive-shaped fields
  (`directive`, `must_execute`, `override`, `required_action`) are rejected by
  a validator owned by Fabric, not by prose — machine-enforcing the doctrine
  that CTI never commands.

### Alternatives considered

- **Keep hand-rolled validation.** Rejected: guarantees eventual contract
  drift between repos as the wire format evolves; the invariant would live in
  four codebases with no shared enforcement.
- **Vendor/copy the Fabric models into this repo.** Rejected: a copy diverges
  the moment Fabric releases, reintroducing exactly the drift adoption is
  meant to eliminate, without the dependency-hygiene benefit.

## Consequences

- Fabric releases become a contract dependency of this repo. The pin is a
  **git tag** (`v0.3.0`), per Azazel-Fabric design-principles §6; a Fabric
  contract change is adopted deliberately by bumping the tag in a future PR,
  never floating.
- CI (`.github/workflows/test.yml`) installs the `api` extra, which now also
  resolves `azazel-fabric` from the public repo. The unit-test environment
  assumes the `api` extra is present (same convention `fastapi` already
  relies on).
- The advisory-only invariant now has a second, type-level enforcement point
  at the response boundary, complementing the static write-SQL scan
  (`test_api_static.py`) and the deterministic `reason[]` completeness tests.
- Superseding the `api`-extra-only scope (e.g. importing `azazel_fabric` into
  `scoring/`/`core/`, or letting a Fabric model rewrite response bytes) would
  require a new ADR.
