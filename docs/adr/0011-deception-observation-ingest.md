# ADR-0011: AZ-06 deception-observation ingest + effectiveness advisory

Status: accepted (2026-08-15, AZ-06 effectiveness boundary — Azazel-Knowledge#58,
parent #52; Azazel-Deception#6)

## Context

AZ-06 (Azazel-Deception) materializes decoy environments and, while an
engagement is live, records **fact-only** observations: what the attacker
contacted, how it behaved after contact, and measured outcomes (dwell,
attempts, resource spend), plus the runtime context that produced them.
Azazel-Knowledge is the analysis node that turns those facts into a
deterministic, evidence-backed **advisory** on deception effectiveness. It never
activates a package, selects a host/tier, approves a transition, or commands
Edge/AZ-06 (`docs/azazel-deception-effectiveness.md`).

The shared wire contract is fixed in **Azazel-Fabric v0.6.0**
(`azazel_fabric.deception_contracts`):

- consume `InteractionObservation` — a fact-only interaction/reaction/outcome
  ladder + `RuntimeContext` + `confounder_tags`; belief/verdict fields are
  *structurally impossible* (`extra="forbid"` + `assert_no_effectiveness_verdict`);
- produce `EffectivenessAdvisory` — `advisory_only`, `executable` pinned
  `False`, carrying `assessment` + `confidence` + `counter_evidence` +
  `observation_refs` + `unknowns`.

Until now Knowledge ingested only Edge events/flows/reactions and had no store
or output for the deception-effectiveness loop.

## Decision

Add a first-class deception-observation ingest path and an effectiveness
advisory output, faithful to every Absolute Constraint.

1. **Ingest endpoint** `POST /v1/deception-observations` (Scope.INGEST),
   following `routers/ingest.py` exactly: fire-and-forget spool, `413` on the
   batch byte cap, `503` on spool quota, and a malformed **line** quarantined at
   drain — never failing the batch (design S4/F-4). No write SQL in `api/`
   (Constraint 1); the durable `SpoolWriter` is the only mutation.

2. **Fabric boundary** — `api/contracts.py` only (Constraint 7 / ADR-0010).
   `maybe_fabric_observation_lines` type-enforces a caller that opts into the
   batch **envelope** (`{environment_id, items:[...]}`) against Fabric
   `InteractionObservation` **and** the honesty invariant
   (`assert_no_effectiveness_verdict`), failing closed `422 ingest_batch_invalid`;
   legacy per-line JSONL is untouched. Fabric ships **no**
   `InteractionObservationBatch`, so the envelope is a thin wrapper whose items
   are each validated. `build_effectiveness_advisory` constructs and
   type-enforces the `EffectivenessAdvisory` output on the way out.

3. **Immutable storage** — new local-tier table `deception_observation`
   (`db/migrations/local/0004_deception_observation.sql`), INSERT-only with
   `BEFORE UPDATE`/`BEFORE DELETE` triggers rejecting mutation exactly like
   `reaction`/`observation` (F-1). Idempotent replay via `observation_uid
   UNIQUE` + `INSERT OR IGNORE`; rows never decrease across imports. Stores the
   honesty-ladder facts only — there is **no** belief/verdict/effectiveness
   column, because interaction does not prove attacker belief.

4. **Deterministic advisory** — `correlate/deception_effectiveness.py`
   (framework-free, Fabric-free) folds the stored rows for an environment into
   the `EffectivenessAdvisory` field set. Pure function of the rows, the
   `deception_effectiveness` config block, `config_hash`, and `query_as_of`
   (pinned once at handler entry): same inputs ⇒ byte-identical advisory
   (`advisory_id` and `content_hash` are hashes of the inputs; `produced_at` is
   `query_as_of`). No wall-clock/random/env/file-order (Constraint 3;
   `time.monotonic` is a budget guard only, as in `correlate/pipeline.py`).

5. **Advisory read endpoint** `GET /v1/deception-effectiveness` (Scope.READ),
   read-only. Fails closed: `503 context_timeout` on the monotonic deadline
   (F-12), `503 audit_unavailable` on an audit-chain append failure (F-17 —
   advice is never served unauditable). The response passes
   `assert_response_advisory_only` and is a Fabric `EffectivenessAdvisory`
   (no executable/directive/verdict field).

### Effectiveness boundary (binding, `docs/azazel-deception-effectiveness.md`)

- **Narrative vs runtime/capacity is separated.** Omitted optional components
  and resource saturation ≥ threshold are surfaced as `counter_evidence` and
  `unknowns`, never read as narrative failure. Early disengagement is not a
  narrative verdict when a capacity confounder is present.
- **Belief is never claimed from interaction.** "attacker belief unknown" is
  always listed under `unknowns`; the assessment states belief is not asserted.
- **Claim-boundary vocabulary** only (observed interaction / observed reaction /
  measured outcome / runtime-context confounder / suggested posture /
  unknown-insufficient-evidence).

### How confidence / counter-evidence / unknowns are computed (deterministic)

From `config/scoring.yaml:deception_effectiveness` (folded into `config_hash`):

- **confidence** ∈ [0,1] =
  `clamp(base + min(per_observation·N, max_observation_bonus)
  + ladder_layer_bonus·layers_present − confounder_penalty·distinct_confounders,
  floor, ceil)`, rounded to `round_ndigits`. `N` = observation count,
  `layers_present` = how many of {interaction, reaction, outcome} appear,
  `distinct_confounders` = distinct `confounder_tags` observed.
- **counter_evidence** = each configured confounder present (config order)
  → "subtract before claiming effectiveness"; then omitted-components note;
  then saturation note.
- **unknowns** = insufficient-evidence (N < min); no measured outcome recorded;
  always the belief-boundary line; narrative-vs-capacity-not-separable when
  components were omitted.
- **observation_refs** = the summarized `observation_uid`s in sorted order.

## Dependency note (Absolute Constraint 7)

**No new runtime dependency.** The only `pyproject.toml` change is bumping the
existing **api-extra** pin `azazel-fabric` from `@v0.3.0` to `@v0.6.0`; core
deps (stdlib + PyYAML + idna + PyNaCl) are unchanged. Fabric remains imported
only in `api/contracts.py`.

> **Pin history.** The api-extra pin moved from `v0.6.0` to `v0.8.0` on
> 2026-09-19 ([ADR-0016](0016-fabric-pin-v0-8-0.md)); it then passed through
> interim `v0.9.0rc2` before the 2026-11-03 move to published pre-release
> `v0.9.0rc5` ([ADR-0019](0019-fabric-pin-v0-9-0rc5.md)), then `v0.9.0rc6`
> ([ADR-0020](0020-fabric-pin-v0-9-0rc6.md)), then the stable `v0.9.0`
> ([ADR-0021](0021-fabric-pin-v0-9-0.md)), then the published pre-release
> `v0.10.0rc1` ([ADR-0022](0022-fabric-pin-v0-10-0rc1.md)). Everything else
> this ADR decided stands.
>
> **Note resolved (2026-09-19, Azazel-Knowledge#73).** This ADR originally
> warned that the `v0.6.0` git tag was unpublished and that CI installing
> `@v0.6.0` would be red until the owner cut it. That tag is now published
> (`refs/tags/v0.6.0`), and a clean `pip install -e ".[api,dev]"` resolves
> `azazel-fabric 0.6.0` from it. Developing against an editable Fabric checkout
> is no longer required. `v0.6.0` is the pin in force; the series R0 baseline
> names `v0.8.0` as its reference candidate, and moving this repository to it
> is a separate cross-repository decision with its own test evidence — see
> [ADR-0015](0015-knowledge-lite-bundle.md) § *Open questions*.

## Constraint tension resolved here

`ingest/validators.py` and `ingest/drain.py` are **core** modules and must not
import Fabric (Constraints 4/7, ADR-0010). "Validate against Fabric
`InteractionObservation`" is therefore satisfied in two places, not one: the
**boundary** (`api/contracts.py`) does the real Fabric type-enforcement for the
envelope path; the **drain** validator (`validate_deception_observation_line`)
is a framework-free structural mirror of the same closed enum/field set and the
honesty invariant — exactly as `validate_event_line`/`validate_reaction_line`
mirror the `Cti*` shapes without importing Fabric. Every string field is treated
as untrusted attacker-authored content: length-bounded, stored as opaque data,
never evaluated or executed.

## Consequences

- A new immutable research table joins the F-1 set; the "rows never decrease"
  discipline now covers `deception_observation`.
- A second advisory surface (`/v1/deception-effectiveness`) now carries the
  advisory-only invariant and the fail-closed audit/timeout discipline.
- Reverting the api-extra-only scope of Fabric, or storing a belief/verdict
  column, would require a new ADR.
