# AZ-06 Azazel-Deception Effectiveness Analysis

Repository: https://github.com/01rabbit/Azazel-Deception
Tracker: https://github.com/01rabbit/Azazel-Knowledge/issues/58
Parent effectiveness work: https://github.com/01rabbit/Azazel-Knowledge/issues/52

## Role

Azazel-Knowledge consumes measured outcomes from AZ-06 and converts them into deterministic, evidence-backed advisory context. Knowledge never activates a deception package, selects a host or tier, approves a transition, schedules a persona, or commands Edge/AZ-06.

## Evidence loop

```text
Edge approves bounded activation/transition
  -> AZ-06 materializes environment
  -> interactions + runtime context + outcomes are recorded
  -> Knowledge correlates behavior and prior outcomes
  -> advisory-only context is returned
  -> Edge independently decides
```

## Required AZ-06 context

Where available through canonical Fabric contracts, retain:

- package / narrative / environment / state IDs
- package/image digest, signer, provenance, SBOM refs
- Edge selected/rejected decision refs
- active surfaces and transition history
- artifact and decoy-credential interaction
- behavior/reaction observations
- selected deployment tier
- architecture and runtime-adapter class/version
- anonymized node/capability class
- active and explicitly omitted optional components
- resource saturation, capability drift, runtime failure
- termination, evidence-finalization, reset, and credential-invalidation outcomes

## Analysis rule

Narrative effectiveness must be separated from runtime and capacity effects.

Do not compare `lite`, `standard`, and `heavy` outcomes as equivalent unless exposed components and budgets are controlled. Early disengagement or missing interaction may be caused by omitted optional surfaces, saturation, runtime degradation, or capability mismatch rather than narrative quality.

Package identity remains portable across ARM64 and AMD64, while architecture/runtime context remains evidence for reproducibility.

## Claim boundary

Use these terms:

- observed interaction
- observed reaction
- measured outcome
- runtime/context confounder
- suggested posture
- unknown / insufficient evidence

Interaction with a lure does not by itself prove that the attacker believed the deception. LLM availability is preparation metadata only and does not imply that an LLM participated in live execution.

## Advisory boundary

Knowledge may suggest bounded posture/profile classes with reasons, confidence, prior outcomes, and counter-evidence. It must not emit executable container commands, firewall rules, host/tier placement instructions, transition approvals, or hidden directive fields.

## Implementation (ADR-0011)

This boundary is realized by a first-class ingest path and a deterministic advisory output.

### Ingest and storage

- `POST /v1/deception-observations` (Scope.INGEST) — fire-and-forget ingest of Fabric `InteractionObservation` facts (honesty ladder layers 1–3). Legacy per-line JSONL, or a `{environment_id, items:[...]}` envelope type-enforced against `InteractionObservation` + `assert_no_effectiveness_verdict` at the boundary (fail closed `422`). A malformed line is quarantined at drain, never failing the batch.
- Table `deception_observation` (`local.db`, migration `0004`) — INSERT-only, UPDATE/DELETE-rejecting triggers (F-1), rows never decrease. Fact-only columns: `observation_class`, `surface`, `reaction_kind`, `lure_id`, latencies (`first_contact_latency_ms`/`dwell_ms`/`attempt_count`), `confounder_tags`, `runtime_context`, `evidence_refs`, plus `edge_id`/`actor_key` linkage. **No belief/verdict/effectiveness column** — interaction does not prove belief.

- Observation identity conflicts (#66/#111): the existing single-writer drain compares the complete stored canonical raw observation before admitting a repeated `observation_id`. Equal JSON content (independent of object-key order or transport whitespace) remains an idempotent duplicate. Different content, including metadata/provenance, runtime context, evidence references or environment/producer changes, is quarantined against its original batch line and excluded from `valid`/duplicate counts. The original fact remains unchanged; a conflict alone cannot change the advisory. Other valid lines still drain; the original conflicting payload remains in the retained batch/status for review. This matches the existing outcome-envelope conflict handling and creates no new schema, API, revision-resolution or automatic correction path. It detects conflicting statements under one identity, not source authenticity, ground truth or all poisoning. Exact duplicates remain counted as valid accepted lines, not new stored facts.

- `POST /v1/deception-outcome-envelopes` (Scope.INGEST) — Fabric `OutcomeObservationEnvelope` + the `EffectObservation` it correlates (Knowledge#111 G7), envelope-only. Stores coverage, telemetry gaps, confounders, limitations and the decision / effect / `advisory:` refs in `deception_outcome_envelope_v0` (migration `0008`; INSERT-only, idempotent on `envelope_id`, no verdict column). `docs/api.md` has the contract.

### Advisory output

- `GET /v1/deception-effectiveness?environment_id=…[&package_id=…]` (Scope.READ) — returns a Fabric `EffectivenessAdvisory` (`advisory_only`, `executable: false`) with `assessment`, `confidence` ∈ [0,1], `counter_evidence[]`, `observation_refs[]`, `unknowns[]`.
- **Deterministic** (`correlate/deception_effectiveness.py`): a pure function of the stored rows, the `config/scoring.yaml:deception_effectiveness` block, `config_hash`, and `query_as_of` (pinned once at handler entry). Same 7-tuple ⇒ byte-identical advisory. No wall-clock/random/env/file-order.
- **`confidence`** = `clamp(base + min(per_observation·N, max_observation_bonus) + ladder_layer_bonus·layers_present − confounder_penalty·distinct_confounders, floor, ceil)`, rounded to `round_ndigits`.
- **`counter_evidence`** surfaces runtime/context confounders (`scanner_noise`, `internal_health_check`, `host_capacity`), omitted optional components, and resource saturation ≥ threshold — the signals to subtract before claiming effectiveness. **Narrative effectiveness is separated from runtime/capacity effects**: early disengagement with a capacity confounder is not a narrative-failure verdict.
- **`unknowns`** covers insufficient evidence, missing measured outcome, the always-present belief boundary ("attacker belief unknown: interaction does not prove the attacker was deceived"), and narrative-vs-capacity non-separability when components were omitted.
- **Coverage and limitations** (when an outcome envelope is stored): incomplete coverage, producer `limitations`, `stale` and observed isolation drift appear under `unknowns` / `counter_evidence`, and `no interaction observed is not evidence of safety` is stated whenever nothing was observed. They never change `confidence`, `assessment` or the suggested posture — an unobserved gap makes the advisory less able to conclude, it is never read as safe or as effective.
- Fails closed: `503 context_timeout` (F-12) on the monotonic deadline, `503 audit_unavailable` (F-17) on audit-chain failure. The response passes `assert_response_advisory_only`.
