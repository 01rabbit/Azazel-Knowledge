# ADR-0020: Move the Azazel-Fabric api-extra pin to `v0.9.0rc6`

Status: accepted (2026-11-05 — owner-merged in Azazel-Knowledge PR #118);
current-pin decision superseded by [ADR-0021](0021-fabric-pin-v0-9-0.md)

## Context

[ADR-0019](0019-fabric-pin-v0-9-0rc5.md) recorded `v0.9.0rc5` as the Knowledge
`api`-extra pin. Fabric has since published the pre-release `v0.9.0rc6`.

- Tag `v0.9.0rc6` resolves to commit
  `023381371b56b3883a89a28a69625ddb87742f2e`. It is a published
  **pre-release**, not a stable release.
- Its release digest is
  `sha256:f1b76901bee8938b45b5a600d967286b7a397933acdbecb30328c6adad1ab1e6`.
  The digest file and its signature were added after the tag, on Fabric `main`
  at `88c47d58e28dfb060fb7c8205c947d712637818b`
  (`release/v0.9.0rc6.digest.json` and `.sig`). Before this ADR was written
  the tag was checked out and Fabric's `tools/rc_digest.py --check
  release/v0.9.0rc6.digest.json` reported that the tree matches that digest.
  Knowledge did **not** verify the signature itself.

`v0.9.0rc6` is **not additive** relative to `v0.9.0rc5` (Fabric
`CHANGELOG.md`, `docs/release-compatibility.md`):

1. Fabric#65 — a typed reference, provisioning digest or MAC ending in a
   newline, accepted by `rc5`, is refused.
2. Fabric#23 — the deception, engagement and effect directive walkers refuse a
   payload nested deeper than 32 levels with a `ValueError`; `rc5` accepted it
   up to the interpreter's recursion limit.
3. Fabric#72 — `decision_ref`, `trace_id` and similar slots typed
   `observation_objective:`, `hypothesis:` or `frame:` are refused; and
   `OutcomeObservationEnvelope` gains four optional fields:
   `observation_objective_ref`, `hypothesis_refs` (at most 8), `frame_ref` and
   `limitations`.

## Decision

The `api`-extra pin is `azazel-fabric @
git+https://github.com/01rabbit/Azazel-Fabric.git@v0.9.0rc6`, as declared in
`pyproject.toml`. It remains an API-boundary dependency only; Fabric is not a
core dependency, and Knowledge's product version (`0.1.0`) is unchanged.
ADR-0019 remains the record of the `rc5` adoption; this ADR supersedes only its
current-pin statement.

### The four new envelope fields: accepted, kept in `raw`, not promoted

Knowledge's drain validator mirrors Fabric's closed field set
(`_OUTCOME_ENVELOPE_FIELDS`, held equal to the Fabric model by a test) and
rejects unknown fields. Left unchanged it would refuse every `rc6` envelope that
uses the new fields, even though the API boundary (which validates with the
Fabric model itself) has already accepted it. The fields are therefore added to
the set. How they are handled follows the existing design:

- **Accept, do not ignore or reject.** They are Fabric-defined, non-executable
  observation context. Refusing them would make Knowledge drop evidence that a
  conforming producer is allowed to send ([ADR-0011](0011-deception-observation-ingest.md):
  "stored as opaque data"). Ignoring them silently would let the validator and
  the boundary disagree about what was sent.
- **Keep them in `raw`, add no column and no migration.** The outcome table is
  append-only and immutable, and migration `0008` states that nothing is
  derived into a column and that objective / hypothesis / frame refs "are kept
  there, not parsed out" so as not to create a second statement of the same
  fact. `raw` stores the verbatim envelope, so nothing is lost.
- **Validate structurally, in the core module, without importing Fabric**
  (ADR-0010, ADR-0011: the drain mirror is Fabric-free). Each ref is a bounded
  string of its own kind (`observation_objective:`, `hypothesis:`, `frame:`)
  without whitespace or control characters; `hypothesis_refs` has at most 8
  unique entries and requires `frame_ref`; an envelope carrying an objective,
  hypothesis or frame without a `decision_ref` may not claim
  `active_materialized`. Violations quarantine the pair, as every other
  structural violation does. Full type enforcement stays at the boundary.
- **The envelope's `limitations` is not merged into the `limitations` column.**
  That column is the `EffectObservation`'s statement; merging would blur two
  producers' statements. Invalid entries are dropped one by one and counted in
  `entries_dropped` (CONVENTIONS C6), like the other token lists; the list is
  bounded to 128.
- **No scoring or advisory effect.** The fields are not read by the correlator.
  An objective is not a decision and never raises authority; the advisory-only
  invariant and the "no verdict column" rule are unchanged.

## Compatibility and verification evidence

Local results (the repository does not rely on GitHub Actions for this change;
see the pull request for the full record):

- `azazel_fabric.__version__ == "0.9.0rc6"` after `pip install -e '.[api,dev]'`
  on Python 3.12.
- With the pin changed alone, the mirror test
  `test_the_mirrored_field_sets_equal_the_fabric_models` failed, the four
  fields being the only difference. No test was removed, skipped or relaxed.
- This evidence does not establish a socket-level Fabric-to-Knowledge service
  integration, TLS, signature verification, or production deployment.

## Behaviour that changes with `rc6`

- Envelopes using the new fields are accepted (before: refused by the drain
  validator).
- Typed refs / digests / MACs with a trailing newline are refused at the
  boundary; very deeply nested (>32) payloads are refused with a `ValueError`
  (surfacing as a 422 `ingest_batch_invalid`).
- Refs in `decision_ref` / `trace_id` typed with the three new kinds are refused.

## Rollback

Set the `pyproject.toml` pin back to `@v0.9.0rc5` and reinstall. Because
`rc6` is not additive, also revert the four fields from
`_OUTCOME_ENVELOPE_FIELDS` and the associated validator and tests (revert this
change as a whole), or the Fabric-mirror test will fail under `rc5`. Rows
already stored remain valid: `raw` is opaque and no column was added. Envelopes
carrying the new fields cannot be sent to an `rc5` Knowledge and would be
quarantined.

## Consequences

- Historical: current documentation named `v0.9.0rc6` as the pin in force at
  the time; superseded by ADR-0021.
- The test baseline in `CLAUDE.md` / `AGENTS.md` / the development guide is
  raised to the new real count.
- No package version, tag, release, signing or deployment is created.
