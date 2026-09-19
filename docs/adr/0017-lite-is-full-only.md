# ADR-0017: Knowledge Lite bundles are full-only; no Lite deltas

Status: accepted (2026-09-19 — owner-authorized)

## Context

[ADR-0015](0015-knowledge-lite-bundle.md) left open whether Lite needs
differential bundles, and noted that `tools/bundle_build.py` documents Phase-1
differentials as emitting only `upsert` with no tombstone tracking. The
question that blocked the decision was concrete: **what should a consumer do
with a stale row it cannot be told to delete?**

Azazel-Knowledge#73's acceptance criteria ask for full/delta round-trip with
wrong-base and wrong-final-tree-digest failures. That is satisfied today for
the general bundle path — `test_differential_with_wrong_base_rejected`,
`test_differential_with_matching_base_accepted`,
`test_differential_import_applies_upserts_to_live_generation`, and
`test_differential_import_delete_op_removes_row` all exist and pass. Note the
last of those: the **importer already consumes tombstones**. It is the
*builder* that does not produce them.

So the choice was never "can we do deltas" but "should Lite have them".

## Decision

**A Knowledge Lite artifact is always `kind: full`.** `build-lite` offers no
`--base` and no `--kind`; it is structurally incapable of emitting a delta, and
a test pins that rather than leaving it to the absence of a flag.

The general (non-Lite) bundle path keeps its existing full and differential
behaviour unchanged. This ADR narrows Lite only.

## Rationale

**The stale-row problem does not exist for Lite.** ADR-0015 D4 requires every
exported claim to carry an expiry, and that requirement is now enforced: a row
whose expiry column is null is refused at build time. A row that should stop
being believed expires, and the consumer's own `query_as_of` makes it
unavailable. There is no category of Lite row that needs an out-of-band delete
instruction, so the problem tombstones would solve is already solved by
something the artifact is required to carry anyway.

**Deltas buy little against a bounded artifact.** Differentials exist to avoid
retransmitting a large corpus. Lite is small by construction — the
`knowledge-lite-16g` ceiling is 64 MiB compressed — and that bound is the
product's purpose, not an accident. Introducing a base-version chain, which can
break, to save a fraction of an already-bounded offline transfer is a poor
trade.

**Deltas would complicate the byte-identity claim.** D2 states that the same
selection tuple reproduces the same unsigned artifact. A delta's content
depends on its base, so the claim would have to grow to "the same tuple *and*
the same base", and reproducing an artifact would require reproducing its
ancestry. Full-only keeps the reproducibility statement as short as it is
strong.

## Consequences

- Azazel-Knowledge#73's delta criterion is satisfied by the general bundle path
  and **deliberately does not apply to Lite**.
- A Nexus or Boot node refreshes its Lite cache by verifying and promoting a
  new full artifact, not by applying increments. Staged-then-atomic promotion
  already works that way.
- The Phase-2 tombstone TODO in `tools/bundle_build.py` remains open for the
  general path. Nothing here forecloses it; it simply stops being a Lite
  blocker.
- If a future Lite corpus grows past the point where full transfer is
  impractical, that is the trigger to revisit this — and the honest signal
  would be a measured transfer cost, not a preference. Revisiting requires a
  new ADR.
