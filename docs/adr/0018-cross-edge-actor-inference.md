# ADR-0018: Knowledge infers cross-edge actor linkage itself, alongside (never over) the Edge-supplied key

Status: accepted (2026-09-19)

## Context

`docs/roadmap.md` (Phase 2) and `docs/design/phase2-implementation.md` §13 S2-3
both state that cross-site logic "is not yet enabled". **That is inaccurate.**
Three cross-edge mechanisms are implemented and reachable today:

| Where | What it does |
|---|---|
| `reactions/eligibility.py` (`recompute_trust_tier`) | A reaction whose corroborating events span more than one `edge_id` is promoted to trust tier `corroborated` rather than `same_edge_corroborated` |
| `feeds/promotion.py` (`PromotionReason.DISTINCT_EDGES`) | `edge_reported_ioc` rows are promoted out of quarantine once `min_distinct_edges` distinct `edge_id`s have reported the same `entity_key` inside the window |
| `scoring/behavior_similarity.py` (`_compute_repeatability`) | Similar behavior patterns drawn from more than one `edge_id` add `cross_edge_score = 15.0` to repeatability |

What does **not** exist is the thing all three quietly depend on: an answer to
*"is the actor at Edge 1 the same actor as the one at Edge 2?"*

`actor_cluster_key` is listed in `ingest/validators.py`'s
`_PHASE2_PROMOTED_FIELDS`. It arrives **from the Edge**, is carried through
`patterns/behavior_generate.py` unchanged, and is read back by
`behavior_similarity.py`'s `cross_cluster_score`. Knowledge never computes it,
never checks it, and has no way to tell a well-formed key from a meaningless
one. Cross-edge identity is therefore an *assumption about Edge behavior* that
Knowledge presents as if it were knowledge.

`correlate/campaign.py` is edge-agnostic and degrades to zero contribution
because Phase 1 intel migrations ship no campaign tables; it is not a
cross-edge mechanism and is not changed here.

## Decision

**Knowledge infers cross-edge actor linkage itself, from evidence it can
observe, and reports it as advisory data with a confidence and a complete
reason breakdown.**

1. **It is an inference, and it is labelled as one.** The result is carried in
   its own field, separate from `actor_cluster_key`. A consumer can always tell
   *"the Edge asserted these are the same actor"* apart from *"Knowledge
   estimates these may be the same actor, for these reasons, at this
   confidence"*.

2. **The Edge-supplied key is never overwritten, corrected, or deleted.**
   Knowledge does not arbitrate identity on the Edge's behalf. Where the two
   disagree, both are reported and the disagreement is itself advisory content.

3. **No Edge cooperation is required.** The inference runs on what is already
   in `local.db`. It does not depend on Edges agreeing a cluster-key scheme,
   and it does not block on a cross-repo contract.

4. **The inference must not feed its own inputs.** Knowledge's inferred linkage
   MUST NOT be written into `actor_cluster_key`, and MUST NOT reach
   `behavior_similarity`'s `cross_cluster_score`. That score exists to reward
   agreement between *independent* sources; letting Knowledge's own estimate
   raise a score that is then cited as evidence for that estimate is circular,
   and it would inflate confidence with no new information. This is a binding
   constraint, not a style preference.

5. **Determinism is unchanged.** The inference lives in `correlate/`, so
   絶対制約3 applies in full: no `datetime.now`, no randomness, no environment
   dependence, no reliance on file or row enumeration order. Time enters only
   as the `query_as_of` taken once at the handler entry, per `core/clock.py`.
   The same inputs must reproduce the same linkage and the same `reason[]`.

6. **Fail-closed.** If the evidence cannot be read, the answer is "no linkage
   asserted", never a partial one. A missing signal appears in `reason[]` as
   `applicable: false`, not as silence — the same completeness rule that binds
   scoring (絶対制約2).

7. **Advisory only.** Nothing here changes who decides anything. A cross-edge
   linkage is context for Azazel-Edge's deterministic arbiter, which remains
   the only decision and enforcement authority. Knowledge being confident that
   two actors are one does not authorize any action, at either Edge.

## Rationale

The alternative — declaring `actor_cluster_key` an Edge-side contract and
waiting for Azazel-Edge to define it — was considered and rejected for now. It
leaves Knowledge asserting cross-edge corroboration today on a field it cannot
validate, and it makes a Knowledge capability wait on another product's
roadmap. The two are not exclusive: if Edges later agree a scheme, it arrives
as a second, independent signal, which is worth strictly more than either
alone precisely because Knowledge's own estimate did not depend on it.

Inferring identity is a claim about an adversary, which is the kind of claim
this project is most careful with. That is why it is confined to advisory
output with mandatory reasons, kept out of its own feedback path, and denied
any authority. The discipline is the same one ADR-0009 applied to behavioral
patterns and ADR-0015 D4 applied to exported claims: a claim travels with its
provenance or it does not travel.

## Consequences

- A new deterministic component under `correlate/` owns the inference, reading
  `local.db` only. No schema change: `edge_id`, `actor_key`, `entity_key` and
  the behavioral tables already carry what it needs.
- `roadmap.md` and `phase2-implementation.md` §13 S2-3 are corrected to state
  the three mechanisms that exist and the one that does not. Leaving the
  inaccurate claim in place risks a fourth mechanism being built beside the
  three, with no one noticing the overlap.
- Confidence is bounded and explainable, never a single opaque number. The
  evidence classes available today are entity overlap between edges, temporal
  proximity evaluated against `query_as_of`, and behavioral similarity from the
  existing deterministic machinery. Which of these actually carry signal, and
  at what weights, is a measurement question and is **not** decided here.
- **Not decided here, deliberately:** the weights themselves, any threshold at
  which a linkage is worth reporting, and whether entity overlap alone is ever
  sufficient. Those need evidence from real multi-Edge data, which does not
  exist yet. Shipping weights chosen by argument would repeat the mistake
  ADR-0015 D3 made with its capacity ceilings, where proposed numbers stood for
  a year until they were measured and found to be 1.4-2.5x wrong.
- **Not true yet:** no multi-Edge deployment exists. Every statement here is
  about intended behavior. Nothing in this ADR is evidence that cross-edge
  inference works, or that its output is useful.
