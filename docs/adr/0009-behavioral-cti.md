# ADR-0009: Behavioral CTI as a separate, additive, deterministic lane

Status: accepted (Phase 2 design)

## Context

Phase 2 (issue #29, tracker #30, children #31–#37) turns tactical delay and
deception into **Behavioral CTI**: reaction records are compiled into
evidence-backed behavior patterns, compared for similarity/repeatability, and
returned to Azazel-Edge as advisory context — the friction loop of ADR-0008
made concrete.

This raises questions ADR-0006 (deterministic scoring, mandatory `reason[]`, no
ML) and ADR-0002 (native model, STIX at boundary only) did not settle for a
*behavioral* dimension:

1. Does behavioral scoring enter the Phase 1 `threat_score` determinism envelope
   (the 7-element replay tuple, `content_hash`, `config_hash` over
   `QUERY_PATH_FILES`)? If it did, every existing advisory would replay
   differently and the byte-identical-replay contract (F-2/F-8) would break.
2. Where do rebuildable behavior patterns live given `local.db` inviolability
   (F-1) and the fact that they derive from immutable local-tier rows?
3. May behavior context influence the final action, or reaction-informed
   scoring change the production score?
4. Is any of this allowed to use ML/LLM?

## Decision

Behavioral CTI is a **separate, additive lane** governed by these rules:

1. **Frozen Phase 1 envelope.** The `threat_score` determinism tuple,
   `content_hash`, `QUERY_PATH_FILES`, and weight-sum invariants are **not
   modified** by Phase 2. Behavioral config files are kept **out of**
   `QUERY_PATH_FILES`; the lane carries its own `behavior_config_hash` over
   `behavior-classify.yaml` / `behavior-similarity.yaml` /
   `behavior-shadow-rules.yaml` plus the active `behavior_generation` and
   `generator_version`. Behavioral output is independently replayable without
   entangling the verdict path.

2. **Local-tier, rebuildable by generation.** `behavior_pattern` and companions
   live in `local.db` (they derive from local-tier `reaction`/`observation`;
   bundles stay intel-tier only — `BUNDLE_TOUCHES_LOCAL_TIER` covers them). They
   are rebuilt via a local `behavior_generation` integer with an atomic
   `behavior_meta` swap and P3 GC — **not** the intel directory-swap machinery
   and **not** row immutability. They are excluded from the F-1 non-decrease
   invariant because they are derived and regenerable.

3. **Advisory-only, deterministic, declarative.** Generation, classification,
   similarity, and repeatability are deterministic and config-versioned.
   `suggested_posture` is a suggestion, never a command; no behavioral field
   instructs Edge to block/drop/redirect/delay (ADR-0007). The `/v1/context`
   behavioral block is additive and optional; its absence is never an error.
   Reaction-informed scoring stays **shadow-only, default-off** (extends F-19):
   it never changes `threat_score` and never enters the Edge advisory —
   research-log output only.

4. **No ML in generation, similarity, or scoring.** No embedding, clustering,
   or LLM in any of these paths (extends ADR-0006). LLM use, if ever added, is
   confined to explanation/report prose and marked in output.

5. **No AI attribution.** Output and docs characterize adaptive / automation-
   like behavior. They never claim proof of AI usage or attribute to a specific
   model. The `behavior_class` vocabulary is a fixed six values excluding any
   attribution term.

6. **STIX boundary unchanged (ADR-0002).** Behavior patterns are internal-
   relational only; no STIX mapping or TAXII export in Phase 2.

The full mechanics are specified in
[phase2-implementation.md](../design/phase2-implementation.md) as F2-1…F2-20.

## Rationale

- Rule 1 is the keystone: a separate hash lane makes the entire phase additive
  and preserves the 487-test baseline structurally, rather than by careful
  case-by-case patching. There is no carry-forward into the verdict path to get
  wrong.
- Rule 2 follows the existing precedent that `pattern` (Tactical Pattern Memory)
  is a rebuildable local-tier artifact, while honoring F-1: nothing a bundle
  does can erase or corrupt behavioral evidence, because the evidence
  (`reaction`/`observation`) is immutable and local, and the derived patterns
  are cheaply rebuilt from it.
- Rules 3–5 keep the Azazel doctrine intact: *AI suggests, CTI contextualizes,
  the deterministic arbiter decides.* Behavioral CTI widens what CTI can
  contextualize without moving authority.
- **External corroboration (2026-11, non-binding).** The no-ML, non-attribution,
  explainable stance of Rules 3–5 is reinforced by the wider field: MITRE
  ATT&CK v20 cataloging prompt injection (T1699 / T1698) as adversary technique
  validates keeping authority out of a promptable path, and the TRACE-CTI work
  names the "predicted vs. trusted" boundary this lane enforces through its own
  hash, complete `reason[]`, and shadow-only gating. This does not reopen the
  decision; adopting ML/embedding/LLM-based behavioral scoring would still
  require a new ADR superseding Rule 4. See
  [`docs/reports/ai-landscape-2026-11.md`](../reports/ai-landscape-2026-11.md) §3.

## Consequences

- All Phase 2 behavioral work is additive; existing advisories replay
  byte-identical; existing scoring/config tests are untouched.
- A new determinism surface (`behavior_config_hash`, generation-replay tests)
  must be maintained for the behavioral lane, parallel to but separate from the
  Phase 1 one.
- Reaction-informed production scoring remains explicitly future work behind the
  shadow gate; promoting it to active requires a new ADR that supersedes the
  shadow-only clause here.
- Cross-edge correlation and pattern export to Edges are schema-compatible but
  deliberately not enabled (deferred items S2-2/S2-3).
