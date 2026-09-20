# Edge-facing API

REST + JSON over the management segment (ADR-0005). Bearer token required on
every endpoint; mTLS optional. All requests and responses are logged as JSONL.

Since [ADR-0010](adr/0010-adopt-fabric-cti-contracts.md) this boundary is also
**type-enforced by `azazel_fabric.cti_contracts`** (tag-pinned,
`api`-extra only; the pin in force is `v0.8.0` per
[ADR-0016](adr/0016-fabric-pin-v0-8-0.md), carried in `pyproject.toml`). The enforcement is additive and the wire **shapes below are
unchanged**: ingest callers may opt into the canonical `Cti<Kind>Batch`
envelope and have it validated (see *Ingest*), and every `/v1/context` response
is checked against Fabric's `BANNED_DIRECTIVE_FIELDS` before it is emitted —
a directive-shaped field (`directive`/`must_execute`/`override`/
`required_action`) fails the request closed with `500
advisory_invariant_violation` and the response is never sent. The check runs on
a copy and never re-serializes the response, so byte-identical replay is
preserved.

## Query discipline — protect the Edge hot path

Azazel-Edge does **not** query per packet. Synchronous queries are limited to
defined triggers:

- Critical alert raised
- Unknown IOC / unknown JA3 / unknown JA4
- First contact with an external entity
- Local risk score above threshold

Everything else flows asynchronously via `POST /v1/events`. Edge enforces a
query timeout (default 250 ms) and proceeds without the answer on expiry.
The CTI node must never be a synchronous dependency of the arbiter.

## Read surfaces (operator-facing, advisory-only)

These endpoints are `Scope.READ` only, return plain JSON, and stay on the
read-only path. They surface behavioral CTI for operator review without
changing the `/v1/context` advisory contract or granting any action
authority to the CTI node.

### `GET /v1/behavior-patterns/{pattern_id}`

Returns one current-generation behavior pattern plus its resolved evidence
links and any precomputed similarity rows:

```json
{
  "pattern": {
    "pattern_id": "bp-9f2c1a77b0e4d135",
    "behavior_generation": 7,
    "actor_key": "ip:203.0.113.7",
    "edge_id": "edge-demo-01",
    "action_applied": "delay",
    "reaction_sequence": ["unknown", "shifted_protocol"],
    "behavior_class": "adaptive_probe"
  },
  "evidence": [
    {
      "evidence_type": "reaction",
      "evidence_id": "41",
      "role": "source",
      "evidence_ref": "reaction:41",
      "resolved": { "reaction_id": 41, "reaction": "shifted_protocol" }
    }
  ],
  "similarity": [],
  "limitations": [
    "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
  ],
  "advisory_notice": "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
}
```

`similarity` may be empty before the similarity pass has populated
`behavior_pattern_similarity`; this is not an error.

### `GET /v1/behavior-patterns/summary`

Lists recent current-generation patterns with optional filters:

- `behavior_class`
- `edge_id`
- `window_hours` (default `168`)
- `limit` (default `20`)

Response shape:

```json
{
  "behavior_generation": 7,
  "time_window": {
    "start": "2026-07-01T00:00:00Z",
    "end": "2026-07-08T00:00:00Z"
  },
  "filters": {
    "behavior_class": "adaptive_probe",
    "edge_id": "edge-demo-01",
    "window_hours": 168,
    "limit": 20
  },
  "patterns": [
    {
      "pattern_id": "bp-9f2c1a77b0e4d135",
      "behavior_class": "adaptive_probe",
      "action_applied": "delay",
      "actor_key": "ip:203.0.113.7"
    }
  ],
  "limitations": [
    "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
  ]
}
```

### `GET /v1/reports/friction-timeline`

Builds the operator-facing friction timeline narrative for one selected
current-generation pattern. Query parameters:

- `pattern_id` to select an exact pattern
- `actor_key` and/or `edge_id` to select the most recent matching pattern

Response shape:

```json
{
  "report_id": "friction-bp-9f2c1a77b0e4d135",
  "actor_key": "ip:203.0.113.7",
  "edge_id": "edge-demo-01",
  "time_window": {
    "start": "2026-07-08T00:00:00Z",
    "end": "2026-07-08T00:01:00Z"
  },
  "timeline": [
    {
      "timestamp": "2026-07-08T00:00:00Z",
      "event_type": "initial_observation",
      "evidence_refs": ["observation:obs-1"],
      "explanation_short": "Initial observation captured before defensive friction was applied."
    },
    {
      "timestamp": "2026-07-08T00:01:00Z",
      "event_type": "cti_advisory_disclaimer",
      "evidence_refs": [],
      "explanation_short": "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
    }
  ],
  "behavior_patterns": [
    {
      "pattern_id": "bp-9f2c1a77b0e4d135",
      "behavior_class": "adaptive_probe"
    }
  ],
  "advisory_summary": null,
  "limitations": [
    "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
  ]
}
```

The timeline always states that CTI is advisory-only and that the
Azazel-Edge Deterministic Arbiter remains final authority. Human-readable
text avoids attribution claims such as "AI attacker confirmed", "LLM
identified", or "autonomous intrusion proven"; preferred wording is
"adaptive behavior observed", "automation-like reaction pattern", and
"behavioral CTI generated from defensive friction".

## Ingest (Edge → CTI, fire-and-forget)

| Endpoint | Payload |
|---|---|
| `POST /v1/events` | JSONL batch: EVE alerts, DNS, HTTP metadata, JA3/JA4, canary hits |
| `POST /v1/flows` | JSONL batch: flow records |
| `POST /v1/reactions` | delay history: action applied + observed attacker reaction |
| `POST /v1/deception-observations` | AZ-06 fact-only deception observations (Fabric `InteractionObservation`; ADR-0011) |
| TAXII 2.1 inbox | STIX bundles from the existing Azazel-Edge push client (#248) |

Responses are `202 Accepted` with a batch id; validation problems are
reported in logs and a `GET /v1/ingest/{batch_id}` status, never by
rejecting the whole batch mid-operation.

**Fabric batch envelope (ADR-0010, additive).** The line-oriented JSONL
contract above is unchanged: a malformed **line** is still quarantined at
drain, never rejecting the batch. A caller may instead POST a single canonical
`Cti<Kind>Batch` envelope (`batch_id`, `source_product` ∈ `{edge, gadget}`,
`source_device_id`, `generated_at`, `items[]`); it is type-enforced against
`azazel_fabric.cti_contracts` and its `items` are flattened into the same JSONL
the drain path consumes. An **envelope-level** contract violation (bad
`source_product`, missing required field) fails closed with `422
ingest_batch_invalid` — this is a client contract error, distinct from an
item-level data problem, which is still quarantined rather than rejected.

### `POST /v1/reactions` payload (Phase 2 additions)

The Phase 1 minimal record (seven required fields) remains valid on its own;
Phase 2 adds further **optional** fields that enrich a reaction record for the
behavioral-pattern generator (`docs/design/phase2-implementation.md` §6.1).
The 8-class reaction taxonomy is unchanged — these fields describe context
around a reaction, they never add or rename a reaction class.

Generator-relevant fields are promoted to typed nullable columns
(`actor_cluster_key`, `action_profile`, `decoy_touched`, `decoy_profile`,
`retry_interval_ms`, `timeout_adaptation`); free-form/forward-compat fields
(`pre_action_summary`, `post_action_summary`, `raw_refs`, and any other
unknown optional field) are preserved verbatim in `payload_ext` for audit —
never silently dropped.

Recommended Phase 2 payload:

```json
{
  "edge_id": "edge-demo-01",
  "actor_key": "ip:203.0.113.7",
  "actor_cluster_key": "optional-session-or-ja3-cluster",
  "action_applied": "delay",
  "action_profile": "aggressive-30s",
  "applied_at": "2026-07-08T01:00:00Z",
  "reaction": "shifted_protocol",
  "reaction_window_s": 60,
  "pre_action_summary": {
    "ports": [22, 80],
    "protocols": ["tcp", "http"],
    "event_count": 12
  },
  "post_action_summary": {
    "ports": [8080, 2222],
    "protocols": ["http", "ssh"],
    "event_count": 8
  },
  "decoy_touched": true,
  "decoy_profile": "ssh-canary-profile-2",
  "retry_interval_ms": 1400,
  "timeout_adaptation": "increased",
  "evidence_refs": ["obs-1", "obs-2"],
  "raw_refs": ["edge-audit-1"]
}
```

`evidence_refs` remains **required and non-empty**; unresolved references are
resolved lazily via the existing linkage state machine and are simply
excluded from behavioral-pattern generation until resolvable — they are never
a reason to reject the record. A malformed line is **quarantined** into the
batch's `invalid[]` status (`GET /v1/ingest/{batch_id}`), never causing the
whole batch to be rejected. All timestamps are normalized to UTC on ingest.

### `POST /v1/deception-observations` (AZ-06, ADR-0011)

Fire-and-forget ingest of AZ-06 **fact-only** deception observations (Fabric
`InteractionObservation`: honesty ladder layers 1–3 — interaction / reaction /
outcome — plus `RuntimeContext` and `confounder_tags`). Same INGEST
scope/auth, same fire-and-forget contract as the endpoints above: `202` with a
batch id, `413` on the batch byte cap, `503` on spool quota, and a malformed
**line** quarantined at drain (`GET /v1/ingest/{batch_id}` `invalid[]`), never
failing the batch. Legacy per-line JSONL is untouched.

A caller may instead POST the batch **envelope** `{ "environment_id": ...,
"items": [ ...InteractionObservation... ] }`; each item is type-enforced against
Fabric `InteractionObservation` **and** the fact-only honesty invariant
(`assert_no_effectiveness_verdict`) at the boundary, failing closed `422
ingest_batch_invalid` on any violation. Its `items` are flattened into the JSONL
the drain path consumes. Every string field is untrusted attacker-authored
content: length-bounded, stored as opaque data, never evaluated. A
belief/verdict/effectiveness field anywhere in an observation is rejected —
interaction does not prove attacker belief (that is a layer-4 inference, the
advisory's job). Observations are stored INSERT-only in the immutable
`deception_observation` table (F-1); `edge_id`/`actor_key` linkage is taken from
the observation `metadata` when Edge stamps it, else `NULL`.

Example item:

```json
{
  "observation_id": "obs-9a1",
  "environment_id": "env-1",
  "package_id": "pkg-1",
  "node_id": "node-1",
  "observed_at": "2026-08-15T00:00:00Z",
  "observation_class": "reaction",
  "surface": "credential_lure",
  "reaction_kind": "authenticate",
  "lure_id": "cred-7",
  "dwell_ms": 1200,
  "attempt_count": 3,
  "confounder_tags": ["scanner_noise"],
  "runtime_context": {
    "selected_tier": "lite",
    "architecture": "arm64",
    "runtime_adapter": "docker_compose",
    "omitted_components": ["db-decoy"],
    "resource_saturation": {"cpu": 0.9}
  },
  "evidence_refs": ["ev-1"],
  "metadata": {"edge_id": "edge-pi4-07", "actor_key": "ip:203.0.113.9"}
}
```

### `GET /v1/deception-effectiveness` (AZ-06 advisory, ADR-0011)

Read-only (`Scope.READ`) deterministic effectiveness advisory for one
environment. Query params: `environment_id` (required), `package_id` (optional
filter). Returns a Fabric `EffectivenessAdvisory` — `advisory_only`,
`executable: false`, carrying `assessment`, `confidence` ∈ [0,1],
`counter_evidence[]`, `observation_refs[]`, and `unknowns[]`. It is a pure
function of the stored `deception_observation` rows, the
`deception_effectiveness` scoring block, `config_hash`, and `query_as_of`
(pinned once at handler entry): the same 7-tuple replays byte-identically.

The advisory enforces the effectiveness boundary
(`docs/azazel-deception-effectiveness.md`): narrative effectiveness is separated
from runtime/capacity effects (omitted components and saturation are
`counter_evidence`, never narrative failure), attacker belief is never claimed
from interaction (always an `unknown`), and only claim-boundary vocabulary is
used. Fails closed: `503 context_timeout` on the monotonic deadline (F-12),
`503 audit_unavailable` on an audit-chain append failure (F-17). The response
passes `assert_response_advisory_only` — no executable/directive/verdict field.

`reaction` rows stay INSERT-only/immutable — Phase 2 adds nullable columns
via migration, it does not add triggers that would allow UPDATE/DELETE.

Field routing on ingest:

- Promoted nullable columns: `actor_cluster_key`, `action_profile`,
  `decoy_touched`, `decoy_profile`, `retry_interval_ms`,
  `timeout_adaptation`
- Preserved verbatim in `payload_ext`: `pre_action_summary`,
  `post_action_summary`, `raw_refs`, and any unknown optional field

`pre_action_summary` / `post_action_summary` are accepted as arbitrary JSON
values, including objects, arrays, or scalars; CTI stores them verbatim in
`payload_ext` without narrowing their type.

## Lookup and context (Edge → CTI, synchronous, triggered)

### `POST /v1/ioc/search`

```json
{ "type": "ip", "value": "203.0.113.7" }
```

```json
{
  "match": true,
  "confidence": 82,
  "sources": ["urlhaus", "threatfox"],
  "first_seen": "2026-05-01T00:00:00Z",
  "last_seen": "2026-07-01T12:00:00Z",
  "source_freshness_days": 4
}
```

`POST /v1/ja3/search`, `POST /v1/ja4/search` follow the same shape.

### `POST /v1/context`

The full advisory contract. Input: a normalized event or entity set.
Output — every field advisory, every score explained. `advisory_id` is
issued per request for auditability and correlation only; it is not an input
to the scoring formula:

```json
{
  "advisory_id": "01JZB2Q8D6NNM2KX4Y7P3A5R9C",
  "threat_context": {
    "ioc_matches": [
      {
        "type": "ip",
        "value": "203.0.113.7",
        "sources": ["threatfox", "edge_reported"]
      }
    ],
    "campaign": { "name": "Coastal Ember", "actor": "UNC-EXAMPLE", "confidence": 61 },
    "attack_mapping": [{ "technique": "T1595.002", "tactic": "reconnaissance" }],
    "pattern_match": { "pattern_id": "pm-2026-0113", "similarity": 0.87 },
    "history": { "prior_observations": 14, "trend": "increasing" }
  },
  "multi_ioc_scope": {
    "matched_count": 2,
    "primary_ioc_id": "ioc-ip-203.0.113.7"
  },
  "threat_score": 75,
  "confidence": 65,
  "reason": [
    { "component": "ioc_match", "config_weight": 0.30, "effective_weight": 0.3529411765, "freshness": 0.90, "contribution": 29, "detail": "0.90 component score from one abuse.ch feed hit plus local Edge corroboration, 4 days old" },
    { "component": "history", "config_weight": 0.20, "effective_weight": 0.2352941176, "freshness": 1.00, "contribution": 14, "detail": "0.60 component score from 14 prior hits with rising trend" },
    { "component": "attack_map", "config_weight": 0.15, "effective_weight": 0.1764705882, "freshness": 1.00, "contribution": 12, "detail": "0.70 component score from T1595.002 via pattern pm-2026-0113" },
    { "component": "cve_exploited", "config_weight": 0.15, "effective_weight": 0.00, "freshness": 0.70, "contribution": 0, "applicable": false, "detail": "not an eve_alert event, so kev enrichment does not apply" },
    { "component": "campaign", "config_weight": 0.10, "effective_weight": 0.1176470588, "freshness": 1.00, "contribution": 10, "detail": "0.85 component score from weak but multi-source actor overlap" },
    { "component": "geo_asn", "config_weight": 0.10, "effective_weight": 0.1176470588, "freshness": 1.00, "contribution": 10, "detail": "0.85 component score from low-reputation ASN and GeoIP context" }
  ],
  "confidence_reason": [
    { "driver": "source_count", "weight": 0.30, "contribution": 15, "detail": "2 distinct source groups -> 0.50 driver score" },
    { "driver": "source_independence", "weight": 0.30, "contribution": 15, "detail": "max single-group share 0.50 -> 0.50 driver score" },
    { "driver": "source_freshness", "weight": 0.25, "contribution": 20, "detail": "oldest contributing source age maps to 0.80 driver score" },
    { "driver": "local_corroboration", "weight": 0.15, "contribution": 15, "detail": "local observation corroboration present -> 1.00 driver score" }
  ],
  "recommendation": {
    "action": "throttle",
    "rule": { "format": "suricata", "draft": "..." },
    "delay_profile": "aggressive-30s",
    "decoy": "ssh-canary-profile-2",
    "rejected_alternatives": [
      { "action": "isolate", "why_not": "single-source IOC, confidence below isolate floor" },
      { "action": "observe", "why_not": "prior reactions show continued scanning under observation" }
    ]
  },
  "source_freshness": { "oldest_feed_days": 12, "attack_version": "15.1" },
  "advisory_notice": "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
}
```

`rejected_alternatives` and the `reason` breakdown implement the Threat
Knowledge Plane idea: the node explains, it does not command. `reason[]`
always uses `config_weight` for the configured value and `effective_weight`
for the post-applicability renormalized value; in the example above
`Σ contribution == threat_score` after excluding the non-applicable
`cve_exploited` weight from the denominator.

### `threat_context.behavioral_cti` (Phase 2, additive, optional)

When a current-generation behavior pattern (from the Phase 2 behavioral CTI
lane; `docs/design/phase2-implementation.md` §5.1) matches the request's
`actor_key`, the response gains an **additive** `threat_context.behavioral_cti`
object. The top-level `threat_score`, `confidence`, `reason[]`,
`confidence_reason[]`, and `advisory_notice` contracts documented above are
**unchanged** by its presence:

```json
{
  "threat_context": {
    "behavioral_cti": {
      "behavior_seen_before": true,
      "behavior_class": "adaptive_probe",
      "pattern_id": "bp-9f2c1a77b0e4d135",
      "similarity": 0.84,
      "repeatability_score": 72,
      "novelty_score": 28,
      "suggested_posture": "delay",
      "confidence": 68,
      "evidence_refs": ["obs-...", "rxn-..."],
      "explanation_short": "Actor shifted protocol and retried after delay; similar reaction sequence observed previously.",
      "limitations": [
        "Behavioral similarity is not attribution.",
        "AI usage is not directly proven.",
        "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
      ],
      "behavior_generation": 7,
      "generator_version": "bpg-1",
      "behavior_config_hash": "…"
    }
  }
}
```

- **Match-gated, entirely omitted otherwise.** `threat_context.behavioral_cti`
  is present only when an indexed point-read against the current
  `behavior_generation` finds a pattern for the request's `actor_key`. When no
  pattern matches, the key is **omitted entirely** from the response — it is
  never sent as `null` or as an empty object.
- **`limitations[]` is mandatory whenever the block is present.** It always
  carries the advisory disclaimer verbatim: "Recommendation is advisory.
  Final authority: Azazel-Edge Deterministic Arbiter."
- **`suggested_posture` is a posture suggestion, not an action command.**
  Valid values: `observe`, `delay`, `decoy`, `escalate`, `no_change`,
  `unknown`. No field in this block instructs Edge to block, drop, redirect,
  or delay directly — final authority always remains with the Azazel-Edge
  Deterministic Arbiter.
- **`suggested_posture` is derived by a deterministic class-to-posture map.**
  The current mapping is:
  `simple_scanner -> observe`, `scripted_automation -> delay`,
  `adaptive_probe -> delay`, `decoy_engaged -> decoy`,
  `disengaged_after_friction -> no_change`, `unknown -> unknown`.
- **Best-effort, never a failure mode.** The block runs under a small
  sub-budget inside the existing context deadline; if the lookup times out or
  errors, the block is simply omitted and the `/v1/context` response still
  succeeds with its normal scored `200`. Its absence is never an error and
  never a `503` — the fail-closed semantics of `threat_score`/`reason[]`
  (`503 context_timeout`) and the audit chain (`503 audit_unavailable`) are
  unaffected.
- **Additive per the existing versioning rule** (see Versioning, below):
  clients that do not understand `behavioral_cti` can ignore it safely; all
  Phase 1 fields keep their existing meaning and shape.

Recommendation is advisory. Final authority: Azazel-Edge Deterministic
Arbiter.

### `engage_refs` / `rule_refs` (additive, optional; usage seam for #60/#61)

`POST /v1/context` gains two **additive, top-level, optional** fields,
default `[]`: `engage_refs` (MITRE Engage catalog activities, ADR-0012) and
`rule_refs` (community Sigma/YARA rule identity, ADR-0013). Both are
advisory-only, best-effort, **match-gated** on the ATT&CK technique(s) already
present in this response's own `threat_context.attack_mapping` -- they add no
new technique-matching input, only cite what the advisory already attributed:

```json
{
  "engage_refs": [
    { "technique": "T1595.002", "activity_id": "EAC0007", "name": "Network Analysis", "approach": "Understand" }
  ],
  "rule_refs": [
    { "technique": "T1595.002", "rule_type": "sigma", "rule_id": "5f2eb852-...", "title": "Suspicious Port Scan", "source_url": "https://github.com/SigmaHQ/sigma/..." },
    { "technique": "T1595.002", "rule_type": "yara", "rule_id": "APT_Scanner_Tool", "title": null, "source_url": "https://github.com/..." }
  ]
}
```

- **Derived only from intel-tier reference feeds** -- `engage_activity`/
  `engage_attack_map` (ADR-0012) and `sigma_rule_corpus`/`yara_rule_corpus`
  (ADR-0013) -- never from `local.db`, never from a new network call on the
  query path.
- **Outside the deterministic 7-tuple and `content_hash`.** Neither field
  ever enters `config/scoring.yaml`, the 7-element replay tuple
  (`intel_generation, local_generation, stats_generation, attack_version,
  config_hash, event, query_as_of`), or the score's `content_hash`; they are
  computed after scoring completes and can never change
  `threat_score`/`confidence`/`reason[]`/the audit event.
- **Match-gated on the advisory's own techniques.** A rule/activity appears
  only when its ATT&CK technique reference, canonicalized to bare uppercase
  `T####[.###]` (uppercase, dropping one leading `ATTACK.` prefix -- Sigma
  ships `attack.t1059.001`, YARA ships raw-cased `T1105`/`t1105`/
  `attack.t1105`), equals one of the advisory's own `threat_context.
  attack_mapping[].technique` values exactly. No mapping, no rule -- both
  lists stay `[]`, they are never `null` and the keys are never omitted
  (unlike `behavioral_cti` above, these are always-present arrays, just
  possibly empty).
- **`rule_refs` carries rule IDENTITY + metadata only** -- `technique`,
  `rule_type` (`"sigma"`/`"yara"`), `rule_id` (the Sigma `rule_uid` or the
  YARA `rule_name`), `title`, `source_url`. It NEVER includes `raw_yaml`/
  `raw_text`/condition logic; nothing executable ever leaves the process
  through this field.
- **Best-effort, never a failure mode.** Empty/absent feeds (the `engage`,
  `sigma_corpus`, or `yara_corpus` adapters have never run), a lookup error,
  or a truncation past the deterministic cap all degrade silently to an
  empty (or shorter) list -- this can never turn a `200` into a `500`, the
  same fail-open posture as `behavioral_cti`.
- **Deterministically sorted.** `engage_refs` sorts by
  `(technique, activity_id)`; `rule_refs` sorts by
  `(technique, rule_type, rule_id)`. Both are capped at a fixed count; a call
  replayed against the same intel generation returns byte-identical lists.

### `reported_defensive_state` (additive, optional; Knowledge#65)

> **Knowledge advises; it never sets Defensive State.**

`POST /v1/context` gains one **additive, top-level, optional** field, default
`null`, and one optional **request** field, `trace_id`. A caller that sends no
`trace_id` gets exactly the response it got before, with
`reported_defensive_state` null.

This is the **fact lane**. It reports what an authoritative producer said about
its *own* Defensive State, with the provenance needed to attribute it. It is
kept structurally apart from `recommendation`, which is Knowledge's inference
and is advisory-only — a consumer has to be able to tell "Edge says it is in
`THROTTLE`" from "Knowledge suggests considering something".

```json
{
  "reported_defensive_state": {
    "reported_state": "THROTTLE",
    "state_vocabulary": "azazel-fabric/defensive-state/v1",
    "producer_product": "azazel-edge",
    "producer_node": "edge-1",
    "trace_id": "trace-1",
    "decision_ref": "decision-1",
    "observed_at": "2026-07-05T00:00:00+00:00",
    "observation_ref": "dso-1",
    "authority_class": "producer_reported_state"
  }
}
```

- **`null` means unknown, and unknown is not a state.** Nothing reported, the
  value unreadable, the local tier unavailable, or everything reported newer
  than this query all yield `null`. Knowledge never substitutes a default —
  specifically never `OBSERVE` — because a default would be Knowledge asserting
  another product's posture out of its own ignorance.
- **Knowledge does not enumerate the values.** `reported_state` is carried
  exactly as it arrived and `state_vocabulary` names the vocabulary it arrived
  in. The canonical vocabulary is Azazel-Fabric's (Fabric#14); a second copy
  in the storage layer would drift from it, so `db/` enumerates nothing and a
  test asserts it stays that way.
- **The canonical reading is added beside the stored value, never over it**
  (Knowledge#65 AC-6, available since the `v0.9.0rc2` pin). `is_canonical`
  says whether the report is in Fabric's vocabulary, and `canonical_state`
  carries the value when it is, `null` when it is not.

  `canonical_state` is **never the coercion fallback.**
  `coerce_defensive_state` lands an unrecognized value on `OBSERVE` so that a
  consumer *deciding what to do* fails safe. Knowledge is not that consumer —
  it is reporting what a producer said, and emitting `OBSERVE` would turn
  "Edge said something this vocabulary does not know" into "Edge said
  `OBSERVE`". A non-canonical report is served verbatim and flagged, never
  rejected, normalized, or replaced: a producer speaking an unknown vocabulary
  is a fact worth keeping.

  Recognition is **exact**. `THROTTLE` is recognized; `throttle` and
  `THROTTLE ` are not. That is what makes "beside, never over" safe — a
  recognized report's stored spelling already is the canonical spelling, so
  there is no value the classification could rewrite.
- **Nothing here is a request.** The storage lane refuses a payload carrying
  `set_state`, `target_state`, `requested_state`, `next_state`,
  `transition_to`, `apply`, `execute`, `enforce`, `command`, `override`, or an
  attacker-belief field, recursively and at any nesting depth. A producer
  sending one has misunderstood the lane, and silently storing a cleaned copy
  would hide that.
- **No state is inferred.** Deception telemetry on the event does not produce a
  `REDIRECT`, and no attacker belief or intent is derived from a reported state.
  The only way this field is non-null is that a producer reported it.
- **Outside the deterministic 7-tuple and `content_hash`.** Read after scoring
  completes, from `local.db` alone (not the intel generation), so it can never
  move `threat_score`/`confidence`/`reason[]`/the audit event.
- **Immutable.** `defensive_state_observation_v0` is append-only; triggers
  reject `UPDATE` and `DELETE` (Absolute Constraint 5). A redelivered report
  with the same `observation_ref` is a no-op; the same ref with different
  content is refused rather than rewritten.

### `engagement_advisory` (additive, optional; Knowledge#52)

> **Knowledge advises; it never selects, commands, schedules, or executes.**

`POST /v1/context` gains one **additive, top-level, optional** field, default
`null`, plus `engagement_repeatability_score`. A caller that names no
`actor_key` gets exactly the response it got before.

The block is a Fabric `EngagementAdvisory`, folded from two immutable
local-tier lanes the caller already populated — `reaction` (which bounded
action was applied, and how the actor behaved after it) and `behavior_pattern`
(the deterministic behavior class and its confidence).

```json
{
  "engagement_advisory": {
    "schema_version": "engagement-advisory/v0.1",
    "advisory_id": "01J...",
    "advisor": "azazel-knowledge",
    "seen_before": true,
    "behavior_class": "adaptive_probe",
    "confidence": 0.79,
    "prior_outcomes": {
      "redirect": {"dominant_reaction": "followed_decoy", "evidence_count": 7, "distinct_reactions": 2},
      "throttle": {"dominant_reaction": "continued_scanning", "evidence_count": 12, "distinct_reactions": 1}
    },
    "posture_suggestion": {
      "objective": "collect",
      "approach": "channel",
      "supported_activities": ["redirect", "redirect_to_decoy"],
      "reasons": ["similar_patterns_previously_engaged_decoy"]
    },
    "limitations": ["describes observed outcomes only; it is not a prediction, ..."],
    "authority": "advisory_only",
    "executable": false
  },
  "engagement_repeatability_score": 62
}
```

- **`null` means Knowledge has nothing to say**, not "Knowledge is unsure".
  Fewer stored reactions than `engagement_advisory.minimum_reactions`, or no
  named actor, yields no block at all. A consumer can only tell the two apart
  if they look different.
- **Keyed on the actor the caller named**, `actor_key` in the request body —
  never on the API client. `reaction.actor_key` is the *source entity* (ip /
  ja3 / session cluster); the client's own identity is a different concept
  wearing the same word, and folding one under the other is a cross-actor leak.
- **A tie is `unknown`.** When no reaction outnumbers the others after an
  action, the outcome is `unknown` and the tie is named in `limitations`. It is
  never resolved by whichever value happens to sort first.
- **A posture needs evidence for that posture.** `redirect_to_decoy` appears
  only where prior decoy actions actually produced decoy engagement, at least
  `decoy_support_minimum` times. Below `posture_confidence_floor` there is no
  suggestion at all, though the observations are still reported.
- **`delay` and `deception` suggest no activity, by design.** They have no
  equivalent in Fabric's canonical activity vocabulary. They still inform
  `prior_outcomes`, whose keys are free-form, and the gap is named in
  `limitations` — inventing a mapping from a product-local action to a
  canonical one would make the product word canonical by the back door.
- **Advisory-only by construction.** `authority` and `executable` are pinned
  `Literal` types on the Fabric model, and `extra="forbid"` leaves nowhere to
  put a command, a deadline, a handler name, or a firewall rule.
- **Two directive layers, two vocabularies.** The builder runs Fabric's
  recursive runtime-directive walk (`shell_command`, `nft_rule`, `execute_now`,
  `bypass_arbiter`, ...) — not redundant with `extra="forbid"`, because
  `prior_outcomes` keys are free-form and a directive could hide one level
  down. The response-level assertion then runs `BANNED_DIRECTIVE_FIELDS`
  (`directive`, `must_execute`, `override`, `required_action`). A word only the
  builder owns drops the block and serves a normal `200`; a word only the
  response layer owns fails the whole response closed with a `500`.
- **Outside the deterministic 7-tuple and `content_hash`.** Folded after
  scoring completes, from `local.db` alone.
- **No attribution.** No identity, intent, belief, or prediction is asserted,
  and the advisory says so in its own `limitations`.

### Other read endpoints

| Endpoint | Purpose |
|---|---|
| `GET /v1/campaigns` / `GET /v1/campaigns/{id}` | campaign browsing for operators |
| `GET /v1/recommendations/rules` | pending advisory rule drafts (ADR-0007: never auto-deployed) |
| `GET /v1/reactions/summary` | attacker-reaction statistics (research/report view) |
| `GET /v1/behavior-patterns/{pattern_id}` | one behavioral CTI pattern + its evidence links + precomputed similarity edges (Phase 2, Scope.READ) |
| `GET /v1/behavior-patterns/summary` | recent behavioral patterns grouped by class/edge/window (Phase 2, Scope.READ) |
| `GET /v1/reports/friction-timeline` | operator-facing friction timeline: observation → action → reaction → classification → pattern → evidence → advisory implication → disclaimer (Phase 2, Scope.READ) |
| `GET /v1/health` | liveness + DB/feed staleness summary |
| TAXII 2.1 collections | STIX export for upstream sharing (Phase 4) |

The three Phase 2 endpoints above are read-only (`Scope.READ`, no write SQL —
see Absolute Constraint 1). They carry a mandatory `limitations[]` array and
the same advisory disclaimer as `/v1/context`, and their prose avoids
AI-attribution language: behavior is described as "adaptive" or
"automation-like," never as proof of AI usage or of a specific actor/model.
`GET /v1/reports/friction-timeline` degrades gracefully when advisory data is
absent — it still renders the stages for which source evidence exists.

## Versioning

All endpoints under `/v1/`. The advisory response contract is the API's most
stable surface: additive changes only within a major version, and the
`reason[]` component breakdown is mandatory in every scoring response.
