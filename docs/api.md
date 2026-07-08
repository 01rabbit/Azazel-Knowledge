# Edge-facing API

REST + JSON over the management segment (ADR-0005). Bearer token required on
every endpoint; mTLS optional. All requests and responses are logged as JSONL.

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

## Ingest (Edge → CTI, fire-and-forget)

| Endpoint | Payload |
|---|---|
| `POST /v1/events` | JSONL batch: EVE alerts, DNS, HTTP metadata, JA3/JA4, canary hits |
| `POST /v1/flows` | JSONL batch: flow records |
| `POST /v1/reactions` | delay history: action applied + observed attacker reaction |
| TAXII 2.1 inbox | STIX bundles from the existing Azazel-Edge push client (#248) |

Responses are `202 Accepted` with a batch id; validation problems are
reported in logs and a `GET /v1/ingest/{batch_id}` status, never by
rejecting the whole batch mid-operation.

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
  "actor_key": "203.0.113.7",
  "edge_id": "edge-pi4-07",
  "action_applied": "delay",
  "applied_at": "2026-07-08T03:14:00Z",
  "reaction": "shifted_port",
  "reaction_window_s": 45,
  "pre_action_summary": "SYN scan across 12 ports over 90s",
  "post_action_summary": "Retried on adjacent port after delay, then backed off",
  "decoy_touched": false,
  "decoy_profile": null,
  "retry_interval_ms": 1500,
  "timeout_adaptation": "backoff_increased",
  "evidence_refs": ["obs-2026-0708-0001", "rxn-2026-0708-0007"],
  "raw_refs": ["edge-audit-id:9f21c8"]
}
```

`evidence_refs` remains **required and non-empty**; unresolved references are
resolved lazily via the existing linkage state machine and are simply
excluded from behavioral-pattern generation until resolvable — they are never
a reason to reject the record. A malformed line is **quarantined** into the
batch's `invalid[]` status (`GET /v1/ingest/{batch_id}`), never causing the
whole batch to be rejected. All timestamps are normalized to UTC on ingest.
`reaction` rows stay INSERT-only/immutable — Phase 2 adds nullable columns
via migration, it does not add triggers that would allow UPDATE/DELETE.

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
