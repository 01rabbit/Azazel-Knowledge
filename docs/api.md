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

## Lookup and context (Edge → CTI, synchronous, triggered)

### `POST /v1/ioc/search`

```json
{ "type": "ip", "value": "203.0.113.7" }
```

```json
{
  "match": true,
  "confidence": 82,
  "sources": ["cisa-kev", "threatfox"],
  "first_seen": "2026-05-01T00:00:00Z",
  "last_seen": "2026-07-01T12:00:00Z",
  "source_freshness_days": 4
}
```

`POST /v1/ja3/search`, `POST /v1/ja4/search` follow the same shape.

### `POST /v1/context`

The full advisory contract. Input: a normalized event or entity set.
Output — every field advisory, every score explained:

```json
{
  "threat_context": {
    "ioc_matches": [ ... ],
    "campaign": { "name": "...", "actor": "...", "confidence": 61 },
    "attack_mapping": [ { "technique": "T1595.002", "tactic": "reconnaissance" } ],
    "pattern_match": { "pattern_id": "pm-2026-0113", "similarity": 0.87 },
    "history": { "prior_observations": 14, "trend": "increasing" }
  },
  "threat_score": 74,
  "confidence": 68,
  "reason": [
    { "component": "ioc_match",    "weight": 0.35, "contribution": 35, "detail": "ip in threatfox, 4 days old" },
    { "component": "history",      "weight": 0.20, "contribution": 12, "detail": "14 prior hits, rising" },
    { "component": "attack_map",   "weight": 0.15, "contribution": 11, "detail": "T1595.002 via pattern pm-2026-0113" },
    { "component": "campaign",     "weight": 0.15, "contribution": 9,  "detail": "weak actor overlap" },
    { "component": "geo_asn",      "weight": 0.15, "contribution": 7,  "detail": "ASN reputation low" }
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
Knowledge Plane idea: the node explains, it does not command.

### Other read endpoints

| Endpoint | Purpose |
|---|---|
| `GET /v1/campaigns` / `GET /v1/campaigns/{id}` | campaign browsing for operators |
| `GET /v1/recommendations/rules` | pending advisory rule drafts (ADR-0007: never auto-deployed) |
| `GET /v1/reactions/summary` | attacker-reaction statistics (research/report view) |
| `GET /v1/health` | liveness + DB/feed staleness summary |
| TAXII 2.1 collections | STIX export for upstream sharing (Phase 4) |

## Versioning

All endpoints under `/v1/`. The advisory response contract is the API's most
stable surface: additive changes only within a major version, and the
`reason[]` component breakdown is mandatory in every scoring response.
