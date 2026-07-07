# Data model

Internal storage uses a **native lightweight relational model** tuned for
lookup latency on Pi 4. STIX 2.1 is an interchange format at the boundary
only (import/export), never the query model. See ADR-0002.

## Stores

### ioc

Indicators of compromise, one row per indicator, unique on `(type, value)`.

| Column | Notes |
|---|---|
| type | `ip`, `domain`, `url`, `hash_md5/sha1/sha256`, `email`, `asn`, `certificate`, `ja3`, `ja4` |
| value | normalized (lowercase, A-label punycode for IDN, defanged input re-armed) |
| first_seen / last_seen | UTC |
| sources | JSON array of feed ids |
| tags | JSON array |
| confidence | 0–100, per [scoring.md](scoring.md) |
| expires_at | TTL per feed policy; expired rows excluded from matches, kept for history |

Indexes: `(type, value)` unique; `last_seen`; per-type partial indexes for
the hot types (`ip`, `domain`, `ja3`, `ja4`).

### attack

MITRE ATT&CK snapshot: technique, sub-technique, tactic, mitigations,
detections, data sources. Refreshed from the official STIX bundle; stored
flattened for join-free lookup. Version pinned per import (`attack_version`).

### campaign

| Column | Notes |
|---|---|
| name, actor | |
| industries, regions | JSON arrays |
| confidence | analyst/source confidence, 0–100 |
| ioc_refs | join table `campaign_ioc` |
| technique_refs | join table `campaign_technique` |

### observation — historical evidence from Edge

Every event received from Azazel-Edge, normalized:

| Column | Notes |
|---|---|
| event_id | Edge-side evidence id (correlates with Edge audit trail) |
| edge_id | which Edge sent it (Phase 2+: several) |
| kind | `eve_alert`, `dns`, `http`, `flow`, `canary_hit`, `delay_history`, ... |
| observed_at | |
| entities | extracted IOC candidates (JSON) |
| raw | original JSONL payload |

Aggregates (frequency, trend per entity) are maintained in
`observation_stats` by the background worker, not computed at query time.

### reaction — the Tactical CTI Sensor core (Azazel-Edge #283)

What makes this node more than an IOC cache: structured records of **attacker
behavior under friction**.

| Column | Notes |
|---|---|
| actor_key | source entity (ip / ja3 / session cluster) |
| action_applied | `throttle`, `redirect`, `isolate`, `delay`, `deception` |
| applied_at | |
| reaction | `continued_scanning`, `shifted_port`, `shifted_protocol`, `shifted_target`, `followed_decoy`, `auth_pattern_changed`, `disengaged`, `unknown` |
| reaction_window_s | seconds observed after the action |
| evidence_refs | observation ids backing the classification |

This table is the input to the Pattern Generator and the primary export for
the "CTI value of delaying defense" research theme (ADR-0008).

### pattern — Tactical Pattern Memory

| Column | Notes |
|---|---|
| pattern_id, version | |
| match_spec | declarative predicate over normalized evidence (JSON) |
| attack_refs | ATT&CK technique ids |
| provenance | which CTI sources / reactions produced it |
| advisory | suggested rule / delay / decoy templates |
| confidence | |

Patterns are **compiled artifacts**, regenerated from source data; the store
can be rebuilt at any time. A pattern match is advisory context, never a
verdict.

### reputation

Rolling reputation per ip / domain / hash: score, contributing sources,
decay timestamps. Derived data — rebuildable from `ioc` + `observation`.

### feed_state

Per-feed cursor: last run, last success, item counts, checksum of last
snapshot, enabled flag. Drives both online pulls and offline bundle
version checks.

## Normalization rules

- All timestamps UTC ISO 8601.
- IOC values canonicalized before insert (case normalization, A-label IDN
  normalization, URL normalization). Internationalized domain names are
  stored in A-label (`xn--` punycode) form, not U-label Unicode display form;
  matching is exact-after-normalization, plus CIDR containment for IPs and
  suffix match for domains.
- U-label storage is not a safe canonical form because visually identical
  homoglyph and mixed-script domains can remain distinct byte strings and
  evade exact matching. Canonicalizing IDNs to A-label with IDNA via the
  `idna` library collapses those variants to one stable representation and
  preserves the soundness of exact-after-normalization matching.
- Every derived row (`reputation`, `observation_stats`, `pattern`) records
  its inputs, so any answer can be traced to raw evidence — the same
  auditability rule Azazel-Edge applies to actions.

## STIX 2.1 mapping (boundary only)

| Internal | STIX |
|---|---|
| ioc | `indicator` (pattern) |
| campaign | `campaign` / `intrusion-set` |
| attack | `attack-pattern` (consumed from MITRE bundle) |
| observation | `observed-data` |
| reaction | `observed-data` + custom extension `x-azazel-reaction` |
| pattern advisory | `course-of-action` (advisory semantics preserved) |

Import: STIX feeds and Edge TAXII pushes are flattened into the tables above.
Export: TAXII 2.1 collections serve generated bundles for upstream sharing
(Phase 4 Regional CTI), reusing the exporter design from Azazel-Edge #224/#238.
