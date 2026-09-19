# Feed sync and offline operation

Offline is the primary mode; online is the convenience (ADR-0004). Nothing
in the query path may depend on internet access.

## Feed adapters (online, optional)

One adapter per source, checkpointed in `feed_state`, rate-limited, run by
the background worker on a schedule only when a link is available.

| Feed | Content | Method |
|---|---|---|
| MITRE ATT&CK | techniques, mitigations, detections | official STIX bundle, version-pinned |
| NVD / CVE, CWE, CAPEC | vulnerability context | JSON feeds / API |
| CISA KEV | exploited-in-the-wild CVEs | JSON |
| AbuseIPDB | IP reputation | API (key, quota-aware) |
| URLHaus / MalwareBazaar / ThreatFox | URLs, hashes, IOCs | abuse.ch exports |
| AlienVault OTX | pulses | API (key) |
| Spamhaus | drop lists | rsync/text |
| GeoIP / ASN | enrichment | MaxMind-style DB files |
| Generic TAXII 2.1 | any STIX source (incl. other Azazel sites) | TAXII pull |

Adapter contract: idempotent, resumable, records source + fetch time per
item, never writes partially validated data into live tables (stage →
validate → swap).

## Offline bundle

A single signed artifact that moves the node's knowledge across an air gap:

```
azazel-knowledge-bundle-YYYYMMDD-NNN.tar.gz
├── manifest.json      # bundle version, base version (for diffs), feed list,
│                      # per-file SHA-256, created_at, attack_version
├── manifest.sig       # detached signature (ed25519, offline signing key)
├── snapshots/         # full table snapshots (first install / periodic full)
└── deltas/            # per-feed differential updates since base version
```

Implementation note: Phase 1 currently uses stdlib gzip (`.tar.gz`); zstd
remains deferred in S13 pending the dependency-minimality tradeoff noted in
`bundle/verify.py`.

- **Full bundle**: complete DB state; used for first provisioning and
  periodic re-baselining.
- **Differential bundle**: deltas since a stated base version; importer
  refuses a delta whose base does not match the local version — no silent
  gaps.
- **Monotonic versioning**: importer rejects version regressions
  (anti-rollback), consistent with the signed-bundle rule in
  [architecture.md](architecture.md#security-boundary).

Transport is whatever the field allows: USB, SSD, or LAN copy from a
better-connected site. The bundle builder runs on any online Azazel-Knowledge (formerly Azazel-CTI) node
(or a plain workstation with the toolchain) — this is also the Phase 4
Regional CTI distribution mechanism.

### Knowledge Lite — a bounded profile of the same bundle

**Knowledge Lite is a capacity profile of the signed bundle above, not a second
format.** Same container, same manifest, same signature and anti-rollback
rules; what differs is that its content is selected down to a bounded subset of
*intel-tier* knowledge so it fits a small node.

- **Who consumes it.** Azazel-Nexus and Azazel-Boot, which embed a read-only
  Lite cache. Knowledge produces and signs; the consumer owns caching, trust
  policy, and what it does when the artifact is missing — **a consumer that
  cannot read a Lite artifact stays fully operational**, like every other
  advisory path here.
- **Always `kind: full`.** `build-lite` offers no `--base` and no `--kind`; a
  Lite artifact is never a differential ([ADR-0017](adr/0017-lite-is-full-only.md)).
  The general bundle path above keeps its differentials.
- **Reproducible from a pinned tuple.** Selection is a pure function of
  `(as_of, intel_generation, stats_generation, attack_version, config_hash,
  export-policy digest, profile)` — no clock, no randomness, no directory
  order — so the same tuple rebuilds the same unsigned bytes on any host, later.
- **Ceilings fail closed.** `knowledge-lite-16g` / `knowledge-lite-32g` declare
  row, byte, dataset, and freshness limits; a build that would exceed one fails
  with a named error instead of shipping a truncated artifact that lies about
  its coverage.
- **Export denies by default.** Only fields an explicit allowlist names leave
  this node; a claim that cannot carry its provenance (citation, source,
  freshness, expiry, confidence ceiling, limitations) is not exported at all.
- **Never touches `local.db` or the active generation.** The build reads a
  snapshot out of the query path and writes only its own artifact.

Building one, with the full flag list, is in
[operations.md](operations.md#knowledge-lite-build-a-bounded-artifact-for-nexus--boot).

**The contract lives in [ADR-0015](adr/0015-knowledge-lite-bundle.md)**
(profile, deterministic selection D2, measured capacity ceilings D3, provenance
D4, export policy D5, signer-role/security-epoch gates D5b, ownership boundary
D7), refined by [ADR-0017](adr/0017-lite-is-full-only.md). Implementation:
`src/azazel_knowledge/bundle/lite_select.py`, `bundle/lite_policy.py`,
`tools/bundle_build.py build-lite`, `tools/lite_fixture.py`.

## Direction of sync

| Path | Content | Mode |
|---|---|---|
| Internet → CTI | external feeds | pull, scheduled, optional |
| Courier → CTI | signed bundles | offline import |
| Edge → CTI | evidence, reactions | push (REST/TAXII), continuous |
| CTI → Edge | advisory context | pull by Edge, triggered |
| CTI → Regional (Phase 4) | STIX export, reaction summaries | TAXII push/pull or bundle |

Note the asymmetry: knowledge flows down freely; **authority never flows
down at all** — even a Regional CTI tier only ever supplies data, never
commands, preserving the advisory-only contract end to end.

## Staleness handling

- `GET /v1/health` reports per-feed age; every advisory answer carries
  `source_freshness`.
- Confidence decays with source age ([scoring.md](scoring.md)) — an offline
  month degrades scores gracefully instead of lying with stale certainty.
- No hard cutoff: in a disaster deployment, old intelligence with an honest
  freshness label is still better than nothing.
