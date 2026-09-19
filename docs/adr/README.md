# Architecture Decision Records

The design questions resolved (or explicitly deferred) with rationale. ADR-0001
through 0008 were left open in the initial concept discussion; ADR-0009 records
the Phase 2 Behavioral CTI lane; ADR-0010 ratifies adopting Azazel-Fabric
`cti_contracts` at the API boundary:

| ADR | Question | Decision |
|---|---|---|
| [0001](0001-repository-naming.md) | Repository / product name | **Accepted (2026-07-10)** — formal name `Azazel-Knowledge Advisor`, AZ-04, repo `01rabbit/Azazel-Knowledge` (formerly `Azazel-CTI`); namespace `azazel_knowledge` |
| [0002](0002-data-model.md) | STIX 2.1 vs. lightweight native model | Native model internally; STIX 2.1 at boundaries only |
| [0003](0003-database.md) | SQLite vs. PostgreSQL | SQLite WAL; PostgreSQL only on measured Phase 2 triggers |
| [0004](0004-sync-strategy.md) | Pull / push / USB / differential sync | Scheduled pull online + signed offline bundles (full & differential) |
| [0005](0005-edge-protocol.md) | REST / gRPC / MQTT; evidence format | REST+JSON and TAXII 2.1; JSONL evidence, no bespoke format |
| [0006](0006-scoring.md) | Scoring and weighting | Deterministic weighted YAML config, mandatory reason breakdown |
| [0007](0007-rule-generation.md) | How far to automate rule generation | Advisory drafts with provenance; never auto-deploy |
| [0008](0008-research-theme.md) | Black Hat research framing | "CTI-optimized delaying defense" friction loop, not "lightweight CTI node" |
| [0009](0009-behavioral-cti.md) | Phase 2 Behavioral CTI: envelope, tier, authority, ML | Separate additive lane; own `behavior_config_hash`; local-tier rebuildable; advisory-only + shadow-gated; no ML; no AI attribution |
| [0010](0010-adopt-fabric-cti-contracts.md) | Adopt `azazel_fabric.cti_contracts` at the API boundary? | **Accepted (2026-07-10)** — adopt `azazel-fabric` as an `api`-extra-only dependency for boundary payload validation; scope `api/`+`taxii/` only, never `scoring/`/`correlate/`/`core/`; additive, shapes unchanged. Originally tag-pinned `v0.3.0`; **pin in force is `v0.8.0`** per ADR-0016 and `pyproject.toml` |
| [0011](0011-deception-observation-ingest.md) | AZ-06 deception-observation ingest + effectiveness advisory | **Accepted (2026-08-15)** — effectiveness boundary; advisory-only |
| [0012](0012-mitre-engage-ingest.md) | MITRE Engage ingest | Proposed (design spike) |
| [0013](0013-yara-sigma-corpus-ingest.md) | YARA/Sigma rule-corpus ingest as knowledge | Proposed (design spike) — store rule text + metadata as intel-tier knowledge, never a scanner; no `yara-python`/`pysigma` |
| [0014](0014-epss-advisory-ingest.md) | EPSS exploit-probability ingest as advisory context | Proposed (design spike) — intel-tier `epss_score`, own `epss_generation` out of the scoring 7-tuple, secondary context only (never a scoring input), stdlib-only, no new dependency; implementation demand-gated |
| [0016](0016-fabric-pin-v0-8-0.md) | Move the Fabric api-extra pin to `v0.8.0`? | **Accepted (2026-09-19)** — aligns with Edge and Deception and with the series R0 reference candidate; 817 tests green and every imported symbol verified against the tag; scope unchanged (api-extra only, never core) |
| [0015](0015-knowledge-lite-bundle.md) | Knowledge Lite bundle profile for Nexus/Boot | Proposed (design) — a **profile** of the existing signed bundle, not a second format; deterministic selection from a pinned tuple; capacity ceilings fail closed rather than truncate; export denies local-sensitive data by default with canary tests; build never touches `local.db` or the active generation; Knowledge produces and signs, consumers own caching and trust |
