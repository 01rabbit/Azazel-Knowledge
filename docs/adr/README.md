# Architecture Decision Records

The design questions resolved (or explicitly deferred) with rationale. ADR-0001
through 0008 were left open in the initial concept discussion; ADR-0009 records
the Phase 2 Behavioral CTI lane:

| ADR | Question | Decision |
|---|---|---|
| [0001](0001-repository-naming.md) | Repository / product name | **Accepted (2026-07-10)** — formal name `Azazel-Grimoire Advisor`, AZ-04, repo `01rabbit/Azazel-Grimoire` (formerly `Azazel-CTI`); namespace `azazel_grimoire` |
| [0002](0002-data-model.md) | STIX 2.1 vs. lightweight native model | Native model internally; STIX 2.1 at boundaries only |
| [0003](0003-database.md) | SQLite vs. PostgreSQL | SQLite WAL; PostgreSQL only on measured Phase 2 triggers |
| [0004](0004-sync-strategy.md) | Pull / push / USB / differential sync | Scheduled pull online + signed offline bundles (full & differential) |
| [0005](0005-edge-protocol.md) | REST / gRPC / MQTT; evidence format | REST+JSON and TAXII 2.1; JSONL evidence, no bespoke format |
| [0006](0006-scoring.md) | Scoring and weighting | Deterministic weighted YAML config, mandatory reason breakdown |
| [0007](0007-rule-generation.md) | How far to automate rule generation | Advisory drafts with provenance; never auto-deploy |
| [0008](0008-research-theme.md) | Black Hat research framing | "CTI-optimized delaying defense" friction loop, not "lightweight CTI node" |
| [0009](0009-behavioral-cti.md) | Phase 2 Behavioral CTI: envelope, tier, authority, ML | Separate additive lane; own `behavior_config_hash`; local-tier rebuildable; advisory-only + shadow-gated; no ML; no AI attribution |
