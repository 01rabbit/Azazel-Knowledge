# ADR-0005: Edge↔CTI protocol = REST/JSON (+ TAXII 2.1 for bundles); evidence format = JSONL

Status: accepted (design phase)

## Context

Candidates: REST, gRPC, MQTT. Also open: evidence format — JSONL, STIX
bundle, or a bespoke format. Azazel-Edge's existing integration stack is
Python/Flask with stdlib `urllib`, plus a working STIX exporter and TAXII 2.1
push client (#238/#248). Suricata already emits EVE JSON; Edge logging is
JSONL throughout.

## Decision

- **Synchronous queries and ingest: REST + JSON** ([api.md](../api.md)),
  bearer token, optional mTLS.
- **Bulk/interop exchange: TAXII 2.1** — the CTI node exposes an inbox the
  existing Edge push client can use unchanged.
- **Evidence format: JSONL** internally and on ingest endpoints; STIX
  bundles only at the TAXII boundary (per ADR-0002). No bespoke format.

## Rationale

- REST works with what Edge already ships; no new client dependencies on the
  constrained device, trivially debuggable offline with curl.
- The latency budget (250 ms full context on LAN) does not need gRPC; the
  hot path is protected by query discipline, not transport speed.
- MQTT adds a broker to operate for a fan-in problem we don't have until
  Phase 2+ — revisit only if multi-Edge ingest measurably needs it.
- JSONL matches EVE and Edge audit logs: evidence flows without
  transformation, and every layer can be tailed and grepped in the field.

## Consequences

- gRPC/MQTT remain open as measured-need upgrades; the API contract in
  api.md is transport-neutral enough to port.
