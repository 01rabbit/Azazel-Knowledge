# Security Policy

Azazel-Knowledge (AZ-04, codename `GRIMOIRE`) is an on-premises, advisory-only
threat-knowledge node. It never commands: it returns threat context,
confidence, reasons, and recommendations only. Final authority always stays
with the Azazel-Edge deterministic arbiter, and Edge must remain fully
functional if this node is absent, slow, or wrong.

## Reporting a vulnerability

Report privately via GitHub Security Advisories:
<https://github.com/01rabbit/Azazel-Knowledge/security/advisories/new>

Do **not** open a public issue for a suspected vulnerability.

Include: affected version/commit, relevant configuration (sanitized — strip
keys, tokens, real IOC data), repro steps or a minimal PoC, and observed
impact.

No bounty program. Reporters are credited unless anonymity is requested.

## Response targets

- Acknowledgement: within 7 days
- Initial assessment (severity, affected versions): within 14 days
- Fix and disclosure are coordinated with the reporter.

## Scope

**In scope** — vulnerability classes specific to this product's invariants:

- Advisory-only bypass: any path letting a `/v1/context` response carry
  directive-shaped content past the boundary validators (fail-closed bypass).
- Signed offline-bundle verification bypass (PyNaCl signature check).
- Write access via the read-only plane: SQL injection, or any write path
  reachable through `api/` or `taxii/` — a single-writer-invariant violation.
- Audit-chain integrity break: bypassing `503 audit_unavailable`, or
  undetected audit-chain tamper.
- Research-data tamper: destructive access to local-tier tables (`reaction`,
  `observation`, `advisory_log`, ...) through any exposed surface.
- Determinism poisoning: crafted input causing identical queries (same
  7-element replay tuple) to return different scores.
- Authentication/authorization bypass on the API.

**Out of scope**: threat-feed content quality/false positives; node-absent or
slow behavior (Azazel-Edge is designed to operate fully without this node);
resource exhaustion from oversized feeds within documented memory limits
(`config/` enforces the budget).

## Supported versions

No tagged releases yet. Only `main` is supported; report against the commit
you tested.
