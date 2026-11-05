# ADR-0024: Isolate the experimental Knowledge Context profile

Status: approved for the Nexus #395 development candidate; awaiting merge (2026-11-05).

## Context

The Knowledge Context v1 semantic contract remains experimental in Fabric.
Knowledge main pins published pre-release `v0.10.0rc1` under ADR-0022; that
normal API pin is distinct from the immutable candidate source commit used to
exercise this integration. The Nexus #395 route must remain testable without
claiming stable-release support.

## Decision

1. Keep the normal `[api]` pin governed by the current release decision (currently published pre-release `v0.10.0rc1`, ADR-0022); do not replace it with the unmerged candidate commit.
2. Provide a separate `api-context-candidate` extra pinned to the immutable
   Fabric main commit `33aa79c79fbabf0bd035e2bbae5bed185a89f9ee` (PR #86,
   carrying the #76 contract).
   Developers use this extra instead of `[api]` for candidate integration
   tests; the two extras must not be combined.
3. Register `/v1/knowledge-context` only when the Fabric semantic module is
   installed. With the current `v0.10.0rc1` API pin, the route is registered,
   but it remains unavailable unless explicit transport configuration is
   injected. A candidate install follows the same disabled-by-default rule.
4. This commit pin is for isolated development verification only. It is not a
   release dependency and must not be used in a shipped artifact. Reassess the
   extra when Fabric publishes a compatible stable contract and version.
5. The adapter and route remain advisory-only. This decision adds no production
   credentials, network configuration, service activation, or deployment.

## Consequences

The candidate contract's source commit, tests, and installation profile are
explicit. The ordinary product API continues to use the published Fabric
version. CI tests the candidate profile and separately checks the ordinary API profile;
route registration and endpoint availability are distinct, and no transport
configuration means the endpoint is unavailable.
