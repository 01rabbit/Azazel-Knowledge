# ADR-0024: Isolate the experimental Knowledge Context profile

Status: accepted for the Nexus #395 development candidate only (2026-11-05).

## Context

The Knowledge Context v1 semantic contract is under review in Azazel-Fabric
Draft PR #76. It is not part of stable Fabric `v0.9.0`. Knowledge main now pins the published
pre-release `v0.10.0rc1` under ADR-0022, which includes the experimental
contract. The Nexus #395 producer route must remain testable against the exact
Fabric #76 candidate without confusing that candidate pin with the normal API
pin or claiming stable-release support.

## Decision

1. Keep the normal `[api]` pin governed by the current release decision (currently published pre-release `v0.10.0rc1`, ADR-0022); do not replace it with the unmerged candidate commit.
2. Provide a separate `api-context-candidate` extra pinned to the immutable
   Fabric PR #76 commit `ec31f7eb9989779594d51b265d3c4dcd78350bbc`.
   Developers use this extra instead of `[api]` for candidate integration
   tests; the two extras must not be combined.
3. Register `/v1/knowledge-context` only when the Fabric semantic module is
   installed. With the current `v0.10.0rc1` API pin, the route is registered,
   but it remains unavailable unless explicit transport configuration is
   injected. A candidate install follows the same disabled-by-default rule.
4. This commit pin is for isolated development verification only. It is not a
   release dependency and must not be used in a shipped artifact. Reassess the
   extra when Fabric publishes a compatible stable contract.
5. The adapter and route remain advisory-only. This decision adds no production
   credentials, network configuration, service activation, or deployment.

## Consequences

The candidate contract's source commit, tests, and installation profile are
explicit. The ordinary product API continues to use the published Fabric
version. CI tests the candidate profile and separately checks the ordinary API profile;
route registration and endpoint availability are distinct, and no transport
configuration means the endpoint is unavailable.
