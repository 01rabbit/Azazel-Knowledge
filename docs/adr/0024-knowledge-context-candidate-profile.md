# ADR-0024: Isolate the experimental Knowledge Context profile

Status: accepted for isolated Context profile tests only (2026-11-05).

## Context

The Knowledge Context v1 profile is published in stable Fabric v0.10.0, but
Fabric classifies it as experimental and makes no compatibility promise.
Knowledge main pins that exact tag under ADR-0023. Nexus #395 needs the
producer route for isolated software integration tests, without confusing
contract integrity with the truth of Knowledge claims or enabling a live
service.

## Decision

1. Keep the normal api extra pinned to published stable Fabric v0.10.0 under
   ADR-0023. Use its exact tag and signed release digest (verification is recorded in
   ADR-0023); do not use floating main references.
2. Keep api-context-candidate as a test-only extra pinned to the same exact
   v0.10.0 tag. It is used instead of api for isolated producer-path tests;
   do not combine the extras.
3. Register /v1/knowledge-context only when the Fabric semantic module is
   installed. Even with v0.10.0 installed, the route remains unavailable
   unless explicit transport configuration is injected.
4. Fabric signature and schema validation establish signer, integrity, and
   contract shape; they do not establish that a Knowledge claim is true.
5. This decision adds no production credentials, network configuration,
   service activation, merge, release, or deployment.

## Consequences

Both ordinary API and isolated Context tests resolve Fabric from the published
v0.10.0 tag. Knowledge keeps the route optional and disabled without explicit
configuration. A later contract update requires a reviewed exact-tag pin and
the existing version, lock, and compatibility checks.
