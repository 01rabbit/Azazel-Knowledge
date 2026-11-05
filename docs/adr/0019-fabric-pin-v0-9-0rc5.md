# ADR-0019: Record the current Azazel-Fabric API-extra pin

Status: accepted (2026-11-03 — owner-merged in Azazel-Knowledge PR #114);
current-pin decision superseded by [ADR-0020](0020-fabric-pin-v0-9-0rc6.md)
and then [ADR-0021](0021-fabric-pin-v0-9-0.md)

## Context

[ADR-0016](0016-fabric-pin-v0-8-0.md) recorded `v0.8.0` as the Knowledge
`api`-extra pin. Knowledge PR #114 later changed `pyproject.toml` from Fabric
`v0.9.0rc2` to `v0.9.0rc5`, but the active README, API guide, architecture
guide, roadmap, and ADR index still named `v0.8.0`.

The merged pin change was needed for the Deception outcome-envelope path:
Fabric `v0.9.0rc5` supports the typed-reference grammar used by that path and
the `EffectObservation` restrictions validated by Knowledge. The released tag
`v0.9.0rc5` resolves to commit
`450d9502884ba533653210056a6fb85012b96b84`; it is a published pre-release,
not a stable release. The interim `v0.9.0rc2` pin was present at PR #114's
base and was replaced by commit `1146eec` in that PR; no separate ADR was
recorded for that interim pin. Fabric main at
`8e765430326fbdf63c8b1a65119c04da3ee88383` reports `0.9.0rc6.dev0`; that
development snapshot is not the Knowledge dependency and has no published
`v0.9.0rc6` tag.

## Decision

The current Knowledge `api`-extra pin is `azazel-fabric @
git+https://github.com/01rabbit/Azazel-Fabric.git@v0.9.0rc5`, as declared in
`pyproject.toml`. It remains an API-boundary dependency only. Fabric is not a
core dependency, and this pin does not change Knowledge's product version
(`0.1.0`) or declare a Knowledge release.

ADR-0016 remains the historical record for adopting `v0.8.0`; this ADR
supersedes only its current-pin statement. It does not adopt Fabric's newer
development candidate or change the API wire contract beyond the already
merged PR #114 implementation.

## Compatibility and verification evidence

- The pin-only step in PR #114 reported 1,437 unit tests passing under both
  `v0.9.0rc2` and `v0.9.0rc5` before the outcome-envelope implementation was
  added.
- GitHub Actions run
  [41601931336](https://github.com/01rabbit/Azazel-Knowledge/actions/runs/41601931336)
  tested current main `1f3ceae1ed1a8998e10f5d246cad1dc80db7200c`. The test
  job installed `azazel-fabric 0.9.0rc5` and reported **1,595 passed**; the
  configuration check also succeeded.
- The run verifies the current Knowledge unit suite with the declared pin. It
  does not establish a socket-level Fabric-to-Knowledge service integration,
  TLS, signature verification, or production deployment.

## Consequences

- Current documentation now agrees with `pyproject.toml` and the tested main
  commit.
- `v0.8.0` references inside this ADR's predecessor and in historical audit
  records continue to describe the versions tested at those times.
- No package version, tag, release, signing, or deployment is created by this
  documentation correction.
