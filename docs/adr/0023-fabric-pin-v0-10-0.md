# ADR-0023: Move the Azazel-Fabric api-extra pin to the stable `v0.10.0`

Status: proposed (Draft PR; becomes accepted when the owner merges it)

## Context

[ADR-0022](0022-fabric-pin-v0-10-0rc1.md) recorded the pre-release
`v0.10.0rc1` as the Knowledge `api`-extra pin, as a bounded deviation from the
stable-tag policy, with the exit condition "move to the stable `v0.10.0` when
Fabric publishes it, in its own ADR". Fabric has published `v0.10.0`; this ADR
is that move, and it closes the deviation.

- The annotated tag `v0.10.0` (tag object `59a5b3c…`) resolves to commit
  `397fcce7a87ca7ab1a5e84bc196c44d70c404907`. The GitHub Release is marked
  stable and Latest, created by Fabric's Release workflow
  (`github-actions[bot]`, run `42005988104`, which succeeded including digest
  and signature verification).
- Its release digest is
  `sha256:d789f27464114bf29bbdc64fcc515cdbdfc02903a0b42af4de3dc707446e302f`.
  The digest file `release/v0.10.0.digest.json` and its signature
  `release/v0.10.0.digest.json.sig` are part of the tag's own tree.
- `src/` differs from `v0.10.0rc1` only in `version.py` (the version string
  and its docstring). The contract surface, including
  `azazel_fabric.knowledge_context` and the producer captures in
  `azazel_fabric.testing`, is the same as `rc1`. A consumer on `rc1` moves with
  no code change.

## Decision

The `api`-extra pin is `azazel-fabric @
git+https://github.com/01rabbit/Azazel-Fabric.git@v0.10.0`, as declared in
`pyproject.toml`. It remains an API-boundary dependency only; Fabric is not a
core dependency, and Knowledge's product version (`0.1.0`) is unchanged.
ADR-0022 remains the record of why a candidate was pinned; this ADR supersedes
only its current-pin statement. No Knowledge source change is needed. The pin
is again an exact stable tag, so no candidate-pin reason or exit condition is
carried forward.

### What stays experimental

Fabric's CHANGELOG `[0.10.0]` divides the surface:

- **Stable**: `deception_contracts`, `effect_contracts`,
  `engagement_contracts`, `outcome_contracts` (the same four as `v0.9.0`), and
  the rest of the `v0.8.0` surface except `cti_contracts`.
- **Experimental, no compatibility promise**: `cti_contracts`,
  `mio_contracts`, `external_security_contracts`, `provisioning_contracts` and
  `knowledge_context`.

A stable tag does **not** make `cti_contracts` (Knowledge's API boundary,
[ADR-0010](0010-adopt-fabric-cti-contracts.md)) or `knowledge_context`
(Knowledge#116) stable: a later Fabric tag may change either. This is why the
pin stays an exact tag, why Fabric stays `api`-extra-only, and why every pin
move is an ADR with a test run.

### What the stable tag does not claim

Per the same changelog: there is no aggregated, signed conformance
attestation; the consumer tests that read the producer captures (Knowledge#120
among them) are cited as evidence, not certification; and the open Knowledge
Context integrations — the producer Knowledge#116 and the consumers MIO#47 and
Nexus#402 — are outside this release's guarantee and are not conditions of the
tag. Knowledge does not read this pin as covering #116.

## Compatibility and verification evidence

- Fabric was checked out at tag `v0.10.0` (HEAD `397fcce…`) in a clean clone:
  `tools/rc_digest.py --check release/v0.10.0.digest.json` reported that the
  tree matches `sha256:d789f27…`, and (with PyNaCl installed)
  `tools/rc_signature.py --check release/v0.10.0.digest.json` reported
  "signed by: release-owner". Knowledge did not itself establish who holds the
  signing key beyond that tool's check.
- `azazel_fabric.__version__ == "0.10.0"` after `pip install -e '.[api,dev]'`
  on Python 3.12 and 3.11. The full unit suite (including the producer-capture
  tests of Knowledge#120), `azctl check-config` and `tools/docs-sync-check.py`
  were run on both; no test was removed, skipped or relaxed (see the pull
  request for the summary lines).
- This evidence does not establish a socket-level Fabric-to-Knowledge service
  integration, TLS, or production deployment.

## Rollback

Set the `pyproject.toml` pin back to `@v0.10.0rc1` and reinstall. Because the
contract surface is the same, no code or test change is needed.

## Consequences

- Current documentation names `v0.10.0` as the pin in force; `v0.10.0rc1` and
  earlier appear only as history.
- No package version, tag, release, signing or deployment is created.
