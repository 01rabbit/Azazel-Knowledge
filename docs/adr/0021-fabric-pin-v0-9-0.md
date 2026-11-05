# ADR-0021: Move the Azazel-Fabric api-extra pin to the stable `v0.9.0`

Status: accepted (owner-merged in PR #119)

## Context

[ADR-0020](0020-fabric-pin-v0-9-0rc6.md) recorded the pre-release `v0.9.0rc6`
as the Knowledge `api`-extra pin. Fabric has since published the stable
release `v0.9.0`.

- The annotated tag `v0.9.0` resolves to commit
  `ee2ab8cf5173b5967481d2452dfd5fd8cf76ade6`. The GitHub Release is marked
  stable and Latest; Fabric's Release workflow (run `41953612183`) succeeded,
  including signature verification.
- Its release digest is
  `sha256:5107054682802f1e615615d0de51471859014d31a8808b61d8cbf6c16b27dbf4`.
  Unlike `rc6`, the digest file `release/v0.9.0.digest.json` and its signature
  `release/v0.9.0.digest.json.sig` are part of the tag's own tree.
- `src/` differs from `v0.9.0rc6` only in `version.py`. The contract surface,
  including the four `OutcomeObservationEnvelope` fields of Fabric#72, is the
  same as `rc6`. A consumer on `rc6` moves with no code change.

## Decision

The `api`-extra pin is `azazel-fabric @
git+https://github.com/01rabbit/Azazel-Fabric.git@v0.9.0`, as declared in
`pyproject.toml`. It remains an API-boundary dependency only; Fabric is not a
core dependency, and Knowledge's product version (`0.1.0`) is unchanged.
ADR-0020 remains the record of the `rc6` adoption and of the handling of the
four envelope fields; this ADR supersedes only its current-pin statement.
No Knowledge source change is needed.

### `cti_contracts` is experimental in Fabric

Fabric's CHANGELOG `[0.9.0]` divides the surface:

- **Stable** (R1c gate met): `deception_contracts`, `effect_contracts`,
  `engagement_contracts`, `outcome_contracts`, and the rest of the `v0.8.0`
  surface **except `cti_contracts`**.
- **Experimental, no compatibility promise**: `cti_contracts`, `mio_contracts`,
  `external_security_contracts`, `provisioning_contracts`.

Knowledge's API boundary uses `azazel_fabric.cti_contracts`
([ADR-0010](0010-adopt-fabric-cti-contracts.md)). Moving to a stable tag
therefore does **not** make that dependency stable: Fabric makes no
compatibility promise for `cti_contracts`, so a later Fabric tag may change it.
This is why the pin stays an exact tag, why Fabric stays `api`-extra-only, and
why every pin move is an ADR with a test run. The outcome, deception, effect
and engagement families Knowledge also reads are stable.

### What the stable tag does not claim

Per Fabric's CHANGELOG, `v0.9.0` does not claim an aggregated, signed
conformance attestation across products, nor interoperability tested against
golden fixtures built from a real producer's output (both are next-release
work). Knowledge's tests use Fabric's own models and do not fill that gap.

## Compatibility and verification evidence

- Fabric was checked out at tag `v0.9.0` (HEAD `ee2ab8c…`):
  `tools/rc_digest.py --check release/v0.9.0.digest.json` reported that the
  tree matches `sha256:5107054…`, and (with PyNaCl installed)
  `tools/rc_signature.py --check release/v0.9.0.digest.json` reported
  "signed by: release-owner". Knowledge did not itself establish who holds the
  signing key beyond that tool's check.
- `azazel_fabric.__version__ == "0.9.0"` after `pip install -e '.[api,dev]'`
  on Python 3.12 and 3.11. The full unit suite and
  `tools/docs-sync-check.py` were run on both; no test was removed, skipped
  or relaxed (see the pull request for the summary lines).
- This evidence does not establish a socket-level Fabric-to-Knowledge service
  integration, TLS, or production deployment.

## Rollback

Set the `pyproject.toml` pin back to `@v0.9.0rc6` and reinstall. Because the
contract surface is the same, no code or test change is needed.

## Consequences

- Current documentation names `v0.9.0` as the pin in force; `rc5` and `rc6`
  appear only as history.
- No package version, tag, release, signing or deployment is created.
