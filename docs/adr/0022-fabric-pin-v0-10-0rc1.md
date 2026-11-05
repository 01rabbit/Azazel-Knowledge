# ADR-0022: Move the Azazel-Fabric api-extra pin to the pre-release `v0.10.0rc1`

Status: proposed (Draft PR; becomes accepted when the owner merges it)

## Context

[ADR-0021](0021-fabric-pin-v0-9-0.md) recorded the stable `v0.9.0` as the
Knowledge `api`-extra pin. Fabric has since published the pre-release
`v0.10.0rc1`, the first candidate toward `v0.10.0`.

- The annotated tag `v0.10.0rc1` resolves to commit
  `36db04412679e2694d697595cbf913d0bfc72019`. The GitHub Release is a
  **pre-release** created by Fabric's Release workflow
  (`github-actions[bot]`, run `41980381843`, which succeeded including digest
  and signature verification). `v0.9.0` remains Fabric's Latest stable
  release.
- Its release digest is
  `sha256:114402979360855ccaeb92fcc1851db1b03572a289c43e3591633f263b7559eb`.
  As with `v0.9.0`, the digest file `release/v0.10.0rc1.digest.json` and its
  signature `release/v0.10.0rc1.digest.json.sig` are part of the tag's own
  tree (signed before the tag was cut).
- It is **additive** over `v0.9.0`. Between the two tags `src/` changes only
  by adding `azazel_fabric/knowledge_context.py` and the producer captures
  (`azazel_fabric/testing/producer_captures.py`,
  `testing/_producer_capture_data.py`, exported from `testing/__init__.py`),
  and by `version.py`. No released name changed.

## Decision

The `api`-extra pin is `azazel-fabric @
git+https://github.com/01rabbit/Azazel-Fabric.git@v0.10.0rc1`, as declared in
`pyproject.toml`. It remains an API-boundary dependency only; Fabric is not a
core dependency, and Knowledge's product version (`0.1.0`) is unchanged.
ADR-0021 remains the record of the `v0.9.0` adoption; this ADR supersedes only
its current-pin statement. No Knowledge source change is needed for the move.

### Why a candidate rather than the stable tag

The pin policy prefers an exact stable tag. This is a recorded, bounded
deviation, with its reason and its exit stated here:

- **Reason.** `v0.10.0rc1` is the first Fabric tag carrying the two surfaces
  Knowledge's next work needs: the experimental Knowledge Context v1 profile
  (`azazel_fabric.knowledge_context`, Fabric#76, landed as Fabric#86), which
  the Knowledge Context producer adapter (Knowledge#116) emits, and the
  producer captures in `azazel_fabric.testing` (Fabric#23, landed as
  Fabric#85), which the consumer tests in Knowledge#120 read. Neither exists in
  `v0.9.0`, and copying either into this repository is what the boundary
  forbids.
- **Exit.** Move to the stable `v0.10.0` when Fabric publishes it, in its own
  ADR; that move is expected to need no code change if the contract surface is
  unchanged from `rc1`. If `v0.10.0` is not cut, the pin is revisited rather
  than left on a candidate.

### Stability of what Knowledge reads

- **Stable** in Fabric: `deception_contracts`, `effect_contracts`,
  `engagement_contracts`, `outcome_contracts` — unchanged from `v0.9.0`.
- **Experimental, no compatibility promise**: `cti_contracts`,
  `mio_contracts`, `external_security_contracts`, `provisioning_contracts`,
  and now `knowledge_context`.

`knowledge_context` is experimental: a later Fabric tag may change it without
a compatibility promise. Knowledge#116 must therefore treat it as such (exact
tag pin, an ADR and a test run on every move), as already applies to
`cti_contracts` ([ADR-0021](0021-fabric-pin-v0-9-0.md)). Producer captures are
records of what one producer commit emitted; they are not a certification of
any product and grant no authority.

## Compatibility and verification evidence

- Fabric was checked out at tag `v0.10.0rc1` (HEAD `36db044…`) in a clean
  clone: `tools/rc_digest.py --check release/v0.10.0rc1.digest.json` reported
  that the tree matches `sha256:1144029…`, and (with PyNaCl installed)
  `tools/rc_signature.py --check release/v0.10.0rc1.digest.json` reported
  "signed by: release-owner". Knowledge did not itself establish who holds the
  signing key beyond that tool's check.
- `azazel_fabric.__version__ == "0.10.0rc1"` after `pip install -e
  '.[api,dev]'` on Python 3.12 and 3.11. The full unit suite and
  `tools/docs-sync-check.py` were run on both; no test was removed, skipped
  or relaxed (see the pull request for the summary lines).
- This evidence does not establish a socket-level Fabric-to-Knowledge service
  integration, TLS, or production deployment.

## Rollback

Set the `pyproject.toml` pin back to `@v0.9.0` and reinstall. Because
`v0.10.0rc1` is additive and this move changes no Knowledge code, no code or
test change is needed; tests that read `knowledge_context` or the producer
captures (added separately) would then skip or fail as their own PRs state.

## Consequences

- Current documentation names `v0.10.0rc1` as the pin in force; `rc5`, `rc6`
  and `v0.9.0` appear only as history.
- No package version, tag, release, signing or deployment is created.
