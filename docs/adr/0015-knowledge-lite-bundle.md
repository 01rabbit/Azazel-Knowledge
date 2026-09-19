# ADR-0015: Knowledge Lite bundle profile for Nexus and Boot (design)

Status: proposed (design, 2026-09-19 — Azazel-Knowledge#73)

## Context

AZ-07 Azazel-Nexus and AZ-03 Azazel-Boot need a bounded, signed, offline
knowledge artifact so that a field node keeps cited threat context when no
AZ-04 full node is reachable. The cross-repository plan calls this
**Knowledge Lite**, and the R0 register assigns its production to this
repository (Azazel#70, Azazel-Nexus#6, Azazel-Boot#1).

Nothing in this repository currently mentions Knowledge Lite: a grep for
`knowledge.lite` over `docs/`, `src/`, `tools/`, and `tests/` returns zero
matches. What *does* exist is a mature offline-bundle mechanism, and the first
job of this ADR is to state plainly that Lite is a **profile of that
mechanism**, not a second artifact format.

### What already exists

`azazel_knowledge.bundle.verify` and `tools/bundle_build.py` implement signed
`.tar.gz` bundles with `manifest.json` then `manifest.sig` as the first two
members. Verified in the tree at the time of writing:

| Property | Where |
|---|---|
| Byte-identical rebuilds — table dumps ordered by primary key | `tools/bundle_build.py` module docstring |
| Full and differential (`--since`) bundles | `tools/bundle_build.py` |
| Trust never read from inside the bundle; keys, threshold, revocations from a caller-supplied `anchors.toml` | `verify.py` module docstring (F-7) |
| Anti-rollback watermark from a caller-supplied `state.toml` | `verify.py` (F-7) |
| A manifest naming a local-tier table hard-aborts before any content byte is written | `verify.py`, `LOCAL_TIER_TABLES` (F-1) |
| A manifest carrying a field shaped like a trust or rollback document hard-aborts | `_FORBIDDEN_MANIFEST_FIELDS` |
| Absolute paths, `..`, empty path parts rejected | `_safe_member` |
| Symlinks, hardlinks, devices, FIFOs, char/block, any non-regular member rejected | `_safe_member` |
| Undeclared members rejected (`BUNDLE_UNDECLARED_MEMBER`); declared-but-absent rejected (`BUNDLE_FILE_MISSING`) | `_extract_declared_files` |
| Per-file, total, manifest, and expansion-ratio caps | `DEFAULT_MAX_*`, `BUNDLE_DECOMPRESSION_BOMB` |
| Per-member SHA-256 verified against `manifest.files` immediately after write | `_extract_declared_files` |

Most of Azazel-Knowledge#73's archive-safety acceptance criterion is therefore
**already satisfied**, and a Lite implementation that reimplements any of it
would be a regression, not a feature.

Two gaps are worth naming precisely rather than vaguely:

- **Duplicate member names have no explicit control.** A second tar member
  reusing a declared name is written over the first, and the per-member hash
  check then compares the *second* member's bytes against the single declared
  hash. A duplicate carrying different content therefore fails
  `BUNDLE_FILE_HASH_MISMATCH`, and a duplicate carrying identical content is
  inert. The safety property holds, but it holds *incidentally*; there is no
  `BUNDLE_DUPLICATE_MEMBER` error and no test pinning the behavior. This is a
  robustness and explicitness gap, **not** a content-substitution
  vulnerability, and it must not be reported as one.
- **Sparse members and nested archives** are not separately named. Sparse
  members are covered transitively (`isreg()` is required and expansion is
  capped); a nested archive is inert because nothing in the reader extracts a
  member's *contents* as an archive.

### Intel tier versus local tier

The intel tier — importable, feed-derived, rebuildable — is
`ioc`, `ioc_cidr`, `ioc_source`, `kev`, `attack_technique`, `attack_relation`,
`attack_mitigation`, `engage_activity`, `engage_attack_map`,
`sigma_rule_corpus`, `yara_rule_corpus`, plus `feed_state` and `stats_meta`.

The local tier — research data, never exported, never overwritten by an import
— is `LOCAL_TIER_TABLES` in `verify.py`. Absolute Constraint 5 and F-1 make
this inviolable, and Lite does not soften it in any direction: Lite neither
reads local-tier rows into an artifact nor lets an artifact touch them.

## Decision

### D1 — Lite is a profile, not a format

A Knowledge Lite artifact is an ordinary signed bundle produced by the existing
builder with a **selection profile** applied and a `profile` block added to the
manifest. Container, member order, signature scheme, trust sourcing, and
anti-rollback semantics are unchanged. A consumer that can verify a full bundle
can verify a Lite bundle with the same code path.

Artifact profile IDs are neutral and carry no deployment policy:
`knowledge-lite-16g`, `knowledge-lite-32g`. Deployment policy stays in the
consuming product's overlay.

### D2 — Selection is deterministic from a pinned tuple

Lite content is a pure function of

```text
(intel_generation, stats_generation, attack_version, config_hash,
 profile_id, export_policy_digest, as_of)
```

`as_of` is supplied by the caller and pinned for the whole build; the builder
MUST NOT read wall-clock time during selection. This is Absolute Constraint 3
applied to the build path: the same tuple over the same database produces a
byte-identical *unsigned* artifact, on any host, at any later date.

The tuple appears verbatim in `manifest.profile.selection_inputs` so that a
rebuild is reproducible by a third party without access to the original
operator.

Byte-identity is claimed for the **artifact**, not merely for its members, so
the container must be deterministic too. Tar member metadata is fixed
(`mtime=0`, fixed mode and ownership), and the gzip header is written with a
zeroed mtime and no embedded filename. Implementation found that
`tarfile.open(mode="w:gz")` stamps the current time into that header, which
made otherwise identical rebuilds differ; a test compares whole-file bytes and
a second test asserts the zeroed header directly, since a same-second rebuild
would satisfy the first by accident. A Lite manifest also carries no
`created_at` for the same reason: the instant that matters is the pinned
`as_of`, already recorded above.

Selection MUST NOT depend on filesystem enumeration order, `dict` iteration
over an unordered source, randomness, locale, or environment variables.
Ordering within every emitted table stays primary-key ordered, as the full
bundle already requires.

### D3 — Capacity profiles are ceilings, not targets

| Ceiling | `knowledge-lite-16g` | `knowledge-lite-32g` |
|---|---|---|
| Uncompressed content bytes | 256 MiB | 1 GiB |
| Compressed artifact bytes | 64 MiB | 256 MiB |
| Total rows | 750 000 | 3 000 000 |
| Rows per dataset | 250 000 | 1 000 000 |
| Distinct datasets | 8 | 12 |
| IOC freshness window | 30 days | 90 days |
| Reader resident memory during import | 128 MiB | 256 MiB |

**These numbers are proposed, not measured.** They are sized from the consuming
products' declared resource envelopes and from the reader memory ceiling a
`core`-envelope host can spare, not from a benchmark of real bundle content.
They need owner ratification, and the implementation PR should re-derive them
against a real corpus and an actual reader measurement — reporting back if the
evidence disagrees with this table rather than quietly adopting it.

These are **ceilings the builder enforces**, not sizes it pads to. A build that
would exceed a ceiling fails closed with a named error rather than silently
truncating: a truncated knowledge bundle is a bundle that lies about its
coverage. Which rows are dropped to fit a ceiling is part of the deterministic
selection function, never a build-time heuristic.

The profile name refers to the consuming host's **resource envelope**, not to
its capability. A `knowledge-lite-32g` artifact on a 32 GB host still grants no
capability by itself; the consumer's own topology, asset, and trust gates
decide that (Azazel-Nexus `docs/capability-model.md`).

### D4 — Claims keep their provenance or are not exported

Every exported claim carries citation, source, source freshness, the
generation it was selected from, expiry, decay behavior, confidence ceiling,
and stated limitations. A row that cannot carry all of them is **not
exported**. A Lite consumer must never have to guess how old or how trusted a
claim is, and "unknown" is a legitimate answer that the artifact must be able
to express.

Expiry and decay are dataset-specific and evaluated by the consumer against
its own `query_as_of`, never against a timestamp baked into the artifact. An
expired security-sensitive entry is unavailable, not merely labelled.

Confidence ceilings are carried per dataset. A Lite artifact MUST NOT raise a
confidence above what the full node would have reported for the same claim;
bounding the data must not sharpen it.

**Where each role lives (settled during implementation).** Requiring all eight
as *columns* is not possible and would not be right. The intel schema has no
`decay` or `limitations` column, and `ioc` alone has no source or generation —
so a column-only rule would make Lite export nothing. It would also be
wasteful where the columns do exist in spirit: decay behaviour and limitations
are the same sentence for every row in a dataset, and copying them onto 750,000
rows would spend the byte ceiling repeating one fact.

Each role is therefore satisfied **either** per row (mapped to an allowlisted,
non-optional column) **or** per dataset (a literal recorded once in the
manifest's `profile.provenance`). The export policy must cover all eight
exactly once — covering a role twice, leaving one out, or inventing a ninth is
rejected — so a consumer can always read every role for any claim: the varying
half from the row, the constant half from the manifest. What D4 requires is
that the provenance be *available*, not that it be duplicated.

Three consequences follow, and each is enforced:

- a provenance column that is **null** refuses the row, because a column that
  exists but holds nothing carries no provenance;
- a provenance column may not be `optional`, since optional provenance is a
  contradiction — the claim could ship without it;
- the `confidence_ceiling` column may not be aliased, because a pseudonymised
  confidence cannot be compared at all, which is worse than raising it.

In practice this means **an indicator that has not been through aggregation is
not exportable**: it has no expiry and no confidence yet, so it cannot carry
D4 provenance however complete the policy looks. That is the intended outcome,
not a limitation to work around.

### D5 — Export privacy defaults to deny

Local-sensitive export is **denied by default**. An export policy names, per
dataset, the allowlisted fields; anything unlisted is not exported, and an
unclassified field is treated as unlisted. There is no "export everything
except" mode.

The policy is versioned and its digest (`export_policy_digest`) is both an
input to selection (D2) and a recorded manifest field, so an artifact states
which privacy rules produced it.

Redaction is deterministic: the same input, policy version, and alias key
produce byte-identical output. A non-deterministic redactor cannot be audited
or replayed and is a defect.

A default Lite artifact contains no canary secret, credential, raw sensitive
evidence, internal hostname, operator identifier, or site identifier. This is
enforced by **canary-secret tests**: seeded canaries in the source database
that must be absent from every default-profile artifact. A canary appearing in
an artifact is a release blocker, not a warning.

Each export records a destination and retention receipt. The receipt is
evidence of what left the node and under which policy; it is not a permission
to export.

### D5b — Signer role and security epoch are gates of their own

A valid signature answers one question only: that *some* trusted key signed
this. Two further questions are independent of it and of each other.

**Which key signed.** `anchors.toml` may declare `key_roles` and a
`required_signer_role`. A cryptographically perfect signature from a key
provisioned for another purpose — a full-node key signing a Lite artifact —
meets the threshold and is still refused. A key with no declared role never
satisfies a required role: silence is not permission.

**Whether the artifact predates a security event.** `anchors.toml` may declare
`minimum_security_epoch`; a Lite manifest declares its `security_epoch`.
Anti-rollback compares version numbers and so cannot catch an artifact that is
*newer* yet was built before a key compromise — it outranks everything before
it. The epoch is the separate statement that such an artifact is no longer
acceptable, however new and however correctly signed.

Both thresholds live in the anchors, never in the manifest (F-7). A bundle may
*claim* an epoch; it may not decide which epoch suffices, or any holder of a
valid key could lower the bar for itself. Both gates are inert when the anchors
declare nothing, so existing deployments are unaffected until they opt in.

### D6 — Build never touches `local.db` or the active generation

The builder reads a consistent snapshot and writes only its output artifact and
receipt. It MUST NOT write to `local.db`, MUST NOT swap or advance a
generation, and MUST NOT run inside the query path. This is Absolute
Constraints 1, 4, and 5 restated for the build path; `tests/unit` already
carries the local-rows-never-decrease guards that must stay green.

Staging is promoted atomically, so an interrupted build or import leaves the
current generation exactly as it was.

### D7 — Ownership boundary

| Concern | Owner |
|---|---|
| Lite artifact production, selection algorithm, export policy, signing, consumer fixtures | **Azazel-Knowledge** (this repository) |
| Canonical wire contracts for the artifact's boundary payloads | **Azazel-Fabric** |
| Embedded read-only cache, staged/atomic reader, commissioning, trust policy, `FULL -> LITE -> CORE` routing | **Azazel-Nexus**, **Azazel-Boot** |

Knowledge produces and signs; it does not decide where an artifact is
installed, when it is trusted, or what a consumer does on its absence. A Lite
artifact is advisory data. It carries no command, no enforcement, no
activation, and no authority, and a consumer that cannot read it must remain
fully operational — Edge Core is never blocked by missing, corrupt, or expired
knowledge (Absolute Constraint 1; ADR-0007).

### D8 — Fabric contracts when released, not before

Lite emits its boundary payloads through released Azazel-Fabric contracts where
they exist, behind the existing api-extra pin. Where a contract does not exist,
Lite uses a repository-local shape and records that fact; it does not invent a
cross-product canonical form or pre-adopt an unreleased contract. Fabric stays
an api-extra dependency and never becomes a core dependency (Absolute
Constraint 7).

## Consequences

### What a later implementation PR must honor

This ADR fixes the shape and the constraints. It implements nothing. A later PR
must:

1. add the profile block and selection function without altering the existing
   container, member order, signature scheme, or trust sourcing;
2. prove byte-identical unsigned content for a repeated tuple, and prove that
   changing any tuple element changes the artifact;
3. prove full and delta round-trip, and that a wrong base or final tree digest
   fails;
4. keep signature, signer role, security epoch, compatibility, semantic and
   privacy policy, and anti-rollback as **separate** gates — a pass on one
   never implies another;
5. add the missing explicit `BUNDLE_DUPLICATE_MEMBER` control and its test,
   and a test pinning nested-archive inertness;
6. add canary-secret tests and a test that an unclassified field is not
   exported;
7. prove the builder mutates neither `local.db` nor the active generation, and
   that interrupted staging leaves the current generation unchanged;
8. ship consumer fixtures that Nexus and Boot can run in their own CI;
9. keep `python -m pytest tests/unit -q` green and **not decrease the test
   count**.

### Baseline correction

The verification baseline recorded in `CLAUDE.md` is stale. A clean
`pip install -e ".[api,dev]"` followed by `python -m pytest tests/unit -q` on
this branch reports **714 passed**, not 487. 714 is the number a later PR must
not decrease. (`CLAUDE.md` also describes the ADR range as 0001–0008; ADRs
through 0014 exist.)

### Open questions, deliberately not decided here

- **Fabric baseline — settled.** Moved to `v0.8.0` by
  [ADR-0016](0016-fabric-pin-v0-8-0.md), with the cross-repository rationale
  and the test evidence recorded there.
- **Delta bundles and deletes — settled.** Lite is full-only by
  [ADR-0017](0017-lite-is-full-only.md): D4's mandatory expiry already retires
  a stale row without an out-of-band delete, so the problem tombstones would
  solve does not arise for Lite. The Phase-2 tombstone TODO stays open for the
  general bundle path.
- **Exact canary seeding mechanism** and the dataset-by-dataset field
  allowlists, which belong in the implementation PR's policy file rather than
  in an ADR.
