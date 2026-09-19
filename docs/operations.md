# Operations quickstart

This is the operator path from a bare Pi 4 to a running Azazel-Knowledge
(formerly Azazel-CTI) node serving
enriched context to an Edge: provision, load intelligence (bundle or
online pull), connect an Edge, and read the first enriched event back.
For the CLI reference behind each step see `azctl <command> --help`;
for deployment/container layout see [ops/hardware-profile.md](../ops/hardware-profile.md)
and `ops/docker-compose.yml`.

## The advisory-only contract

Before touching the CLI, the one rule every other section assumes.
Quoting [docs/architecture.md](architecture.md) verbatim:

> | Plane | Device | Responsibility | Authority |
> |---|---|---|---|
> | Knowledge Plane | Azazel-Knowledge (Pi 4) | IOC management, correlation, campaign analysis, pattern memory, feed ingestion | Advisory only |

> The Knowledge Plane enriches evidence and explains context. It never
> selects, schedules, or vetoes an action.

Concretely: every `/v1/context` and `/v1/*/search` response is one more
piece of evidence Edge folds into its own deterministic evaluators.
There is no enforcement channel anywhere in this codebase -- not a rule
push, not a block list Edge is required to honor, not a "recommended
action" Edge is obligated to take. If the CTI node is down, wrong, or
stale, Edge keeps running on local logic; this is why `source_freshness`
and `confidence` are mandatory on every answer instead of a single
"trust me" verdict.

## 1. Provision the node

```sh
azctl provision --root /srv/azazel-knowledge --check-thermal
```

This creates the working tree (`var/{run,audit,ingest/{events,flows,
reactions,advisory}}`, `data/db/` with a migrated `local.db` and a
`gen-1/intel.db` current generation, `secrets/` with a fresh node
signing key and empty trust-anchor/anti-rollback templates), and mints
the node's first API client token:

```
first admin API client token (shown once -- store it now):
  key_id: 2720682c
  token:  azcti_2720682c_<secret>
```

**Copy that token now.** It is hashed at rest (`api_client.token_sha256`)
and never printed again; if lost, mint a new one with `azctl client
add`.

Sanity-check the configuration the node will run with before starting
anything:

```sh
azctl check-config --config-dir config
```

This validates `scoring.yaml`'s `weights`/`confidence_weights` both sum
to 1.0, prints the `config_hash` that will be folded into every
`content_hash` (design F-2), and prints the memory arithmetic the
`api`/`worker` container limits in `ops/docker-compose.yml` are sized
against (3 x 64 MiB `GenCache` + the two container `mem_limit`s against
the 2 GB Pi 4 budget).

Then bring the containers up (`ops/docker-compose.yml` mounts
`var/`, `data/`, `secrets/`, `config/` from the paths `azctl provision`
just created):

```sh
docker compose -f ops/docker-compose.yml up -d
```

## 2. Load intelligence: bundle import or online pull

Offline is the primary path (design ADR-0004); online is the
convenience.

### Offline: import a signed bundle

```sh
# Preview before trusting it:
azctl bundle import bundle.tar.gz --fingerprint

# Once the operator has verified the fingerprint out of band
# (courier manifest, second channel, etc.):
azctl bundle import --root /srv/azazel-knowledge bundle.tar.gz --confirm
```

Import verifies signature threshold, per-file hashes, and the
anti-rollback watermark in `secrets/trust/state.toml` before touching
any content file (design S6); a full bundle builds the next
`gen-<N+1>/intel.db` out of process and only then swaps the `current`
symlink, so an in-progress import never blocks a running query. If
`azctl bundle import` reports an `INTEGRITY_ALERT` or an unexplained
version gap, do not retry blindly -- run `azctl bundle resolve-state`
first to inspect `state.toml` and confirm what happened.

Trust anchors (the keys a bundle's signature is checked against) are
managed separately and are empty by default after provisioning:

```sh
azctl keys add <key_id> <verify_key_hex>
azctl keys set-threshold 2   # require 2 of N signatures, once you have N >= 2 keys
```

### Online: scheduled feed pulls

The worker container's command in `ops/docker-compose.yml` already
passes `--online`, so ATT&CK/KEV/urlhaus/malwarebazaar/threatfox/
spamhaus_asndrop are pulled on the worker's normal P2 cycle whenever
the node has a route to the internet -- nothing else to do. For a
one-off manual pull (including the air-gapped, file-based path for
`geoip_asn`, which is never fetched over the network):

```sh
azctl feed pull urlhaus --online          # live pull
azctl feed pull geoip_asn --file GeoLite2-ASN-Blocks-IPv4.csv   # offline file
```

A feed that trips the volume-halt or critical-infra-quarantine guard
(design S6) stops applying updates until an operator reviews it:

```sh
azctl feed inspect urlhaus     # feed_state + open feed_quarantine rows
azctl feed approve urlhaus     # re-enable + resolve open quarantine entries
```

### Knowledge Lite: build a bounded artifact for Nexus / Boot

Azazel-Nexus and Azazel-Boot embed a read-only cache of a **Knowledge Lite**
artifact: a bounded capacity profile of the same signed bundle, always full,
never differential. This node produces and signs it; the consumer owns trust,
caching, and promotion, and keeps working without it.

```sh
# Profiles: knowledge-lite-16g | knowledge-lite-32g
# --as-of pins the whole selection; the builder never reads the clock.
# The generation/version/hash values below must be the ones the artifact
# claims to have been built from -- they are recorded in its manifest.
ROOT=/srv/azazel-knowledge
python tools/bundle_build.py build-lite \
    --source-db "$ROOT/data/db/current/intel.db" \
    --out lite.tar.gz \
    --version 7 \
    --profile knowledge-lite-16g \
    --export-policy config/lite-export-policy.yaml \
    --alias-key-file "$ROOT/secrets/lite-alias.hex" \
    --alias-scope mission-alpha \
    --as-of 2026-09-19T00:00:00Z \
    --intel-generation 7 \
    --stats-generation 3 \
    --attack-version v15.1 \
    --config-hash "$CONFIG_HASH" \
    --security-epoch 1 \
    --sign-key "$ROOT/secrets/keys/offline-signing.hex"
```

What to expect when running it:

- **The same flags rebuild the same bytes.** Selection is a pure function of
  that tuple, so an artifact is reproducible by someone who was not there when
  it was built. `--as-of` is the pin — the builder never reads the clock.
- **A ceiling fails the build; it never truncates.** `LITE_CEILING_EXCEEDED`
  names which limit was passed (datasets, rows per dataset, bytes per dataset,
  rows total, bytes total). Make it fit on purpose — export fewer datasets or
  fields, or build the larger profile — because a truncated bundle would lie
  about its coverage, and a consumer cannot tell "this is all there was" from
  "this is all that fit". The freshness window is a property of the profile
  (30 days at 16g, 90 at 32g), not a flag; the ceilings themselves are measured
  values fixed in ADR-0015 D3 and are not tuned per build.
- **A row without provenance is refused,** including an indicator that has not
  been through aggregation yet (it has no expiry or confidence). Export is
  deny-by-default: fields the policy does not name never leave this node.
- **`config/lite-export-policy.yaml` is the default profile.** It exports
  `ioc` (indicator aliased, plus type, freshness, expiry and confidence
  ceiling) and `attack_technique` (id, name, tactics, ATT&CK version), and
  nothing else — every other intel table, and every other column of those two,
  is left out on purpose, with the reasoning written in the file. Point
  `--export-policy` at a different file only after deciding what else may
  leave this node; the digest of whichever policy was used is recorded in the
  artifact's manifest.
- **It is a full-node operation.** Peak builder memory is roughly 0.9 GB at the
  16g row ceiling and 3.4 GB at 32g, so a 4 GB Pi 4 cannot build a 32g
  artifact. The build reads a snapshot outside the query path and never writes
  `local.db` or swaps a generation.

To hand consumers something to test their reader against:

```sh
python tools/lite_fixture.py emit --out /tmp/lite-fixture
# lite.tar.gz + anchors.toml + expected.json  (rebuilt, not a committed blob)
# negative/ + negative.json                   (what a reader must refuse)
```

The negative set is there so Nexus and Boot can prove their fail-open path
against artifacts this node actually emits rather than against broken files
they forged themselves: `corrupt-signature` (refused on trust, nothing
staged), `corrupt-payload` (a raised confidence; every trust gate passes and
only the per-member digest catches it, with bytes already in staging),
`corrupt-truncated` (fails in the tar decoder, with **no** `BUNDLE_*` code —
a reader must treat any exception as a refusal), `expired` (verifies cleanly;
every indicator in it has passed its `agg_next_expiry`), and `absent` (a path
the emitter guarantees stays empty). `negative.json` states, per fixture,
which gate it hits and what a conforming reader should see.

Contract and rationale: [ADR-0015](adr/0015-knowledge-lite-bundle.md)
(profile, deterministic selection, measured ceilings, provenance, export
policy, signer-role/security-epoch gates, ownership boundary) and
[ADR-0017](adr/0017-lite-is-full-only.md) (full-only, no Lite deltas).

#### When a Lite build aborts on one row

`LITE_PROVENANCE_MISSING` names a single row and stops the whole build. That is
ADR-0015 D4 working as decided, not a bug to route around: every exported claim
must carry its provenance, and a row that has not been through aggregation
carries no expiry and no confidence. Exporting it anyway would ship a claim
with nothing behind it, and D4 calls that outcome "the intended one, not a
limitation to work around".

It is operationally sharp all the same — **one un-aggregated indicator stops
the artifact** — so it is worth recognising quickly:

```sh
# Which rows are not aggregated yet? (agg_next_expiry is the usual one.)
sqlite3 intel.db \
  "SELECT COUNT(*) FROM ioc WHERE agg_next_expiry IS NULL OR agg_raw_confidence IS NULL;"
```

The fix is to let aggregation finish, not to relax the policy. A row appears
here because the worker has not reached it yet, or because aggregation failed
for it; both are worth knowing about on their own terms. Removing the field
from the export policy would make the build succeed and the artifact weaker,
which is the trade D4 exists to refuse.

#### Datasets exempt from the freshness window

A dataset may declare `freshness_exempt: true` in the export policy. The
shipped default uses it for exactly one dataset, `kev`, and the reason
generalises: KEV's only timestamp is `date_added`, which records when an entry
joined the catalogue rather than when anything was last seen here. Windowing on
it would ship the recent tail of the catalogue in an artifact whose manifest
looks complete, and a consumer could not tell **"not in KEV"** from **"aged out
of this bundle"**.

Use it only for that shape — a catalogue or reference set whose timestamp is
about the *entry*, not about *observation here*. It never widens what is
exported: the field allowlist and every capacity ceiling still apply, and the
dataset still carries its full D4 provenance. Adding or removing it changes
`export_policy_digest`, so an artifact always states which rules produced it.

## 3. Connect an Edge

Mint a scoped token for the Edge node (`ingest+query`, never `admin` --
design S7):

```sh
azctl client add --scopes ingest,query
```

```
key_id: 9f21ab04
scopes: ['ingest', 'query']
token (shown once): azcti_9f21ab04_<secret>
```

Give Edge that token as its bearer credential for every request on the
management segment (`https://<node>:8443`, per
[architecture.md](architecture.md#security-boundary)). Endpoint shapes,
request/response bodies, and the query-discipline rules Edge must
follow (only query on defined triggers, never per packet) are in
[api.md](api.md) -- start there for the wire contract. `ops/nftables.conf`
must allow that Edge's subnet through `MGMT_SEGMENT` before traffic will
reach 8443 at all.

## 4. First enriched event

Edge sends evidence fire-and-forget (`POST /v1/events`, `/v1/flows`);
the worker's P1 stage drains that spool into `observation` rows every
`--drain-interval-s` (default 0.5 s), or immediately under `--once`.

The drains (P0/P1) and the periodic stages (P2 feed pulls and sweeps, P3
retention) run on separate cadences: `--drain-interval-s` for the drains,
`--interval-s` (default 5 s) for the rest. They used to share one loop, which
put the 5 s maintenance cadence under every ingested record's wait — measured
at p50 2 579 ms for a single Edge at 200 records/s, none of it database
contention (ADR-0003). Ingest is still fire-and-forget and still promises no
visibility deadline; this is a better default, not a new guarantee. Setting
`--drain-interval-s` equal to `--interval-s` restores the earlier
single-cadence behaviour exactly. Once Edge hits a query trigger (critical alert, unknown IOC/
JA3/JA4, first contact, high local score) it calls `POST /v1/context`
and gets back the full advisory contract: `threat_context`,
`threat_score`, `confidence`, `reason[]`, `recommendation` with
`rejected_alternatives[]`, `source_freshness`, and `advisory_id`. To
confirm the round trip end to end without waiting on real Edge traffic,
check `azctl health` for `audit_writer_ok`/feed freshness first, then
watch `var/ingest/events/` drain and `data/db/local.db:observation`
grow as Edge sends its first batch.

If Edge later reports what happened after that advisory (a reaction
POST carrying the `advisory_id` it was given), the worker's P0 stage
resolves that linkage from `echoed_pending` to `echoed_resolved` once
the matching `advisory_log` row has landed -- see
[architecture.md](architecture.md) and `reactions/linkage.py` for the
full state machine; unresolved or missing linkage never invalidates the
underlying reaction row (design F-6).

## 5. Behavioral CTI: generation, reports, shadow (Phase 2)

Once reactions are landing, the node compiles them into evidence-backed
behavior patterns. Generation is an **offline** deterministic pass — it never
sits on the `/v1/context` hot path — and it only reads immutable
`reaction`/`observation` rows, so it can be replayed safely.

```sh
# Preview what would be generated, without writing (safe, read-only):
azctl behavior dry-run

# Incrementally generate patterns from unprocessed reactions:
azctl behavior generate

# Rebuild the whole current generation from source (idempotent):
azctl behavior rebuild
```

The worker also runs generation on its P2 cycle. Each run stages
`behavior_generation = N+1`, precomputes similarity/repeatability, and swaps
`behavior_meta` atomically in a single writer transaction — a reader only ever
sees the prior complete generation, never a half-built one. `azctl behavior`
refuses to write while the worker holds the local writer lock (run it against a
paused worker, or let the P2 pass own generation).

Operator-facing read surfaces (all `Scope.READ`, SELECT-only):

```sh
# Same read code as the API, rendered for a human/demo:
azctl behavior report <pattern-id>
```

- `GET /v1/behavior-patterns/{pattern_id}` — one pattern + evidence + similarity
- `GET /v1/behavior-patterns/summary` — recent patterns by class/edge/window
- `GET /v1/reports/friction-timeline` — the observe → track → classify → advise
  narrative, with a mandatory CTI-advisory disclaimer and no attribution terms

**Shadow reaction-informed scoring** ships **default-off and shadow-only**
(`config/behavior-shadow-rules.yaml`, `enabled: false`, `mode: shadow` — the
loader rejects `mode: active`). When the P2 pass runs, potential
reaction-informed adjustments are written to the JSONL research log at
`var/research/behavioral_shadow.jsonl` **only**. A `shadow_score_delta` never
changes the production `threat_score`, never appears in the `/v1/context`
response, and never adds or removes a `reason[]` line — it is research data, not
a verdict.

## 6. Reading health and staleness

```sh
azctl health
```

```json
{
  "feeds": [
    {"feed_id": "urlhaus", "last_run": "...", "last_success": "...", "enabled": 1}
  ],
  "intel_generation": 4,
  "open_quarantine": 0,
  "pending_edge_reported": 3,
  "bundle_state": {"last_imported_version": 4, "needs_full_rebaseline": false}
}
```

How to read it:

- **Per-feed age** -- compare `last_success` to now for each feed in
  `feeds[]`; a feed with no route to the internet simply stops
  advancing, it does not error. `GET /v1/health` (Edge-facing) reports
  the same per-feed ages plus pin status and `cache_state`.
- **Freshness decay, not a cliff** -- every advisory's `confidence` and
  `threat_score` fold in a `freshness` factor that decays smoothly
  (`0.5^(age_days/30)`, floor `0.2`) as a feed goes stale; there is no
  hard cutoff where intelligence "expires" and answers stop -- an
  offline month degrades scores honestly instead of serving falsely
  fresh-looking certainty (design S5, [architecture.md](architecture.md#failure-model--edge-must-not-care)).
- **`open_quarantine`** -- feeds halted by the volume/critical-infra
  guards, pending `azctl feed inspect`/`approve`.
- **`pending_edge_reported`** -- Edge-reported IOCs not yet promoted to
  scored intelligence (needs cross-group corroboration, 3 distinct
  edges in 7 days, or an analyst confirm -- design S6).
- **`bundle_state.needs_full_rebaseline`** -- set by `azctl restore`;
  true means the next bundle import must be a full bundle, not a
  differential, before anti-rollback trusts the local generation again.

Finally, verify the audit chain periodically (it is the source of
truth behind every advisory and every admin action this CLI took):

```sh
azctl audit verify
```
