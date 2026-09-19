# ADR-0013: YARA/Sigma rule-corpus ingest as knowledge

Status: **accepted — implemented** (spike proposed 2026-08-21; shipped and
verified against the code 2026-09-19 — Azazel-Knowledge#61)

## Implementation status (verified 2026-09-19)

Both corpora are ingested and the `rule_refs` usage seam this spike deferred
has shipped. Recorded here so the status is readable from the ADR rather than
inferred from the code.

| What the spike fixed | Where it lives now |
|---|---|
| Adapters (`full_replace`, no rule engine) | `src/azazel_knowledge/feeds/adapters/sigma_corpus.py` (`SigmaCorpusAdapter`), `.../yara_corpus.py` (`YaraCorpusAdapter`) |
| Schema: `sigma_rule_corpus`, `yara_rule_corpus` (raw text + license + `source_url` + `corpus_version` + `attack_refs`) | `src/azazel_knowledge/db/migrations/intel/0003_rule_corpus.sql` |
| Feed configuration: pinned `corpus_version` (empty = inert, fail-closed), `allowed_licenses`, `max_rules` | `config/feeds.yaml`, `sigma_corpus:` / `yara_corpus:` blocks |
| The deferred usage seam — `rule_refs` on `POST /v1/context` | `correlate/engage_rule_refs.py` (`lookup_rule_refs`), `api/routers/context.py`; contract in [`docs/api.md`](../api.md) §`engage_refs` / `rule_refs` |
| "Never a scanner" enforced statically | `tests/unit/test_no_rule_execution.py` — asserts neither adapter nor `pyproject.toml` reaches a rule engine, and that the guard survives aliased/reordered imports |
| Tests | `tests/unit/test_adapter_rule_corpus.py`, `tests/unit/test_context_engage_rule_refs.py` |

The central risk this ADR existed to foreclose held in the implementation:
`rule_refs` carries rule **identity and metadata only** — `technique`,
`rule_type`, `rule_id`, `title`, `source_url` — never `raw_yaml`/`raw_text` or
condition logic, pinned by
`test_lookup_rule_refs_never_includes_rule_body`. Nothing compiles, matches, or
executes a corpus rule; `pyproject.toml` gained neither `yara-python` nor
`pysigma` nor any other dependency. Sigma inserts are gated on `lint_sigma`
round-trip and a failing rule is quarantined via `insert_quarantine`, not
inserted.

## Context

Azazel-Knowledge already generates its own advisory rule drafts
(`rules/suricata.py`, `rules/sigma.py`, linted by `rules/lint.py`), and
ADR-0007 fixed that those drafts are never compiled, deployed, or executed —
Knowledge is not a scanner. Separately, the wider community publishes large
YARA and Sigma rule corpora (SigmaHQ/sigma, YARAhub, Neo23x0
signature-base) that encode reusable detection knowledge: rule names, MITRE
ATT&CK tags, hash/string-match structure, authorship, and licensing. None of
that corpus is currently reachable from Knowledge — an analyst asking "is
there already a known community rule near this indicator?" gets no answer.

#61 asks for a spike on ingesting these corpora **as knowledge, not as a
scanner**: store the rule text and its metadata, so a later PR can surface
`rule_refs` as secondary context on `/v1/context` and annotate Knowledge's
own generated drafts with "nearby existing community rule" references. This
ADR fixes the storage shape, the parsing boundary, and the constraints a
later PR must honor; it does not wire `rule_refs` into `/v1/context` or the
draft annotator (separable, later PRs, out of scope here per #61).

The central risk this ADR exists to foreclose: a "rule corpus" feature is an
obvious, tempting on-ramp to bringing in `yara-python` and a real YARA/Sigma
engine, which would turn Knowledge into a scanner and directly violate
ADR-0007 and Absolute Constraint 8. This ADR draws that line explicitly,
before any adapter code exists.

## Decision

Add two full-replace feed adapters, `feeds/adapters/sigma_corpus.py` and
`feeds/adapters/yara_corpus.py`, that fetch a pinned corpus release, extract
rule text + metadata only, and store both in new intel-tier tables. No
parser in this path ever compiles or evaluates a rule.

1. **Adapters follow the ATT&CK full-replace pattern exactly**
   (`feeds/adapters/attack.py`): `full_replace = True`, one writer
   transaction per run that `DELETE`s and re-`INSERT`s the corpus tables,
   pinned to a `corpus_version` resolved at parse time. `fetch()` uses the
   existing `fetch_https_with_pins` SPKI-pinned HTTPS helper (`feeds/base.py`)
   against a **pinned release tarball**, not a moving branch HEAD — same
   determinism discipline as every other feed.

2. **Two adapters, two sources, one shared row shape.**
   - `sigma_corpus`: SigmaHQ/sigma release tarball (pinned tag), Detection
     Rule License (DRL) 1.1.
   - `yara_corpus`: a license-compatible YARA source — YARAhub export or
     Neo23x0/signature-base release (pinned tag) — with license recorded
     per rule/feed; sources requiring bespoke commercial licensing are out
     of scope for this spike.

3. **Parsing never compiles.** Sigma rules are YAML: parsed with the
   **existing** core dependency `yaml.safe_load` (same call `rules/lint.py`
   already makes via `lint_sigma`). YARA rules are **not** YAML; metadata
   (rule name, `meta` block key/values, tag list) is extracted with stdlib
   `re` against the textual `rule NAME : tags { meta: ... }` grammar — a
   metadata-only regex extractor, not a YARA grammar parser, and never a
   condition evaluator. Neither adapter imports `yara-python`, `pysigma`, or
   any rule-execution library.

4. **Storage keeps raw text and extracted metadata side by side** (see
   Schema) so a later PR can do fuzzy/near-match work off the raw text
   without re-fetching, while `/v1/context` secondary-context lookups stay
   cheap index reads off the metadata columns.

## Constraints

1. **Advisory-only, no execution path.** Rule rows are inert knowledge: text
   + metadata columns only, no compiled-form column, no `condition`
   evaluator anywhere. ADR-0007's "drafts only, no deploy path" extends to
   the ingest side. Enforced by a new static test (§Acceptance criteria)
   that greps both adapter modules and `pyproject.toml` for `yara`,
   `pysigma`, `sigma_correlation`, `compile(` and fails the build if any
   appears outside a comment.
2. **Deterministic, but out of the scoring tuple.** `corpus_version` is
   pinned once per adapter run (full-replace, like `attack_version`) but is
   **not** added to the scoring 7-tuple (`intel_generation,
   local_generation, stats_generation, attack_version, config_hash, event,
   query_as_of`). Like the EPSS spike (#55), `rule_refs` is SECONDARY
   context — informational, never a scoring input — so adding or dropping
   the corpus cannot change a `raw_confidence`/`reason[]` replay.
3. **Offline-first.** Both adapters fetch only from `worker.py`'s scheduled
   run (`--online`) or a signed offline bundle swap (`tools/bundle_build`) —
   identical to every existing feed. The query path
   (`api/routers/context.py`) never fetches.
4. **local.db immutable (F-1) untouched.** Corpus tables live in the
   **intel-tier** database only (`db/migrations/intel/`), exactly where
   `attack_technique`/`kev`/`ioc` already live. Nothing here touches
   `db/migrations/local/` or the F-1 "rows never decrease" tables.
5. **Dependency minimal — no new pip dependency.** Sigma parsing reuses the
   **existing** core dependency PyYAML (`yaml.safe_load`, already used by
   `rules/lint.py`). YARA metadata extraction uses stdlib `re` only.
   `yara-python` is explicitly rejected (see Alternatives); a future real
   need for it would require its own `pyproject.toml` change **and** its
   own ADR.
6. **Size/licensing budget.** Both adapters sub-select the corpus by license
   compatibility and a configured size cap before writing (§Pi 4 budget).
   `license` and `source_url` are recorded per row (not just per-feed) since
   SigmaHQ mixes a few non-DRL rules and community YARA sets mix licenses
   per file.
7. **Fail-closed and additive.** `sigma_rule_corpus`/`yara_rule_corpus` are
   new, empty-by-default tables. Every existing endpoint and
   scoring/correlation path is byte-identical when both are empty.
   `rule_refs` (later PR) must be an optional/absent field, never required.

## Schema (intel-tier, `db/migrations/intel/000X_rule_corpus.sql` sketch)

```sql
CREATE TABLE sigma_rule_corpus (
    rule_uid        TEXT NOT NULL,      -- Sigma 'id' (UUID) from the rule YAML
    title           TEXT NOT NULL,
    raw_yaml        TEXT NOT NULL,      -- verbatim rule text, round-trips via yaml.safe_load
    tags            TEXT NOT NULL DEFAULT '[]',   -- JSON array, e.g. ["attack.t1059.001"]
    attack_refs     TEXT NOT NULL DEFAULT '[]',   -- JSON array, tags filtered to attack.tXXXX
    log_source      TEXT,               -- JSON object: category/product/service
    level           TEXT,               -- Sigma 'level' (informational..critical), as published
    author          TEXT,
    license         TEXT NOT NULL,
    source_url      TEXT NOT NULL,
    corpus_version  TEXT NOT NULL,      -- pinned SigmaHQ release tag
    feed_id         TEXT NOT NULL DEFAULT 'sigma_corpus',
    PRIMARY KEY (rule_uid, corpus_version)
) STRICT;

CREATE INDEX idx_sigma_rule_corpus_attack ON sigma_rule_corpus (attack_refs);

CREATE TABLE yara_rule_corpus (
    rule_name       TEXT NOT NULL,
    raw_text        TEXT NOT NULL,      -- verbatim rule source, never parsed past metadata
    tags            TEXT NOT NULL DEFAULT '[]',      -- JSON array, YARA `rule NAME : tag1 tag2`
    meta            TEXT NOT NULL DEFAULT '{}',       -- JSON object of the `meta:` block, string values only
    attack_refs     TEXT NOT NULL DEFAULT '[]',      -- JSON array, meta values matching attack.tXXXX
    condition_summary TEXT,             -- e.g. "3 hex strings, 1 hash condition" — a description, never re-evaluable
    author          TEXT,
    license         TEXT NOT NULL,
    source_url      TEXT NOT NULL,
    corpus_version  TEXT NOT NULL,      -- pinned source release tag
    feed_id         TEXT NOT NULL DEFAULT 'yara_corpus',
    PRIMARY KEY (rule_name, corpus_version)
) STRICT;

CREATE INDEX idx_yara_rule_corpus_attack ON yara_rule_corpus (attack_refs);
```

Both tables are full-replace per adapter run, checkpointed through the
existing `feed_state` row (keyed by `feed_id = 'sigma_corpus'` /
`'yara_corpus'`) — no new bookkeeping table needed. `condition_summary` is a
human-readable string built by the metadata extractor (e.g. counting
`$hex`/`$s`-style string definitions and detecting a `hash.sha256(...) ==`
pattern) — it exists to make near-match search legible, and is explicitly
**not** a re-parseable condition AST.

## Data sources & licensing

| Adapter | Candidate source | License to record | Notes |
|---|---|---|---|
| `sigma_corpus` | SigmaHQ/sigma release tarball (pinned tag) | DRL 1.1 (per-rule; a small subset carries other licenses — recorded per row) | YAML, parses with existing PyYAML |
| `yara_corpus` | YARAhub export, or Neo23x0/signature-base release (pinned tag) | recorded per file/rule as published (mixed — some CC-BY-NC, some unrestricted) | textual, stdlib-regex metadata only |

Both adapters reject (skip, log, do not insert) any rule whose license field
cannot be resolved to an allow-listed license in `config/feeds.yaml`
(`sigma_corpus.allowed_licenses` / `yara_corpus.allowed_licenses`) — same
fail-closed posture as an unparseable STIX object in the ATT&CK adapter.

## Parsing approach

- **Sigma (YAML).** `yaml.safe_load(raw_yaml)` — the same call
  `rules/lint.py:lint_sigma` already performs to round-trip a *generated*
  Sigma draft. The corpus adapter reuses that round-trip check as an ingest
  validator: a rule that does not survive `safe_load` → `safe_dump` →
  `safe_load` unchanged is quarantined via `insert_quarantine`, not
  half-inserted. `attack_refs` is `[t for t in tags if t.startswith("attack.")]`.
  No Sigma **backend** (pySigma or otherwise) is invoked.
- **YARA (regex-metadata only).** A small stdlib-`re` grammar walks
  `rule NAME : tag1 tag2 { meta: key = "value" ... strings: ... condition: ... }`
  far enough to pull `rule NAME`, the tag list, and `key = "value"` pairs
  inside `meta:`. It does **not** parse `strings:`/`condition:` into an AST;
  `condition_summary` counts string-definition lines and pattern-matches a
  couple of common idioms (hash equality, `all of them`) rather than
  understanding the boolean expression. A rule the extractor cannot
  confidently split into a `rule { }` block is quarantined.
- **Neither path ever calls `yara.compile`, `yara.match`, a Sigma backend's
  `.convert()`, or anything that treats rule content as executable.**

## Determinism handling

`corpus_version` is resolved once per adapter run (the pinned release tag),
exactly like `attack_version` in `attack.py`. It is stored on every row and
surfaced in the `/v1/context` secondary-context payload (later PR) as
provenance, but is **excluded** from the scoring 7-tuple — mirroring how the
EPSS spike (#55) treats EPSS scores as informational, not score-affecting.
Consequence: replaying the same `(intel_generation, local_generation,
stats_generation, attack_version, config_hash, event, query_as_of)` tuple
still reproduces a byte-identical `raw_confidence`/`reason[]` regardless of
which corpus generation is loaded — the corpus can be absent, stale, or
mid-swap without perturbing the deterministic core.

## Pi 4 budget (spike output — estimate, to be confirmed on hardware per T4/S9)

- SigmaHQ (rules/ directory only, DRL-licensed): ~3,000 rules, ~2–4 KB raw
  YAML each ⇒ roughly 6–12 MB of `raw_yaml` plus a similar-order metadata
  footprint once indexed → **budget ~30 MB** for `sigma_rule_corpus`
  (table + index); full-replace, so peak-during-swap is ~2x that.
- YARAhub/signature-base subset (license-filtered): an order of magnitude
  fewer rules after the license sub-select (signature-base alone is a few
  hundred rules) ⇒ **budget ~10–15 MB** for `yara_rule_corpus`.
- **Total added intel.db footprint: ≤ ~50 MB steady-state, ≤ ~100 MB
  transient during a full-replace swap** — small relative to the existing
  `ioc`/`attack_*` tables on the documented 8 GB Pi 4 target
  (`docs/architecture.md`). RSS impact is adapter-run-only (worker process);
  the query-path API process gains no RSS since it never parses YARA/Sigma,
  only reads already-stored columns.
- The size cap and license allow-list (Constraint 6) are config-driven
  (`config/feeds.yaml`) so the budget can be tightened without a code change
  if real Pi 4 numbers (S9 harness) come in worse.

## Consequences

- Two new intel-tier tables and two new feed adapters join the existing
  full-replace family (`attack`, `kev`); `feed_state`/`feed_quarantine`
  bookkeeping is reused as-is, no new plumbing.
- `/v1/context` and the draft-rule generator gain a **future** hook
  (`rule_refs`), but this ADR ships no such wiring — deferred to a later,
  separable PR per #61.
- A static "no execution path" test becomes a permanent guard alongside
  `test_api_static.py`'s "no write SQL in api/" test — a future contributor
  adding `yara-python` for a legitimate-sounding reason (e.g. "just to
  validate syntax") is caught by CI, not by review alone.
- Corpus staleness is possible and acceptable: an adapter that stops running
  simply serves the last full-replace generation until the next successful
  worker run — fail-closed on parse errors (quarantine), fail-open on
  absence (Constraint 7).

## Alternatives considered

- **`yara-python` for real compile/match.** Rejected: gives Knowledge a
  working scan engine, directly contradicting ADR-0007 and Absolute
  Constraint 8, and adds a compiled C-extension dependency (Constraint 7)
  the stated use case — near-match context, "nearby existing rule"
  annotation — does not need.
- **`pysigma` to convert Sigma rules to backend queries.** Rejected: same
  shape of problem, a conversion/compile step is exactly the
  scanner-adjacent capability ADR-0007 forecloses, and unnecessary when
  `yaml.safe_load` already yields the metadata needed.
- **Store only a hash/fingerprint, not raw text.** Rejected: the later-PR
  near-match/annotation use case needs raw text for a human-facing diff or
  similarity signal; a bare hash only proves exact-match, a weaker product
  for the same fetch cost.
- **Ingest the full unfiltered corpora.** Rejected on both the licensing
  constraint (Constraint 6 — some source licenses are not
  redistribution-safe) and the Pi 4 budget — full YARAhub alone would blow
  the storage budget for a "secondary context" feature.
- **Wire `rule_refs` into `/v1/context` in this same PR.** Rejected per
  #61's own scoping: separate PRs let the storage/parsing design be
  reviewed without re-litigating the `/v1/context` response contract
  (`docs/api.md`) at the same time.

## Acceptance criteria

- `feeds/adapters/sigma_corpus.py` and `feeds/adapters/yara_corpus.py` exist,
  both subclass `FeedAdapter`, both set `full_replace = True`.
- New intel-tier migration adds `sigma_rule_corpus` and `yara_rule_corpus`
  per the schema sketch above (exact columns may be refined in
  implementation, but raw text + license + source_url + corpus_version +
  attack_refs are non-negotiable).
- `pyproject.toml` is **unchanged** (no `yara-python`, no `pysigma`, no
  other new dependency) — checked directly in diff review.
- A new static test (alongside `tests/unit/test_api_static.py`) asserts
  neither adapter module, nor `pyproject.toml`, contains `yara-python`,
  `pysigma`, or a call matching `\.compile\(|\.match\(` against rule content.
- `lint_sigma`-style round-trip validation gates every Sigma corpus insert;
  a rule failing round-trip is quarantined via `insert_quarantine`, not
  inserted.
- With both corpus tables empty (fresh DB), every existing unit test still
  passes unchanged — the test baseline does not shrink (CLAUDE.md is the
  single source for that number; no raw count is copied here), no existing
  response shape changes.
- License allow-list is config-driven (`config/feeds.yaml`); a rule with an
  unresolved/disallowed license is skipped and logged, not inserted.

## Non-goals

- No rule evaluation, matching, scanning, or compilation of any kind — this
  ADR stores knowledge *about* rules, never runs a rule against anything.
- No deploy path to Suricata, a SIEM, or any external detection engine —
  ADR-0007's boundary is unchanged and unextended by this feature.
- No `rule_refs` wiring into `/v1/context` and no draft-rule annotation in
  this ADR's scope — both are explicitly later, separable PRs (#61).
- No full, unfiltered corpus dump — both adapters sub-select by license and
  size (Constraint 6); "ingest everything SigmaHQ/YARAhub publish" is out of
  scope.
- No new scoring input — `rule_refs`/corpus presence never enters the
  7-element scoring tuple or `raw_confidence`/`reason[]` computation.
