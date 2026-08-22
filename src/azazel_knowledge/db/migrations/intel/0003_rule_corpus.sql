-- YARA/Sigma rule-corpus ingest (ADR-0013, #61).
--
-- Advisory-only knowledge: text + metadata columns only. No compiled-form
-- column, no condition-evaluator column, nothing here is ever executed.
-- Both tables are full-replace per adapter run, pinned to `corpus_version`
-- (mirrors `attack_version` in `attack_technique`), checkpointed through the
-- existing `feed_state` row keyed by feed_id 'sigma_corpus' / 'yara_corpus'.

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
    condition_summary TEXT,             -- e.g. "3 hex strings, 1 hash condition" -- a description, never re-evaluable
    author          TEXT,
    license         TEXT NOT NULL,
    source_url      TEXT NOT NULL,
    corpus_version  TEXT NOT NULL,      -- pinned source release tag
    feed_id         TEXT NOT NULL DEFAULT 'yara_corpus',
    PRIMARY KEY (rule_name, corpus_version)
) STRICT;

CREATE INDEX idx_yara_rule_corpus_attack ON yara_rule_corpus (attack_refs);
