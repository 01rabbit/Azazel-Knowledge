PRAGMA journal_mode = WAL;

CREATE TABLE ioc (
    ioc_id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    agg_raw_confidence REAL NOT NULL DEFAULT 0,
    agg_next_expiry TEXT,
    agg_computed_at TEXT,
    UNIQUE (type, value)
) STRICT;

CREATE INDEX idx_ioc_last_seen ON ioc (last_seen);
CREATE INDEX idx_ioc_type_ip ON ioc (value) WHERE type = 'ip';
CREATE INDEX idx_ioc_type_domain ON ioc (value) WHERE type = 'domain';
CREATE INDEX idx_ioc_type_ja3 ON ioc (value) WHERE type = 'ja3';
CREATE INDEX idx_ioc_type_ja4 ON ioc (value) WHERE type = 'ja4';

CREATE TABLE ioc_source (
    ioc_id INTEGER NOT NULL REFERENCES ioc (ioc_id),
    feed_id TEXT NOT NULL,
    source_confidence INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    intel_generation INTEGER NOT NULL,
    flagged_critical_infra INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ioc_id, feed_id)
) STRICT;

CREATE INDEX idx_ioc_source_expires_at ON ioc_source (expires_at);

CREATE TABLE ioc_cidr (
    tier TEXT NOT NULL CHECK (tier IN ('host', '/24', '/16', 'asn')),
    range_start INTEGER NOT NULL,
    range_end INTEGER NOT NULL,
    ioc_id INTEGER NOT NULL REFERENCES ioc (ioc_id),
    feed_id TEXT NOT NULL,
    expires_at TEXT,
    PRIMARY KEY (tier, range_start, ioc_id, feed_id)
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_ioc_cidr_range_end ON ioc_cidr (tier, range_end);

CREATE TABLE kev (
    cve_id TEXT PRIMARY KEY,
    catalog_version TEXT NOT NULL,
    date_added TEXT NOT NULL,
    due_date TEXT,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    short_description TEXT,
    required_action TEXT
) STRICT;

CREATE TABLE attack_technique (
    technique_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tactics TEXT NOT NULL DEFAULT '[]',
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    parent_technique_id TEXT,
    description TEXT,
    data_sources TEXT NOT NULL DEFAULT '[]',
    platforms TEXT NOT NULL DEFAULT '[]',
    attack_version TEXT NOT NULL
) STRICT;

CREATE INDEX idx_attack_technique_version ON attack_technique (attack_version);

CREATE TABLE attack_mitigation (
    mitigation_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    attack_version TEXT NOT NULL
) STRICT;

CREATE INDEX idx_attack_mitigation_version ON attack_mitigation (attack_version);

CREATE TABLE attack_relation (
    relation_id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL,
    source_type TEXT,
    relation_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_type TEXT,
    attack_version TEXT NOT NULL
) STRICT;

CREATE INDEX idx_attack_relation_source ON attack_relation (source_id);
CREATE INDEX idx_attack_relation_target ON attack_relation (target_id);

CREATE TABLE feed_state (
    feed_id TEXT PRIMARY KEY,
    cursor TEXT,
    last_run TEXT,
    last_success TEXT,
    item_count INTEGER NOT NULL DEFAULT 0,
    checksum TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    consecutive_polls INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE _stage_ioc (
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]'
) STRICT;

CREATE TABLE _stage_ioc_source (
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    feed_id TEXT NOT NULL,
    source_confidence INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    intel_generation INTEGER NOT NULL,
    flagged_critical_infra INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE stats_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
