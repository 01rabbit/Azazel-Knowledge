PRAGMA journal_mode = WAL;

CREATE TABLE reaction (
    reaction_id INTEGER PRIMARY KEY,
    edge_id TEXT NOT NULL,
    actor_key TEXT NOT NULL,
    action_applied TEXT NOT NULL CHECK (action_applied IN ('throttle', 'redirect', 'isolate', 'delay', 'deception')),
    applied_at TEXT NOT NULL,
    reaction TEXT NOT NULL CHECK (reaction IN ('continued_scanning', 'shifted_port', 'shifted_protocol', 'shifted_target', 'followed_decoy', 'auth_pattern_changed', 'disengaged', 'unknown')),
    reaction_window_s INTEGER NOT NULL,
    events_in_window INTEGER NOT NULL DEFAULT 0,
    classifier TEXT NOT NULL,
    classifier_version TEXT NOT NULL,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    evidence_modality_count INTEGER NOT NULL DEFAULT 0,
    trust_tier TEXT NOT NULL DEFAULT 'provisional' CHECK (trust_tier IN ('provisional', 'same_edge_corroborated', 'human_confirmed', 'corroborated')),
    advisory_id TEXT,
    advisory_linkage TEXT NOT NULL DEFAULT 'none' CHECK (advisory_linkage IN ('echoed_resolved', 'echoed_pending', 'echoed_unresolved', 'temporal', 'none')),
    created_at TEXT NOT NULL,
    UNIQUE (edge_id, actor_key, action_applied, applied_at, classifier)
) STRICT;

CREATE INDEX idx_reaction_actor_key ON reaction (actor_key);
CREATE INDEX idx_reaction_advisory_id ON reaction (advisory_id);
CREATE INDEX idx_reaction_advisory_linkage ON reaction (advisory_linkage);

CREATE TRIGGER trg_reaction_no_update BEFORE UPDATE ON reaction
BEGIN
    SELECT RAISE(ABORT, 'reaction rows are immutable');
END;

CREATE TRIGGER trg_reaction_no_delete BEFORE DELETE ON reaction
BEGIN
    SELECT RAISE(ABORT, 'reaction rows are immutable');
END;

CREATE TABLE reaction_trust_event (
    event_id INTEGER PRIMARY KEY,
    reaction_id INTEGER NOT NULL REFERENCES reaction (reaction_id),
    edge_id TEXT NOT NULL,
    actor_key TEXT NOT NULL,
    event_type TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_reaction_trust_event_reaction_id ON reaction_trust_event (reaction_id);

CREATE TRIGGER trg_reaction_trust_event_no_update BEFORE UPDATE ON reaction_trust_event
BEGIN
    SELECT RAISE(ABORT, 'reaction_trust_event rows are immutable');
END;

CREATE TRIGGER trg_reaction_trust_event_no_delete BEFORE DELETE ON reaction_trust_event
BEGIN
    SELECT RAISE(ABORT, 'reaction_trust_event rows are immutable');
END;

CREATE TABLE advisory_log (
    advisory_id TEXT PRIMARY KEY,
    event_id TEXT,
    actor_key TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    intel_generation INTEGER NOT NULL,
    local_generation INTEGER NOT NULL,
    stats_generation INTEGER NOT NULL,
    attack_version TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_advisory_log_event_id ON advisory_log (event_id);
CREATE INDEX idx_advisory_log_created_at ON advisory_log (created_at);

CREATE TABLE observation (
    observation_id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    entity_key BLOB,
    entities TEXT NOT NULL DEFAULT '[]',
    raw TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_observation_entity_key ON observation (entity_key);
CREATE INDEX idx_observation_observed_at ON observation (observed_at);
CREATE INDEX idx_observation_event_id ON observation (event_id);

CREATE TABLE observation_stats (
    entity_key BLOB NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    trend REAL,
    stats_generation INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (entity_key, window_start)
) STRICT;

CREATE TABLE reputation (
    entity_key BLOB PRIMARY KEY,
    score REAL NOT NULL,
    contributing_sources TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE edge_reported_ioc (
    entity_key BLOB NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    first_reported TEXT NOT NULL,
    report_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'quarantined' CHECK (status IN ('quarantined', 'promoted', 'revoked')),
    PRIMARY KEY (entity_key, edge_id)
) STRICT;

CREATE INDEX idx_edge_reported_ioc_status ON edge_reported_ioc (status);

CREATE TABLE pattern (
    pattern_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    match_spec TEXT NOT NULL,
    attack_refs TEXT NOT NULL DEFAULT '[]',
    provenance TEXT NOT NULL DEFAULT '{}',
    advisory TEXT,
    confidence REAL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (pattern_id, version)
) STRICT;

CREATE TABLE pattern_index (
    pattern_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    key TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (pattern_id, version, key)
) STRICT;

CREATE INDEX idx_pattern_index_key ON pattern_index (key, priority DESC);

CREATE TABLE rule_draft (
    rule_id INTEGER PRIMARY KEY,
    sid TEXT NOT NULL UNIQUE,
    format TEXT NOT NULL CHECK (format IN ('suricata', 'sigma')),
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'reviewed', 'superseded')),
    provenance TEXT NOT NULL DEFAULT '{}',
    confidence REAL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE bundle_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE api_client (
    key_id TEXT PRIMARY KEY,
    token_sha256 TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    quota_bytes INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE feed_quarantine (
    feed_id TEXT NOT NULL,
    quarantined_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    detail TEXT,
    resolved_at TEXT,
    PRIMARY KEY (feed_id, quarantined_at)
) STRICT;

CREATE TABLE local_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
