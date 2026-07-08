CREATE TABLE behavior_pattern (
    pattern_id           TEXT NOT NULL,
    behavior_generation  INTEGER NOT NULL,
    version              INTEGER NOT NULL DEFAULT 1,   -- generator schema version
    actor_key            TEXT NOT NULL,
    actor_cluster_key    TEXT,
    edge_id              TEXT NOT NULL,                -- source node; source_node_id alias
    observation_start    TEXT NOT NULL,
    observation_end      TEXT NOT NULL,
    action_applied       TEXT NOT NULL,
    reaction_sequence    TEXT NOT NULL DEFAULT '[]',   -- ordered JSON array of reaction classes
    reaction_window_s    INTEGER,
    behavior_class       TEXT NOT NULL CHECK (behavior_class IN (
                             'simple_scanner','scripted_automation','adaptive_probe',
                             'decoy_engaged','disengaged_after_friction','unknown')),
    confidence           INTEGER NOT NULL DEFAULT 0,   -- 0-100
    novelty_score        INTEGER NOT NULL DEFAULT 0,   -- 0-100
    repeatability_score  INTEGER NOT NULL DEFAULT 0,   -- 0-100; 0 = not yet computed / insufficient prior data (#34 fills)
    suspected_stage      TEXT,
    related_iocs         TEXT NOT NULL DEFAULT '[]',
    related_ttps         TEXT NOT NULL DEFAULT '[]',
    generated_at         TEXT NOT NULL,
    generator_version    TEXT NOT NULL,
    behavior_config_hash TEXT NOT NULL,
    provenance           TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (pattern_id, behavior_generation)
) STRICT;
CREATE INDEX idx_behavior_pattern_actor ON behavior_pattern (actor_key, behavior_generation);
CREATE INDEX idx_behavior_pattern_gen   ON behavior_pattern (behavior_generation);
CREATE INDEX idx_behavior_pattern_edge  ON behavior_pattern (edge_id, behavior_generation);

CREATE TABLE behavior_pattern_evidence (
    pattern_id           TEXT NOT NULL,
    behavior_generation  INTEGER NOT NULL,
    evidence_type        TEXT NOT NULL CHECK (evidence_type IN ('observation','reaction','pattern')),
    evidence_id          TEXT NOT NULL,                -- reaction_id / observation_id / event_id as text
    role                 TEXT NOT NULL CHECK (role IN ('source','supporting','derived_from')),
    PRIMARY KEY (pattern_id, behavior_generation, evidence_type, evidence_id, role)
) STRICT;
CREATE INDEX idx_bpe_pattern ON behavior_pattern_evidence (pattern_id, behavior_generation);

-- Precomputed similarity edges (written by #34 during the generation pass).
CREATE TABLE behavior_pattern_similarity (
    pattern_id           TEXT NOT NULL,
    behavior_generation  INTEGER NOT NULL,
    other_pattern_id     TEXT NOT NULL,
    similarity           REAL NOT NULL,                -- 0.0-1.0
    repeatability        INTEGER NOT NULL DEFAULT 0,   -- 0-100
    shared_features      TEXT NOT NULL DEFAULT '[]',
    differences          TEXT NOT NULL DEFAULT '[]',
    evidence_refs        TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (pattern_id, behavior_generation, other_pattern_id)
) STRICT;
CREATE INDEX idx_bps_pattern ON behavior_pattern_similarity (pattern_id, behavior_generation, similarity DESC);

CREATE TABLE behavior_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
) STRICT;   -- rows: current_behavior_generation, generator_version, built_at
