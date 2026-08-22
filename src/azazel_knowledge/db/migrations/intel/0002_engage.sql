CREATE TABLE engage_activity (
    activity_id  TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    approach     TEXT NOT NULL,
    goal         TEXT,
    description  TEXT,
    engage_version TEXT NOT NULL
) STRICT;

CREATE INDEX idx_engage_activity_version ON engage_activity (engage_version);

CREATE TABLE engage_attack_map (
    technique_id TEXT NOT NULL,
    activity_id  TEXT NOT NULL REFERENCES engage_activity (activity_id),
    engage_version TEXT NOT NULL,
    PRIMARY KEY (technique_id, activity_id)
) STRICT;

CREATE INDEX idx_engage_attack_map_technique ON engage_attack_map (technique_id);

ALTER TABLE feed_state ADD COLUMN license TEXT;
