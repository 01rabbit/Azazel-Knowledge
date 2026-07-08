-- migrations/local/0003_reaction_ext.sql  (#36; all additive nullable columns,
-- reaction stays INSERT-only/immutable — ADD COLUMN is DDL, triggers are on UPDATE/DELETE)
ALTER TABLE reaction ADD COLUMN actor_cluster_key TEXT;
ALTER TABLE reaction ADD COLUMN action_profile    TEXT;
ALTER TABLE reaction ADD COLUMN decoy_touched     INTEGER;   -- 0/1
ALTER TABLE reaction ADD COLUMN decoy_profile     TEXT;
ALTER TABLE reaction ADD COLUMN retry_interval_ms INTEGER;
ALTER TABLE reaction ADD COLUMN timeout_adaptation TEXT;
ALTER TABLE reaction ADD COLUMN payload_ext       TEXT NOT NULL DEFAULT '{}';  -- pre/post summaries, raw_refs, unknown fields (audit)
