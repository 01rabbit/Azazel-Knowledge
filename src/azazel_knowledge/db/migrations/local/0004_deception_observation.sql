-- migrations/local/0004_deception_observation.sql  (AZ-06, ADR-0011)
-- First-class ingest of AZ-06 fact-only deception observations
-- (Fabric InteractionObservation, honesty ladder layers 1-3).
--
-- F-1: local-tier research data is immutable, INSERT-only. Triggers reject
-- UPDATE/DELETE exactly like `reaction`/`observation`; rows never decrease
-- across imports. Idempotent replay is via `observation_uid UNIQUE` +
-- INSERT OR IGNORE on the drain path (no destructive change ever runs).
--
-- The stored fields are the Fabric honesty-ladder facts only. There is NO
-- belief/verdict/effectiveness column: interaction does not prove attacker
-- belief (Azazel-Deception#6, Azazel-Knowledge#58); that inference is layer-4
-- and lives only in the advisory OUTPUT (EffectivenessAdvisory), never here.

CREATE TABLE deception_observation (
    deception_observation_id INTEGER PRIMARY KEY,
    -- Fabric InteractionObservation.observation_id: idempotency/dedupe key.
    observation_uid TEXT NOT NULL UNIQUE,
    environment_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    -- Linkage into the existing reaction/observation model (F-1 §data-model):
    -- Edge stamps these into the observation metadata when available; NULL
    -- otherwise. Never synthesised.
    edge_id TEXT,
    actor_key TEXT,
    observed_at TEXT NOT NULL,
    observation_class TEXT NOT NULL CHECK (observation_class IN ('interaction', 'reaction', 'outcome')),
    surface TEXT NOT NULL CHECK (surface IN ('service', 'port', 'file', 'document', 'credential_lure', 'config_breadcrumb', 'service_history', 'persona_artifact', 'unknown')),
    reaction_kind TEXT CHECK (reaction_kind IS NULL OR reaction_kind IN ('read', 'enumerate', 'authenticate', 'lateral_move', 'exfiltrate', 'modify', 'execute', 'escalate', 'unknown')),
    lure_id TEXT,
    first_contact_latency_ms INTEGER,
    dwell_ms INTEGER,
    attempt_count INTEGER,
    -- honesty-ladder side facts, stored as canonical JSON arrays/objects.
    confounder_tags TEXT NOT NULL DEFAULT '[]',
    runtime_context TEXT,               -- tier/arch/adapter/active+omitted components/saturation/drift
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    raw TEXT NOT NULL,                  -- full canonical observation JSON (audit; attacker-authored strings are data only)
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_deception_observation_environment ON deception_observation (environment_id);
CREATE INDEX idx_deception_observation_package ON deception_observation (package_id);
CREATE INDEX idx_deception_observation_actor_key ON deception_observation (actor_key);
CREATE INDEX idx_deception_observation_observed_at ON deception_observation (observed_at);

CREATE TRIGGER trg_deception_observation_no_update BEFORE UPDATE ON deception_observation
BEGIN
    SELECT RAISE(ABORT, 'deception_observation rows are immutable');
END;

CREATE TRIGGER trg_deception_observation_no_delete BEFORE DELETE ON deception_observation
BEGIN
    SELECT RAISE(ABORT, 'deception_observation rows are immutable');
END;
