-- Outcome-as-Evidence v0 fact memory.
--
-- Execution, mechanism, outcome and tactical assessment remain separate facts.
-- No table contains a universal success field, attacker belief, or executable directive.
-- All rows are immutable; duplicate handling is performed by canonical identity/content
-- checks in db/outcome_memory.py before INSERT.

CREATE TABLE outcome_execution_v0 (
    outcome_execution_id INTEGER PRIMARY KEY,
    execution_ref TEXT NOT NULL UNIQUE,
    producer_product TEXT NOT NULL,
    producer_node TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    decision_ref TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('applied','partial','failed','rejected','unverified','released')),
    observed_at TEXT NOT NULL,
    release_ref TEXT,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    authority_class TEXT NOT NULL CHECK (authority_class = 'producer_execution_fact'),
    schema_version TEXT NOT NULL CHECK (schema_version = 'outcome-execution/v0.1'),
    raw TEXT NOT NULL,
    received_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_outcome_execution_trace ON outcome_execution_v0 (trace_id, decision_ref);

CREATE TABLE outcome_mechanism_v0 (
    outcome_mechanism_id INTEGER PRIMARY KEY,
    observation_id TEXT NOT NULL UNIQUE,
    producer_product TEXT NOT NULL,
    producer_node TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    decision_ref TEXT NOT NULL,
    execution_ref TEXT NOT NULL,
    mechanism_kind TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('observed','not_observed','unverified','released','stale','disputed')),
    observed_parameters TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    limitations TEXT NOT NULL DEFAULT '[]',
    authority_class TEXT NOT NULL CHECK (authority_class = 'producer_mechanism_fact'),
    schema_version TEXT NOT NULL CHECK (schema_version = 'outcome-mechanism/v0.1'),
    raw TEXT NOT NULL,
    received_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_outcome_mechanism_chain ON outcome_mechanism_v0 (trace_id, decision_ref, execution_ref);

CREATE TABLE outcome_observation_v0 (
    outcome_observation_id INTEGER PRIMARY KEY,
    observation_id TEXT NOT NULL UNIQUE,
    producer_product TEXT NOT NULL,
    producer_node TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    decision_ref TEXT NOT NULL,
    execution_ref TEXT NOT NULL,
    mechanism_observation_ref TEXT,
    subject_ref TEXT,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('before','during','after')),
    observation_class TEXT NOT NULL,
    observation_values TEXT NOT NULL DEFAULT '{}',
    telemetry_coverage TEXT NOT NULL DEFAULT '{}',
    confounders TEXT NOT NULL DEFAULT '[]',
    resource_impact TEXT NOT NULL DEFAULT '{}',
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT NOT NULL,
    authority_class TEXT NOT NULL CHECK (authority_class = 'producer_outcome_fact'),
    schema_version TEXT NOT NULL CHECK (schema_version = 'outcome-observation/v0.1'),
    raw TEXT NOT NULL,
    received_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_outcome_observation_chain ON outcome_observation_v0 (trace_id, decision_ref, execution_ref);
CREATE INDEX idx_outcome_observation_window ON outcome_observation_v0 (window_start, window_end);

CREATE TABLE outcome_effect_assessment_v0 (
    outcome_effect_assessment_id INTEGER PRIMARY KEY,
    assessment_id TEXT NOT NULL UNIQUE,
    producer_product TEXT NOT NULL,
    producer_node TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    decision_ref TEXT NOT NULL,
    execution_ref TEXT NOT NULL,
    mechanism_observation_ref TEXT NOT NULL,
    outcome_observation_refs TEXT NOT NULL,
    tactical_effect TEXT NOT NULL,
    assessment TEXT NOT NULL CHECK (assessment IN ('supported','unsupported','inconclusive')),
    evaluator TEXT NOT NULL,
    policy_ref TEXT NOT NULL,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    limitations TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT NOT NULL,
    executable INTEGER NOT NULL CHECK (executable = 0),
    authority_class TEXT NOT NULL CHECK (authority_class = 'producer_assessment_fact'),
    schema_version TEXT NOT NULL CHECK (schema_version = 'tactical-effect-assessment/v0.1'),
    raw TEXT NOT NULL,
    received_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_outcome_assessment_chain ON outcome_effect_assessment_v0 (trace_id, decision_ref, execution_ref);

CREATE TRIGGER trg_outcome_execution_no_update BEFORE UPDATE ON outcome_execution_v0 BEGIN SELECT RAISE(ABORT, 'outcome execution facts are immutable'); END;
CREATE TRIGGER trg_outcome_execution_no_delete BEFORE DELETE ON outcome_execution_v0 BEGIN SELECT RAISE(ABORT, 'outcome execution facts are immutable'); END;
CREATE TRIGGER trg_outcome_mechanism_no_update BEFORE UPDATE ON outcome_mechanism_v0 BEGIN SELECT RAISE(ABORT, 'outcome mechanism facts are immutable'); END;
CREATE TRIGGER trg_outcome_mechanism_no_delete BEFORE DELETE ON outcome_mechanism_v0 BEGIN SELECT RAISE(ABORT, 'outcome mechanism facts are immutable'); END;
CREATE TRIGGER trg_outcome_observation_no_update BEFORE UPDATE ON outcome_observation_v0 BEGIN SELECT RAISE(ABORT, 'outcome observation facts are immutable'); END;
CREATE TRIGGER trg_outcome_observation_no_delete BEFORE DELETE ON outcome_observation_v0 BEGIN SELECT RAISE(ABORT, 'outcome observation facts are immutable'); END;
CREATE TRIGGER trg_outcome_assessment_no_update BEFORE UPDATE ON outcome_effect_assessment_v0 BEGIN SELECT RAISE(ABORT, 'outcome assessment facts are immutable'); END;
CREATE TRIGGER trg_outcome_assessment_no_delete BEFORE DELETE ON outcome_effect_assessment_v0 BEGIN SELECT RAISE(ABORT, 'outcome assessment facts are immutable'); END;
