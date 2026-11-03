-- AZ-06 outcome-envelope memory (Deception#55 / Knowledge#111 G7).
--
-- Fabric `InteractionObservation` says what touched a decoy. It cannot say how
-- much of the world the producer could see while it was watching, and that is
-- what decides whether "nothing happened" means anything. This table is where
-- a producer's `OutcomeObservationEnvelope` (coverage, gaps, confounders,
-- refs) and the `EffectObservation` it correlates (status, limitations) land.
--
-- ## It is a fact lane, and it holds no verdict
--
-- There is no success / safe / effective / believed column. `coverage_complete`
-- is a statement about telemetry, not about the outcome: complete coverage of
-- a window in which nothing was observed is still not evidence of safety, and
-- the advisory says so. The envelope contract itself has no verdict field and
-- refuses one; this table gives it no place to hide one either.
--
-- ## Nothing is derived into a column
--
-- Isolation state is not stored as its own column. The producer states it only
-- through `limitations` (`isolation_drift_observed`, `isolation_not_asserted`)
-- and the effect observation's status; a column computed from those at write
-- time would be a second statement of the same fact that could disagree with
-- the first. The reader derives it from the stored limitations instead.
--
-- Objective / hypothesis / frame refs travel as typed `advisory:` refs inside
-- `evidence_refs`; they are kept there, not parsed out, for the same reason.
--
-- ## Immutable and idempotent (Absolute Constraint 5)
--
-- INSERT-only, triggers reject UPDATE/DELETE. `envelope_ref` is UNIQUE so an
-- at-least-once re-delivery is a no-op; the drain additionally refuses (and
-- quarantines) a re-used `envelope_id` that arrives with different bytes.
-- The CHECKs below are a last line behind the validator: a row claiming
-- complete coverage while naming gaps, or incomplete coverage naming none,
-- cannot be stored whoever wrote it.

CREATE TABLE deception_outcome_envelope_v0 (
    deception_outcome_envelope_id INTEGER PRIMARY KEY,
    envelope_ref TEXT NOT NULL UNIQUE,
    environment_id TEXT NOT NULL,
    package_id TEXT,
    producer_product TEXT NOT NULL,
    producer_node TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    decision_ref TEXT,
    effect_ref TEXT NOT NULL,
    presentation_ref TEXT,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    observation_class TEXT NOT NULL,
    coverage_complete INTEGER NOT NULL CHECK (coverage_complete IN (0, 1)),
    telemetry_coverage TEXT NOT NULL DEFAULT '{}',
    telemetry_gaps TEXT NOT NULL DEFAULT '[]',
    confounders TEXT NOT NULL DEFAULT '[]',
    impact_observations TEXT NOT NULL DEFAULT '{}',
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    effect_observation_ref TEXT NOT NULL,
    effect_status TEXT NOT NULL,
    termination_reason TEXT,
    limitations TEXT NOT NULL DEFAULT '[]',
    -- Entries of limitations / telemetry_gaps / confounders discarded one by one
    -- because they were not valid tokens (CONVENTIONS C6). The rest of the pair is
    -- kept; `raw` still holds what arrived.
    entries_dropped INTEGER NOT NULL DEFAULT 0 CHECK (entries_dropped >= 0),
    -- Fixed-width UTC (`%Y-%m-%dT%H:%M:%S.%fZ`) so string order is time order.
    observed_at TEXT NOT NULL,
    authority_class TEXT NOT NULL CHECK (authority_class IN ('observed_fact', 'active_materialized')),
    schema_version TEXT NOT NULL CHECK (schema_version = 'outcome-observation-envelope/v0.1'),
    raw TEXT NOT NULL,
    received_at TEXT NOT NULL,
    CHECK (coverage_complete = 0 OR telemetry_gaps = '[]'),
    CHECK (coverage_complete = 1 OR telemetry_gaps <> '[]')
) STRICT;

CREATE INDEX idx_deception_outcome_envelope_environment
    ON deception_outcome_envelope_v0 (environment_id, package_id, observed_at);

CREATE INDEX idx_deception_outcome_envelope_trace
    ON deception_outcome_envelope_v0 (trace_id, effect_ref);

CREATE TRIGGER trg_deception_outcome_envelope_no_update
BEFORE UPDATE ON deception_outcome_envelope_v0
BEGIN
    SELECT RAISE(ABORT, 'deception_outcome_envelope_v0 is append-only');
END;

CREATE TRIGGER trg_deception_outcome_envelope_no_delete
BEFORE DELETE ON deception_outcome_envelope_v0
BEGIN
    SELECT RAISE(ABORT, 'deception_outcome_envelope_v0 is append-only');
END;
