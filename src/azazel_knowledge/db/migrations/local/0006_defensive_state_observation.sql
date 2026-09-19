-- Authoritative Defensive State, as *reported* by its producer (Knowledge#65).
--
-- Knowledge advises; it never sets Defensive State. This table is a fact lane:
-- every row records what an authoritative producer said about itself, with the
-- provenance needed to attribute it. Nothing here is a request, a target, or a
-- transition Knowledge wants.
--
-- `reported_state` is deliberately NOT constrained to an enum.
--
-- The canonical vocabulary belongs to Azazel-Fabric (Fabric#14). A CHECK
-- constraint listing the five values here would make this file a second place
-- that defines what they are, and the two would drift. Knowledge stores what it
-- was told, names the vocabulary it was told in, and leaves the meaning where
-- it belongs. When a Fabric release carries the vocabulary, validation is added
-- at the boundary that receives the value -- not here.
--
-- Rows are immutable (Absolute Constraint 5): local-tier research data is
-- append-only and the triggers below enforce it, matching `reaction`.

CREATE TABLE defensive_state_observation_v0 (
    defensive_state_observation_id INTEGER PRIMARY KEY,
    observation_ref TEXT NOT NULL UNIQUE,
    -- The value exactly as the producer reported it. Never normalized, never
    -- upper/lower-cased, never mapped: a consumer comparing this against the
    -- canonical vocabulary must see what actually arrived.
    reported_state TEXT NOT NULL,
    -- Which vocabulary the producer said it was speaking. An unrecognized
    -- vocabulary is stored, not rejected -- Knowledge cannot tell a new
    -- canonical release from a mistake, and discarding the row would lose the
    -- only evidence that either happened.
    state_vocabulary TEXT NOT NULL,
    producer_product TEXT NOT NULL,
    producer_node TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    -- The producer's own decision. Knowledge records which decision the
    -- producer attributed its state to; it never supplies one.
    decision_ref TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    authority_class TEXT NOT NULL
        CHECK (authority_class = 'producer_reported_state'),
    schema_version TEXT NOT NULL
        CHECK (schema_version = 'defensive-state-observation/v0.1'),
    raw TEXT NOT NULL,
    received_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_defensive_state_observation_trace
    ON defensive_state_observation_v0 (trace_id, observed_at);

CREATE INDEX idx_defensive_state_observation_producer
    ON defensive_state_observation_v0 (producer_product, producer_node, observed_at);

CREATE TRIGGER trg_defensive_state_observation_no_update
BEFORE UPDATE ON defensive_state_observation_v0
BEGIN
    SELECT RAISE(ABORT, 'defensive_state_observation_v0 is append-only');
END;

CREATE TRIGGER trg_defensive_state_observation_no_delete
BEFORE DELETE ON defensive_state_observation_v0
BEGIN
    SELECT RAISE(ABORT, 'defensive_state_observation_v0 is append-only');
END;
