-- Edge's record of an engagement it ran (Azazel-Fabric#23, R1c).
--
-- Azazel-Edge builds a Fabric `EngagementEvent` "for audit / Knowledge
-- ingest" -- its own words -- and until this lane nobody read one. This table
-- is where a read one lands.
--
-- It is a fact lane. An `EngagementEvent` is descriptive by contract ("the
-- product records what it selected and the reaction it observed; this contract
-- never re-runs the action"), and nothing Knowledge does with a row makes it
-- otherwise. Knowledge advises; it does not select, and a record of somebody
-- else's selection is not Knowledge's selection.
--
-- ## The Engage vocabulary is stored verbatim and mapped to nothing
--
-- `objective`, `approach`, `activity` and `attacker_reaction` are MITRE
-- Engage-aligned values owned by Azazel-Fabric. They are not constrained to an
-- enum here, for the reason `0006_defensive_state_observation.sql` gives: a
-- CHECK listing them would make this file a second place that defines them,
-- and the two would drift.
--
-- They are also NOT projected into `reaction.action_applied`. The two
-- vocabularies genuinely differ:
--
--   Fabric activity : observe notify throttle redirect isolate
--                     redirect_to_decoy expose_decoy_surface collect_credentials
--   reaction action : throttle redirect isolate delay deception
--
-- Three values coincide; five do not. Deciding that `redirect_to_decoy` "is"
-- `deception` would invent a mapping between two product vocabularies, which
-- is how a product-local word becomes canonical by the back door --
-- `correlate/engagement_advisory.py` already refuses the same invention in the
-- other direction and names the gap in `limitations` instead. An engagement
-- event is therefore its own lane, not a reaction in disguise.
--
-- ## What the contract does not carry
--
-- `EngagementEvent` has no actor and no edge identity: it records what was
-- done, not to whom. Those arrive on the batch envelope, which is why they are
-- separate columns here rather than fields parsed out of `raw`. A row whose
-- envelope supplied neither would be unattributable, so both are NOT NULL.
--
-- Rows are immutable (Absolute Constraint 5), matching `reaction` and
-- `defensive_state_observation_v0`.

CREATE TABLE engagement_event_v0 (
    engagement_event_id INTEGER PRIMARY KEY,
    -- The producer's own id for this engagement. UNIQUE so a re-delivered
    -- batch is a no-op rather than a duplicate: at-least-once transport is
    -- assumed, and counting one engagement twice would distort every summary
    -- built over this table.
    event_ref TEXT NOT NULL UNIQUE,
    -- Who ran it. `product` comes from the event; `edge_id` and `actor_key`
    -- come from the envelope (see above).
    product TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    actor_key TEXT NOT NULL,

    -- Engage vocabulary, exactly as Fabric defines it and exactly as it
    -- arrived. No normalization, no case folding, no mapping.
    objective TEXT NOT NULL,
    approach TEXT NOT NULL,
    activity TEXT NOT NULL,

    -- The observed outcome, if the producer recorded one. Absent is a real
    -- state -- an engagement whose outcome is not yet known -- and is stored
    -- as NULL rather than as a value meaning "none", which a consumer could
    -- not distinguish from an observation.
    attacker_reaction TEXT,
    reaction_window_s INTEGER,
    started_at TEXT,
    ended_at TEXT,
    termination_reason TEXT,

    evidence_refs TEXT NOT NULL DEFAULT '[]',
    schema_version TEXT NOT NULL
        CHECK (schema_version = 'engagement-event/v0.1'),
    -- The line as received. A consumer that disagrees with how a column above
    -- was filled can check it against what actually arrived.
    raw TEXT NOT NULL,
    received_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_engagement_event_actor
    ON engagement_event_v0 (actor_key, started_at);

CREATE INDEX idx_engagement_event_edge
    ON engagement_event_v0 (edge_id, received_at);

CREATE INDEX idx_engagement_event_activity
    ON engagement_event_v0 (activity, attacker_reaction);

CREATE TRIGGER trg_engagement_event_no_update
BEFORE UPDATE ON engagement_event_v0
BEGIN
    SELECT RAISE(ABORT, 'engagement_event_v0 is append-only');
END;

CREATE TRIGGER trg_engagement_event_no_delete
BEFORE DELETE ON engagement_event_v0
BEGIN
    SELECT RAISE(ABORT, 'engagement_event_v0 is append-only');
END;
