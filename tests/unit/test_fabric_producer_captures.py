"""Knowledge's ingest, fed what the real producers emitted (Fabric producer captures).

Every other Fabric-contract test here builds its payloads through Fabric's own
models or from hand-written fixtures. A payload built from the contract proves
Knowledge accepts what the contract *allows*; it cannot show that Knowledge
accepts what a producer actually *sends*. `azazel_fabric.testing` ships the
second kind: outputs recorded from Azazel-Edge and Azazel-Deception running
their own code on their own test inputs. This file puts those through the real
consumer path -- the API boundary in `api/contracts.py`, the spool, then
`ingest/validators.py` + `ingest/drain.py` -- and asserts what is stored,
what is quarantined, and what is correlated.

Provenance of the captures (see `producer_capture_provenance`):

* Azazel-Edge        e84af9a8ca7c9668416db41cd085d17264cbd8b9
* Azazel-Deception   305af8524bc362c3f6f9615d369794f72888e1c4

Availability: the captures arrive with Fabric v0.10.0rc1. Under the Fabric
v0.9.0 pin (this repo's formal pin until a later PR moves it) the module is
skipped, not failed -- there is nothing to read.

Which captures Knowledge consumes (the adoption table: deception / engagement /
outcome), and the lane each one takes:

* `InteractionObservation`  (Deception)  -> `/v1/deception-observations`
* `EngagementEvent`         (Edge)       -> `/v1/engagement-events`
* `ExecutionRefV0`, `MechanismObservationV0`, `OutcomeObservationV0`,
  `TacticalEffectAssessmentRefV0` (Edge; one `OutcomeObservationV0` pair from
  Deception)                              -> `/v1/outcome-evidence`

Out of scope, because Knowledge has no ingest for them (test_every_capture_is_
accounted_for pins this list, so a new capture or a new Knowledge lane cannot
go unnoticed):

* `EngagementCandidate`, `EnvironmentTransitionDecision`, `DefensiveEffectRef`
  (Edge): Knowledge is not their consumer.
* `PresentedTerrainRef` (Deception): not ingested.
* `EffectObservation` (Deception): Knowledge reads it only as the second half
  of a `deception-outcome-envelopes` pair, and the captures contain no
  `OutcomeObservationEnvelope` to pair it with, so that lane cannot be driven
  from captures. It is left to `test_deception_outcome_envelopes.py`.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

azazel_testing = pytest.importorskip("azazel_fabric.testing")
if not hasattr(azazel_testing, "producer_capture_names"):
    pytest.skip(
        "Fabric producer captures arrive with v0.10.0rc1; this environment has an "
        "earlier azazel-fabric (the v0.9.0 pin ships none)",
        allow_module_level=True,
    )

from _api_support import add_api_client, auth_header, make_client  # noqa: E402
from azazel_knowledge.core.clock import FixedClock  # noqa: E402
from azazel_knowledge.db.writer import PrioritySingleWriterQueue  # noqa: E402
from azazel_knowledge.ingest.drain import drain_endpoint  # noqa: E402
from azazel_knowledge.ingest.spool import SpoolWriter  # noqa: E402

body = azazel_testing.producer_capture_body
names = azazel_testing.producer_capture_names
provenance = azazel_testing.producer_capture_provenance

EDGE_COMMIT = "e84af9a8ca7c9668416db41cd085d17264cbd8b9"
DECEPTION_COMMIT = "305af8524bc362c3f6f9615d369794f72888e1c4"

# The captures carry fixed 2026 timestamps; Knowledge's validators bound a line
# to +/-48h of the drain clock, so the drain clock is set beside the capture
# rather than the captures being rewritten.
DECEPTION_OBS_NOW = datetime(2026, 1, 1, 0, 10, 0, tzinfo=timezone.utc)
EDGE_OUTCOME_NOW = datetime(2026, 8, 26, 0, 10, 0, tzinfo=timezone.utc)
DECEPTION_OUTCOME_NOW = datetime(2026, 8, 26, 6, 20, 0, tzinfo=timezone.utc)
ENGAGEMENT_NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)

EDGE = "edge/"
DECEPTION = "deception/"


# --------------------------------------------------------------------------
# harness: POST through the real API, drain through the real worker path
# --------------------------------------------------------------------------


class _Lane:
    """One Knowledge instance: post an envelope, drain it, read what was stored."""

    def __init__(self, tmp_path: Path, endpoint: str, url: str) -> None:
        self.client, self.settings, self.local_db, _ = make_client(tmp_path)
        self.token = add_api_client(self.local_db, "capture-edge", ["ingest"])
        self.read_token = add_api_client(self.local_db, "capture-reader", ["read"])
        self.tmp_path = tmp_path
        self.endpoint = endpoint
        self.url = url
        self._n = 0

    def post(self, payload: dict[str, Any]):
        return self.client.post(self.url, json=payload, headers=auth_header(self.token))

    def spooled_lines(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for path in sorted((self.settings.spool_root / self.endpoint).rglob("*.jsonl")):
            out += [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
        return out

    def drain(self, now: datetime):
        self._n += 1
        writer = PrioritySingleWriterQueue(self.local_db, self.tmp_path / f"w{self._n}.lock")
        writer.open()
        try:
            return drain_endpoint(
                self.endpoint,
                SpoolWriter(self.settings.spool_root),
                writer,
                clock=FixedClock(now),
            )
        finally:
            writer.close()

    def post_and_drain(self, payload: dict[str, Any], now: datetime):
        resp = self.post(payload)
        assert resp.status_code == 202, resp.text
        stats = self.drain(now)
        return resp.json()["batch_id"], stats

    def batch_status(self, batch_id: str) -> dict[str, Any]:
        resp = self.client.get(f"/v1/ingest/{batch_id}", headers=auth_header(self.token))
        assert resp.status_code == 200, resp.text
        return resp.json()

    def rows(self, table: str) -> list[sqlite3.Row]:
        conn = sqlite3.connect(self.local_db)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
        finally:
            conn.close()


# --------------------------------------------------------------------------
# the captures themselves are what they claim to be
# --------------------------------------------------------------------------


def test_the_captures_come_from_the_pinned_product_commits():
    assert {provenance(n)["commit"] for n in names(product="edge")} == {EDGE_COMMIT}
    assert {provenance(n)["commit"] for n in names(product="deception")} == {DECEPTION_COMMIT}


KNOWLEDGE_CONSUMED_MODELS = {
    "azazel_fabric.deception_contracts.InteractionObservation",
    "azazel_fabric.engagement_contracts.EngagementEvent",
    "azazel_fabric.outcome_contracts.ExecutionRefV0",
    "azazel_fabric.outcome_contracts.MechanismObservationV0",
    "azazel_fabric.outcome_contracts.OutcomeObservationV0",
    "azazel_fabric.outcome_contracts.TacticalEffectAssessmentRefV0",
}
NOT_CONSUMED_BY_KNOWLEDGE = {
    "azazel_fabric.engagement_contracts.EngagementCandidate",
    "azazel_fabric.deception_contracts.EnvironmentTransitionDecision",
    "azazel_fabric.effect_contracts.DefensiveEffectRef",
    "azazel_fabric.effect_contracts.PresentedTerrainRef",
    "azazel_fabric.effect_contracts.EffectObservation",
}


def test_every_capture_is_accounted_for():
    """A capture of a model that is neither consumed nor listed out of scope fails here."""

    seen = {provenance(n)["model"] for n in names()}
    assert seen <= KNOWLEDGE_CONSUMED_MODELS | NOT_CONSUMED_BY_KNOWLEDGE, sorted(
        seen - KNOWLEDGE_CONSUMED_MODELS - NOT_CONSUMED_BY_KNOWLEDGE
    )
    # ...and the in-scope list is not vacuous.
    assert KNOWLEDGE_CONSUMED_MODELS <= seen


# --------------------------------------------------------------------------
# deception: InteractionObservation -> /v1/deception-observations
# --------------------------------------------------------------------------

OBS_PORT = DECEPTION + "deception_contracts_interaction_observation_interaction_port_v0"
OBS_SERVICE = DECEPTION + "deception_contracts_interaction_observation_reaction_service_v0"
OBS_LIST = DECEPTION + "deception_contracts_interaction_observation_export_list_v0"


def _obs_lane(tmp_path: Path) -> _Lane:
    return _Lane(tmp_path, "deception-observations", "/v1/deception-observations")


def _obs_envelope(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"environment_id": items[0]["environment_id"], "items": items}


def test_deception_export_list_is_the_two_single_observations():
    """`export_observations` returns a list; the singles are its elements."""

    assert body(OBS_LIST) == [body(OBS_PORT), body(OBS_SERVICE)]


def test_real_deception_observations_are_stored_with_their_facts(tmp_path):
    lane = _obs_lane(tmp_path)
    items = body(OBS_LIST)
    batch_id, stats = lane.post_and_drain(_obs_envelope(items), DECEPTION_OBS_NOW)

    # accepted at the boundary and flattened one JSON line per observation
    assert [l["observation_id"] for l in lane.spooled_lines()] == [
        "env-export-1-obs-0001",
        "env-export-1-obs-0002",
    ]
    assert stats.lines_valid == 2 and stats.lines_invalid == 0
    assert lane.batch_status(batch_id)["invalid"] == []

    port, service = lane.rows("deception_observation")
    assert (port["observation_uid"], port["observation_class"], port["surface"]) == (
        "env-export-1-obs-0001", "interaction", "port",
    )
    assert port["reaction_kind"] is None and port["dwell_ms"] is None
    assert json.loads(port["confounder_tags"]) == []

    assert (service["observation_uid"], service["observation_class"], service["surface"]) == (
        "env-export-1-obs-0002", "reaction", "service",
    )
    assert service["reaction_kind"] == "enumerate"
    assert (service["first_contact_latency_ms"], service["dwell_ms"], service["attempt_count"]) == (
        120, 3000, 2,
    )
    assert json.loads(service["confounder_tags"]) == ["scanner_noise"]
    assert json.loads(service["evidence_refs"]) == ["evidence:obs:1"]
    context = json.loads(service["runtime_context"])
    assert context["selected_tier"] == "lite" and context["runtime_adapter"] == "docker_compose"
    assert context["omitted_components"] == ["evidence-sidecar-placeholder"]

    for row in (port, service):
        assert (row["environment_id"], row["package_id"], row["node_id"]) == (
            "env-export-1", "municipal-linux-v1", "az06-test",
        )
        # Deception's observation metadata is empty, so no actor or edge is
        # stamped. Knowledge never synthesises one: these rows are not
        # attributable to an actor, and the advisory reads them per environment.
        assert row["edge_id"] is None and row["actor_key"] is None
        # the stored raw is the observation as sent, descriptive only
        assert json.loads(row["raw"])["authority"] == "descriptive_only"


def test_redelivering_the_export_is_idempotent(tmp_path):
    lane = _obs_lane(tmp_path)
    lane.post_and_drain(_obs_envelope([body(OBS_PORT)]), DECEPTION_OBS_NOW)
    _, stats = lane.post_and_drain(_obs_envelope(body(OBS_LIST)), DECEPTION_OBS_NOW)
    # the port observation is a duplicate, the service observation is new
    assert stats.lines_valid == 2 and stats.duplicates_skipped == 1
    assert len(lane.rows("deception_observation")) == 2


def test_real_deception_observations_are_correlated_into_the_advisory(tmp_path):
    """Read side: the stored producer facts reach `/v1/deception-effectiveness`."""

    lane = _obs_lane(tmp_path)
    lane.post_and_drain(_obs_envelope(body(OBS_LIST)), DECEPTION_OBS_NOW)
    resp = lane.client.get(
        "/v1/deception-effectiveness?environment_id=env-export-1",
        headers=auth_header(lane.read_token),
    )
    assert resp.status_code == 200, resp.text
    advisory = resp.json()
    assert advisory["authority"] == "advisory_only" and advisory["executable"] is False
    assert advisory["environment_id"] == "env-export-1"
    # both observations are cited, by the producer's own ids
    assert advisory["observation_refs"] == ["env-export-1-obs-0001", "env-export-1-obs-0002"]
    assert advisory["metadata"]["observation_count"] == 2
    # the reaction's `scanner_noise` and the omitted component are read as
    # counter-evidence, not as a verdict about the deception
    assert advisory["metadata"]["distinct_confounders"] == 1
    assert advisory["metadata"]["omitted_components"] == 1
    assert advisory["metadata"]["suggested_posture"] == "inconclusive-control-confounders"
    assert any("scanner_noise" in c for c in advisory["counter_evidence"])
    assert any("insufficient evidence: only 2" in u for u in advisory["unknowns"])
    assert "Attacker belief is not asserted" in advisory["assessment"]


def test_observations_older_than_the_skew_window_are_quarantined_not_stored(tmp_path):
    """The captures' timestamps are fixed literals; against a drain clock months
    later Knowledge's +/-48h bound applies to them like to any other line."""

    lane = _obs_lane(tmp_path)
    batch_id, stats = lane.post_and_drain(
        _obs_envelope(body(OBS_LIST)), datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)
    )
    assert stats.lines_valid == 0 and stats.lines_invalid == 2
    assert [i["error"] for i in lane.batch_status(batch_id)["invalid"]] == [
        "timestamp outside +/-48h skew window"
    ] * 2
    assert lane.rows("deception_observation") == []


# --------------------------------------------------------------------------
# engagement: EngagementEvent -> /v1/engagement-events
# --------------------------------------------------------------------------

ENG_ACCEPTED = EDGE + "engagement_event_redirect_accepted_v0"
ENG_DOWNGRADED = EDGE + "engagement_event_redirect_downgraded_to_notify_v0"


def _eng_lane(tmp_path: Path) -> _Lane:
    return _Lane(tmp_path, "engagement-events", "/v1/engagement-events")


def _eng_envelope(*events: dict[str, Any]) -> dict[str, Any]:
    # `edge_id` / `actor_key` are the envelope's: the contract models neither.
    return {"edge_id": "edge-1", "actor_key": "actor-1", "items": list(events)}


def test_real_engagement_events_are_stored_in_the_engage_vocabulary(tmp_path):
    lane = _eng_lane(tmp_path)
    _, stats = lane.post_and_drain(_eng_envelope(body(ENG_ACCEPTED), body(ENG_DOWNGRADED)), ENGAGEMENT_NOW)

    assert stats.lines_valid == 2 and stats.lines_invalid == 0
    # the envelope identity is folded onto each line under an `_envelope_` name
    assert {(l["_envelope_edge_id"], l["_envelope_actor_key"]) for l in lane.spooled_lines()} == {
        ("edge-1", "actor-1")
    }

    rows = {r["event_ref"]: r for r in lane.rows("engagement_event_v0")}
    assert set(rows) == {"AZ-01-engev-redirect", "AZ-01-engev-notify"}

    accepted = rows["AZ-01-engev-redirect"]
    assert (accepted["objective"], accepted["approach"], accepted["activity"]) == (
        "collect", "channel", "redirect_to_decoy",
    )
    assert accepted["attacker_reaction"] == "decoy_engaged"

    # The producer downgraded a redirect to a notify. Knowledge stores the
    # downgrade as the producer reported it -- it is a different engagement,
    # not a redirect that failed, and nothing maps it back.
    downgraded = rows["AZ-01-engev-notify"]
    assert (downgraded["objective"], downgraded["approach"], downgraded["activity"]) == (
        "detect", "detect", "notify",
    )
    assert downgraded["attacker_reaction"] == "disengaged"

    for row in rows.values():
        assert (row["product"], row["edge_id"], row["actor_key"]) == ("AZ-01", "edge-1", "actor-1")
        assert row["schema_version"] == "engagement-event/v0.1"
        assert json.loads(row["evidence_refs"]) == ["ev-soc-1", "ev-noc-1"]
        # absent stays NULL: the producer recorded no window and no end
        assert row["reaction_window_s"] is None
        assert row["started_at"] is None and row["ended_at"] is None
        assert row["termination_reason"] is None
        assert json.loads(row["raw"])["trigger"]["attack_technique"] == "T1110"


def test_redelivering_an_engagement_event_is_idempotent(tmp_path):
    lane = _eng_lane(tmp_path)
    lane.post_and_drain(_eng_envelope(body(ENG_ACCEPTED)), ENGAGEMENT_NOW)
    _, stats = lane.post_and_drain(_eng_envelope(body(ENG_ACCEPTED), body(ENG_DOWNGRADED)), ENGAGEMENT_NOW)
    assert stats.duplicates_skipped == 1
    assert len(lane.rows("engagement_event_v0")) == 2


def test_an_engagement_event_with_a_directive_added_is_refused_at_the_boundary(tmp_path):
    """A real event plus one directive-shaped key is not a real event any more."""

    lane = _eng_lane(tmp_path)
    tampered = dict(body(ENG_ACCEPTED), firewall_rule="drop all")
    resp = lane.post(_eng_envelope(tampered))
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "ingest_batch_invalid"
    assert lane.spooled_lines() == []


# --------------------------------------------------------------------------
# outcome: the four Outcome-as-Evidence records -> /v1/outcome-evidence
# --------------------------------------------------------------------------

OUTCOME_TABLES = {
    "outcome-execution/v0.1": "outcome_execution_v0",
    "outcome-mechanism/v0.1": "outcome_mechanism_v0",
    "outcome-observation/v0.1": "outcome_observation_v0",
    "tactical-effect-assessment/v0.1": "outcome_effect_assessment_v0",
}


def _outcome_lane(tmp_path: Path) -> _Lane:
    return _Lane(tmp_path, "outcome-evidence", "/v1/outcome-evidence")


def _edge_chain(action: str) -> list[dict[str, Any]]:
    """Edge's four records for one action, in the producer's dependency order."""

    return [
        body(f"{EDGE}outcome_{kind}_{action}_v0")
        for kind in ("execution", "mechanism", "outcome", "assessment")
    ]


def _stored_counts(lane: _Lane) -> dict[str, int]:
    return {schema: len(lane.rows(table)) for schema, table in OUTCOME_TABLES.items()}


@pytest.mark.parametrize("action", ["redirect", "throttle"])
def test_a_real_edge_chain_is_stored_as_four_separate_facts(tmp_path, action):
    lane = _outcome_lane(tmp_path)
    chain = _edge_chain(action)
    # The assessment first and the execution last: arrival order must not matter,
    # because the drain stores a chain in dependency order.
    _, stats = lane.post_and_drain({"items": list(reversed(chain))}, EDGE_OUTCOME_NOW)

    assert stats.lines_valid == 4 and stats.lines_invalid == 0
    assert _stored_counts(lane) == {schema: 1 for schema in OUTCOME_TABLES}

    (execution,) = lane.rows("outcome_execution_v0")
    assert execution["action"] == action and execution["status"] == "applied"
    assert (execution["producer_product"], execution["producer_node"]) == ("azazel-edge", "edge-1")
    assert execution["authority_class"] == "producer_execution_fact"

    (mechanism,) = lane.rows("outcome_mechanism_v0")
    assert mechanism["execution_ref"] == execution["execution_ref"]
    assert mechanism["mechanism_kind"] == {"redirect": "redirection", "throttle": "traffic_shaping"}[action]
    # provider exit status only: Edge says "unverified", and so does the table
    assert mechanism["status"] == "unverified"

    (outcome,) = lane.rows("outcome_observation_v0")
    assert outcome["mechanism_observation_ref"] == mechanism["observation_id"]
    assert outcome["phase"] == "after" and outcome["observation_class"] == "edge_outcome_record"
    assert json.loads(outcome["confounders"]) == ["source_ip_is_not_actor_identity"]

    (assessment,) = lane.rows("outcome_effect_assessment_v0")
    # "inconclusive" is what the producer said; it is stored as a reference to
    # the facts it rests on, never as a success flag
    assert assessment["assessment"] == "inconclusive" and assessment["executable"] == 0
    assert assessment["mechanism_observation_ref"] == mechanism["observation_id"]
    assert json.loads(assessment["outcome_observation_refs"]) == [outcome["observation_id"]]
    assert json.loads(assessment["limitations"]) == ["causal_support_inconclusive"]

    # one trace across all four tables
    traces = {r["trace_id"] for t in OUTCOME_TABLES.values() for r in lane.rows(t)}
    assert traces == {"trace-test-1"}


@pytest.mark.parametrize(
    ("variant", "kind", "status", "limitation"),
    [
        ("outcome_mechanism_throttle_observed_v0", "traffic_shaping", "observed", None),
        (
            "outcome_mechanism_route_change_degraded_to_unknown_v0",
            "unknown",
            "unverified",
            "internal_route_change_not_representable_in_shared_v0.1",
        ),
    ],
)
def test_mechanism_variants_are_stored_as_the_producer_stated_them(tmp_path, variant, kind, status, limitation):
    """An observed mechanism stays `observed`; a degraded one stays `unknown` with its reason."""

    lane = _outcome_lane(tmp_path)
    _, stats = lane.post_and_drain(
        {"items": [body(f"{EDGE}outcome_execution_throttle_v0"), body(EDGE + variant)]},
        EDGE_OUTCOME_NOW,
    )
    assert stats.lines_valid == 2 and stats.lines_invalid == 0
    (mechanism,) = lane.rows("outcome_mechanism_v0")
    assert (mechanism["mechanism_kind"], mechanism["status"]) == (kind, status)
    assert json.loads(mechanism["limitations"]) == ([limitation] if limitation else [])


def test_edge_fact_ids_are_one_per_decision_so_a_second_action_is_quarantined(tmp_path):
    """The redirect and throttle captures share `execution_ref` and the mechanism
    fixtures share `observation_id`s while differing in content (the capture
    harness reuses `trace-test-1`). Knowledge's rule -- an identity is one
    statement -- quarantines the second chain rather than overwriting the
    first, and says why. This pins that behaviour; it is not an Edge defect."""

    lane = _outcome_lane(tmp_path)
    lane.post_and_drain({"items": _edge_chain("redirect")}, EDGE_OUTCOME_NOW)
    batch_id, stats = lane.post_and_drain({"items": _edge_chain("throttle")}, EDGE_OUTCOME_NOW)

    invalid = lane.batch_status(batch_id)["invalid"]
    assert {i["error"] for i in invalid} == {"fact identity collision with different canonical content"}
    # lines 1, 3, 4 of the throttle chain: execution, outcome (`outcome-1`) and
    # assessment (`effect-1`) reuse an identity with different content
    assert [i["line_no"] for i in invalid] == [1, 3, 4]
    assert stats.lines_valid == 1 and stats.lines_invalid == 3
    # The first chain is untouched. The throttle mechanism has its own id, so it
    # is stored, joined by reference to the execution that is there; Knowledge
    # joins by reference and does not compare `mechanism_kind` with `action`.
    (execution,) = lane.rows("outcome_execution_v0")
    assert execution["action"] == "redirect"
    assert sorted(r["mechanism_kind"] for r in lane.rows("outcome_mechanism_v0")) == [
        "redirection",
        "traffic_shaping",
    ]
    assert len(lane.rows("outcome_observation_v0")) == 1
    assert len(lane.rows("outcome_effect_assessment_v0")) == 1


DECEPTION_DURING = DECEPTION + "outcome_contracts_presented_terrain_lifecycle_during_v0"
DECEPTION_AFTER = DECEPTION + "outcome_contracts_presented_terrain_lifecycle_after_reset_v0"


def test_deception_lifecycle_outcomes_without_edges_execution_are_quarantined(tmp_path):
    """Deception's outcomes name an execution and a mechanism Edge produced
    (`execution-golden-redirect-1`); no capture contains them, so Knowledge
    refuses them as dangling and says so. Nothing is stored."""

    lane = _outcome_lane(tmp_path)
    batch_id, stats = lane.post_and_drain(
        {"items": [body(DECEPTION_DURING), body(DECEPTION_AFTER)]}, DECEPTION_OUTCOME_NOW
    )
    assert stats.lines_valid == 0 and stats.lines_invalid == 2
    assert {i["error"] for i in lane.batch_status(batch_id)["invalid"]} == {
        "referenced execution fact is not present"
    }
    assert _stored_counts(lane) == {schema: 0 for schema in OUTCOME_TABLES}


def test_deception_lifecycle_outcomes_join_the_chain_they_reference(tmp_path):
    """With the execution and mechanism they name present, both lifecycle
    outcomes are stored and joined to that chain by reference.

    The execution and mechanism here are DERIVED, not captured: Edge's captured
    records re-addressed to the refs Deception's capture names, because the two
    products' captures were taken independently and do not share a trace. The
    Deception outcomes themselves are the captures, unmodified."""

    during, after = body(DECEPTION_DURING), body(DECEPTION_AFTER)
    execution = dict(
        body(f"{EDGE}outcome_execution_redirect_v0"),
        execution_ref=during["execution_ref"],
        trace_id=during["trace_id"],
        decision_ref=during["decision_ref"],
    )
    mechanism = dict(
        body(f"{EDGE}outcome_mechanism_redirect_v0"),
        observation_id=during["mechanism_observation_ref"],
        execution_ref=during["execution_ref"],
        trace_id=during["trace_id"],
        decision_ref=during["decision_ref"],
    )
    lane = _outcome_lane(tmp_path)
    _, stats = lane.post_and_drain(
        {"items": [after, during, mechanism, execution]}, DECEPTION_OUTCOME_NOW
    )
    assert stats.lines_valid == 4 and stats.lines_invalid == 0

    rows = {r["phase"]: r for r in lane.rows("outcome_observation_v0")}
    assert set(rows) == {"during", "after"}
    for row in rows.values():
        assert row["producer_product"] == "azazel-deception"
        assert row["observation_class"] == "presented_terrain_lifecycle"
        assert row["execution_ref"] == "execution-golden-redirect-1"
        assert row["mechanism_observation_ref"] == "mechanism-golden-redirection-1"
        assert row["subject_ref"] == "presentation-golden-1"
        assert json.loads(row["observation_values"])["environment_id"] == "env-golden-1"
    assert json.loads(rows["during"]["observation_values"])["lifecycle_state"] == "active"
    # nothing in these is an assessment: Deception states a lifecycle, not a verdict
    assert lane.rows("outcome_effect_assessment_v0") == []


def test_an_outcome_record_with_a_success_claim_added_is_refused_at_the_boundary(tmp_path):
    """The Edge outcome record with a verdict-shaped key added inside its descriptive fact map."""

    lane = _outcome_lane(tmp_path)
    outcome = body(f"{EDGE}outcome_outcome_redirect_v0")
    outcome["observation_values"] = dict(outcome["observation_values"], success=True)
    resp = lane.post({"items": [outcome]})
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "ingest_batch_invalid"
    assert lane.spooled_lines() == []
