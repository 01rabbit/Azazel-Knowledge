"""Knowledge reads Azazel-Edge's `EngagementEvent` (Azazel-Fabric#23, R1c).

Edge builds these "for audit / Knowledge ingest" -- its own docstring -- and
until this lane nobody read one. `engagement_contracts` had two producers and
no consumer: a contract that has only ever been serialized is not known to
interoperate, and the first read is where a disagreement shows.

What these tests hold is the shape of that read:

* the boundary type-enforces the canonical model and fails closed (`422`);
* the Engage vocabulary is stored **verbatim and mapped to nothing** -- three
  of its eight activity values coincide with `reaction.action_applied` and
  five do not, and inventing the missing five is how a product-local word
  becomes canonical by the back door;
* rows are append-only and idempotent (Absolute Constraint 5, F-1);
* reading somebody else's record of what they selected is not Knowledge
  selecting.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from _api_support import QUERY_AS_OF, add_api_client, auth_header, make_client
from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.db.repository import apply_migrations
from azazel_knowledge.db.writer import PrioritySingleWriterQueue
from azazel_knowledge.ingest.drain import drain_endpoint
from azazel_knowledge.ingest.spool import SpoolWriter
from azazel_knowledge.ingest.validators import validate_engagement_event_line

NOW = QUERY_AS_OF
STARTED_AT = QUERY_AS_OF.isoformat().replace("+00:00", "Z")
ENDPOINT = "engagement-events"


# --------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------


def _event(event_id: str = "ev-1", **overrides) -> dict:
    """A valid `EngagementEvent`, built through Fabric's own model.

    Built from the contract rather than hand-written JSON: a hand-written wire
    shape drifts from the contract silently, because nothing checks it.
    """

    from azazel_fabric.engagement_contracts import (
        EngagementConstraint,
        EngagementEvent,
        EngagementOutcome,
    )

    event = EngagementEvent(
        event_id=event_id,
        product="AZ-01",
        objective="collect",
        approach="channel",
        activity="redirect_to_decoy",
        constraints=EngagementConstraint(max_duration_seconds=600),
        outcome=EngagementOutcome(
            attacker_reaction="decoy_engaged",
            reaction_window_s=30,
            started_at=STARTED_AT,
            evidence_refs=["edge:nft:1"],
        ),
        evidence_refs=["edge:decision:1"],
    )
    payload = event.model_dump(mode="json")
    payload.update(overrides)
    return payload


def _envelope(*events: dict, edge_id: str = "edge-1", actor_key: str = "ip:198.51.100.7") -> bytes:
    body = {"edge_id": edge_id, "actor_key": actor_key, "items": list(events or (_event(),))}
    return json.dumps(body).encode("utf-8")


def _line(event: dict | None = None, **envelope_fields) -> str:
    """One spool line as the boundary would emit it."""
    payload = dict(event or _event())
    payload.setdefault("_envelope_edge_id", "edge-1")
    payload.setdefault("_envelope_actor_key", "ip:198.51.100.7")
    payload.update(envelope_fields)
    return json.dumps(payload, sort_keys=True)


def _make_writer(tmp_path: Path) -> PrioritySingleWriterQueue:
    db_path = tmp_path / "local.db"
    conn = sqlite3.connect(db_path)
    apply_migrations(conn, "local")
    conn.close()
    writer = PrioritySingleWriterQueue(db_path, tmp_path / "writer.lock")
    writer.open()
    return writer


def _count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM engagement_event_v0").fetchone()[0]


def _rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return list(conn.execute("SELECT * FROM engagement_event_v0 ORDER BY event_ref"))


# --------------------------------------------------------------------------
# the read: Knowledge parses what Edge wrote
# --------------------------------------------------------------------------


def test_knowledge_reads_an_event_edge_produced(tmp_path):
    from azazel_knowledge.api.contracts import maybe_fabric_engagement_lines

    lines = maybe_fabric_engagement_lines(_envelope(), ENDPOINT)

    assert lines is not None and len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["event_id"] == "ev-1"
    assert parsed["activity"] == "redirect_to_decoy"
    assert parsed["_envelope_edge_id"] == "edge-1"
    assert parsed["_envelope_actor_key"] == "ip:198.51.100.7"


def test_a_line_lands_as_a_row_with_the_vocabulary_untouched(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        spool.write_batch(ENDPOINT, "c1", [_line()])
        stats = drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))

        assert stats.lines_valid == 1
        (row,) = _rows(writer._conn)
        assert row["objective"] == "collect"
        assert row["approach"] == "channel"
        assert row["activity"] == "redirect_to_decoy"
        assert row["attacker_reaction"] == "decoy_engaged"
        assert row["edge_id"] == "edge-1"
        assert row["actor_key"] == "ip:198.51.100.7"
    finally:
        writer.close()


def test_the_engage_vocabulary_is_not_mapped_onto_knowledges_own(tmp_path):
    """`redirect_to_decoy` stays `redirect_to_decoy`.

    `reaction.action_applied` admits `throttle`, `redirect`, `isolate`,
    `delay`, `deception`. Deciding that `redirect_to_decoy` "is" `deception`
    would invent a correspondence between two product vocabularies --
    `correlate/engagement_advisory.py` already refuses the same invention in
    the other direction and names the gap in `limitations` instead.
    """

    from azazel_knowledge.ingest.validators import ACTION_APPLIED_ENUM

    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        spool.write_batch(ENDPOINT, "c1", [_line()])
        drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))

        (row,) = _rows(writer._conn)
        assert row["activity"] not in ACTION_APPLIED_ENUM, (
            "the stored activity landed in Knowledge's own action vocabulary, "
            "which means something mapped it on the way in"
        )
    finally:
        writer.close()


@pytest.mark.parametrize(
    "activity",
    ["observe", "notify", "redirect_to_decoy", "expose_decoy_surface", "collect_credentials"],
)
def test_an_activity_knowledge_has_no_word_for_is_still_stored(tmp_path, activity):
    """Five of eight Engage activities have no `action_applied` counterpart.

    Rejecting them would mean Knowledge only remembers engagements it already
    had a word for, which is the opposite of what a memory node is for.
    """

    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        spool.write_batch(ENDPOINT, "c1", [_line(_event(activity=activity))])
        drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))

        (row,) = _rows(writer._conn)
        assert row["activity"] == activity
    finally:
        writer.close()


# --------------------------------------------------------------------------
# fail-closed boundary
# --------------------------------------------------------------------------


def test_a_body_that_is_not_an_envelope_falls_through(tmp_path):
    """Legacy per-line JSONL is untouched, as on every other ingest endpoint."""
    from azazel_knowledge.api.contracts import maybe_fabric_engagement_lines

    assert maybe_fabric_engagement_lines(b"not json", ENDPOINT) is None
    assert maybe_fabric_engagement_lines(b'{"event_id": "x"}', ENDPOINT) is None


def test_the_envelope_only_applies_to_its_own_endpoint():
    from azazel_knowledge.api.contracts import maybe_fabric_engagement_lines

    assert maybe_fabric_engagement_lines(_envelope(), "reactions") is None


@pytest.mark.parametrize("missing", ["edge_id", "actor_key"])
def test_an_envelope_without_attribution_is_refused(missing):
    """A row nobody can attribute is a row the correlation cannot use."""
    from azazel_knowledge.api.contracts import (
        IngestBatchInvalid,
        maybe_fabric_engagement_lines,
    )

    body = json.loads(_envelope())
    body[missing] = ""
    with pytest.raises(IngestBatchInvalid):
        maybe_fabric_engagement_lines(json.dumps(body).encode("utf-8"), ENDPOINT)


def test_an_item_violating_the_contract_fails_closed():
    from azazel_knowledge.api.contracts import (
        IngestBatchInvalid,
        maybe_fabric_engagement_lines,
    )

    with pytest.raises(IngestBatchInvalid):
        maybe_fabric_engagement_lines(
            _envelope(_event(activity="deploy_ransomware")), ENDPOINT
        )


@pytest.mark.parametrize(
    "directive", ["shell_command", "nft_rule", "execute_now", "bypass_arbiter"]
)
def test_a_directive_smuggled_into_a_record_fails_closed(directive):
    """A record of something already done must not carry an instruction."""
    from azazel_knowledge.api.contracts import (
        IngestBatchInvalid,
        maybe_fabric_engagement_lines,
    )

    hostile = _event()
    hostile["outcome"] = dict(hostile["outcome"])
    hostile["outcome"][directive] = "x"
    with pytest.raises(IngestBatchInvalid):
        maybe_fabric_engagement_lines(_envelope(hostile), ENDPOINT)


def test_the_contract_has_no_free_form_field_yet():
    """What makes the boundary's directive walk a backstop rather than a guard.

    Every model in the `EngagementEvent` tree forbids extra fields and none
    carries a free-form mapping, so a directive key cannot reach the walk --
    the model rejects it first. That is why removing the walk breaks no test,
    and why it is documented as unreachable rather than quietly kept.

    The day a free-form field is added, the walk becomes the only thing
    standing. This fails then, which is the only notice there would be.
    """

    from azazel_fabric.engagement_contracts import (
        EngagementConstraint,
        EngagementEvent,
        EngagementOutcome,
        EngagementTrigger,
    )

    for model in (EngagementEvent, EngagementOutcome, EngagementConstraint, EngagementTrigger):
        assert model.model_config.get("extra") == "forbid", (
            f"{model.__name__} no longer forbids extra fields; the boundary's "
            "directive walk is now load-bearing -- verify it still catches one"
        )
        free_form = [
            name
            for name, field in model.model_fields.items()
            if "dict[" in str(field.annotation) or "Mapping" in str(field.annotation)
        ]
        assert free_form == [], (
            f"{model.__name__} grew free-form field(s) {free_form}. A directive "
            "can now hide a level below where the model's own validation looks, "
            "which is exactly what the boundary walk is for -- add a test that "
            "exercises it through that field."
        )


def test_the_drain_validator_also_refuses_a_directive():
    """Second line, for a line that reached the spool another way."""
    hostile = _event()
    hostile["outcome"] = {**hostile["outcome"], "execute_now": True}
    ok, error = validate_engagement_event_line(_line(hostile), now=NOW)

    assert ok is False
    assert "directive" in str(error)


@pytest.mark.parametrize("field", ["_envelope_edge_id", "_envelope_actor_key"])
@pytest.mark.parametrize("how", ["missing", "empty", "not_a_string"])
def test_the_drain_validator_requires_attribution(field, how):
    """A row nobody can attribute is a row the correlation cannot use.

    Three shapes, because two different checks stand behind this and each
    alone covers only part of it: the required-field list catches a *missing*
    key, and the non-empty check catches a key that is present but says
    nothing. Testing only the first left the second unexercised.
    """

    line = json.loads(_line())
    if how == "missing":
        del line[field]
    elif how == "empty":
        line[field] = ""
    else:
        line[field] = 42

    ok, _ = validate_engagement_event_line(json.dumps(line), now=NOW)

    assert ok is False


def test_an_unknown_schema_version_is_refused():
    ok, error = validate_engagement_event_line(
        _line(_event(schema_version="engagement-event/v9.9")), now=NOW
    )

    assert ok is False
    assert "schema_version" in str(error)


# --------------------------------------------------------------------------
# local-tier discipline (Absolute Constraint 5, F-1)
# --------------------------------------------------------------------------


def test_rows_are_append_only(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    conn.execute(
        "INSERT INTO engagement_event_v0 (event_ref, product, edge_id, actor_key, "
        "objective, approach, activity, evidence_refs, schema_version, raw, received_at) "
        "VALUES ('ev-1','AZ-01','edge-1','ip:1','collect','channel','redirect_to_decoy',"
        "'[]','engagement-event/v0.1','{}','2026-01-01T00:00:00Z')"
    )

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE engagement_event_v0 SET activity = 'isolate'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM engagement_event_v0")


def test_a_redelivered_event_dedupes_rather_than_duplicating(tmp_path):
    """Transport is at-least-once; counting one engagement twice would distort
    every summary built over this table."""
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        spool.write_batch(ENDPOINT, "c1", [_line()])
        drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))
        assert _count(writer._conn) == 1

        spool.write_batch(ENDPOINT, "c1", [_line(), _line(_event("ev-2"))])
        drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))

        assert _count(writer._conn) == 2, "the row count only ever grows (F-1)"
    finally:
        writer.close()


def test_an_absent_outcome_stays_absent(tmp_path):
    """An engagement whose outcome is not yet known is a real state.

    A placeholder would be indistinguishable from an observation that the
    attacker did nothing.
    """

    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        spool.write_batch(ENDPOINT, "c1", [_line(_event(outcome=None))])
        drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))

        (row,) = _rows(writer._conn)
        assert row["attacker_reaction"] is None
        assert row["reaction_window_s"] is None
    finally:
        writer.close()


def test_a_bad_line_is_quarantined_without_failing_the_batch(tmp_path):
    """Design S4: one malformed line never rejects the surrounding batch."""
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        spool.write_batch(ENDPOINT, "c1", ["{not json", _line()])
        stats = drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))

        assert stats.lines_valid == 1
        assert _count(writer._conn) == 1
    finally:
        writer.close()


# --------------------------------------------------------------------------
# the endpoint
# --------------------------------------------------------------------------


def test_the_endpoint_accepts_an_envelope(tmp_path):
    client, _settings, local_db, _data = make_client(tmp_path)
    token = add_api_client(local_db, "edge-1", scopes=["ingest"])

    response = client.post(
        "/v1/engagement-events",
        content=_envelope(),
        headers={**auth_header(token), "Content-Type": "application/json"},
    )

    assert response.status_code == 202
    assert response.json()["batch_id"]


def test_the_endpoint_fails_closed_on_a_contract_violation(tmp_path):
    client, _settings, local_db, _data = make_client(tmp_path)
    token = add_api_client(local_db, "edge-1", scopes=["ingest"])

    response = client.post(
        "/v1/engagement-events",
        content=_envelope(_event(objective="conquer")),
        headers={**auth_header(token), "Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "ingest_batch_invalid"


def test_the_endpoint_requires_the_ingest_scope(tmp_path):
    client, _settings, local_db, _data = make_client(tmp_path)
    token = add_api_client(local_db, "reader", scopes=["read"])

    response = client.post(
        "/v1/engagement-events",
        content=_envelope(),
        headers={**auth_header(token), "Content-Type": "application/json"},
    )

    assert response.status_code in (401, 403)


# --------------------------------------------------------------------------
# reading is not selecting
# --------------------------------------------------------------------------


def test_no_write_sql_reached_the_api_layer():
    """Absolute Constraint 1, restated for this lane.

    The endpoint spools; the worker writes. `test_api_static.py` scans the
    whole api package, and this says out loud that the new endpoint did not
    become the exception.
    """

    import ast

    source = Path("src/azazel_knowledge/api/routers/ingest.py")
    tree = ast.parse(source.read_text(encoding="utf-8"))
    literals = [
        node.value.upper()
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    offenders = [
        text for text in literals
        if any(verb in text for verb in ("INSERT INTO", "UPDATE ", "DELETE FROM"))
    ]

    assert offenders == [], f"write SQL in the ingest router: {offenders}"


def test_reading_an_event_gives_knowledge_no_engagement_it_can_run():
    """The contract is descriptive and the row keeps it that way.

    An `EngagementEvent` records what a product selected. Knowledge storing it
    is memory, not selection -- there is no column here an executor could read
    as an instruction, and the directive walk above refuses one being added
    through the data.
    """

    conn = sqlite3.connect(":memory:")
    apply_migrations(conn, "local")
    columns = {
        row[1] for row in conn.execute("PRAGMA table_info(engagement_event_v0)")
    }

    forbidden = {
        name
        for name in columns
        if any(verb in name for verb in ("command", "exec", "run", "apply", "enforce"))
    }
    assert forbidden == set(), f"the lane grew an executable-shaped column: {forbidden}"
