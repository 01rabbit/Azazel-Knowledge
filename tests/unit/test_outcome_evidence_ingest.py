"""Knowledge reads Azazel-Fabric's `outcome_contracts` (R1c consumer).

Azazel-Edge's `outcome/shared_export.py` builds these four records and dumps
them with, in its own words, "deliberately no fallback": a record Fabric did
not validate must never travel as one that it did. Until this lane nobody held
up the other end. `outcome_contracts` had a producer and no consumer, and a
contract that has only ever been serialized is not known to interoperate.

Knowledge already *stored* Outcome-as-Evidence -- four tables since migration
`0005`, and `db/outcome_memory.py` validating the wire shapes on its own.
Storing a shape that happens to match is not consuming a contract, which is
precisely what Azazel-Edge#413 said about its own side. What was missing was
the boundary where Fabric's models decide what gets in. That boundary is
`api/contracts.fabric_outcome_evidence_lines`, and this file is what holds it.

Two things these tests are careful about:

* **There is no unvalidated way into this lane.** Every other ingest endpoint
  falls through to a legacy per-line JSONL splitter, because each has callers
  that predate Fabric. This one has none, so a non-envelope body is a `422`
  rather than a quietly spooled line.
* **Nothing stored here is a verdict.** The four records stay separate --
  execution, mechanism, observation, assessment -- and a success field,
  directive or tactical claim smuggled into a descriptive fact map is refused
  at the boundary and again at the drain.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from _api_support import QUERY_AS_OF, add_api_client, auth_header, make_client
from azazel_knowledge.api.contracts import (
    IngestBatchInvalid,
    fabric_outcome_evidence_lines,
)
from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.db.repository import apply_migrations
from azazel_knowledge.db.writer import PrioritySingleWriterQueue
from azazel_knowledge.ingest.drain import drain_endpoint
from azazel_knowledge.ingest.spool import SpoolWriter
from azazel_knowledge.ingest.validators import validate_outcome_evidence_line
from test_outcome_contract_drift import (
    OBSERVED_AT,
    _assessment,
    _execution,
    _mechanism,
    _observation,
)

NOW = QUERY_AS_OF
ENDPOINT = "outcome-evidence"

TABLES = {
    "outcome-execution/v0.1": "outcome_execution_v0",
    "outcome-mechanism/v0.1": "outcome_mechanism_v0",
    "outcome-observation/v0.1": "outcome_observation_v0",
    "tactical-effect-assessment/v0.1": "outcome_effect_assessment_v0",
}


def _envelope(*facts: dict) -> bytes:
    items = list(facts) if facts else [_execution()]
    return json.dumps({"items": items}).encode("utf-8")


def _chain() -> list[dict]:
    return [_execution(), _mechanism(), _observation(), _assessment()]


def _make_writer(tmp_path: Path) -> PrioritySingleWriterQueue:
    db_path = tmp_path / "local.db"
    conn = sqlite3.connect(db_path)
    apply_migrations(conn, "local")
    conn.close()
    writer = PrioritySingleWriterQueue(db_path, tmp_path / "writer.lock")
    writer.open()
    return writer


def _count(conn: sqlite3.Connection, table: str) -> int:
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def _drain(tmp_path: Path, lines: list[str], writer=None, spool=None):
    spool = spool or SpoolWriter(tmp_path / "ingest")
    spool.write_batch(ENDPOINT, "c1", lines)
    stats = drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))
    return stats, spool


# --------------------------------------------------------------------------
# the read: the boundary is Fabric's, not a shape that resembles it
# --------------------------------------------------------------------------


def test_knowledge_reads_the_four_records_edge_exports():
    lines = fabric_outcome_evidence_lines(_envelope(*_chain()), ENDPOINT)

    assert lines is not None and len(lines) == 4
    assert [json.loads(line)["schema_version"] for line in lines] == [
        "outcome-execution/v0.1",
        "outcome-mechanism/v0.1",
        "outcome-observation/v0.1",
        "tactical-effect-assessment/v0.1",
    ]


def test_the_boundary_emits_the_fields_fabric_defaults():
    """`model_dump`, not the caller's bytes.

    A producer may omit `evidence_refs`, `limitations` and the fact maps --
    Fabric defaults them. Storage dereferences them. Passing the caller's
    bytes through would push that gap into the write transaction; dumping the
    model closes it at the boundary.
    """

    sparse = {
        k: v
        for k, v in _execution().items()
        if k not in {"evidence_refs", "release_ref", "schema_version", "authority_class"}
    }
    sparse["schema_version"] = "outcome-execution/v0.1"

    (line,) = fabric_outcome_evidence_lines(_envelope(sparse), ENDPOINT)
    parsed = json.loads(line)
    assert parsed["evidence_refs"] == []
    assert parsed["release_ref"] is None
    assert parsed["authority_class"] == "producer_execution_fact"


def test_the_boundary_is_off_for_every_other_endpoint():
    for other in ("events", "flows", "reactions", "engagement-events", "deception-observations"):
        assert fabric_outcome_evidence_lines(_envelope(), other) is None


@pytest.mark.parametrize(
    ("body", "why"),
    [
        (b"not json at all", "bare text"),
        (b"[]", "a top-level list"),
        (b'{"batch_id": "b1"}', "no items"),
        (b'{"items": {}}', "items is not a list"),
        (b'{"items": ["a string"]}', "an item that is not an object"),
        (b'{"items": [{"schema_version": "outcome-execution/v0.2"}]}', "an unknown version"),
        (b'{"items": [{"schema_version": 7}]}', "a non-string version"),
        (b'{"items": [{}]}', "an item with no version at all"),
    ],
)
def test_a_body_that_is_not_a_valid_envelope_fails_closed(body, why):
    with pytest.raises(IngestBatchInvalid):
        fabric_outcome_evidence_lines(body, ENDPOINT)


def test_plain_jsonl_has_no_way_in():
    """The design decision that separates this lane from the others.

    `/v1/events` and friends return `None` for a body they do not recognize,
    so the caller falls through to the line splitter -- they have documented
    JSONL callers older than Fabric. This endpoint has none. Accepting an
    unvalidated line here would be manufacturing a legacy on purpose, and a
    lane where the contract is optional is a lane where the consumption is
    optional.
    """

    jsonl = b"\n".join(json.dumps(fact).encode("utf-8") for fact in _chain())
    with pytest.raises(IngestBatchInvalid):
        fabric_outcome_evidence_lines(jsonl, ENDPOINT)

    # Even a single valid record, sent bare, is refused: it is the *envelope*
    # that marks the caller as speaking this contract.
    with pytest.raises(IngestBatchInvalid):
        fabric_outcome_evidence_lines(json.dumps(_execution()).encode("utf-8"), ENDPOINT)


def test_an_empty_envelope_is_accepted_and_stores_nothing():
    assert fabric_outcome_evidence_lines(b'{"items": []}', ENDPOINT) == []


@pytest.mark.parametrize("extra", ["execute", "success", "approve", "arbiter_override"])
def test_a_directive_field_on_a_record_is_refused(extra):
    fact = _execution()
    fact[extra] = "anything"
    with pytest.raises(IngestBatchInvalid):
        fabric_outcome_evidence_lines(_envelope(fact), ENDPOINT)


@pytest.mark.parametrize("key", ["success", "attacker_belief", "provider_command"])
def test_a_directive_buried_in_a_free_form_fact_map_is_refused(key):
    """Not covered by `extra="forbid"`, which is why it is checked separately.

    `observed_parameters` is `dict[str, Any]`: the model has no opinion about
    what is inside it. A directive one level down is exactly the thing the
    recursive walk exists for, and unlike the `EngagementEvent` lane -- where
    the same walk is an unreachable backstop -- here it is load-bearing.
    """

    fact = _mechanism()
    fact["observed_parameters"] = {key: "x"}
    with pytest.raises(IngestBatchInvalid):
        fabric_outcome_evidence_lines(_envelope(fact), ENDPOINT)


@pytest.mark.parametrize("key", ["tactical_effect", "effectiveness", "initiative_score"])
def test_a_tactical_claim_in_a_descriptive_fact_map_is_refused(key):
    """A descriptive record may not carry the conclusion drawn from it.

    Tactical effect is legal in exactly one place -- the assessment record,
    which is separate on purpose and pinned non-executable. Letting a
    mechanism observation say `effectiveness: 0.9` would put the verdict back
    inside the fact and make the separation decorative.
    """

    fact = _observation()
    fact["observation_values"] = {key: 1}
    with pytest.raises(IngestBatchInvalid):
        fabric_outcome_evidence_lines(_envelope(fact), ENDPOINT)


# --------------------------------------------------------------------------
# the endpoint
# --------------------------------------------------------------------------


def test_the_endpoint_accepts_a_valid_envelope(tmp_path):
    client, _settings, local_db_path, _data = make_client(tmp_path)
    token = add_api_client(local_db_path, "c1", ["ingest"])
    response = client.post(
        "/v1/outcome-evidence", content=_envelope(*_chain()), headers=auth_header(token)
    )
    assert response.status_code == 202
    assert response.json()["batch_id"]


def test_the_endpoint_rejects_an_invalid_envelope(tmp_path):
    client, _settings, local_db_path, _data = make_client(tmp_path)
    token = add_api_client(local_db_path, "c1", ["ingest"])
    fact = _execution()
    fact["success"] = True
    response = client.post(
        "/v1/outcome-evidence", content=_envelope(fact), headers=auth_header(token)
    )
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "ingest_batch_invalid"


def test_the_endpoint_requires_the_ingest_scope(tmp_path):
    client, _settings, local_db_path, _data = make_client(tmp_path)
    token = add_api_client(local_db_path, "c1", ["read"])
    response = client.post(
        "/v1/outcome-evidence", content=_envelope(), headers=auth_header(token)
    )
    assert response.status_code == 403


def test_a_rejected_envelope_spools_nothing(tmp_path):
    """Fail closed means nothing lands, not "nothing useful lands"."""

    client, _settings, local_db_path, _data = make_client(tmp_path)
    token = add_api_client(local_db_path, "c1", ["ingest"])
    response = client.post(
        "/v1/outcome-evidence",
        content=b'{"items": [{"schema_version": "made-up/v9"}]}',
        headers=auth_header(token),
    )
    assert response.status_code == 422
    spool_dir: Path = client.app.state.spool.root / ENDPOINT
    assert not list(spool_dir.rglob("*.jsonl"))

    # The same client sending a valid envelope does land one, so the emptiness
    # above is the rejection and not a spool that was never reachable.
    assert (
        client.post(
            "/v1/outcome-evidence", content=_envelope(), headers=auth_header(token)
        ).status_code
        == 202
    )
    assert len(list(spool_dir.rglob("*.jsonl"))) == 1


# --------------------------------------------------------------------------
# the drain: facts become rows
# --------------------------------------------------------------------------


def test_a_whole_chain_lands_as_rows(tmp_path):
    writer = _make_writer(tmp_path)
    try:
        lines = fabric_outcome_evidence_lines(_envelope(*_chain()), ENDPOINT)
        stats, _ = _drain(tmp_path, lines, writer)

        assert stats.lines_valid == 4
        assert stats.lines_invalid == 0
        for table in TABLES.values():
            assert _count(writer._conn, table) == 1
    finally:
        writer.close()


def test_a_chain_sent_out_of_order_still_lands(tmp_path):
    """The four facts are a set joined by reference, not a sequence.

    A mechanism fact is refused until the execution it names is stored, so a
    batch whose bytes happen to arrive assessment-first would lose three
    quarters of the chain. Ordering by dependency at insert time is satisfying
    a storage precondition, not reinterpreting the producer.
    """

    writer = _make_writer(tmp_path)
    try:
        reversed_chain = list(reversed(_chain()))
        lines = fabric_outcome_evidence_lines(_envelope(*reversed_chain), ENDPOINT)
        stats, _ = _drain(tmp_path, lines, writer)

        assert stats.lines_valid == 4
        assert stats.lines_invalid == 0
        for table in TABLES.values():
            assert _count(writer._conn, table) == 1
    finally:
        writer.close()


def test_a_fact_whose_execution_is_missing_is_quarantined_alone(tmp_path):
    """One unusable fact must not cost the batch the rest of the evidence."""

    writer = _make_writer(tmp_path)
    try:
        orphan = _mechanism(observation_id="mech-orphan", execution_ref="exec-nowhere")
        lines = fabric_outcome_evidence_lines(
            _envelope(_execution(), orphan, _mechanism()), ENDPOINT
        )
        stats, spool = _drain(tmp_path, lines, writer)

        assert stats.lines_valid == 2
        assert stats.lines_invalid == 1
        assert _count(writer._conn, "outcome_execution_v0") == 1
        assert _count(writer._conn, "outcome_mechanism_v0") == 1
        assert (
            writer._conn.execute(
                "SELECT COUNT(*) FROM outcome_mechanism_v0 WHERE observation_id = ?",
                ("mech-orphan",),
            ).fetchone()[0]
            == 0
        )

        (batch_id,) = [
            path.stem for path in (spool.root / ENDPOINT / "drained").glob("*.jsonl")
        ] or [None]
        status = spool.read_status(batch_id)
        assert status.valid == 2
        assert [item["line_no"] for item in status.invalid] == [2]
        assert "execution" in status.invalid[0]["error"]
    finally:
        writer.close()


def test_a_cross_trace_join_is_refused(tmp_path):
    """Evidence borrowed from another trace is not this trace's evidence."""

    writer = _make_writer(tmp_path)
    try:
        foreign = _mechanism(trace_id="trace-elsewhere")
        lines = fabric_outcome_evidence_lines(_envelope(_execution(), foreign), ENDPOINT)
        stats, _ = _drain(tmp_path, lines, writer)

        assert stats.lines_valid == 1
        assert stats.lines_invalid == 1
        assert _count(writer._conn, "outcome_mechanism_v0") == 0
    finally:
        writer.close()


def test_redelivery_of_the_same_batch_adds_no_rows(tmp_path):
    """Transport is at-least-once; memory must not double-count evidence."""

    writer = _make_writer(tmp_path)
    try:
        lines = fabric_outcome_evidence_lines(_envelope(*_chain()), ENDPOINT)
        spool = SpoolWriter(tmp_path / "ingest")
        _drain(tmp_path, lines, writer, spool)
        stats, _ = _drain(tmp_path, lines, writer, spool)

        assert stats.duplicates_skipped == 4
        for table in TABLES.values():
            assert _count(writer._conn, table) == 1
    finally:
        writer.close()


def test_reusing_an_identity_with_different_content_is_refused(tmp_path):
    """A replay is a no-op; a rewrite is not a replay.

    `INSERT OR IGNORE` would make the two indistinguishable and let a second
    sender silently keep the first one's version of a fact. Refusing says
    which one arrived.
    """

    writer = _make_writer(tmp_path)
    try:
        spool = SpoolWriter(tmp_path / "ingest")
        _drain(tmp_path, fabric_outcome_evidence_lines(_envelope(), ENDPOINT), writer, spool)

        rewritten = _execution(status="failed")
        stats, _ = _drain(
            tmp_path, fabric_outcome_evidence_lines(_envelope(rewritten), ENDPOINT), writer, spool
        )

        assert stats.lines_invalid == 1
        (status,) = writer._conn.execute(
            "SELECT status FROM outcome_execution_v0 WHERE execution_ref = ?", ("exec-1",)
        ).fetchone()
        assert status == "applied"
    finally:
        writer.close()


@pytest.mark.parametrize("table", sorted(TABLES.values()))
def test_stored_rows_are_append_only(tmp_path, table):
    """Absolute Constraint 5: local-tier research data is never rewritten.

    Parametrized over all four tables on purpose. A guard that checks only
    `outcome_execution_v0` is the shape of guard that has passed in this repo
    while three quarters of its subject went unprotected.
    """

    writer = _make_writer(tmp_path)
    try:
        _drain(tmp_path, fabric_outcome_evidence_lines(_envelope(*_chain()), ENDPOINT), writer)
        assert _count(writer._conn, table) == 1
        for statement in (
            f"UPDATE {table} SET trace_id = 'rewritten'",
            f"DELETE FROM {table}",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                writer._conn.execute(statement)
        assert _count(writer._conn, table) == 1
        (trace_id,) = writer._conn.execute(f"SELECT trace_id FROM {table}").fetchone()
        assert trace_id == "trace-1"
    finally:
        writer.close()


def test_nothing_stored_carries_a_success_verdict(tmp_path):
    """The whole point of four separate records.

    No row in this lane may answer "did it work". The assessment record is
    the only one that reaches a conclusion at all, and it is pinned
    non-executable and stored with `executable = 0`.
    """

    writer = _make_writer(tmp_path)
    try:
        _drain(tmp_path, fabric_outcome_evidence_lines(_envelope(*_chain()), ENDPOINT), writer)
        writer._conn.row_factory = sqlite3.Row
        for table in TABLES.values():
            for row in writer._conn.execute(f"SELECT * FROM {table}"):
                keys = {key.lower() for key in row.keys()}
                assert not keys & {"success", "successful", "attacker_belief"}
                stored = json.loads(row["raw"])
                assert "success" not in stored
        (executable,) = writer._conn.execute(
            "SELECT executable FROM outcome_effect_assessment_v0"
        ).fetchone()
        assert executable == 0
    finally:
        writer.close()


# --------------------------------------------------------------------------
# the drain validator, on its own
# --------------------------------------------------------------------------


def test_the_drain_revalidates_what_the_boundary_let_through():
    """The spool sits on disk between accept and drain.

    The worker does not have `azazel_fabric` installed (it is an `api` extra),
    so it cannot re-run the boundary check. It re-runs the shape rules from
    `outcome_memory` instead -- the same statement the drift guard pins --
    rather than trusting bytes it read back off disk.
    """

    ok, row = validate_outcome_evidence_line(json.dumps(_execution()), now=NOW)
    assert ok and row["execution_ref"] == "exec-1"


@pytest.mark.parametrize(
    "line",
    [
        "not json",
        "[]",
        '{"schema_version": "made-up/v1"}',
        json.dumps({**_execution(), "status": "invented"}),
        json.dumps({**_execution(), "authority_class": "arbiter_decision"}),
    ],
)
def test_the_drain_validator_quarantines_a_bad_line(line):
    ok, error = validate_outcome_evidence_line(line, now=NOW)
    assert not ok and isinstance(error, str)


def test_an_oversized_line_is_quarantined_rather_than_stored():
    fact = _execution()
    fact["evidence_refs"] = ["x" * 4096] * 64
    ok, error = validate_outcome_evidence_line(json.dumps(fact), now=NOW)
    assert not ok
    assert "size" in error


def test_observed_at_is_not_skew_bounded():
    """Late evidence is the evidence most worth keeping.

    Every other validator bounds `observed_at` against `now`, because those
    lanes describe live traffic. An outcome fact describes a window that has
    already closed, and a node that was degraded or disconnected is exactly
    the one that sends its evidence late.
    """

    ok, _ = validate_outcome_evidence_line(
        json.dumps(_execution(observed_at="2019-01-01T00:00:00Z")), now=NOW
    )
    assert ok
    ok, _ = validate_outcome_evidence_line(
        json.dumps(_execution(observed_at="2099-01-01T00:00:00Z")), now=NOW
    )
    assert ok


def test_the_stored_bytes_are_the_producers_bytes(tmp_path):
    """`raw` must be what arrived, not Knowledge's retelling of it."""

    writer = _make_writer(tmp_path)
    try:
        (line,) = fabric_outcome_evidence_lines(_envelope(), ENDPOINT)
        _drain(tmp_path, [line], writer)
        (raw,) = writer._conn.execute("SELECT raw FROM outcome_execution_v0").fetchone()
        assert json.loads(raw) == json.loads(line)
    finally:
        writer.close()


def test_the_facts_survive_as_a_replayable_bundle(tmp_path):
    """The reason the chain is stored as a chain (`OBSERVED_AT` anchors it)."""

    from azazel_knowledge.db.outcome_memory import export_trajectory_bundle

    writer = _make_writer(tmp_path)
    try:
        _drain(tmp_path, fabric_outcome_evidence_lines(_envelope(*_chain()), ENDPOINT), writer)
        bundle = json.loads(export_trajectory_bundle(writer._conn, "trace-1"))
        assert bundle["executable"] is False
        assert bundle["replay_context"] is True
        assert len(bundle["facts"]) == 4
        assert {fact["schema_version"] for fact in bundle["facts"]} == set(TABLES)
        assert OBSERVED_AT in {fact["observed_at"] for fact in bundle["facts"]}
    finally:
        writer.close()
