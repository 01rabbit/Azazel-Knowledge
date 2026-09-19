"""Knowledge#65: Knowledge advises; it never sets Defensive State.

The invariant is one sentence, and everything here attacks it from a different
side: Knowledge can *store and serve* what an authoritative producer reported
about itself, and can do nothing that reads as setting, requesting, or
inferring a state.

Organized by the issue's acceptance criteria, so a reader can check coverage
against the issue rather than against this file.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from azazel_knowledge.db.defensive_state_memory import (
    AUTHORITY_CLASS,
    SCHEMA_VERSION,
    DefensiveStateMemoryError,
    lookup_reported_defensive_state,
    record_defensive_state_observation,
)
from azazel_knowledge.db.repository import apply_migrations

from _api_support import add_api_client, auth_header, make_client

#: The `_api_support` harness pins a FixedClock at 2026-07-06T12:00Z, and the
#: lookup serves nothing newer than the caller's `query_as_of`. These instants
#: straddle it deliberately: `EARLIER` is servable through the API, `LATER` is
#: not, and a test that mixed them up would silently prove nothing.
HARNESS_CLOCK = "2026-07-06T12:00:00+00:00"
AS_OF = HARNESS_CLOCK
EARLIER = "2026-07-05T00:00:00+00:00"
LATER = "2026-10-01T00:00:00+00:00"

_SCAN_EVENT = {"kind": "scan", "dest_port": 22, "proto": "tcp"}


def observation(**overrides) -> dict:
    payload = {
        "observation_ref": "dso-1",
        "reported_state": "THROTTLE",
        "state_vocabulary": "azazel-fabric/defensive-state/v1",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "observed_at": EARLIER,
        "evidence_refs": ["evidence:arbiter-1"],
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def local_conn(tmp_path) -> sqlite3.Connection:
    path = tmp_path / "local.db"
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    yield conn
    conn.close()


def _context_body(**overrides):
    body = {
        "entities": [{"type": "ip", "value": "203.0.113.7"}],
        "event": dict(_SCAN_EVENT),
        "edge_id": "edge-1",
        "actor_key": "actor-1",
    }
    body.update(overrides)
    return body


def _seed(local_db_path: Path, payload: dict) -> None:
    conn = sqlite3.connect(local_db_path)
    try:
        record_defensive_state_observation(conn, payload, received_at=AS_OF)
        conn.commit()
    finally:
        conn.close()


# -- AC-1: store and query with provenance ----------------------------------


def test_a_reported_state_round_trips_with_its_provenance(local_conn):
    assert record_defensive_state_observation(local_conn, observation(), received_at=AS_OF)

    found = lookup_reported_defensive_state(local_conn, "trace-1", query_as_of=AS_OF)

    assert found is not None
    assert found.reported_state == "THROTTLE"
    assert found.producer_product == "azazel-edge"
    assert found.decision_ref == "decision-1"
    assert found.authority_class == AUTHORITY_CLASS


@pytest.mark.parametrize(
    "missing",
    [
        "observation_ref",
        "reported_state",
        "state_vocabulary",
        "producer_product",
        "producer_node",
        "trace_id",
        "decision_ref",
        "observed_at",
    ],
)
def test_a_state_without_provenance_cannot_be_stored(local_conn, missing):
    """A state value with no author is an assertion nobody made."""
    payload = observation()
    payload.pop(missing)

    with pytest.raises(DefensiveStateMemoryError, match=missing):
        record_defensive_state_observation(local_conn, payload, received_at=AS_OF)


def test_the_latest_report_wins_and_ties_resolve_deterministically(local_conn):
    record_defensive_state_observation(
        local_conn, observation(observation_ref="a", reported_state="OBSERVE"), received_at=AS_OF
    )
    record_defensive_state_observation(
        local_conn,
        observation(observation_ref="b", reported_state="ISOLATE", observed_at=AS_OF),
        received_at=AS_OF,
    )
    # Same instant as `b`, lower ref: the ordering must not depend on insert order.
    record_defensive_state_observation(
        local_conn,
        observation(observation_ref="aa", reported_state="NOTIFY", observed_at=AS_OF),
        received_at=AS_OF,
    )

    found = lookup_reported_defensive_state(local_conn, "trace-1", query_as_of=AS_OF)

    assert found is not None and found.observation_ref == "b"
    for _ in range(3):
        assert lookup_reported_defensive_state(
            local_conn, "trace-1", query_as_of=AS_OF
        ).observation_ref == "b"


def test_a_report_newer_than_the_query_is_not_served(local_conn):
    record_defensive_state_observation(
        local_conn, observation(observed_at=LATER), received_at=AS_OF
    )

    assert lookup_reported_defensive_state(local_conn, "trace-1", query_as_of=AS_OF) is None


def test_a_redelivered_report_does_not_become_a_second_fact(local_conn):
    assert record_defensive_state_observation(local_conn, observation(), received_at=AS_OF) is True
    assert record_defensive_state_observation(local_conn, observation(), received_at=AS_OF) is False

    count = local_conn.execute(
        "SELECT COUNT(*) FROM defensive_state_observation_v0"
    ).fetchone()[0]
    assert count == 1


def test_the_same_ref_with_different_content_is_refused(local_conn):
    record_defensive_state_observation(local_conn, observation(), received_at=AS_OF)

    with pytest.raises(DefensiveStateMemoryError, match="different content"):
        record_defensive_state_observation(
            local_conn, observation(reported_state="ISOLATE"), received_at=AS_OF
        )


def test_the_lane_is_append_only(local_conn):
    """Absolute Constraint 5: local-tier research data is never rewritten."""
    record_defensive_state_observation(local_conn, observation(), received_at=AS_OF)

    with pytest.raises(sqlite3.IntegrityError):
        local_conn.execute(
            "UPDATE defensive_state_observation_v0 SET reported_state = 'ISOLATE'"
        )
    with pytest.raises(sqlite3.IntegrityError):
        local_conn.execute("DELETE FROM defensive_state_observation_v0")


# -- AC-2: Knowledge cannot set or command a transition ---------------------


@pytest.mark.parametrize(
    "directive",
    [
        "set_state",
        "target_state",
        "requested_state",
        "next_state",
        "transition_to",
        "apply",
        "execute",
        "enforce",
        "command",
        "override",
    ],
)
def test_a_payload_that_reads_as_a_transition_is_refused(local_conn, directive):
    with pytest.raises(DefensiveStateMemoryError, match="never what anyone should do next"):
        record_defensive_state_observation(
            local_conn, observation(**{directive: "ISOLATE"}), received_at=AS_OF
        )


def test_a_directive_nested_inside_evidence_is_still_refused(local_conn):
    """The walk is recursive, so nesting does not help."""
    payload = observation()
    payload["extra"] = {"nested": {"transition_to": "ISOLATE"}}

    with pytest.raises(DefensiveStateMemoryError):
        record_defensive_state_observation(local_conn, payload, received_at=AS_OF)


def test_the_module_exposes_no_function_that_sets_a_state():
    """Stated as a test because the invariant is an absence.

    An absence is what a later change quietly fills in, so it is asserted by
    name rather than left to a reader's inspection.
    """

    import azazel_knowledge.db.defensive_state_memory as module

    offenders = [
        name
        for name in dir(module)
        if not name.startswith("_")
        and callable(getattr(module, name, None))
        and any(
            verb in name.lower()
            for verb in ("set_", "apply", "transition", "enforce", "command", "execute")
        )
    ]
    assert offenders == [], f"a state-setting function appeared: {offenders}"


def test_knowledge_defines_no_defensive_state_vocabulary_of_its_own():
    """Fabric#14 owns the canonical values.

    A second copy here would drift from it, and a drifting copy is how a
    product-local reading of the vocabulary becomes canonical by the back door.
    """

    import ast

    import azazel_knowledge.db.defensive_state_memory as module

    # Parse rather than grep: the module *discusses* the vocabulary in prose
    # (explaining why it does not default to the weakest value), and a text
    # search cannot tell an explanation from a definition. Docstrings are
    # excluded; every other string literal in the module is checked.
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc is not None:
                docstrings.add(doc)

    canonical = {"OBSERVE", "NOTIFY", "THROTTLE", "REDIRECT", "ISOLATE"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in docstrings:
                continue
            assert node.value not in canonical, (
                f"{node.value!r} is a string literal in Knowledge's code; the canonical "
                "vocabulary is Fabric's and a second copy here would drift from it"
            )

    migration = (
        Path(module.__file__).resolve().parents[0]
        / "migrations"
        / "local"
        / "0006_defensive_state_observation.sql"
    )
    sql = migration.read_text(encoding="utf-8")
    assert "CHECK (reported_state" not in sql, (
        "the migration constrains reported_state to an enum; that makes this file a "
        "second definition of the vocabulary"
    )


# -- AC-3/AC-4: fact lane and inference lane stay separate ------------------


def test_the_fact_lane_is_served_separately_from_the_recommendation(tmp_path):
    client, _settings, local_db_path, _ = make_client(tmp_path)
    _seed(local_db_path, observation())
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post(
        "/v1/context", json=_context_body(trace_id="trace-1"), headers=auth_header(token)
    )

    assert resp.status_code == 200
    body = resp.json()
    fact = body["reported_defensive_state"]
    assert fact is not None
    assert fact["reported_state"] == "THROTTLE"
    assert fact["authority_class"] == "producer_reported_state"
    assert fact["producer_product"] == "azazel-edge"
    # The inference lane is a different key and never carries the state.
    assert "reported_state" not in body["recommendation"]
    assert "defensive_state" not in body["recommendation"]


def test_an_unknown_state_is_null_and_never_a_default(tmp_path):
    """Knowledge does not substitute `OBSERVE` for "nothing known".

    A default here would be Knowledge asserting another product's posture out
    of its own ignorance.
    """

    client, _settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post(
        "/v1/context", json=_context_body(trace_id="trace-unknown"), headers=auth_header(token)
    )

    assert resp.status_code == 200
    assert resp.json()["reported_defensive_state"] is None


def test_a_caller_that_sends_no_trace_id_gets_the_previous_response_shape(tmp_path):
    """Additive and backward-compatible: an existing caller is untouched."""
    client, _settings, local_db_path, _ = make_client(tmp_path)
    _seed(local_db_path, observation())
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))

    assert resp.status_code == 200
    assert resp.json()["reported_defensive_state"] is None


def test_the_fact_lane_does_not_perturb_the_determinism_tuple(tmp_path):
    """The enrichment sits outside scoring, so `content_hash` cannot move.

    Compares the scored fields with and without a reported state present for
    the same request -- the same shape as the `engage_refs`/`rule_refs` proof.
    """

    client, _settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    body = _context_body(trace_id="trace-1")

    before = client.post("/v1/context", json=body, headers=auth_header(token)).json()
    _seed(local_db_path, observation())
    after = client.post("/v1/context", json=body, headers=auth_header(token)).json()

    assert after["reported_defensive_state"] is not None
    for field in ("threat_score", "confidence", "reason", "confidence_reason", "threat_context"):
        assert before[field] == after[field], f"{field} moved when a state was reported"


def test_deception_telemetry_alone_does_not_produce_a_state(tmp_path):
    """The issue names this explicitly: do not infer REDIRECT merely because
    deception telemetry exists."""
    client, _settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post(
        "/v1/context",
        json=_context_body(trace_id="trace-1", event={**_SCAN_EVENT, "decoy_engaged": True}),
        headers=auth_header(token),
    )

    assert resp.status_code == 200
    assert resp.json()["reported_defensive_state"] is None


def test_the_response_carries_no_attacker_belief(tmp_path):
    """Do not infer attacker belief or intent from a state transition."""
    client, _settings, local_db_path, _ = make_client(tmp_path)
    _seed(local_db_path, observation())
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post(
        "/v1/context", json=_context_body(trace_id="trace-1"), headers=auth_header(token)
    )

    serialized = json.dumps(resp.json()).lower()
    for forbidden in ("attacker_belief", "adversary_belief", "belief_state", "attacker_intent"):
        assert forbidden not in serialized


def test_the_advisory_only_invariant_still_holds_with_the_fact_present(tmp_path):
    """The fact lane goes through the same Fabric advisory-only assertion as
    the rest of the response, so a directive-shaped field in it would 500."""
    client, _settings, local_db_path, _ = make_client(tmp_path)
    _seed(local_db_path, observation())
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post(
        "/v1/context", json=_context_body(trace_id="trace-1"), headers=auth_header(token)
    )

    assert resp.status_code == 200
    assert resp.json()["advisory_notice"]


# -- AC-5: no ambiguous `mode` terminology ----------------------------------


def test_the_api_surface_uses_no_ambiguous_mode_field(tmp_path):
    """`mode` is the word that gets confused with Edge/Gadget Defensive State.

    `model_dump(mode="json")` is pydantic's own keyword argument and is not a
    wire field, so the check is against the response body rather than the
    source.
    """

    client, _settings, local_db_path, _ = make_client(tmp_path)
    _seed(local_db_path, observation())
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post(
        "/v1/context", json=_context_body(trace_id="trace-1"), headers=auth_header(token)
    )

    def _keys(value):
        if isinstance(value, dict):
            for key, child in value.items():
                yield key
                yield from _keys(child)
        elif isinstance(value, list):
            for child in value:
                yield from _keys(child)

    ambiguous = sorted({k for k in _keys(resp.json()) if k.lower() == "mode"})
    assert ambiguous == [], f"ambiguous mode field on the wire: {ambiguous}"


# -- AC-6 is open, and says so ----------------------------------------------


def test_the_fabric_pin_does_not_yet_carry_the_canonical_vocabulary():
    """AC-6 is "consume Fabric#14 semantics **when available**". It is not.

    This repository pins `v0.8.0`; `DefensiveState` shipped to no tag. The
    assertion is written so that it fails once a pin that carries the
    vocabulary lands -- which is the moment AC-6 becomes actionable, and a
    louder signal than a comment nobody re-reads.
    """

    import tomllib

    manifest = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text("utf-8")
    )
    # Absolute Constraint 7: Fabric is an `api`-extra dependency, never a core
    # one, so the pin lives there rather than in `project.dependencies`.
    extras = manifest["project"]["optional-dependencies"]["api"]
    pins = [d for d in extras if "azazel-fabric" in d]
    assert len(pins) == 1, f"expected exactly one Fabric pin in the api extra, got {pins}"
    assert "@v" in pins[0], f"Fabric must be pinned to an exact tag, got {pins[0]!r}"

    try:
        from azazel_fabric.schema.defensive_state import DefensiveState  # noqa: F401
    except ImportError:
        return
    pytest.fail(
        f"the pinned Fabric ({pins[0]}) now carries DefensiveState; Knowledge#65 AC-6 is "
        "actionable -- validate reported_state against the canonical enum at the ingest "
        "boundary and delete this test"
    )


# -- the two pins the tests above did not exercise ---------------------------


@pytest.mark.parametrize(
    "field,bad",
    [
        ("authority_class", "producer_decision_ref"),
        ("authority_class", "advisory_only"),
        ("schema_version", "defensive-state-observation/v0.2"),
    ],
)
def test_the_lane_holds_exactly_one_kind_of_claim(local_conn, field, bad):
    """A row here is a producer's report about itself and can be nothing else.

    Without this, relaxing the pin would let a differently-classed claim into
    the same table, and a consumer reading `authority_class` to decide how much
    to trust a row would be reading a value nobody checked.
    """

    with pytest.raises(DefensiveStateMemoryError, match=field):
        record_defensive_state_observation(
            local_conn, observation(**{field: bad}), received_at=AS_OF
        )


def test_the_fact_lane_passes_through_the_advisory_only_assertion(tmp_path, monkeypatch):
    """Pin the wiring, not just the outcome.

    The router asserts the advisory-only invariant over a copy it assembles by
    hand. Dropping the fact lane from that copy would leave every response test
    green while the new field stopped being checked at all -- so what the
    assertion actually receives is what gets pinned.
    """

    import azazel_knowledge.api.routers.context as context_router

    seen: list[dict] = []
    original = context_router.assert_response_advisory_only

    def _capture(view):
        seen.append(view)
        return original(view)

    monkeypatch.setattr(context_router, "assert_response_advisory_only", _capture)

    client, _settings, local_db_path, _ = make_client(tmp_path)
    _seed(local_db_path, observation())
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post(
        "/v1/context", json=_context_body(trace_id="trace-1"), headers=auth_header(token)
    )

    assert resp.status_code == 200
    assert seen, "the advisory-only assertion was never called"
    assert "reported_defensive_state" in seen[0], (
        "the fact lane is not part of what the advisory-only invariant checks"
    )
    assert seen[0]["reported_defensive_state"]["reported_state"] == "THROTTLE"
