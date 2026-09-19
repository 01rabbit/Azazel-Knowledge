"""Knowledge#52: engagement-effectiveness advisory, advisory-only.

    **Knowledge advises; it never selects, commands, schedules, or executes.**

Organized by the issue's own headings so coverage can be checked against the
issue rather than against this file. The API-level tests matter as much as the
fold: the enrichment is fail-open by design, and a fail-open path hides its own
wiring bugs unless something proves it actually ran.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from azazel_knowledge.api.contracts import (
    AdvisoryInvariantViolation,
    build_engagement_advisory,
)
from azazel_knowledge.correlate.engagement_advisory import (
    ACTIONS_WITHOUT_A_CANONICAL_ACTIVITY,
    DECOY_ENGAGEMENT_REACTIONS,
    DEFAULTS,
    summarize_engagement,
)
from azazel_knowledge.db.repository import apply_migrations

from _api_support import add_api_client, auth_header, make_client

AS_OF = "2026-07-06T12:00:00+00:00"
BEFORE = "2026-07-05T00:00:00+00:00"
ACTOR = "actor-1"

_SCAN_EVENT = {"kind": "scan", "dest_port": 22, "proto": "tcp"}


@pytest.fixture
def conn(tmp_path) -> sqlite3.Connection:
    connection = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(connection, "local")
    yield connection
    connection.close()


def add_reaction(
    connection: sqlite3.Connection,
    *,
    action: str,
    reaction: str,
    applied_at: str = BEFORE,
    trust_tier: str = "corroborated",
    actor: str = ACTOR,
    classifier: str = "c1",
) -> None:
    connection.execute(
        "INSERT INTO reaction (edge_id, actor_key, action_applied, applied_at, reaction, "
        "reaction_window_s, classifier, classifier_version, trust_tier, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("edge-1", actor, action, applied_at, reaction, 60, classifier, "1", trust_tier, applied_at),
    )
    connection.commit()


def add_pattern(
    connection: sqlite3.Connection,
    *,
    behavior_class: str = "adaptive_probe",
    confidence: int = 80,
    repeatability: int = 60,
    end: str = BEFORE,
    pattern_id: str = "pat-1",
    actor: str = ACTOR,
) -> None:
    connection.execute(
        "INSERT INTO behavior_pattern (pattern_id, behavior_generation, actor_key, edge_id, "
        "observation_start, observation_end, action_applied, behavior_class, confidence, "
        "repeatability_score, generated_at, generator_version, behavior_config_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            pattern_id, 1, actor, "edge-1", BEFORE, end, "redirect", behavior_class,
            confidence, repeatability, end, "1", "sha256:" + "0" * 64,
        ),
    )
    connection.commit()


def seed_decoy_history(connection: sqlite3.Connection, *, count: int = 3) -> None:
    for index in range(count):
        add_reaction(
            connection,
            action="redirect",
            reaction="followed_decoy",
            classifier=f"c{index}",
        )
    add_pattern(connection)


# -- no evidence yields no advisory -----------------------------------------


def test_an_actor_with_no_history_gets_no_advisory(conn):
    assert summarize_engagement(conn, ACTOR, query_as_of=AS_OF) is None


def test_too_little_evidence_yields_no_advisory_rather_than_an_empty_one(conn):
    """A consumer must be able to tell "Knowledge has nothing" from "Knowledge
    looked and is unsure". Those only look different if one of them is None."""
    for index in range(int(DEFAULTS["minimum_reactions"]) - 1):
        add_reaction(conn, action="redirect", reaction="disengaged", classifier=f"c{index}")

    assert summarize_engagement(conn, ACTOR, query_as_of=AS_OF) is None


def test_an_empty_actor_key_yields_no_advisory(conn):
    seed_decoy_history(conn)
    assert summarize_engagement(conn, "", query_as_of=AS_OF) is None
    assert summarize_engagement(conn, "   ", query_as_of=AS_OF) is None


def test_a_missing_table_is_silent_not_an_error(tmp_path):
    """Knowledge failure cannot block Edge or Gadget operation."""
    bare = sqlite3.connect(tmp_path / "empty.db")
    try:
        assert summarize_engagement(bare, ACTOR, query_as_of=AS_OF) is None
    finally:
        bare.close()


def test_reactions_after_the_query_instant_are_not_counted(conn):
    for index in range(4):
        add_reaction(
            conn,
            action="redirect",
            reaction="followed_decoy",
            applied_at="2026-10-01T00:00:00+00:00",
            classifier=f"c{index}",
        )

    assert summarize_engagement(conn, ACTOR, query_as_of=AS_OF) is None


# -- prior outcomes ----------------------------------------------------------


def test_prior_outcomes_are_folded_per_action(conn):
    seed_decoy_history(conn)
    add_reaction(conn, action="throttle", reaction="continued_scanning", classifier="t1")
    add_reaction(conn, action="throttle", reaction="continued_scanning", classifier="t2")

    advisory = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)

    assert advisory is not None
    assert advisory["prior_outcomes"]["redirect"] == {
        "dominant_reaction": "followed_decoy",
        "evidence_count": 3,
        "distinct_reactions": 1,
    }
    assert advisory["prior_outcomes"]["throttle"]["dominant_reaction"] == "continued_scanning"


def test_a_tie_is_unknown_and_is_named_rather_than_resolved(conn):
    """Contradictory evidence yields `unknown`, not whichever sorts first."""
    add_reaction(conn, action="redirect", reaction="followed_decoy", classifier="a")
    add_reaction(conn, action="redirect", reaction="disengaged", classifier="b")
    add_reaction(conn, action="throttle", reaction="continued_scanning", classifier="c")

    advisory = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)

    assert advisory is not None
    assert advisory["prior_outcomes"]["redirect"]["dominant_reaction"] == "unknown"
    assert any("outnumbered" in item for item in advisory["limitations"])


def test_another_actors_history_does_not_leak_in(conn):
    seed_decoy_history(conn)
    for index in range(5):
        add_reaction(
            conn, action="isolate", reaction="shifted_target", actor="actor-2", classifier=f"x{index}"
        )

    advisory = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)

    assert advisory is not None
    assert "isolate" not in advisory["prior_outcomes"]


# -- posture suggestion ------------------------------------------------------


def test_a_posture_is_suggested_only_where_the_evidence_supports_it(conn):
    seed_decoy_history(conn)

    advisory = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)
    posture = advisory["posture_suggestion"]

    assert posture is not None
    assert "redirect_to_decoy" in posture["supported_activities"]
    assert "similar_patterns_previously_engaged_decoy" in posture["reasons"]


def test_decoy_redirection_is_not_suggested_without_decoy_evidence(conn):
    """`redirect_to_decoy` needs prior decoy engagement, not prior redirection."""
    for index in range(4):
        add_reaction(conn, action="redirect", reaction="shifted_port", classifier=f"c{index}")
    add_pattern(conn)

    advisory = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)
    posture = advisory["posture_suggestion"]

    assert posture is not None
    assert "redirect_to_decoy" not in posture["supported_activities"]
    assert posture["supported_activities"] == ["redirect"]


def test_low_confidence_suggests_no_posture_but_still_reports_what_was_seen(conn):
    # Seeded low-trust from the start: `reaction` rows are immutable by
    # trigger (Absolute Constraint 5), so this cannot be set up by UPDATE.
    for index in range(3):
        add_reaction(
            conn,
            action="redirect",
            reaction="followed_decoy",
            trust_tier="provisional",
            classifier=f"c{index}",
        )
    add_pattern(conn, confidence=0)

    advisory = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)

    assert advisory is not None
    assert advisory["posture_suggestion"] is None
    assert advisory["prior_outcomes"]  # the observations are still reported
    assert any("floor" in item for item in advisory["limitations"])


@pytest.mark.parametrize("action", sorted(ACTIONS_WITHOUT_A_CANONICAL_ACTIVITY))
def test_an_action_with_no_canonical_activity_suggests_none_and_says_so(conn, action):
    """Inventing a mapping from a product-local action to a canonical one would
    make the product word canonical by the back door."""
    for index in range(4):
        add_reaction(conn, action=action, reaction="disengaged", classifier=f"c{index}")
    add_pattern(conn)

    advisory = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)

    assert advisory is not None
    assert advisory["prior_outcomes"][action]["evidence_count"] == 4
    assert advisory["posture_suggestion"] is None
    assert any("no equivalent" in item for item in advisory["limitations"])


def test_knowledge_defines_no_engagement_vocabulary_of_its_own():
    """The posture vocabulary is Fabric's. A second copy would drift from it."""
    import ast

    import azazel_knowledge.correlate.engagement_advisory as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    docstrings = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
        and ast.get_docstring(node, clean=False) is not None
    }
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    }
    # The module may name the two bounded values it emits and the activities it
    # can support; it must not restate Fabric's whole objective/approach lists.
    forbidden = {"detect", "prevent", "direct", "disrupt", "reassure"}
    assert literals & forbidden == set(), (
        f"Knowledge restated Fabric's engagement vocabulary: {sorted(literals & forbidden)}"
    )


# -- determinism -------------------------------------------------------------


def test_the_fold_is_byte_deterministic_across_repeated_calls(conn):
    seed_decoy_history(conn)
    add_reaction(conn, action="throttle", reaction="continued_scanning", classifier="t1")

    first = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)
    for _ in range(3):
        assert json.dumps(summarize_engagement(conn, ACTOR, query_as_of=AS_OF), sort_keys=True) == (
            json.dumps(first, sort_keys=True)
        )


def test_insertion_order_does_not_change_the_result(tmp_path):
    """Two nodes that stored the same facts in a different order must fold
    identically, or replay is not reproducible."""
    results = []
    for order in ([("redirect", "followed_decoy"), ("throttle", "continued_scanning")],
                  [("throttle", "continued_scanning"), ("redirect", "followed_decoy")]):
        connection = sqlite3.connect(tmp_path / f"local-{len(results)}.db")
        apply_migrations(connection, "local")
        for index, (action, reaction) in enumerate(order * 2):
            add_reaction(connection, action=action, reaction=reaction, classifier=f"c{index}")
        add_pattern(connection)
        results.append(json.dumps(summarize_engagement(connection, ACTOR, query_as_of=AS_OF), sort_keys=True))
        connection.close()
    assert results[0] == results[1]


# -- advisory-only, at the Fabric boundary -----------------------------------


def test_the_fabric_boundary_pins_authority_and_non_executability(conn):
    seed_decoy_history(conn)
    folded = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)

    built = build_engagement_advisory(folded, advisory_id="adv-1", advisor="azazel-knowledge")

    assert built["authority"] == "advisory_only"
    assert built["executable"] is False
    assert built["advisory_notice"]


@pytest.mark.parametrize(
    "directive",
    [
        {"execute": "redirect"},
        {"command": "nft add rule"},
        {"override": True},
        {"deadline": "2026-07-06T13:00:00Z", "must_apply": True},
    ],
)
def test_an_extra_top_level_field_is_refused_at_the_boundary(conn, directive):
    seed_decoy_history(conn)
    folded = {**summarize_engagement(conn, ACTOR, query_as_of=AS_OF), **directive}

    with pytest.raises(AdvisoryInvariantViolation):
        build_engagement_advisory(folded, advisory_id="adv-1", advisor="azazel-knowledge")


@pytest.mark.parametrize(
    "smuggled",
    [
        {"shell_command": "sh -c ..."},
        {"nft_rule": "add rule inet filter ..."},
        {"execute_now": True},
        {"bypass_arbiter": True},
    ],
)
def test_a_runtime_directive_hidden_inside_prior_outcomes_is_refused(conn, smuggled):
    """`prior_outcomes` has free-form keys, so `extra="forbid"` does not reach
    inside it. The recursive walk in the builder is what does.

    These are the words the *builder's* walk owns
    (`BANNED_RUNTIME_DIRECTIVE_FIELDS`: shell/nft/docker commands, `execute_now`,
    `bypass_arbiter`). The advisory-directive words (`directive`,
    `must_execute`, `override`, `required_action`) belong to the response-level
    assertion and are covered by the test below -- two layers, two vocabularies,
    and neither one is the other's backstop.
    """

    seed_decoy_history(conn)
    folded = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)
    folded["prior_outcomes"]["redirect"].update(smuggled)

    with pytest.raises(AdvisoryInvariantViolation):
        build_engagement_advisory(folded, advisory_id="adv-1", advisor="azazel-knowledge")


def test_a_non_canonical_activity_is_refused_at_the_boundary(conn):
    """Knowledge cannot widen the shared activity vocabulary on the way out."""
    seed_decoy_history(conn)
    folded = summarize_engagement(conn, ACTOR, query_as_of=AS_OF)
    folded["posture_suggestion"]["supported_activities"].append("exfiltrate_everything")

    with pytest.raises(AdvisoryInvariantViolation):
        build_engagement_advisory(folded, advisory_id="adv-1", advisor="azazel-knowledge")


def test_the_advisory_asserts_no_belief_intent_or_identity(conn):
    seed_decoy_history(conn)
    built = build_engagement_advisory(
        summarize_engagement(conn, ACTOR, query_as_of=AS_OF),
        advisory_id="adv-1",
        advisor="azazel-knowledge",
    )

    # Checked against field NAMES, not the serialized blob: the advisory's own
    # limitations say in prose that it is "not a claim about the actor's intent
    # or belief", and a substring search cannot tell a disclaimer from a claim.
    def _keys(value):
        if isinstance(value, dict):
            for key, child in value.items():
                yield key
                yield from _keys(child)
        elif isinstance(value, list):
            for child in value:
                yield from _keys(child)

    names = {key.lower() for key in _keys(built)}
    for forbidden in ("attacker_belief", "belief", "intent", "identity", "attribution"):
        assert forbidden not in names, f"the advisory carries an {forbidden} field"
    assert any("not a prediction" in item for item in built["limitations"])


# -- the wire, end to end ----------------------------------------------------


def _context_body(**overrides):
    body = {
        "entities": [{"type": "ip", "value": "203.0.113.7"}],
        "event": dict(_SCAN_EVENT),
        "edge_id": "edge-1",
        "actor_key": ACTOR,
    }
    body.update(overrides)
    return body


def test_the_advisory_reaches_the_wire(tmp_path):
    """The enrichment is fail-open, and a fail-open path hides its own wiring
    bugs. Something has to prove it actually ran."""
    client, _settings, local_db_path, _ = make_client(tmp_path)
    connection = sqlite3.connect(local_db_path)
    try:
        seed_decoy_history(connection)
    finally:
        connection.close()
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))

    assert resp.status_code == 200
    body = resp.json()
    advisory = body["engagement_advisory"]
    assert advisory is not None, "the engagement advisory never reached the response"
    assert advisory["authority"] == "advisory_only"
    assert advisory["executable"] is False
    assert advisory["behavior_class"] == "adaptive_probe"
    assert advisory["prior_outcomes"]["redirect"]["dominant_reaction"] == "followed_decoy"
    assert body["engagement_repeatability_score"] == 60


def test_an_actor_with_no_history_leaves_the_block_null(tmp_path):
    client, _settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))

    assert resp.status_code == 200
    assert resp.json()["engagement_advisory"] is None
    assert resp.json()["engagement_repeatability_score"] is None


def test_the_block_does_not_perturb_the_determinism_tuple(tmp_path):
    """Read after scoring, so `content_hash` and every scored field must be
    identical with and without engagement history present."""
    client, _settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    body = _context_body()

    before = client.post("/v1/context", json=body, headers=auth_header(token)).json()
    connection = sqlite3.connect(local_db_path)
    try:
        seed_decoy_history(connection)
    finally:
        connection.close()
    after = client.post("/v1/context", json=body, headers=auth_header(token)).json()

    assert after["engagement_advisory"] is not None
    for field in ("threat_score", "confidence", "reason", "confidence_reason", "threat_context"):
        assert before[field] == after[field], f"{field} moved when engagement history appeared"


def test_the_block_goes_through_the_advisory_only_assertion(tmp_path, monkeypatch):
    """Pin the wiring: dropping the block from the assertion's input would
    leave every response test green while the new field stopped being checked."""
    import azazel_knowledge.api.routers.context as context_router

    seen: list[dict] = []
    original = context_router.assert_response_advisory_only
    monkeypatch.setattr(
        context_router,
        "assert_response_advisory_only",
        lambda view: (seen.append(view), original(view))[1],
    )

    client, _settings, local_db_path, _ = make_client(tmp_path)
    connection = sqlite3.connect(local_db_path)
    try:
        seed_decoy_history(connection)
    finally:
        connection.close()
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))

    assert resp.status_code == 200
    assert seen, "the advisory-only assertion was never called"
    assert "engagement_advisory" in seen[0]
    assert seen[0]["engagement_advisory"] is not None


def test_the_advisory_is_never_keyed_on_the_api_client(tmp_path):
    """Two different concepts wear the name `actor_key`, and mixing them up is
    a cross-actor leak.

    `reaction.actor_key` is the *source entity* the caller observed. The
    router's own `actor_key` local is `auth.key_id or body.actor_key or
    body.edge_id` -- the *client's* identity, used to attribute the advisory
    audit event. Keying the fold on the latter would answer "what has this API
    client done", which is not a question anyone asked, and would silently
    attach one actor's history to another whenever the caller omitted the
    field.

    Seeded here under the API key id and under the edge id, with nothing under
    the actor the caller names: a correct implementation finds nothing.
    """

    client, _settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    connection = sqlite3.connect(local_db_path)
    try:
        for wrong_key in ("edge1", "edge-1"):
            for index in range(4):
                add_reaction(
                    connection,
                    action="redirect",
                    reaction="followed_decoy",
                    actor=wrong_key,
                    classifier=f"{wrong_key}-{index}",
                )
            add_pattern(connection, actor=wrong_key, pattern_id=f"pat-{wrong_key}")
    finally:
        connection.close()

    resp = client.post(
        "/v1/context",
        json=_context_body(actor_key="an-actor-with-no-history"),
        headers=auth_header(token),
    )

    assert resp.status_code == 200
    assert resp.json()["engagement_advisory"] is None, (
        "the advisory was keyed on the API client or the edge id, not on the "
        "actor the caller named"
    )


def test_a_caller_that_names_no_actor_gets_no_advisory(tmp_path):
    """No actor named means no question asked. Falling back to the client's own
    identity would answer a different one."""
    client, _settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    connection = sqlite3.connect(local_db_path)
    try:
        for index in range(4):
            add_reaction(
                connection, action="redirect", reaction="followed_decoy",
                actor="edge1", classifier=f"c{index}",
            )
        add_pattern(connection, actor="edge1")
    finally:
        connection.close()

    body = _context_body()
    body.pop("actor_key")
    resp = client.post("/v1/context", json=body, headers=auth_header(token))

    assert resp.status_code == 200
    assert resp.json()["engagement_advisory"] is None


def _patch_fold(monkeypatch, smuggled):
    import azazel_knowledge.api.routers.context as context_router

    def _fold_with_a_directive(conn, actor_key, *, query_as_of, config=None):
        return {
            "seen_before": True,
            "behavior_class": "adaptive_probe",
            "confidence": 0.9,
            "prior_outcomes": {"redirect": {"dominant_reaction": "followed_decoy", **smuggled}},
            "posture_suggestion": None,
            "reasons": [],
            "limitations": [],
        }

    monkeypatch.setattr(context_router, "summarize_engagement", _fold_with_a_directive)


@pytest.mark.parametrize("smuggled", [{"override": True}, {"directive": "x"}])
def test_an_advisory_directive_nested_in_the_block_fails_the_response_closed(
    tmp_path, monkeypatch, smuggled
):
    """The response-level layer, tested with the words it alone owns.

    `override` and `directive` are in Fabric's `BANNED_DIRECTIVE_FIELDS` but
    NOT in the builder's `BANNED_RUNTIME_DIRECTIVE_FIELDS`, so they pass the
    builder and must be stopped here. `/v1/context` then fails closed with a
    500 rather than emitting a directive-shaped response.
    """

    _patch_fold(monkeypatch, smuggled)
    client, _settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))

    assert resp.status_code == 500
    assert resp.json()["detail"]["error"] == "advisory_invariant_violation"


@pytest.mark.parametrize("smuggled", [{"must_execute": True}, {"bypass_arbiter": True}])
def test_a_word_both_layers_own_is_stopped_at_the_earlier_one(tmp_path, monkeypatch, smuggled):
    """`must_execute` and `bypass_arbiter` are in BOTH banned sets.

    The builder sees them first, so the block is dropped and the rest of the
    response is served normally -- a 200 with a null advisory, not a 500. That
    is the better outcome and worth pinning: a directive in the enrichment must
    not cost the caller their threat context.
    """

    _patch_fold(monkeypatch, smuggled)
    client, _settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))

    assert resp.status_code == 200
    assert resp.json()["engagement_advisory"] is None
    assert resp.json()["threat_score"] is not None
