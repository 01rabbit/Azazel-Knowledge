from __future__ import annotations

import json
import sqlite3

from _api_support import QUERY_AS_OF, add_api_client, auth_header, make_client
from azazel_knowledge.core.config import TrackedConfigLoader
from azazel_knowledge.correlate.pipeline import ADVISORY_NOTICE
from azazel_knowledge.db.repository import Repository
from azazel_knowledge.patterns.behavior_generate import apply_generation_plan
from azazel_knowledge.reports.friction_timeline import (
    build_friction_timeline_report,
    get_behavior_pattern_detail,
    get_behavior_patterns_summary,
)
from test_behavior_generate import _insert_observation, _insert_reaction


def _seed_generated_behavior(local_db_path, config_dir) -> str:
    conn = sqlite3.connect(local_db_path)
    _insert_observation(conn, event_id="obs-1", observed_at="2026-07-06T11:59:58Z")
    _insert_observation(conn, event_id="obs-2", observed_at="2026-07-06T11:59:59Z")
    _insert_reaction(
        conn,
        action_applied="throttle",
        applied_at="2026-07-06T11:59:59Z",
        reaction="unknown",
        evidence_refs=["obs-1"],
    )
    _insert_reaction(
        conn,
        action_applied="throttle",
        applied_at="2026-07-06T12:00:00Z",
        reaction="shifted_protocol",
        evidence_refs=["obs-2"],
    )
    apply_generation_plan(
        conn,
        TrackedConfigLoader(config_dir),
        query_as_of=QUERY_AS_OF,
        mode="rebuild",
    )
    conn.commit()
    pattern_id = conn.execute(
        "SELECT pattern_id FROM behavior_pattern ORDER BY pattern_id ASC"
    ).fetchone()[0]
    conn.close()
    return str(pattern_id)


def test_friction_timeline_contains_all_required_stages_and_evidence_refs(tmp_path):
    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    pattern_id = _seed_generated_behavior(local_db_path, settings.config_dir)
    repo = Repository(local_db_path, data_db_dir)

    report = build_friction_timeline_report(repo, query_as_of=QUERY_AS_OF, pattern_id=pattern_id)

    assert [entry["event_type"] for entry in report["timeline"]] == [
        "initial_observation",
        "edge_action_applied",
        "reaction_window",
        "reaction_classification",
        "generated_behavior_pattern",
        "evidence_references",
        "advisory_implication",
        "cti_advisory_disclaimer",
    ]
    for entry in report["timeline"][:-1]:
        assert entry["evidence_refs"]
    assert report["behavior_patterns"][0]["pattern_id"] == pattern_id
    client.close()


def test_friction_timeline_gracefully_degrades_without_advisory_data(tmp_path):
    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    pattern_id = _seed_generated_behavior(local_db_path, settings.config_dir)
    repo = Repository(local_db_path, data_db_dir)

    report = build_friction_timeline_report(repo, query_as_of=QUERY_AS_OF, pattern_id=pattern_id)

    assert report["advisory_summary"] is None
    assert any("advisory data was unavailable" in item for item in report["limitations"])
    implication = next(entry for entry in report["timeline"] if entry["event_type"] == "advisory_implication")
    assert "unavailable" in implication["explanation_short"]
    client.close()


def test_friction_timeline_includes_disclaimer_and_no_attribution_terms(tmp_path):
    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    pattern_id = _seed_generated_behavior(local_db_path, settings.config_dir)
    repo = Repository(local_db_path, data_db_dir)

    report = build_friction_timeline_report(repo, query_as_of=QUERY_AS_OF, pattern_id=pattern_id)
    rendered = json.dumps(report, sort_keys=True)

    assert ADVISORY_NOTICE in report["limitations"]
    assert ADVISORY_NOTICE == report["timeline"][-1]["explanation_short"]
    assert "AI attacker confirmed" not in rendered
    assert "LLM identified" not in rendered
    assert "autonomous intrusion proven" not in rendered
    assert "ai_attacker" not in rendered
    client.close()


def test_behavior_report_endpoints_and_read_scope(tmp_path):
    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    pattern_id = _seed_generated_behavior(local_db_path, settings.config_dir)
    _ = Repository(local_db_path, data_db_dir)
    read_token = add_api_client(local_db_path, "reader1", ["read"])
    query_token = add_api_client(local_db_path, "query1", ["query"])

    detail = client.get(f"/v1/behavior-patterns/{pattern_id}", headers=auth_header(read_token))
    summary = client.get(
        "/v1/behavior-patterns/summary?behavior_class=adaptive_probe&edge_id=edge-1",
        headers=auth_header(read_token),
    )
    report = client.get(
        f"/v1/reports/friction-timeline?pattern_id={pattern_id}",
        headers=auth_header(read_token),
    )
    forbidden = client.get(
        f"/v1/reports/friction-timeline?pattern_id={pattern_id}",
        headers=auth_header(query_token),
    )

    assert detail.status_code == 200
    assert detail.json()["pattern"]["pattern_id"] == pattern_id
    assert detail.json()["similarity"] == []
    assert summary.status_code == 200
    assert summary.json()["patterns"][0]["pattern_id"] == pattern_id
    assert report.status_code == 200
    assert report.json()["report_id"] == f"friction-{pattern_id}"
    assert forbidden.status_code == 403
    client.close()


def test_report_reads_render_from_generator_fixture_data(tmp_path):
    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    pattern_id = _seed_generated_behavior(local_db_path, settings.config_dir)
    repo = Repository(local_db_path, data_db_dir)

    detail = get_behavior_pattern_detail(repo, pattern_id=pattern_id)
    summary = get_behavior_patterns_summary(repo, query_as_of=QUERY_AS_OF)
    report = build_friction_timeline_report(repo, query_as_of=QUERY_AS_OF, pattern_id=pattern_id)

    assert detail["pattern"]["behavior_class"] == "adaptive_probe"
    assert detail["evidence"][0]["resolved"] is not None
    assert summary["patterns"][0]["pattern_id"] == pattern_id
    assert report["actor_key"] == "actor-1"
    client.close()
