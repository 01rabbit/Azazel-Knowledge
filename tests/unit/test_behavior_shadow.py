from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from _api_support import add_api_client, auth_header, make_client
from azazel_grimoire import worker
from azazel_grimoire.core.clock import FixedClock
from azazel_grimoire.core.config import ConfigError, TrackedConfigLoader
from azazel_grimoire.correlate.pipeline import ContextRequest, Entity, run_context
from azazel_grimoire.db import generations
from azazel_grimoire.db.behavior import BehaviorPattern, behavior_pattern_id
from azazel_grimoire.db.repository import Repository, apply_migrations, entity_key
from azazel_grimoire.db.writer import PrioritySingleWriterQueue
from azazel_grimoire.patterns.behavior_generate import GenerationPlan, PersistedPattern
from azazel_grimoire.scoring.behavior_shadow import (
    build_behavioral_shadow_record,
    evaluate_behavioral_shadow,
)

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"
QUERY_AS_OF = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)
CLOCK = FixedClock(QUERY_AS_OF)


def _copy_config(tmp_path: Path) -> Path:
    dest = tmp_path / "config"
    shutil.copytree(REPO_CONFIG, dest)
    return dest


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _dump_yaml(path: Path, document: dict) -> None:
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def _make_local_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    conn.execute("INSERT INTO local_meta (key, value) VALUES ('local_generation', '3')")
    conn.execute("INSERT INTO local_meta (key, value) VALUES ('stats_generation', '7')")
    conn.commit()
    conn.close()


def _make_intel_generation(data_db_dir: Path, n: int = 1) -> None:
    intel_path = generations.build_next_generation(data_db_dir)
    conn = sqlite3.connect(intel_path)
    apply_migrations(conn, "intel")
    conn.execute(
        "INSERT INTO ioc (ioc_id, type, value, first_seen, last_seen, agg_raw_confidence, agg_computed_at) "
        "VALUES (1, 'ip', '203.0.113.7', '2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 80.0, '2026-07-02T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, intel_generation) "
        "VALUES (1, 'urlhaus', 85, '2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 1)"
    )
    conn.execute("INSERT INTO stats_meta (key, value) VALUES ('intel_generation', ?)", (str(n),))
    conn.commit()
    conn.close()
    generations.swap_current(data_db_dir, n)


def _seed_local_stats(local_db_path: Path) -> None:
    key = entity_key("ip", "203.0.113.7")
    conn = sqlite3.connect(local_db_path)
    conn.execute(
        "INSERT INTO observation_stats (entity_key, window_start, window_end, event_count, trend, stats_generation, updated_at) "
        "VALUES (?, '2026-07-05T00:00:00Z', '2026-07-06T00:00:00Z', 14, 0.3, 7, '2026-07-06T11:59:30Z')",
        (key,),
    )
    conn.execute(
        "INSERT INTO reputation (entity_key, score, updated_at) VALUES (?, 55.0, '2026-07-06T11:59:30Z')",
        (key,),
    )
    conn.commit()
    conn.close()


def _request() -> ContextRequest:
    return ContextRequest(
        entities=[Entity("ip", "203.0.113.7")],
        event={"kind": "generic", "event_types": ["generic"]},
        edge_id="edge-1",
        actor_key="actor-1",
    )


def _pattern(**overrides: object) -> BehaviorPattern:
    pattern = BehaviorPattern(
        pattern_id="bp-shadow-1",
        behavior_generation=7,
        version=1,
        actor_key="actor-1",
        actor_cluster_key="cluster-1",
        edge_id="edge-1",
        observation_start="2026-07-06T00:00:00.000Z",
        observation_end="2026-07-06T00:10:00.000Z",
        action_applied="delay",
        reaction_sequence=["continued_scanning", "shifted_port"],
        reaction_window_s=60,
        behavior_class="scripted_automation",
        confidence=68,
        novelty_score=28,
        repeatability_score=72,
        suspected_stage="reconnaissance",
        related_iocs=["203.0.113.7"],
        related_ttps=["T1595"],
        generated_at="2026-07-06T00:10:01.000Z",
        generator_version="bpg-1",
        behavior_config_hash="cfg-1",
        provenance={"builder": "unit"},
    )
    return BehaviorPattern(**{**pattern.__dict__, **overrides})


def _seed_behavioral_pattern(local_db_path: Path) -> str:
    conn = sqlite3.connect(local_db_path)
    conn.execute(
        """
        INSERT INTO observation (
            event_id, edge_id, kind, observed_at, entity_key, entities, raw, created_at
        ) VALUES (
            'evt-1', 'edge-1', 'http', '2026-07-06T00:00:00.000Z', NULL,
            '["203.0.113.7"]', '{"path":"/login"}', '2026-07-06T00:00:00.000Z'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO reaction (
            edge_id, actor_key, action_applied, applied_at, reaction,
            reaction_window_s, events_in_window, classifier, classifier_version,
            evidence_refs, evidence_modality_count, trust_tier, advisory_id,
            advisory_linkage, created_at
        ) VALUES (
            'edge-1', 'actor-1', 'delay', '2026-07-06T00:00:01.000Z', 'continued_scanning',
            60, 3, 'ladder-v1', '1', '[1]', 1, 'provisional', NULL, 'none',
            '2026-07-06T00:00:01.000Z'
        )
        """
    )
    observation_id = conn.execute("SELECT observation_id FROM observation").fetchone()[0]
    reaction_id = conn.execute("SELECT reaction_id FROM reaction").fetchone()[0]
    pattern_id = behavior_pattern_id(
        "edge-1",
        "actor-1",
        "2026-07-06T00:00:00.000Z",
        "2026-07-06T00:10:00.000Z",
        "bpg-1",
    )
    conn.execute(
        """
        INSERT INTO behavior_pattern (
            pattern_id, behavior_generation, version, actor_key, actor_cluster_key,
            edge_id, observation_start, observation_end, action_applied,
            reaction_sequence, reaction_window_s, behavior_class, confidence,
            novelty_score, repeatability_score, suspected_stage, related_iocs,
            related_ttps, generated_at, generator_version, behavior_config_hash, provenance
        ) VALUES (
            ?, 7, 1, 'actor-1', 'cluster-1', 'edge-1', '2026-07-06T00:00:00.000Z',
            '2026-07-06T00:10:00.000Z', 'delay', '["continued_scanning"]',
            60, 'scripted_automation', 68, 28, 72, 'reconnaissance', '["203.0.113.7"]',
            '["T1595"]', '2026-07-06T00:10:01.000Z', 'bpg-1', 'cfg-1', '{"builder":"unit"}'
        )
        """,
        (pattern_id,),
    )
    conn.execute(
        """
        INSERT INTO behavior_pattern_evidence (
            pattern_id, behavior_generation, evidence_type, evidence_id, role
        ) VALUES (?, 7, 'observation', ?, 'supporting')
        """,
        (pattern_id, str(observation_id)),
    )
    conn.execute(
        """
        INSERT INTO behavior_pattern_evidence (
            pattern_id, behavior_generation, evidence_type, evidence_id, role
        ) VALUES (?, 7, 'reaction', ?, 'source')
        """,
        (pattern_id, str(reaction_id)),
    )
    conn.execute(
        """
        INSERT INTO behavior_pattern_similarity (
            pattern_id, behavior_generation, other_pattern_id, similarity,
            repeatability, shared_features, differences, evidence_refs
        ) VALUES (?, 7, 'bp-prior', 0.84, 72, '["same-action"]', '["new-decoy"]', '["1","2"]')
        """,
        (pattern_id,),
    )
    conn.execute(
        "INSERT OR REPLACE INTO behavior_meta (key, value) VALUES ('current_behavior_generation', '7')"
    )
    conn.commit()
    conn.close()
    return pattern_id


@pytest.fixture()
def repo_env(tmp_path: Path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    _make_intel_generation(data_db_dir)
    _seed_local_stats(local_db_path)
    repo = Repository(local_db_path, data_db_dir, pool_size=2)
    yield repo, local_db_path
    repo.close()


def test_behavior_shadow_defaults_to_disabled() -> None:
    loader = TrackedConfigLoader(REPO_CONFIG)
    rules = loader.behavior_shadow_rules()

    assert rules["enabled"] is False
    assert rules["mode"] == "shadow"


def test_disabled_shadow_rules_do_not_change_production_score(tmp_path: Path, repo_env) -> None:
    repo, _ = repo_env
    config_dir = _copy_config(tmp_path)
    baseline = run_context(repo, TrackedConfigLoader(REPO_CONFIG), _request(), CLOCK)

    document = _load_yaml(config_dir / "behavior-shadow-rules.yaml")
    document["behavioral_shadow_rules"]["rules"][0]["shadow_effect"]["delta"] = 19
    _dump_yaml(config_dir / "behavior-shadow-rules.yaml", document)
    result = run_context(repo, TrackedConfigLoader(config_dir), _request(), CLOCK)

    assert result.threat_score == baseline.threat_score
    assert result.reason == baseline.reason
    assert result.content_hash == baseline.content_hash


def test_computed_shadow_delta_does_not_change_production_fields(tmp_path: Path, repo_env) -> None:
    repo, _ = repo_env
    config_dir = _copy_config(tmp_path)
    document = _load_yaml(config_dir / "behavior-shadow-rules.yaml")
    document["behavioral_shadow_rules"]["enabled"] = True
    _dump_yaml(config_dir / "behavior-shadow-rules.yaml", document)
    loader = TrackedConfigLoader(config_dir)

    shadow = evaluate_behavioral_shadow(_pattern(), loader.behavior_shadow_rules())
    baseline = run_context(repo, TrackedConfigLoader(REPO_CONFIG), _request(), CLOCK)
    result = run_context(repo, loader, _request(), CLOCK)

    assert shadow.would_adjust is True
    assert shadow.shadow_score_delta == 5
    assert result.threat_score == baseline.threat_score
    assert result.reason == baseline.reason
    assert result.content_hash == baseline.content_hash


def test_behavior_shadow_evaluation_is_deterministic_and_versioned(tmp_path: Path) -> None:
    config_dir = _copy_config(tmp_path)
    loader = TrackedConfigLoader(config_dir)
    pattern = _pattern(
        behavior_config_hash=loader.behavior_config_hash(
            behavior_generation=7,
            generator_version="bpg-1",
        )
    )

    first = evaluate_behavioral_shadow(pattern, loader.behavior_shadow_rules())
    second = evaluate_behavioral_shadow(pattern, loader.behavior_shadow_rules())

    document = _load_yaml(config_dir / "behavior-shadow-rules.yaml")
    document["behavioral_shadow_rules"]["rules"].append(
        {
            "id": "scan-after-delay-2",
            "when": {
                "behavior_class": "scripted_automation",
                "action_applied": "delay",
                "reaction_contains": "continued_scanning",
            },
            "shadow_effect": {"component": "history", "delta": 1},
            "explanation": "Secondary shadow-only history adjustment.",
        }
    )
    _dump_yaml(config_dir / "behavior-shadow-rules.yaml", document)
    mutated = TrackedConfigLoader(config_dir)

    assert first == second
    assert mutated.behavior_config_hash(
        behavior_generation=7,
        generator_version="bpg-1",
    ) != loader.behavior_config_hash(
        behavior_generation=7,
        generator_version="bpg-1",
    )


def test_worker_shadow_output_contains_explanation_and_rules_hit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = _copy_config(tmp_path / "cfg")
    root = tmp_path / "node"
    paths = worker.WorkerPaths.from_root(root, config_dir=config_dir)
    paths.ensure_dirs()
    worker.ensure_local_db(paths.local_db_path)
    _ = worker.current_intel_db_path(paths.data_db_dir)
    local_writer = PrioritySingleWriterQueue(paths.local_db_path, paths.local_lock_path)
    intel_writer = PrioritySingleWriterQueue(
        worker.current_intel_db_path(paths.data_db_dir),
        paths.intel_lock_path,
    )
    local_writer.open()
    intel_writer.open()

    fake_pattern = _pattern()
    plan = GenerationPlan(
        mode="incremental",
        behavior_generation=7,
        query_as_of="2026-07-06T12:00:00Z",
        generated_at="2026-07-06T12:00:00Z",
        behavior_config_hash="cfg-1",
        patterns=(PersistedPattern(fake_pattern, (), (1,)),),
        carried_forward=0,
        rebuilt_tail_partitions=(),
    )

    monkeypatch.setattr(worker, "apply_generation_plan", lambda *args, **kwargs: plan)
    monkeypatch.setattr(worker, "run_similarity", lambda *args, **kwargs: None)
    try:
        stats = worker.run_p2(
            intel_writer,
            local_writer,
            TrackedConfigLoader(config_dir),
            clock=CLOCK,
            online=False,
            behavior_shadow_log_path=paths.behavior_shadow_log_path,
        )
    finally:
        local_writer.close()
        intel_writer.close()

    lines = paths.behavior_shadow_log_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    assert stats["behavior_shadow_emitted"] == 1
    assert record["behavioral_shadow"]["enabled"] is False
    assert record["behavioral_shadow"]["rules_hit"] == ["continued-scan-after-delay"]
    assert record["behavioral_shadow"]["explanation"] == "Shadow-only; production threat_score unchanged."


def test_behavior_shadow_without_required_evidence_has_no_adjustment() -> None:
    loader = TrackedConfigLoader(REPO_CONFIG)
    shadow = evaluate_behavioral_shadow(
        _pattern(reaction_sequence=["shifted_port"], behavior_class="adaptive_probe"),
        loader.behavior_shadow_rules(),
    )

    assert shadow.would_adjust is False
    assert shadow.shadow_score_delta == 0
    assert shadow.rules_hit == ()


def test_behavior_shadow_does_not_change_reason_contract(tmp_path: Path, repo_env) -> None:
    repo, _ = repo_env
    config_dir = _copy_config(tmp_path)
    document = _load_yaml(config_dir / "behavior-shadow-rules.yaml")
    document["behavioral_shadow_rules"]["enabled"] = True
    _dump_yaml(config_dir / "behavior-shadow-rules.yaml", document)

    baseline = run_context(repo, TrackedConfigLoader(REPO_CONFIG), _request(), CLOCK)
    result = run_context(repo, TrackedConfigLoader(config_dir), _request(), CLOCK)

    assert [line["component"] for line in result.reason] == [
        "ioc_match",
        "history",
        "attack_map",
        "campaign",
        "geo_asn",
        "cve_exploited",
    ]
    assert result.reason == baseline.reason


def test_behavior_shadow_loader_rejects_active_mode(tmp_path: Path) -> None:
    config_dir = _copy_config(tmp_path)
    document = _load_yaml(config_dir / "behavior-shadow-rules.yaml")
    document["behavioral_shadow_rules"]["mode"] = "active"
    _dump_yaml(config_dir / "behavior-shadow-rules.yaml", document)

    with pytest.raises(ConfigError, match="shadow"):
        TrackedConfigLoader(config_dir)


def test_behavior_shadow_file_does_not_change_frozen_config_hash(tmp_path: Path) -> None:
    config_dir = _copy_config(tmp_path)
    baseline = TrackedConfigLoader(config_dir)
    document = _load_yaml(config_dir / "behavior-shadow-rules.yaml")
    document["behavioral_shadow_rules"]["rules"][0]["shadow_effect"]["delta"] = 9
    _dump_yaml(config_dir / "behavior-shadow-rules.yaml", document)
    mutated = TrackedConfigLoader(config_dir)

    assert mutated.config_hash == baseline.config_hash
    assert mutated.behavior_config_hash(
        behavior_generation=7,
        generator_version="bpg-1",
    ) != baseline.behavior_config_hash(
        behavior_generation=7,
        generator_version="bpg-1",
    )


def test_shadow_score_delta_never_appears_in_context_response(tmp_path: Path) -> None:
    client, _, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "actor-1", ["query"])
    _seed_behavioral_pattern(local_db_path)

    response = client.post(
        "/v1/context",
        json={
            "entities": [{"type": "ip", "value": "203.0.113.7"}],
            "event": {"kind": "eve_alert", "event_types": ["eve_alert"], "cves": ["CVE-2024-0001"]},
            "edge_id": "edge-1",
            "actor_key": "actor-1",
        },
        headers=auth_header(token),
    )

    body = response.json()
    assert response.status_code == 200
    assert "shadow_score_delta" not in json.dumps(body, sort_keys=True)
    assert "behavioral_shadow" not in body["threat_context"]
    assert "behavioral_cti" in body["threat_context"]
    assert "shadow_score_delta" not in body["threat_context"]["behavioral_cti"]


def test_build_behavioral_shadow_record_preserves_output_shape() -> None:
    loader = TrackedConfigLoader(REPO_CONFIG)
    evaluation = evaluate_behavioral_shadow(_pattern(), loader.behavior_shadow_rules())
    record = build_behavioral_shadow_record(_pattern(), evaluation)

    assert record["behavioral_shadow"] == {
        "enabled": False,
        "would_adjust": True,
        "shadow_score_delta": 5,
        "rules_hit": ["continued-scan-after-delay"],
        "explanation": "Shadow-only; production threat_score unchanged.",
    }
