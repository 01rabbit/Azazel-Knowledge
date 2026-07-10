from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from azazel_knowledge.core.config import ConfigError, TrackedConfigLoader
from azazel_knowledge.db.behavior import BehaviorPattern, behavior_pattern_id
from azazel_knowledge.db.repository import apply_migrations
from azazel_knowledge.patterns.behavior_generate import GENERATOR_VERSION, apply_generation_plan
from azazel_knowledge.scoring.behavior_similarity import (
    find_similar_by_actor_or_time_window,
    find_similar_by_pattern_id,
    run_similarity,
)

NOW = datetime(2026, 7, 8, 0, 0, 0, tzinfo=timezone.utc)
REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"


def _copy_config(tmp_path: Path) -> Path:
    dest = tmp_path / "config"
    shutil.copytree(REPO_CONFIG, dest)
    return dest


def _make_conn(tmp_path: Path) -> tuple[sqlite3.Connection, TrackedConfigLoader]:
    config_dir = _copy_config(tmp_path)
    loader = TrackedConfigLoader(config_dir)
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    return conn, loader


def _insert_observation(
    conn: sqlite3.Connection,
    *,
    event_id: str,
    edge_id: str = "edge-1",
    observed_at: str = "2026-07-08T00:00:00Z",
) -> int:
    cursor = conn.execute(
        "INSERT INTO observation (event_id, edge_id, kind, observed_at, entity_key, entities, raw, created_at) "
        "VALUES (?, ?, 'netflow', ?, NULL, '[]', '{}', ?)",
        (event_id, edge_id, observed_at, observed_at),
    )
    return int(cursor.lastrowid)


def _insert_reaction(
    conn: sqlite3.Connection,
    *,
    actor_key: str,
    action_applied: str,
    applied_at: str,
    reaction: str,
    evidence_refs: list[str],
    edge_id: str = "edge-1",
    actor_cluster_key: str | None = None,
    decoy_touched: int | None = None,
    retry_interval_ms: int | None = None,
) -> int:
    cursor = conn.execute(
        "INSERT INTO reaction (edge_id, actor_key, action_applied, applied_at, reaction, reaction_window_s, "
        "events_in_window, classifier, classifier_version, evidence_refs, evidence_modality_count, trust_tier, "
        "advisory_id, advisory_linkage, created_at, actor_cluster_key, decoy_touched, retry_interval_ms, payload_ext) "
        "VALUES (?, ?, ?, ?, ?, 60, 1, 'ladder', '1', ?, 2, 'provisional', NULL, 'none', ?, ?, ?, ?, '{}')",
        (
            edge_id,
            actor_key,
            action_applied,
            applied_at,
            reaction,
            json.dumps(evidence_refs),
            applied_at,
            actor_cluster_key,
            decoy_touched,
            retry_interval_ms,
        ),
    )
    return int(cursor.lastrowid)


def _insert_pattern(
    conn: sqlite3.Connection,
    loader: TrackedConfigLoader,
    *,
    behavior_generation: int,
    actor_key: str,
    action_applied: str,
    reaction_sequence: list[str],
    behavior_class: str,
    observation_start: str,
    observation_end: str,
    edge_id: str = "edge-1",
    actor_cluster_key: str | None = None,
    related_iocs: list[str] | None = None,
    related_ttps: list[str] | None = None,
    source_reaction_ids: list[int] | None = None,
    source_observation_ids: list[int] | None = None,
) -> str:
    pattern_id = behavior_pattern_id(
        edge_id=edge_id,
        actor_key=actor_key,
        observation_start=observation_start,
        observation_end=observation_end,
        generator_version=GENERATOR_VERSION,
    )
    pattern = BehaviorPattern(
        pattern_id=pattern_id,
        behavior_generation=behavior_generation,
        version=1,
        actor_key=actor_key,
        actor_cluster_key=actor_cluster_key,
        edge_id=edge_id,
        observation_start=observation_start,
        observation_end=observation_end,
        action_applied=action_applied,
        reaction_sequence=reaction_sequence,
        reaction_window_s=60,
        behavior_class=behavior_class,
        confidence=70,
        novelty_score=20,
        repeatability_score=0,
        suspected_stage=None,
        related_iocs=related_iocs or [],
        related_ttps=related_ttps or [],
        generated_at=observation_end,
        generator_version=GENERATOR_VERSION,
        behavior_config_hash=loader.behavior_config_hash(
            behavior_generation=behavior_generation, generator_version=GENERATOR_VERSION
        ),
        provenance={"source_reaction_ids": source_reaction_ids or []},
    )
    conn.execute(
        "INSERT INTO behavior_pattern ("
        "pattern_id, behavior_generation, version, actor_key, actor_cluster_key, edge_id, "
        "observation_start, observation_end, action_applied, reaction_sequence, reaction_window_s, "
        "behavior_class, confidence, novelty_score, repeatability_score, suspected_stage, "
        "related_iocs, related_ttps, generated_at, generator_version, behavior_config_hash, provenance"
        ") VALUES ("
        ":pattern_id, :behavior_generation, :version, :actor_key, :actor_cluster_key, :edge_id, "
        ":observation_start, :observation_end, :action_applied, :reaction_sequence, :reaction_window_s, "
        ":behavior_class, :confidence, :novelty_score, :repeatability_score, :suspected_stage, "
        ":related_iocs, :related_ttps, :generated_at, :generator_version, :behavior_config_hash, :provenance"
        ")",
        pattern.to_record(),
    )
    for reaction_id in sorted(source_reaction_ids or []):
        conn.execute(
            "INSERT INTO behavior_pattern_evidence "
            "(pattern_id, behavior_generation, evidence_type, evidence_id, role) "
            "VALUES (?, ?, 'reaction', ?, 'source')",
            (pattern_id, behavior_generation, str(reaction_id)),
        )
    for observation_id in sorted(source_observation_ids or []):
        conn.execute(
            "INSERT INTO behavior_pattern_evidence "
            "(pattern_id, behavior_generation, evidence_type, evidence_id, role) "
            "VALUES (?, ?, 'observation', ?, 'supporting')",
            (pattern_id, behavior_generation, str(observation_id)),
        )
    return pattern_id


def _build_prior_and_query(
    conn: sqlite3.Connection,
    loader: TrackedConfigLoader,
    *,
    prior_actor_key: str = "actor-a",
    query_actor_key: str = "actor-b",
    prior_sequence: list[str] | None = None,
    query_sequence: list[str] | None = None,
    prior_class: str = "adaptive_probe",
    query_class: str = "adaptive_probe",
    prior_action: str = "throttle",
    query_action: str = "throttle",
    prior_retry_ms: int | None = 1400,
    query_retry_ms: int | None = 1400,
    prior_decoy: int | None = 0,
    query_decoy: int | None = 0,
    prior_cluster: str | None = None,
    query_cluster: str | None = None,
    prior_iocs: list[str] | None = None,
    query_iocs: list[str] | None = None,
    prior_ttps: list[str] | None = None,
    query_ttps: list[str] | None = None,
    prior_edge: str = "edge-1",
    query_edge: str = "edge-2",
    prior_start: str = "2026-07-07T00:00:00Z",
    query_start: str = "2026-07-08T00:00:00Z",
) -> tuple[str, str]:
    prior_sequence = prior_sequence or ["continued_scanning", "shifted_port"]
    query_sequence = query_sequence or ["continued_scanning", "shifted_port"]
    prior_event = "obs-prior"
    query_event = "obs-query"
    prior_obs_id = _insert_observation(
        conn, event_id=prior_event, edge_id=prior_edge, observed_at=prior_start
    )
    query_obs_id = _insert_observation(
        conn, event_id=query_event, edge_id=query_edge, observed_at=query_start
    )
    prior_reaction_ids = [
        _insert_reaction(
            conn,
            actor_key=prior_actor_key,
            actor_cluster_key=prior_cluster,
            edge_id=prior_edge,
            action_applied=prior_action,
            applied_at="2026-07-07T00:00:01Z",
            reaction=prior_sequence[0],
            evidence_refs=[prior_event],
            decoy_touched=prior_decoy,
            retry_interval_ms=prior_retry_ms,
        ),
        _insert_reaction(
            conn,
            actor_key=prior_actor_key,
            actor_cluster_key=prior_cluster,
            edge_id=prior_edge,
            action_applied=prior_action,
            applied_at="2026-07-07T00:00:02Z",
            reaction=prior_sequence[-1],
            evidence_refs=[prior_event],
            decoy_touched=prior_decoy,
            retry_interval_ms=prior_retry_ms,
        ),
    ]
    query_reaction_ids = [
        _insert_reaction(
            conn,
            actor_key=query_actor_key,
            actor_cluster_key=query_cluster,
            edge_id=query_edge,
            action_applied=query_action,
            applied_at="2026-07-08T00:00:01Z",
            reaction=query_sequence[0],
            evidence_refs=[query_event],
            decoy_touched=query_decoy,
            retry_interval_ms=query_retry_ms,
        ),
        _insert_reaction(
            conn,
            actor_key=query_actor_key,
            actor_cluster_key=query_cluster,
            edge_id=query_edge,
            action_applied=query_action,
            applied_at="2026-07-08T00:00:02Z",
            reaction=query_sequence[-1],
            evidence_refs=[query_event],
            decoy_touched=query_decoy,
            retry_interval_ms=query_retry_ms,
        ),
    ]
    prior_pattern_id = _insert_pattern(
        conn,
        loader,
        behavior_generation=1,
        actor_key=prior_actor_key,
        actor_cluster_key=prior_cluster,
        edge_id=prior_edge,
        action_applied=prior_action,
        reaction_sequence=prior_sequence,
        behavior_class=prior_class,
        observation_start=prior_start,
        observation_end="2026-07-07T00:00:02Z",
        related_iocs=prior_iocs,
        related_ttps=prior_ttps,
        source_reaction_ids=prior_reaction_ids,
        source_observation_ids=[prior_obs_id],
    )
    query_pattern_id = _insert_pattern(
        conn,
        loader,
        behavior_generation=2,
        actor_key=query_actor_key,
        actor_cluster_key=query_cluster,
        edge_id=query_edge,
        action_applied=query_action,
        reaction_sequence=query_sequence,
        behavior_class=query_class,
        observation_start=query_start,
        observation_end="2026-07-08T00:00:02Z",
        related_iocs=query_iocs,
        related_ttps=query_ttps,
        source_reaction_ids=query_reaction_ids,
        source_observation_ids=[query_obs_id],
    )
    return prior_pattern_id, query_pattern_id


def test_exact_reaction_sequence_match_scores_high_similarity(tmp_path: Path) -> None:
    conn, loader = _make_conn(tmp_path)
    _, query_pattern_id = _build_prior_and_query(
        conn,
        loader,
        prior_actor_key="actor-a",
        query_actor_key="actor-a",
        prior_iocs=["203.0.113.10"],
        query_iocs=["203.0.113.10"],
        prior_ttps=["T1595"],
        query_ttps=["T1595"],
    )

    run_similarity(conn, loader, 2)

    matches = find_similar_by_pattern_id(conn, pattern_id=query_pattern_id, behavior_generation=2)
    assert matches[0]["similarity"] >= 0.9


def test_different_actor_same_sequence_still_matches_behaviorally(tmp_path: Path) -> None:
    conn, loader = _make_conn(tmp_path)
    _, query_pattern_id = _build_prior_and_query(
        conn,
        loader,
        prior_actor_key="actor-a",
        query_actor_key="actor-b",
    )

    run_similarity(conn, loader, 2)

    matches = find_similar_by_pattern_id(conn, pattern_id=query_pattern_id, behavior_generation=2)
    assert len(matches) == 1
    assert matches[0]["similarity"] >= 0.8


def test_same_actor_unrelated_behavior_does_not_overmatch(tmp_path: Path) -> None:
    conn, loader = _make_conn(tmp_path)
    _, query_pattern_id = _build_prior_and_query(
        conn,
        loader,
        prior_actor_key="actor-a",
        query_actor_key="actor-a",
        prior_sequence=["continued_scanning", "continued_scanning"],
        query_sequence=["shifted_target", "auth_pattern_changed"],
        prior_class="simple_scanner",
        query_class="adaptive_probe",
        prior_action="redirect",
        query_action="delay",
        prior_retry_ms=500,
        query_retry_ms=8000,
    )

    run_similarity(conn, loader, 2)

    matches = find_similar_by_pattern_id(conn, pattern_id=query_pattern_id, behavior_generation=2)
    assert matches[0]["similarity"] < 0.2


def test_decoy_engagement_materially_changes_similarity(tmp_path: Path) -> None:
    conn, loader = _make_conn(tmp_path)
    prior_decoy_id, query_pattern_id = _build_prior_and_query(
        conn,
        loader,
        prior_actor_key="actor-a",
        query_actor_key="actor-b",
        prior_decoy=1,
        query_decoy=1,
        prior_class="decoy_engaged",
        query_class="decoy_engaged",
        prior_sequence=["followed_decoy", "shifted_port"],
        query_sequence=["followed_decoy", "shifted_port"],
    )
    non_decoy_obs = _insert_observation(
        conn, event_id="obs-prior-plain", edge_id="edge-3", observed_at="2026-07-06T00:00:00Z"
    )
    non_decoy_rxn = _insert_reaction(
        conn,
        actor_key="actor-c",
        edge_id="edge-3",
        action_applied="throttle",
        applied_at="2026-07-06T00:00:01Z",
        reaction="followed_decoy",
        evidence_refs=["obs-prior-plain"],
        decoy_touched=0,
        retry_interval_ms=1400,
    )
    non_decoy_id = _insert_pattern(
        conn,
        loader,
        behavior_generation=1,
        actor_key="actor-c",
        edge_id="edge-3",
        action_applied="throttle",
        reaction_sequence=["followed_decoy", "shifted_port"],
        behavior_class="adaptive_probe",
        observation_start="2026-07-06T00:00:00Z",
        observation_end="2026-07-06T00:00:02Z",
        source_reaction_ids=[non_decoy_rxn],
        source_observation_ids=[non_decoy_obs],
    )

    run_similarity(conn, loader, 2)

    decoy_match = next(
        item
        for item in find_similar_by_pattern_id(conn, pattern_id=query_pattern_id, behavior_generation=2)
        if item["other_pattern_id"] == prior_decoy_id
    )
    plain_match = next(
        item
        for item in find_similar_by_pattern_id(conn, pattern_id=query_pattern_id, behavior_generation=2)
        if item["other_pattern_id"] == non_decoy_id
    )
    assert decoy_match["similarity"] - plain_match["similarity"] >= 0.1


def test_missing_features_degrade_gracefully(tmp_path: Path) -> None:
    conn, loader = _make_conn(tmp_path)
    _, query_pattern_id = _build_prior_and_query(
        conn,
        loader,
        prior_retry_ms=None,
        query_retry_ms=None,
        prior_iocs=[],
        query_iocs=[],
        prior_ttps=[],
        query_ttps=[],
        prior_cluster=None,
        query_cluster=None,
    )

    run_similarity(conn, loader, 2)

    matches = find_similar_by_pattern_id(conn, pattern_id=query_pattern_id, behavior_generation=2)
    assert matches[0]["similarity"] > 0.7
    assert all("ioc_overlap" not in item for item in matches[0]["differences"])


def test_similarity_explains_shared_features_and_differences(tmp_path: Path) -> None:
    conn, loader = _make_conn(tmp_path)
    _, query_pattern_id = _build_prior_and_query(
        conn,
        loader,
        prior_action="redirect",
        query_action="delay",
        prior_iocs=["198.51.100.20"],
        query_iocs=["198.51.100.20", "scan.example"],
        prior_ttps=["T1595"],
        query_ttps=["T1595", "T1110"],
    )

    run_similarity(conn, loader, 2)

    matches = find_similar_by_pattern_id(conn, pattern_id=query_pattern_id, behavior_generation=2)
    assert "reaction_sequence:exact" in matches[0]["shared_features"]
    assert any(item.startswith("action_applied:delay!=redirect") for item in matches[0]["differences"])
    assert any(item.startswith("ioc_overlap:shared=198.51.100.20") for item in matches[0]["shared_features"])


def test_behavior_similarity_module_has_no_ml_or_llm_dependency(tmp_path: Path) -> None:
    module_path = Path(__file__).resolve().parents[2] / "src/azazel_knowledge/scoring/behavior_similarity.py"
    source = module_path.read_text(encoding="utf-8").lower()
    for forbidden in ("sklearn", "embedding", "openai", "llm", "numpy", "torch"):
        assert forbidden not in source


def test_behavior_similarity_weight_sum_must_be_one(tmp_path: Path) -> None:
    config_dir = _copy_config(tmp_path)
    path = config_dir / "behavior-similarity.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["weights"]["ttp_overlap"] = 0.14
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(ConfigError, match="behavior-similarity.yaml 'weights' must sum to 1.0"):
        TrackedConfigLoader(config_dir)


def test_behavior_similarity_yaml_does_not_change_frozen_config_hash(tmp_path: Path) -> None:
    config_dir = _copy_config(tmp_path)
    original = TrackedConfigLoader(config_dir).config_hash
    path = config_dir / "behavior-similarity.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["weights"]["actor_identity"] = 0.02
    document["weights"]["reaction_sequence"] = 0.34
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    mutated_loader = TrackedConfigLoader(config_dir)
    assert mutated_loader.config_hash == original
    assert mutated_loader.behavior_config_hash(
        behavior_generation=2, generator_version=GENERATOR_VERSION
    ) != TrackedConfigLoader(_copy_config(tmp_path / "fresh")).behavior_config_hash(
        behavior_generation=2, generator_version=GENERATOR_VERSION
    )


def test_similarity_and_repeatability_are_byte_deterministic(tmp_path: Path) -> None:
    snapshots: list[str] = []
    for name in ("run-a", "run-b"):
        conn, loader = _make_conn(tmp_path / name)
        _build_prior_and_query(
            conn,
            loader,
            prior_actor_key="actor-a",
            query_actor_key="actor-b",
            prior_cluster="cluster-1",
            query_cluster="cluster-2",
            prior_iocs=["203.0.113.10", "scan.example"],
            query_iocs=["203.0.113.10", "scan.example"],
            prior_ttps=["T1595", "T1110"],
            query_ttps=["T1595", "T1110"],
        )
        results = run_similarity(conn, loader, 2)
        rows = conn.execute(
            "SELECT pattern_id, other_pattern_id, similarity, repeatability, shared_features, differences, evidence_refs "
            "FROM behavior_pattern_similarity ORDER BY pattern_id ASC, other_pattern_id ASC"
        ).fetchall()
        repeatability = conn.execute(
            "SELECT pattern_id, repeatability_score FROM behavior_pattern "
            "WHERE behavior_generation = 2 ORDER BY pattern_id ASC"
        ).fetchall()
        snapshots.append(
            json.dumps(
                {
                    "results": [
                        {
                            "query_pattern_id": item.query_pattern_id,
                            "matches": [
                                {
                                    "pattern_id": match.pattern_id,
                                    "similarity": match.similarity,
                                    "repeatability": match.repeatability,
                                    "shared_features": match.shared_features,
                                    "differences": match.differences,
                                    "evidence_refs": match.evidence_refs,
                                }
                                for match in item.matches
                            ],
                        }
                        for item in results
                    ],
                    "rows": [tuple(row) for row in rows],
                    "repeatability": [tuple(row) for row in repeatability],
                },
                sort_keys=True,
            )
        )
    assert snapshots[0] == snapshots[1]


def test_generation_integration_writes_similarity_and_preserves_atomic_swap(tmp_path: Path) -> None:
    conn, loader = _make_conn(tmp_path)
    db_path = Path(conn.execute("PRAGMA database_list").fetchone()[2])
    _insert_observation(conn, event_id="obs-1")
    _insert_reaction(
        conn,
        actor_key="actor-a",
        action_applied="throttle",
        applied_at="2026-07-08T00:00:01Z",
        reaction="continued_scanning",
        evidence_refs=["obs-1"],
        retry_interval_ms=1400,
    )
    apply_generation_plan(conn, loader, query_as_of=NOW, mode="rebuild")
    conn.commit()

    _insert_observation(conn, event_id="obs-2", observed_at="2026-07-08T00:01:00Z")
    _insert_reaction(
        conn,
        actor_key="actor-a",
        action_applied="throttle",
        applied_at="2026-07-08T00:01:01Z",
        reaction="continued_scanning",
        evidence_refs=["obs-2"],
        retry_interval_ms=1400,
    )
    conn.commit()

    observed: dict[str, int] = {}

    def _before_swap(next_generation: int) -> None:
        run_similarity(conn, loader, next_generation)
        ro = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            observed["current_generation"] = int(
                ro.execute(
                    "SELECT value FROM behavior_meta WHERE key = 'current_behavior_generation'"
                ).fetchone()[0]
            )
            observed["next_generation_similarity_rows"] = ro.execute(
                "SELECT COUNT(*) FROM behavior_pattern_similarity WHERE behavior_generation = ?",
                (next_generation,),
            ).fetchone()[0]
            observed["next_generation_repeatability_rows"] = ro.execute(
                "SELECT COUNT(*) FROM behavior_pattern WHERE behavior_generation = ? "
                "AND repeatability_score > 0",
                (next_generation,),
            ).fetchone()[0]
        finally:
            ro.close()

    conn.execute("BEGIN IMMEDIATE")
    apply_generation_plan(
        conn,
        loader,
        query_as_of=NOW,
        mode="incremental",
        before_meta_swap=_before_swap,
    )
    conn.execute("COMMIT")

    current_generation = conn.execute(
        "SELECT value FROM behavior_meta WHERE key = 'current_behavior_generation'"
    ).fetchone()[0]
    query_pattern_id = conn.execute(
        "SELECT pattern_id FROM behavior_pattern WHERE behavior_generation = 2"
    ).fetchone()[0]
    similar = find_similar_by_pattern_id(conn, pattern_id=query_pattern_id, behavior_generation=2)
    actor_window = find_similar_by_actor_or_time_window(
        conn,
        actor_key="actor-a",
        observation_start="2026-07-08T00:00:00Z",
        observation_end="2026-07-08T01:00:00Z",
        behavior_generation=2,
    )

    assert observed == {
        "current_generation": 1,
        "next_generation_similarity_rows": 0,
        "next_generation_repeatability_rows": 0,
    }
    assert current_generation == "2"
    assert len(similar) == 1
    assert similar[0]["repeatability"] > 0
    assert actor_window[0]["pattern_id"] == query_pattern_id
