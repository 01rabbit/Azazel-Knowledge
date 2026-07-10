from __future__ import annotations

import sqlite3

import pytest

from azazel_grimoire.db.behavior import (
    BehaviorPattern,
    BehaviorPatternEvidence,
    behavior_pattern_id,
    canonical_behavior_json,
    require_behavior_evidence,
)
from azazel_grimoire.db.generations import build_next_generation, swap_current
from azazel_grimoire.db.repository import Repository, apply_migrations


def _make_local_db(path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    conn.close()


def _make_intel_db(data_db_dir) -> None:
    intel_path = build_next_generation(data_db_dir)
    conn = sqlite3.connect(intel_path)
    apply_migrations(conn, "intel")
    conn.commit()
    conn.close()
    swap_current(data_db_dir, 1)


def _seed_traceability_rows(conn: sqlite3.Connection) -> tuple[int, int]:
    conn.execute(
        """
        INSERT INTO observation (
            event_id, edge_id, kind, observed_at, entity_key, entities, raw, created_at
        ) VALUES (
            'evt-1', 'edge-1', 'http', '2026-07-06T00:00:00.000Z', NULL,
            '["1.2.3.4"]', '{"path":"/login"}', '2026-07-06T00:00:00.000Z'
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
            'edge-1', 'actor-1', 'throttle', '2026-07-06T00:00:01.000Z', 'shifted_port',
            60, 3, 'ladder-v1', '1', '[1]', 1, 'provisional', NULL, 'none',
            '2026-07-06T00:00:01.000Z'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO pattern (
            pattern_id, version, match_spec, attack_refs, provenance, advisory, confidence, created_at
        ) VALUES (
            'ptn-1', 1, '{"kind":"http"}', '["T1110"]', '{"source":"unit"}',
            'draft only', 0.4, '2026-07-06T00:00:02.000Z'
        )
        """
    )
    conn.commit()
    observation_id = conn.execute("SELECT observation_id FROM observation").fetchone()[0]
    reaction_id = conn.execute("SELECT reaction_id FROM reaction").fetchone()[0]
    return observation_id, reaction_id


def _insert_behavior_pattern(
    conn: sqlite3.Connection,
    *,
    edge_id: str = "edge-1",
    actor_key: str = "actor-1",
    behavior_generation: int = 7,
    evidence: list[BehaviorPatternEvidence] | None = None,
) -> BehaviorPattern:
    pattern = BehaviorPattern(
        pattern_id=behavior_pattern_id(
            edge_id,
            actor_key,
            "2026-07-06T00:00:00.000Z",
            "2026-07-06T00:10:00.000Z",
            "gen-v1",
        ),
        behavior_generation=behavior_generation,
        version=1,
        actor_key=actor_key,
        actor_cluster_key="cluster-1",
        edge_id=edge_id,
        observation_start="2026-07-06T00:00:00.000Z",
        observation_end="2026-07-06T00:10:00.000Z",
        action_applied="throttle",
        reaction_sequence=["shifted_port", "followed_decoy"],
        reaction_window_s=60,
        behavior_class="adaptive_probe",
        confidence=82,
        novelty_score=51,
        repeatability_score=0,
        suspected_stage="reconnaissance",
        related_iocs=["1.2.3.4", "scan.example"],
        related_ttps=["T1110", "T1595"],
        generated_at="2026-07-06T00:10:01.000Z",
        generator_version="gen-v1",
        behavior_config_hash="cfg-1",
        provenance={"builder": "unit", "nested": {"b": 2, "a": 1}},
    )
    evidence_rows = [] if evidence is None else evidence
    require_behavior_evidence(evidence_rows)
    record = pattern.to_record()
    conn.execute(
        """
        INSERT INTO behavior_pattern (
            pattern_id, behavior_generation, version, actor_key, actor_cluster_key,
            edge_id, observation_start, observation_end, action_applied,
            reaction_sequence, reaction_window_s, behavior_class, confidence,
            novelty_score, repeatability_score, suspected_stage, related_iocs,
            related_ttps, generated_at, generator_version, behavior_config_hash, provenance
        ) VALUES (
            :pattern_id, :behavior_generation, :version, :actor_key, :actor_cluster_key,
            :edge_id, :observation_start, :observation_end, :action_applied,
            :reaction_sequence, :reaction_window_s, :behavior_class, :confidence,
            :novelty_score, :repeatability_score, :suspected_stage, :related_iocs,
            :related_ttps, :generated_at, :generator_version, :behavior_config_hash, :provenance
        )
        """,
        record,
    )
    conn.executemany(
        """
        INSERT INTO behavior_pattern_evidence (
            pattern_id, behavior_generation, evidence_type, evidence_id, role
        ) VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                row.pattern_id,
                row.behavior_generation,
                row.evidence_type,
                row.evidence_id,
                row.role,
            )
            for row in evidence_rows
        ],
    )
    conn.execute(
        """
        INSERT INTO behavior_pattern_similarity (
            pattern_id, behavior_generation, other_pattern_id, similarity,
            repeatability, shared_features, differences, evidence_refs
        ) VALUES (
            ?, ?, 'bp-prior', 0.8, 73, '["same-action"]', '["new-decoy"]', '["1","2"]'
        )
        """,
        (pattern.pattern_id, behavior_generation),
    )
    conn.execute(
        "INSERT OR REPLACE INTO behavior_meta (key, value) VALUES ('current_behavior_generation', ?)",
        (str(behavior_generation),),
    )
    conn.commit()
    return pattern


def test_behavior_pattern_requires_evidence_links():
    with pytest.raises(ValueError):
        require_behavior_evidence([])


def test_behavior_pattern_round_trip_and_traceability(tmp_path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    _make_intel_db(data_db_dir)

    conn = sqlite3.connect(local_db_path)
    observation_id, reaction_id = _seed_traceability_rows(conn)
    pattern = _insert_behavior_pattern(
        conn,
        evidence=[
            BehaviorPatternEvidence(
                pattern_id=behavior_pattern_id(
                    "edge-1",
                    "actor-1",
                    "2026-07-06T00:00:00.000Z",
                    "2026-07-06T00:10:00.000Z",
                    "gen-v1",
                ),
                behavior_generation=7,
                evidence_type="reaction",
                evidence_id=str(reaction_id),
                role="source",
            ),
            BehaviorPatternEvidence(
                pattern_id=behavior_pattern_id(
                    "edge-1",
                    "actor-1",
                    "2026-07-06T00:00:00.000Z",
                    "2026-07-06T00:10:00.000Z",
                    "gen-v1",
                ),
                behavior_generation=7,
                evidence_type="observation",
                evidence_id=str(observation_id),
                role="supporting",
            ),
            BehaviorPatternEvidence(
                pattern_id=behavior_pattern_id(
                    "edge-1",
                    "actor-1",
                    "2026-07-06T00:00:00.000Z",
                    "2026-07-06T00:10:00.000Z",
                    "gen-v1",
                ),
                behavior_generation=7,
                evidence_type="pattern",
                evidence_id="ptn-1",
                role="derived_from",
            ),
        ],
    )
    conn.close()

    repo = Repository(local_db_path, data_db_dir)
    try:
        with repo.connection() as read_conn:
            assert repo.get_current_behavior_generation(read_conn) == 7
            patterns = repo.get_behavior_patterns(read_conn, actor_key="actor-1")
            assert len(patterns) == 1
            loaded = patterns[0]
            assert loaded.pattern_id == pattern.pattern_id
            assert loaded.reaction_sequence == ["shifted_port", "followed_decoy"]
            assert loaded.related_iocs == ["1.2.3.4", "scan.example"]
            assert loaded.related_ttps == ["T1110", "T1595"]
            assert loaded.provenance == {"builder": "unit", "nested": {"a": 1, "b": 2}}
            assert loaded.to_record()["reaction_sequence"] == '["shifted_port","followed_decoy"]'
            assert loaded.to_record()["related_iocs"] == '["1.2.3.4","scan.example"]'
            assert loaded.to_record()["related_ttps"] == '["T1110","T1595"]'
            assert loaded.to_record()["provenance"] == '{"builder":"unit","nested":{"a":1,"b":2}}'

            evidence_rows = repo.get_behavior_pattern_evidence(read_conn, loaded.pattern_id, 7)
            assert [(row.evidence_type, row.role) for row in evidence_rows] == [
                ("observation", "supporting"),
                ("pattern", "derived_from"),
                ("reaction", "source"),
            ]
            resolved = [repo.resolve_behavior_evidence(read_conn, row) for row in evidence_rows]
            assert [
                row.payload["observation_id"]
                for row in resolved
                if row is not None and "observation_id" in row.payload
            ] == [
                observation_id
            ]
            assert [
                row.payload["reaction_id"]
                for row in resolved
                if row is not None and "reaction_id" in row.payload
            ] == [
                reaction_id
            ]
            assert [
                row.payload["pattern_id"]
                for row in resolved
                if row is not None and row.evidence.evidence_type == "pattern"
            ] == ["ptn-1"]

            similarities = repo.get_behavior_pattern_similarities(read_conn, loaded.pattern_id, 7)
            assert len(similarities) == 1
            assert similarities[0].shared_features == ["same-action"]
            assert similarities[0].differences == ["new-decoy"]
            assert similarities[0].evidence_refs == ["1", "2"]
    finally:
        repo.close()


def test_behavior_pattern_is_deleteable_and_regenerable(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    _, reaction_id = _seed_traceability_rows(conn)
    pattern = _insert_behavior_pattern(
        conn,
        evidence=[
            BehaviorPatternEvidence(
                pattern_id=behavior_pattern_id(
                    "edge-1",
                    "actor-1",
                    "2026-07-06T00:00:00.000Z",
                    "2026-07-06T00:10:00.000Z",
                    "gen-v1",
                ),
                behavior_generation=7,
                evidence_type="reaction",
                evidence_id=str(reaction_id),
                role="source",
            )
        ],
    )

    trigger_names = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name LIKE 'behavior_%'"
        ).fetchall()
    }
    assert trigger_names == set()

    conn.execute(
        "DELETE FROM behavior_pattern_similarity WHERE pattern_id = ? AND behavior_generation = ?",
        (pattern.pattern_id, 7),
    )
    conn.execute(
        "DELETE FROM behavior_pattern_evidence WHERE pattern_id = ? AND behavior_generation = ?",
        (pattern.pattern_id, 7),
    )
    conn.execute(
        "DELETE FROM behavior_pattern WHERE pattern_id = ? AND behavior_generation = ?",
        (pattern.pattern_id, 7),
    )
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM behavior_pattern").fetchone()[0] == 0

    _insert_behavior_pattern(
        conn,
        evidence=[
            BehaviorPatternEvidence(
                pattern_id=pattern.pattern_id,
                behavior_generation=7,
                evidence_type="reaction",
                evidence_id=str(reaction_id),
                role="source",
            )
        ],
    )
    assert conn.execute("SELECT COUNT(*) FROM behavior_pattern").fetchone()[0] == 1


def test_behavior_pattern_supports_multiple_edges_for_same_actor(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    _, reaction_id = _seed_traceability_rows(conn)
    _insert_behavior_pattern(
        conn,
        edge_id="edge-1",
        evidence=[
            BehaviorPatternEvidence(
                pattern_id=behavior_pattern_id(
                    "edge-1",
                    "actor-1",
                    "2026-07-06T00:00:00.000Z",
                    "2026-07-06T00:10:00.000Z",
                    "gen-v1",
                ),
                behavior_generation=7,
                evidence_type="reaction",
                evidence_id=str(reaction_id),
                role="source",
            )
        ],
    )
    _insert_behavior_pattern(
        conn,
        edge_id="edge-2",
        evidence=[
            BehaviorPatternEvidence(
                pattern_id=behavior_pattern_id(
                    "edge-2",
                    "actor-1",
                    "2026-07-06T00:00:00.000Z",
                    "2026-07-06T00:10:00.000Z",
                    "gen-v1",
                ),
                behavior_generation=7,
                evidence_type="reaction",
                evidence_id=str(reaction_id),
                role="source",
            )
        ],
    )
    conn.close()

    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "repo-local.db"
    _make_local_db(local_db_path)
    with sqlite3.connect(local_db_path) as target, sqlite3.connect(tmp_path / "local.db") as source:
        source.backup(target)
    _make_intel_db(data_db_dir)

    repo = Repository(local_db_path, data_db_dir)
    try:
        with repo.connection() as read_conn:
            patterns = repo.get_behavior_patterns(read_conn, actor_key="actor-1", behavior_generation=7)
            assert [pattern.edge_id for pattern in patterns] == ["edge-1", "edge-2"]
    finally:
        repo.close()


def test_behavior_class_check_rejects_unknown_value(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO behavior_pattern (
                pattern_id, behavior_generation, actor_key, edge_id, observation_start,
                observation_end, action_applied, behavior_class, generated_at,
                generator_version, behavior_config_hash
            ) VALUES (
                'bp-invalid', 1, 'actor-1', 'edge-1', '2026-07-06T00:00:00.000Z',
                '2026-07-06T00:10:00.000Z', 'throttle', 'ai_attacker',
                '2026-07-06T00:10:01.000Z', 'gen-v1', 'cfg-1'
            )
            """
        )


def test_behavior_pattern_id_is_deterministic():
    first = behavior_pattern_id(
        "edge-1",
        "actor-1",
        "2026-07-06T00:00:00.000Z",
        "2026-07-06T00:10:00.000Z",
        "gen-v1",
    )
    second = behavior_pattern_id(
        "edge-1",
        "actor-1",
        "2026-07-06T00:00:00.000Z",
        "2026-07-06T00:10:00.000Z",
        "gen-v1",
    )
    changed = behavior_pattern_id(
        "edge-2",
        "actor-1",
        "2026-07-06T00:00:00.000Z",
        "2026-07-06T00:10:00.000Z",
        "gen-v1",
    )
    assert first == second
    assert first.startswith("bp-")
    assert len(first) == 19
    assert first != changed


def test_canonical_behavior_json_is_stable():
    value = {"nested": {"b": 2, "a": 1}, "items": ["x", "y"]}
    assert canonical_behavior_json(value) == '{"items":["x","y"],"nested":{"a":1,"b":2}}'
