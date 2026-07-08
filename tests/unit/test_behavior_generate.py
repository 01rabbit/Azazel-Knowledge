from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from azazel_cti.core.config import TrackedConfigLoader
from azazel_cti.db.repository import apply_migrations
from azazel_cti.patterns.behavior_generate import (
    GENERATOR_VERSION,
    apply_generation_plan,
    plan_generation,
)
from azazel_cti.worker import WorkerPaths, current_intel_db_path, ensure_local_db, run_p2
from azazel_cti.db.writer import PrioritySingleWriterQueue
from azazel_cti.core.clock import FixedClock

NOW = datetime(2026, 7, 8, 0, 0, 0, tzinfo=timezone.utc)
REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"


def _copy_config(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    dest = tmp_path / "config"
    shutil.copytree(REPO_CONFIG, dest)
    return dest


def _make_conn(tmp_path: Path) -> tuple[sqlite3.Connection, TrackedConfigLoader]:
    config_dir = _copy_config(tmp_path)
    loader = TrackedConfigLoader(config_dir)
    db_path = tmp_path / "local.db"
    conn = sqlite3.connect(db_path)
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
    actor_key: str = "actor-1",
    edge_id: str = "edge-1",
    action_applied: str = "throttle",
    applied_at: str = "2026-07-08T00:00:01Z",
    reaction: str = "continued_scanning",
    reaction_window_s: int = 60,
    evidence_refs: list[str] | None = None,
    evidence_modality_count: int = 2,
) -> int:
    cursor = conn.execute(
        "INSERT INTO reaction (edge_id, actor_key, action_applied, applied_at, reaction, reaction_window_s, "
        "events_in_window, classifier, classifier_version, evidence_refs, evidence_modality_count, trust_tier, "
        "advisory_id, advisory_linkage, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, 'ladder', '1', ?, ?, 'provisional', NULL, 'none', ?)",
        (
            edge_id,
            actor_key,
            action_applied,
            applied_at,
            reaction,
            reaction_window_s,
            json.dumps(evidence_refs or []),
            evidence_modality_count,
            applied_at,
        ),
    )
    return int(cursor.lastrowid)


def _pattern_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute(
        "SELECT pattern_id, behavior_generation, actor_key, edge_id, observation_start, observation_end, "
        "action_applied, reaction_sequence, behavior_class, generated_at, generator_version, "
        "behavior_config_hash, provenance "
        "FROM behavior_pattern ORDER BY behavior_generation ASC, pattern_id ASC"
    ).fetchall()


def test_single_reaction_generates_one_pattern(tmp_path):
    conn, loader = _make_conn(tmp_path)
    _insert_observation(conn, event_id="obs-1")
    _insert_reaction(conn, evidence_refs=["obs-1"])

    plan = apply_generation_plan(conn, loader, query_as_of=NOW, mode="rebuild")
    conn.commit()

    assert plan.behavior_generation == 1
    assert len(plan.patterns) == 1
    row = conn.execute(
        "SELECT reaction_sequence, behavior_class FROM behavior_pattern"
    ).fetchone()
    assert row == ('["continued_scanning"]', "simple_scanner")


def test_multiple_reactions_preserve_ordered_sequence(tmp_path):
    conn, loader = _make_conn(tmp_path)
    _insert_observation(conn, event_id="obs-1")
    _insert_observation(conn, event_id="obs-2")
    _insert_reaction(
        conn,
        action_applied="delay",
        applied_at="2026-07-08T00:00:01Z",
        reaction="unknown",
        evidence_refs=["obs-1"],
    )
    _insert_reaction(
        conn,
        action_applied="throttle",
        applied_at="2026-07-08T00:00:02Z",
        reaction="shifted_port",
        evidence_refs=["obs-2"],
    )

    apply_generation_plan(conn, loader, query_as_of=NOW, mode="rebuild")
    conn.commit()

    sequence = conn.execute("SELECT reaction_sequence, action_applied FROM behavior_pattern").fetchone()
    assert sequence == ('["unknown","shifted_port"]', "delay")


def test_generation_persists_evidence_links(tmp_path):
    conn, loader = _make_conn(tmp_path)
    observation_id = _insert_observation(conn, event_id="obs-1")
    reaction_id = _insert_reaction(conn, evidence_refs=["obs-1"], reaction="followed_decoy")

    apply_generation_plan(conn, loader, query_as_of=NOW, mode="rebuild")
    conn.commit()

    pattern_id = conn.execute("SELECT pattern_id FROM behavior_pattern").fetchone()[0]
    links = conn.execute(
        "SELECT evidence_type, evidence_id, role FROM behavior_pattern_evidence "
        "WHERE pattern_id = ? ORDER BY evidence_type ASC, evidence_id ASC, role ASC",
        (pattern_id,),
    ).fetchall()
    assert links == [
        ("observation", str(observation_id), "supporting"),
        ("reaction", str(reaction_id), "source"),
    ]


def test_missing_evidence_skips_pattern_generation(tmp_path):
    conn, loader = _make_conn(tmp_path)
    _insert_reaction(conn, evidence_refs=["missing-obs"], evidence_modality_count=2)

    plan = apply_generation_plan(conn, loader, query_as_of=NOW, mode="rebuild")
    conn.commit()

    assert len(plan.patterns) == 0
    assert conn.execute("SELECT COUNT(*) FROM behavior_pattern").fetchone()[0] == 0


def test_incremental_generation_is_idempotent(tmp_path):
    conn, loader = _make_conn(tmp_path)
    _insert_observation(conn, event_id="obs-1")
    _insert_reaction(conn, evidence_refs=["obs-1"])

    first = apply_generation_plan(conn, loader, query_as_of=NOW, mode="incremental")
    conn.commit()
    assert first.behavior_generation == 1
    assert conn.execute("SELECT COUNT(*) FROM behavior_pattern").fetchone()[0] == 1

    second = apply_generation_plan(conn, loader, query_as_of=NOW, mode="incremental")
    conn.commit()
    assert second.behavior_generation == 1
    assert len(second.patterns) == 0
    assert conn.execute("SELECT COUNT(*) FROM behavior_pattern").fetchone()[0] == 1
    assert conn.execute(
        "SELECT value FROM behavior_meta WHERE key = 'current_behavior_generation'"
    ).fetchone()[0] == "1"


def test_classification_mapping_is_deterministic(tmp_path):
    cases = [
        (
            "scripted_automation",
            [
                ("delay", "unknown", "obs-a", 2, "2026-07-08T00:00:01Z"),
                ("throttle", "continued_scanning", "obs-b", 2, "2026-07-08T00:00:02Z"),
            ],
        ),
        (
            "adaptive_probe",
            [
                ("throttle", "unknown", "obs-a", 2, "2026-07-08T00:00:01Z"),
                ("throttle", "shifted_port", "obs-b", 2, "2026-07-08T00:00:02Z"),
            ],
        ),
        (
            "adaptive_probe",
            [
                ("throttle", "unknown", "obs-a", 2, "2026-07-08T00:00:01Z"),
                ("throttle", "shifted_protocol", "obs-b", 2, "2026-07-08T00:00:02Z"),
            ],
        ),
        (
            "adaptive_probe",
            [
                ("deception", "unknown", "obs-a", 2, "2026-07-08T00:00:01Z"),
                ("delay", "shifted_target", "obs-b", 2, "2026-07-08T00:00:02Z"),
            ],
        ),
        (
            "decoy_engaged",
            [("deception", "followed_decoy", "obs-a", 2, "2026-07-08T00:00:01Z")],
        ),
        (
            "adaptive_probe",
            [("throttle", "auth_pattern_changed", "obs-a", 2, "2026-07-08T00:00:01Z")],
        ),
        (
            "disengaged_after_friction",
            [
                ("delay", "unknown", "obs-a", 2, "2026-07-08T00:00:01Z"),
                ("delay", "disengaged", "obs-b", 2, "2026-07-08T00:00:02Z"),
            ],
        ),
        (
            "unknown",
            [("throttle", "unknown", "obs-a", 0, "2026-07-08T00:00:01Z")],
        ),
        (
            "simple_scanner",
            [
                ("redirect", "continued_scanning", "obs-a", 2, "2026-07-08T00:00:01Z"),
                ("redirect", "continued_scanning", "obs-b", 2, "2026-07-08T00:00:02Z"),
            ],
        ),
    ]

    for expected, rows in cases:
        case_dir = tmp_path / expected / str(abs(hash(tuple(rows))))
        conn, loader = _make_conn(case_dir)
        for action_applied, reaction, event_id, modalities, applied_at in rows:
            _insert_observation(conn, event_id=event_id, observed_at=applied_at)
            _insert_reaction(
                conn,
                action_applied=action_applied,
                reaction=reaction,
                applied_at=applied_at,
                evidence_refs=[event_id],
                evidence_modality_count=modalities,
            )
        apply_generation_plan(conn, loader, query_as_of=NOW, mode="rebuild")
        conn.commit()
        actual = conn.execute("SELECT behavior_class FROM behavior_pattern").fetchone()[0]
        assert actual == expected


def test_generated_rows_include_metadata_and_no_attribution_label(tmp_path):
    conn, loader = _make_conn(tmp_path)
    _insert_observation(conn, event_id="obs-1")
    _insert_reaction(conn, evidence_refs=["obs-1"], reaction="followed_decoy")

    apply_generation_plan(conn, loader, query_as_of=NOW, mode="rebuild")
    conn.commit()

    row = conn.execute(
        "SELECT generated_at, generator_version, provenance, behavior_config_hash, behavior_class "
        "FROM behavior_pattern"
    ).fetchone()
    assert row[0] == "2026-07-08T00:00:00Z"
    assert row[1] == GENERATOR_VERSION
    assert json.loads(row[2])["source_reaction_ids"] == [1]
    assert len(row[3]) == 64
    assert row[4] in {
        "simple_scanner",
        "scripted_automation",
        "adaptive_probe",
        "decoy_engaged",
        "disengaged_after_friction",
        "unknown",
    }
    assert row[4] != "ai_attacker"


def test_three_run_replay_is_byte_identical_for_same_source_and_hash(tmp_path):
    snapshots: list[list[tuple[str, str, str, str, str]]] = []
    for run in range(3):
        conn, loader = _make_conn(tmp_path / f"run-{run}")
        _insert_observation(conn, event_id="obs-1")
        _insert_observation(conn, event_id="obs-2")
        _insert_reaction(
            conn,
            action_applied="delay",
            applied_at="2026-07-08T00:00:01Z",
            reaction="unknown",
            evidence_refs=["obs-1"],
        )
        _insert_reaction(
            conn,
            action_applied="throttle",
            applied_at="2026-07-08T00:00:02Z",
            reaction="shifted_protocol",
            evidence_refs=["obs-2"],
        )
        apply_generation_plan(conn, loader, query_as_of=NOW, mode="rebuild")
        conn.commit()
        snapshots.append(
            [
                (
                    row["pattern_id"],
                    row["behavior_class"],
                    row["reaction_sequence"],
                    row["generator_version"],
                    row["behavior_config_hash"],
                )
                for row in _pattern_rows(conn)
            ]
        )
    assert snapshots[0] == snapshots[1] == snapshots[2]


def test_behavior_generation_swap_is_atomic(tmp_path):
    conn, loader = _make_conn(tmp_path)
    db_path = Path(conn.execute("PRAGMA database_list").fetchone()[2])
    _insert_observation(conn, event_id="obs-1")
    first_reaction = _insert_reaction(conn, evidence_refs=["obs-1"], reaction="continued_scanning")
    first = apply_generation_plan(conn, loader, query_as_of=NOW, mode="rebuild")
    conn.commit()
    assert first.behavior_generation == 1

    _insert_observation(conn, event_id="obs-2", observed_at="2026-07-08T00:00:03Z")
    _insert_reaction(
        conn,
        action_applied="throttle",
        applied_at="2026-07-08T00:00:03Z",
        reaction="shifted_port",
        evidence_refs=["obs-2"],
    )
    conn.commit()

    observed: dict[str, int | str] = {}

    def _before_swap(next_generation: int) -> None:
        ro = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            observed["current_generation"] = int(
                ro.execute(
                    "SELECT value FROM behavior_meta WHERE key = 'current_behavior_generation'"
                ).fetchone()[0]
            )
            observed["rows_at_next_generation"] = ro.execute(
                "SELECT COUNT(*) FROM behavior_pattern WHERE behavior_generation = ?",
                (next_generation,),
            ).fetchone()[0]
            observed["source_reaction"] = ro.execute(
                "SELECT evidence_id FROM behavior_pattern_evidence "
                "WHERE behavior_generation = 1 AND evidence_type = 'reaction' AND role = 'source' "
                "ORDER BY evidence_id ASC"
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

    assert observed == {
        "current_generation": 1,
        "rows_at_next_generation": 0,
        "source_reaction": str(first_reaction),
    }
    assert conn.execute(
        "SELECT value FROM behavior_meta WHERE key = 'current_behavior_generation'"
    ).fetchone()[0] == "2"


def test_behavior_config_hash_does_not_change_frozen_config_hash(tmp_path):
    config_dir = _copy_config(tmp_path)
    with_behavior = TrackedConfigLoader(config_dir).config_hash
    (config_dir / "behavior-classify.yaml").unlink()
    without_behavior = TrackedConfigLoader(config_dir).config_hash
    assert with_behavior == without_behavior


def test_worker_p2_writes_behavior_generation(tmp_path):
    root = tmp_path / "node"
    config_dir = _copy_config(tmp_path / "cfg")
    paths = WorkerPaths.from_root(root, config_dir=config_dir)
    paths.ensure_dirs()
    ensure_local_db(paths.local_db_path)
    _ = current_intel_db_path(paths.data_db_dir)

    conn = sqlite3.connect(paths.local_db_path)
    _insert_observation(conn, event_id="obs-1")
    _insert_reaction(conn, evidence_refs=["obs-1"])
    conn.commit()
    conn.close()

    local_writer = PrioritySingleWriterQueue(paths.local_db_path, paths.local_lock_path)
    intel_writer = PrioritySingleWriterQueue(current_intel_db_path(paths.data_db_dir), paths.intel_lock_path)
    local_writer.open()
    intel_writer.open()
    try:
        stats = run_p2(
            intel_writer,
            local_writer,
            TrackedConfigLoader(config_dir),
            clock=FixedClock(NOW),
            online=False,
        )
        assert stats["behavior_generation"] == 1
        assert stats["behavior_patterns_written"] == 1
    finally:
        local_writer.close()
        intel_writer.close()
