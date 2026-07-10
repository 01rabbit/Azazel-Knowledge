from __future__ import annotations

import os
import sqlite3

from azazel_grimoire.db import generations
from azazel_grimoire.db.repository import apply_migrations


def test_current_generation_is_none_when_absent(tmp_path):
    data_db_dir = tmp_path / "db"
    assert generations.current_generation(data_db_dir) is None


def test_build_next_generation_increments(tmp_path):
    data_db_dir = tmp_path / "db"
    first = generations.build_next_generation(data_db_dir)
    assert first == generations.intel_db_path(data_db_dir, 1)
    assert first.parent.is_dir()

    conn = sqlite3.connect(first)
    apply_migrations(conn, "intel")
    conn.close()
    generations.swap_current(data_db_dir, 1)

    second = generations.build_next_generation(data_db_dir)
    assert second == generations.intel_db_path(data_db_dir, 2)


def test_swap_current_repoints_atomically(tmp_path):
    data_db_dir = tmp_path / "db"
    path1 = generations.build_next_generation(data_db_dir)
    sqlite3.connect(path1).close()
    generations.swap_current(data_db_dir, 1)
    assert generations.current_generation(data_db_dir) == 1
    assert os.readlink(data_db_dir / "current") == "gen-1"

    path2 = generations.build_next_generation(data_db_dir)
    sqlite3.connect(path2).close()
    generations.swap_current(data_db_dir, 2)
    assert generations.current_generation(data_db_dir) == 2
    assert os.readlink(data_db_dir / "current") == "gen-2"


def test_gc_old_generations_keeps_most_recent(tmp_path):
    data_db_dir = tmp_path / "db"
    for n in range(1, 5):
        path = generations.build_next_generation(data_db_dir)
        sqlite3.connect(path).close()
        generations.swap_current(data_db_dir, n)

    removed = generations.gc_old_generations(data_db_dir, keep=2)
    assert sorted(removed) == [1, 2]
    remaining_dirs = sorted(
        p.name for p in data_db_dir.iterdir() if p.name.startswith("gen-")
    )
    assert remaining_dirs == ["gen-3", "gen-4"]
    assert generations.current_generation(data_db_dir) == 4


def test_intel_generation_read_and_bump_roundtrip(tmp_path):
    conn = sqlite3.connect(tmp_path / "intel.db")
    apply_migrations(conn, "intel")
    assert generations.read_intel_generation(conn) == 0
    generations.bump_intel_generation(conn, 5)
    conn.commit()
    assert generations.read_intel_generation(conn) == 5
    generations.bump_intel_generation(conn, 6)
    conn.commit()
    assert generations.read_intel_generation(conn) == 6
