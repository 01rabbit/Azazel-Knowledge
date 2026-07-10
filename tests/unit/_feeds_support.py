"""Shared SQLite scaffolding for feed-adapter tests (not collected by pytest)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from azazel_grimoire.db.repository import apply_migrations
from azazel_grimoire.db.writer import PrioritySingleWriterQueue


def make_writer(tmp_path: Path, which: str, name: str) -> PrioritySingleWriterQueue:
    db_path = tmp_path / name
    conn = sqlite3.connect(db_path)
    apply_migrations(conn, which)
    conn.close()
    writer = PrioritySingleWriterQueue(db_path, tmp_path / f"{name}.lock")
    writer.open()
    return writer


def make_intel_writer(tmp_path: Path, name: str = "intel.db") -> PrioritySingleWriterQueue:
    return make_writer(tmp_path, "intel", name)


def make_local_writer(tmp_path: Path, name: str = "local.db") -> PrioritySingleWriterQueue:
    return make_writer(tmp_path, "local", name)
