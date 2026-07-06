from __future__ import annotations

import sqlite3
import time

import pytest

from azazel_cti.db.repository import apply_migrations
from azazel_cti.db.writer import P0, P1, P2, P3, PrioritySingleWriterQueue, WriterLockHeld


def _make_local_db(path) -> None:
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    conn.close()


def test_writer_executes_higher_priority_before_lower_when_both_pending(tmp_path):
    db_path = tmp_path / "local.db"
    _make_local_db(db_path)
    lock_path = tmp_path / "writer.lock"

    writer = PrioritySingleWriterQueue(db_path, lock_path)
    writer.open()
    try:
        order: list[str] = []
        writer.submit(P2, lambda conn: order.append("p2"))
        writer.submit(P0, lambda conn: order.append("p0"))
        writer.submit(P3, lambda conn: order.append("p3"))
        writer.submit(P1, lambda conn: order.append("p1"))

        processed = writer.process_pending()
        assert processed == 4
        assert order == ["p0", "p1", "p2", "p3"]
        assert writer.stats["processed"] == 4
    finally:
        writer.close()


def test_writer_batch_executes_in_single_transaction(tmp_path):
    db_path = tmp_path / "local.db"
    _make_local_db(db_path)
    lock_path = tmp_path / "writer.lock"

    writer = PrioritySingleWriterQueue(db_path, lock_path)
    writer.open()
    try:
        def insert(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO local_meta (key, value) VALUES ('k', 'v')"
            )

        def fail(conn: sqlite3.Connection) -> None:
            raise RuntimeError("boom")

        writer.submit(P0, insert)
        writer.submit(P0, fail)
        with pytest.raises(RuntimeError):
            writer.process_pending()

        rows = writer._conn.execute("SELECT COUNT(*) FROM local_meta").fetchone()[0]
        assert rows == 0
    finally:
        writer.close()


def test_second_writer_instance_fails_on_flock(tmp_path):
    db_path = tmp_path / "local.db"
    _make_local_db(db_path)
    lock_path = tmp_path / "writer.lock"

    first = PrioritySingleWriterQueue(db_path, lock_path)
    first.open()
    try:
        second = PrioritySingleWriterQueue(db_path, lock_path)
        with pytest.raises(WriterLockHeld):
            second.open()
    finally:
        first.close()

    third = PrioritySingleWriterQueue(db_path, lock_path)
    third.open()
    third.close()


def test_writer_thread_processes_submitted_work(tmp_path):
    db_path = tmp_path / "local.db"
    _make_local_db(db_path)
    lock_path = tmp_path / "writer.lock"

    writer = PrioritySingleWriterQueue(db_path, lock_path)
    writer.start()
    try:
        done = []
        writer.submit(P0, lambda conn: done.append(1))

        deadline = time.monotonic() + 2.0
        while not done and time.monotonic() < deadline:
            time.sleep(0.01)
        assert done == [1]
    finally:
        writer.stop()
