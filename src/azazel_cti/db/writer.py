from __future__ import annotations

import fcntl
import heapq
import itertools
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

P0 = 0
P1 = 1
P2 = 2
P3 = 3

WRITER_PRAGMAS = (
    "PRAGMA journal_mode = WAL",
    "PRAGMA synchronous = NORMAL",
    "PRAGMA busy_timeout = 5000",
)


class WriterLockHeld(Exception):
    pass


@dataclass(order=True)
class _Item:
    priority: int
    seq: int
    fn: Callable[[sqlite3.Connection], None] = field(compare=False)


class PrioritySingleWriterQueue:
    def __init__(
        self,
        db_path: Path,
        lock_path: Path,
        max_batch_s: float = 0.05,
    ) -> None:
        self.db_path = Path(db_path)
        self.lock_path = Path(lock_path)
        self.max_batch_s = max_batch_s
        self._lock_file: object | None = None
        self._heap: list[_Item] = []
        self._heap_lock = threading.Lock()
        self._not_empty = threading.Condition(self._heap_lock)
        self._seq = itertools.count()
        self._exec_lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._stats = {"processed": 0, "batches": 0, "errors": 0}

    def _acquire_flock(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.lock_path, "w")
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            fh.close()
            raise WriterLockHeld(str(self.lock_path)) from exc
        self._lock_file = fh

    def open(self) -> None:
        self._acquire_flock()
        conn = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
        for pragma in WRITER_PRAGMAS:
            conn.execute(pragma)
        self._conn = conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        if self._lock_file is not None:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            self._lock_file.close()
            self._lock_file = None

    def start(self) -> None:
        self.open()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._thread_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._not_empty:
            self._not_empty.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self.close()

    def submit(self, priority: int, fn: Callable[[sqlite3.Connection], None]) -> None:
        with self._not_empty:
            heapq.heappush(self._heap, _Item(priority, next(self._seq), fn))
            self._not_empty.notify()

    def _try_pop(self) -> _Item | None:
        with self._heap_lock:
            if not self._heap:
                return None
            return heapq.heappop(self._heap)

    def _drain_cycle(self) -> int:
        assert self._conn is not None
        with self._exec_lock:
            count = 0
            deadline = time.monotonic() + self.max_batch_s
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                while True:
                    item = self._try_pop()
                    if item is None:
                        break
                    item.fn(self._conn)
                    count += 1
                    if time.monotonic() >= deadline:
                        break
            except Exception:
                self._conn.execute("ROLLBACK")
                self._stats["errors"] += 1
                raise
            else:
                self._conn.execute("COMMIT")
                if count:
                    self._stats["processed"] += count
                    self._stats["batches"] += 1
            return count

    def process_pending(self) -> int:
        total = 0
        while True:
            n = self._drain_cycle()
            total += n
            if n == 0:
                break
        return total

    def _thread_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._not_empty:
                if not self._heap:
                    self._not_empty.wait(timeout=0.1)
                    if not self._heap:
                        continue
            self.process_pending()

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
