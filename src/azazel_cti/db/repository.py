from __future__ import annotations

import contextlib
import hashlib
import os
import queue
import sqlite3
import threading
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from azazel_cti.db.behavior import (
    BehaviorPattern,
    BehaviorPatternEvidence,
    BehaviorPatternSimilarity,
    ResolvedBehaviorEvidence,
)

MIGRATIONS_ROOT = Path(__file__).resolve().parent / "migrations"


def utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def entity_key(type_: str, value: str) -> bytes:
    normalized_type = type_.strip().lower()
    normalized_value = value.strip().lower()
    digest = hashlib.sha256(
        normalized_type.encode("utf-8") + b"\x00" + normalized_value.encode("utf-8")
    ).digest()
    return digest[:16]


def _migration_files(which: str) -> list[Path]:
    directory = MIGRATIONS_ROOT / which
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("[0-9][0-9][0-9][0-9]_*.sql"))


def apply_migrations(conn: sqlite3.Connection, which: str) -> list[str]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version TEXT PRIMARY KEY, applied_at TEXT NOT NULL) STRICT"
    )
    applied = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
    newly_applied: list[str] = []
    for path in _migration_files(which):
        version = path.stem
        if version in applied:
            continue
        conn.executescript(path.read_text())
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
            (version, utc_now_rfc3339()),
        )
        newly_applied.append(version)
    conn.commit()
    return newly_applied


class _ReaderConnection(sqlite3.Connection):
    generation: str


class ConnectionPool:
    def __init__(self, size: int, factory: Callable[[], sqlite3.Connection]) -> None:
        self._factory = factory
        self._size = size
        self._queue: queue.Queue[sqlite3.Connection] = queue.Queue()
        self._lock = threading.Lock()
        self._created = 0

    def acquire(self) -> sqlite3.Connection:
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            if self._created < self._size:
                self._created += 1
                return self._factory()
        return self._queue.get()

    def release(self, conn: sqlite3.Connection) -> None:
        self._queue.put(conn)

    def discard(self, conn: sqlite3.Connection) -> None:
        conn.close()
        with self._lock:
            self._created -= 1

    def closeall(self) -> None:
        while True:
            try:
                conn = self._queue.get_nowait()
            except queue.Empty:
                break
            conn.close()
            with self._lock:
                self._created -= 1


class Repository:
    def __init__(self, local_db_path: Path, data_db_dir: Path, pool_size: int = 4) -> None:
        self.local_db_path = Path(local_db_path)
        self.data_db_dir = Path(data_db_dir)
        self._pool = ConnectionPool(pool_size, self._open_connection)

    def _resolve_current(self) -> tuple[Path, str]:
        link = self.data_db_dir / "current"
        target = os.readlink(link)
        intel_path = (self.data_db_dir / target / "intel.db").resolve()
        return intel_path, target

    def _open_connection(self) -> sqlite3.Connection:
        intel_path, generation = self._resolve_current()
        conn = sqlite3.connect(
            self.local_db_path,
            isolation_level=None,
            check_same_thread=False,
            factory=_ReaderConnection,
        )
        conn.execute("PRAGMA query_only = ON")
        conn.execute("ATTACH DATABASE ? AS intel", (str(intel_path),))
        conn.generation = generation
        return conn

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._pool.acquire()
        _, current = self._resolve_current()
        if conn.generation != current:
            self._pool.discard(conn)
            conn = self._pool.acquire()
        try:
            yield conn
        finally:
            self._pool.release(conn)

    def close(self) -> None:
        self._pool.closeall()

    def get_ioc(self, conn: sqlite3.Connection, type_: str, value: str) -> sqlite3.Row | None:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT ioc_id, type, value, first_seen, last_seen, tags, "
            "agg_raw_confidence, agg_next_expiry, agg_computed_at "
            "FROM intel.ioc WHERE type = ? AND value = ?",
            (type_, value),
        ).fetchone()

    def find_cidr_containing(
        self, conn: sqlite3.Connection, tier: str, packed_ip: int
    ) -> sqlite3.Row | None:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT tier, range_start, range_end, ioc_id, feed_id, expires_at "
            "FROM intel.ioc_cidr "
            "WHERE tier = ? AND range_start <= ? AND range_end >= ? "
            "LIMIT 1",
            (tier, packed_ip, packed_ip),
        ).fetchone()

    def get_kev(self, conn: sqlite3.Connection, cve_ids: Iterable[str]) -> list[sqlite3.Row]:
        ids = list(cve_ids)
        if not ids:
            return []
        conn.row_factory = sqlite3.Row
        placeholders = ",".join("?" for _ in ids)
        return conn.execute(
            f"SELECT cve_id, catalog_version, date_added FROM intel.kev "
            f"WHERE cve_id IN ({placeholders})",
            ids,
        ).fetchall()

    def get_reputation(self, conn: sqlite3.Connection, key: bytes) -> sqlite3.Row | None:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT entity_key, score, contributing_sources, updated_at "
            "FROM reputation WHERE entity_key = ?",
            (key,),
        ).fetchone()

    def get_observation_stats(self, conn: sqlite3.Connection, key: bytes) -> list[sqlite3.Row]:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT entity_key, window_start, window_end, event_count, trend, "
            "stats_generation, updated_at FROM observation_stats "
            "WHERE entity_key = ? ORDER BY window_start DESC",
            (key,),
        ).fetchall()

    def get_current_behavior_generation(self, conn: sqlite3.Connection) -> int | None:
        row = conn.execute(
            "SELECT value FROM behavior_meta WHERE key = 'current_behavior_generation'"
        ).fetchone()
        if row is None:
            return None
        return int(row[0])

    def get_behavior_patterns(
        self,
        conn: sqlite3.Connection,
        *,
        actor_key: str,
        behavior_generation: int | None = None,
    ) -> list[BehaviorPattern]:
        conn.row_factory = sqlite3.Row
        generation = behavior_generation
        if generation is None:
            generation = self.get_current_behavior_generation(conn)
        if generation is None:
            return []
        rows = conn.execute(
            "SELECT pattern_id, behavior_generation, version, actor_key, actor_cluster_key, "
            "edge_id, observation_start, observation_end, action_applied, reaction_sequence, "
            "reaction_window_s, behavior_class, confidence, novelty_score, "
            "repeatability_score, suspected_stage, related_iocs, related_ttps, "
            "generated_at, generator_version, behavior_config_hash, provenance "
            "FROM behavior_pattern WHERE actor_key = ? AND behavior_generation = ? "
            "ORDER BY observation_start ASC, pattern_id ASC",
            (actor_key, generation),
        ).fetchall()
        return [BehaviorPattern.from_row(row) for row in rows]

    def get_behavior_pattern_evidence(
        self, conn: sqlite3.Connection, pattern_id: str, behavior_generation: int
    ) -> list[BehaviorPatternEvidence]:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT pattern_id, behavior_generation, evidence_type, evidence_id, role "
            "FROM behavior_pattern_evidence WHERE pattern_id = ? AND behavior_generation = ? "
            "ORDER BY evidence_type ASC, evidence_id ASC, role ASC",
            (pattern_id, behavior_generation),
        ).fetchall()
        return [BehaviorPatternEvidence.from_row(row) for row in rows]

    def get_behavior_pattern_similarities(
        self, conn: sqlite3.Connection, pattern_id: str, behavior_generation: int
    ) -> list[BehaviorPatternSimilarity]:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT pattern_id, behavior_generation, other_pattern_id, similarity, "
            "repeatability, shared_features, differences, evidence_refs "
            "FROM behavior_pattern_similarity "
            "WHERE pattern_id = ? AND behavior_generation = ? "
            "ORDER BY similarity DESC, other_pattern_id ASC",
            (pattern_id, behavior_generation),
        ).fetchall()
        return [BehaviorPatternSimilarity.from_row(row) for row in rows]

    def resolve_behavior_evidence(
        self, conn: sqlite3.Connection, evidence: BehaviorPatternEvidence
    ) -> ResolvedBehaviorEvidence | None:
        conn.row_factory = sqlite3.Row
        if evidence.evidence_type == "observation":
            row = conn.execute(
                "SELECT observation_id, event_id, edge_id, kind, observed_at, "
                "entities, raw, created_at FROM observation WHERE observation_id = ?",
                (int(evidence.evidence_id),),
            ).fetchone()
        elif evidence.evidence_type == "reaction":
            row = conn.execute(
                "SELECT reaction_id, edge_id, actor_key, action_applied, applied_at, "
                "reaction, reaction_window_s, evidence_refs, created_at "
                "FROM reaction WHERE reaction_id = ?",
                (int(evidence.evidence_id),),
            ).fetchone()
        elif evidence.evidence_type == "pattern":
            row = conn.execute(
                "SELECT pattern_id, version, match_spec, attack_refs, provenance, "
                "advisory, confidence, created_at FROM pattern WHERE pattern_id = ?",
                (evidence.evidence_id,),
            ).fetchone()
        else:
            raise ValueError(f"unsupported evidence_type: {evidence.evidence_type}")
        if row is None:
            return None
        return ResolvedBehaviorEvidence(evidence=evidence, payload=dict(row))
