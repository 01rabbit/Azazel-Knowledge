"""`edge_reported_ioc` promotion rules (design S6, S16 promotion.*).

Promotion to a scored `ioc`/`ioc_source` row (`feed_id: edge_reported`)
happens only via one of three gates: (a) cross-group external
corroboration on the same `(type, value)`; (b) at least
`promotion.min_distinct_edges` (default 3) distinct `edge_id`s within
`window_days` (default 7) of `query_as_of`; or (c) an analyst `confirm`
call (invoked by the API layer, not evaluated here). Every promotion
logs its reason to `local_meta` (there is no dedicated log table) and
is revocable: `quarantined -> promoted -> revoked`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Mapping

from azazel_knowledge.core.clock import to_rfc3339
from azazel_knowledge.db.generations import read_intel_generation
from azazel_knowledge.db.repository import entity_key
from azazel_knowledge.db.writer import P2

DEFAULT_MIN_DISTINCT_EDGES = 3
DEFAULT_WINDOW_DAYS = 7


class PromotionReason(Enum):
    CROSS_GROUP_CORROBORATION = "cross_group_corroboration"
    DISTINCT_EDGES = "distinct_edges"
    ANALYST_CONFIRM = "analyst_confirm"


@dataclass(frozen=True)
class PromotionResult:
    promoted: bool
    reason: PromotionReason | None = None
    detail: str | None = None


class PromotionEngine:
    def __init__(
        self,
        intel_writer: Any,
        local_writer: Any,
        feed_groups: Mapping[str, str] | None = None,
        min_distinct_edges: int = DEFAULT_MIN_DISTINCT_EDGES,
        window_days: int = DEFAULT_WINDOW_DAYS,
        edge_reported_feed_id: str = "edge_reported",
        edge_reported_confidence: int = 35,
        edge_reported_ttl_days: int = 3,
    ) -> None:
        self.intel_writer = intel_writer
        self.local_writer = local_writer
        self.feed_groups = dict(feed_groups or {})
        self.min_distinct_edges = min_distinct_edges
        self.window_days = window_days
        self.edge_reported_feed_id = edge_reported_feed_id
        self.edge_reported_confidence = edge_reported_confidence
        self.edge_reported_ttl_days = edge_reported_ttl_days

    def _exec(self, writer: Any, fn: Any, priority: int = P2) -> Any:
        box: dict[str, Any] = {}

        def wrapper(conn: Any) -> None:
            box["value"] = fn(conn)

        writer.submit(priority, wrapper)
        writer.process_pending()
        return box.get("value")

    def _exec_intel(self, fn: Any) -> Any:
        return self._exec(self.intel_writer, fn)

    def _exec_local(self, fn: Any) -> Any:
        return self._exec(self.local_writer, fn)

    def _group_of(self, feed_id: str) -> str:
        return self.feed_groups.get(feed_id, feed_id)

    def evaluate(self, type_: str, value: str, query_as_of: datetime) -> PromotionResult:
        key = entity_key(type_, value)
        window_start = to_rfc3339(query_as_of - timedelta(days=self.window_days))

        def read_edges(conn: Any) -> list[str]:
            rows = conn.execute(
                "SELECT DISTINCT edge_id FROM edge_reported_ioc WHERE entity_key = ? "
                "AND status = 'quarantined' AND first_reported >= ?",
                (key, window_start),
            ).fetchall()
            return [row[0] for row in rows]

        edges = self._exec_local(read_edges)
        if len(edges) >= self.min_distinct_edges:
            return PromotionResult(
                True, PromotionReason.DISTINCT_EDGES, f"{len(edges)} distinct edges within {self.window_days}d"
            )

        def read_source_feeds(conn: Any) -> list[str]:
            ioc_row = conn.execute("SELECT ioc_id FROM ioc WHERE type = ? AND value = ?", (type_, value)).fetchone()
            if not ioc_row:
                return []
            rows = conn.execute("SELECT feed_id FROM ioc_source WHERE ioc_id = ?", (ioc_row[0],)).fetchall()
            return [row[0] for row in rows]

        feed_ids = self._exec_intel(read_source_feeds)
        groups = {self._group_of(fid) for fid in feed_ids}
        groups.discard(self._group_of(self.edge_reported_feed_id))
        if groups:
            return PromotionResult(
                True, PromotionReason.CROSS_GROUP_CORROBORATION, f"corroborating groups={sorted(groups)}"
            )

        return PromotionResult(False)

    def confirm(self, type_: str, value: str, edge_id: str, actor: str, query_as_of: datetime) -> PromotionResult:
        result = PromotionResult(True, PromotionReason.ANALYST_CONFIRM, f"confirmed_by={actor} edge_id={edge_id}")
        self.promote(type_, value, query_as_of, result)
        return result

    def promote(self, type_: str, value: str, query_as_of: datetime, result: PromotionResult) -> None:
        if not result.promoted or result.reason is None:
            raise ValueError("cannot promote: gate not satisfied")
        key = entity_key(type_, value)
        now_s = to_rfc3339(query_as_of)
        expires_at = to_rfc3339(query_as_of + timedelta(days=self.edge_reported_ttl_days))

        def intel_txn(conn: Any) -> None:
            conn.execute(
                "INSERT INTO ioc (type, value, first_seen, last_seen, tags) VALUES (?, ?, ?, ?, '[]') "
                "ON CONFLICT(type, value) DO UPDATE SET last_seen = excluded.last_seen",
                (type_, value, now_s, now_s),
            )
            ioc_id = conn.execute(
                "SELECT ioc_id FROM ioc WHERE type = ? AND value = ?", (type_, value)
            ).fetchone()[0]
            generation = read_intel_generation(conn)
            conn.execute(
                "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
                "expires_at, intel_generation, flagged_critical_infra) VALUES (?, ?, ?, ?, ?, ?, ?, 0) "
                "ON CONFLICT(ioc_id, feed_id) DO UPDATE SET "
                "source_confidence = excluded.source_confidence, last_seen = excluded.last_seen, "
                "expires_at = excluded.expires_at, intel_generation = excluded.intel_generation",
                (ioc_id, self.edge_reported_feed_id, self.edge_reported_confidence, now_s, now_s, expires_at, generation),
            )

        self._exec_intel(intel_txn)

        def local_txn(conn: Any) -> None:
            conn.execute(
                "UPDATE edge_reported_ioc SET status = 'promoted' WHERE entity_key = ? AND status = 'quarantined'",
                (key,),
            )
            self._log(conn, key, now_s, "promoted", result.reason.value, result.detail)

        self._exec_local(local_txn)

    def revoke(self, type_: str, value: str, query_as_of: datetime, reason: str) -> None:
        key = entity_key(type_, value)
        now_s = to_rfc3339(query_as_of)

        def local_txn(conn: Any) -> None:
            conn.execute(
                "UPDATE edge_reported_ioc SET status = 'revoked' WHERE entity_key = ? AND status = 'promoted'",
                (key,),
            )
            self._log(conn, key, now_s, "revoked", reason, None)

        self._exec_local(local_txn)

        def intel_txn(conn: Any) -> None:
            conn.execute(
                "DELETE FROM ioc_source WHERE feed_id = ? AND ioc_id = "
                "(SELECT ioc_id FROM ioc WHERE type = ? AND value = ?)",
                (self.edge_reported_feed_id, type_, value),
            )

        self._exec_intel(intel_txn)

    def _log(self, conn: Any, key: bytes, now_s: str, status: str, reason: str, detail: str | None) -> None:
        log_key = f"promotion_log:{key.hex()}:{now_s}"
        conn.execute(
            "INSERT INTO local_meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (log_key, json.dumps({"status": status, "reason": reason, "detail": detail, "at": now_s})),
        )
