"""Feed adapter framework (design S6, sync-offline.md).

`FeedAdapter` is the offline-first lifecycle every feed adapter runs
through: `fetch -> parse -> validate -> apply`, checkpointed in
`feed_state` so a killed process resumes without reprocessing already
committed batches. Nothing here is called from the query path; adapters
run only when a caller invokes `.run()` (a scheduled worker task or
`azctl feed` command).

IOC-bearing feeds never mutate `ioc`/`ioc_source` directly: each batch is
written to the `_stage_ioc`/`_stage_ioc_source` tables in one writer
transaction, then swapped into the live tables in a second writer
transaction (`stage_ioc_rows` / `swap_staged_ioc_rows`). A crash between
those two transactions leaves the live tables untouched. Full-replace
feeds (KEV, ATT&CK) instead perform one DELETE+INSERT in a single writer
transaction, which is atomic by construction.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import ssl
import statistics
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from azazel_knowledge.core.clock import Clock, SystemClock, parse_rfc3339, to_rfc3339
from azazel_knowledge.db.generations import read_intel_generation
from azazel_knowledge.db.writer import P2

DEFAULT_CHECKPOINT_SIZE = 5000
DEFAULT_VOLUME_HALT_MULTIPLIER = 3.0
DEFAULT_TRAILING_RUNS = 7


class FeedError(Exception):
    pass


class PinMismatch(FeedError):
    pass


@dataclass(frozen=True)
class FeedRunOutcome:
    feed_id: str
    items_fetched: int
    items_applied: int
    status: str
    reason: str | None = None


@dataclass
class IocRow:
    type: str
    value: str
    first_seen: str
    last_seen: str
    tags: list[str] = field(default_factory=list)


@dataclass
class IocSourceRow:
    type: str
    value: str
    feed_id: str
    source_confidence: int
    first_seen: str
    last_seen: str
    expires_at: str | None
    intel_generation: int
    flagged_critical_infra: bool = False


@dataclass
class IocCidrRow:
    tier: str
    range_start: int
    range_end: int
    type: str
    value: str
    feed_id: str
    expires_at: str | None


_DURATION_UNITS = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds"}


def parse_duration(value: str) -> timedelta:
    text = str(value).strip()
    if len(text) < 2 or text[-1] not in _DURATION_UNITS:
        raise ValueError(f"unrecognized duration {value!r} (expected e.g. '14d', '48h')")
    return timedelta(**{_DURATION_UNITS[text[-1]]: int(text[:-1])})


_HASH_TYPES = frozenset({"md5", "sha1", "sha256"})


def resolve_ttl(ttl_config: Mapping[str, Any] | None, type_: str) -> timedelta | None:
    if not ttl_config:
        return None
    raw = ttl_config.get(type_)
    if raw is None and type_ in _HASH_TYPES:
        raw = ttl_config.get("hash")
    if raw is None:
        raw = ttl_config.get("default")
    return parse_duration(raw) if raw is not None else None


def merge_feed_config(feeds_doc: Mapping[str, Any], feed_id: str) -> dict[str, Any]:
    defaults = dict(feeds_doc.get("defaults") or {})
    feed = dict((feeds_doc.get("feeds") or {}).get(feed_id) or {})
    merged = defaults
    merged.update(feed)
    return merged


def _row_to_dict(cursor, row) -> dict[str, Any] | None:
    if row is None:
        return None
    columns = [d[0] for d in cursor.description]
    return dict(zip(columns, row))


# --- SPKI pinning (F-16): cryptography-free minimal DER walker -------------


def _read_der_length(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    if first & 0x80 == 0:
        return first, pos + 1
    n = first & 0x7F
    if n == 0:
        raise ValueError("indefinite-length DER is not supported")
    if pos + 1 + n > len(data):
        raise ValueError("truncated DER length")
    return int.from_bytes(data[pos + 1 : pos + 1 + n], "big"), pos + 1 + n


def _der_content_bounds(data: bytes, tag_pos: int) -> tuple[int, int]:
    length, content_start = _read_der_length(data, tag_pos + 1)
    return content_start, content_start + length


def _der_tlv_end(data: bytes, tag_pos: int) -> int:
    _, content_end = _der_content_bounds(data, tag_pos)
    return content_end


def extract_subject_public_key_info(cert_der: bytes) -> bytes:
    """Walk an X.509 `Certificate` DER structure down to the raw
    `SubjectPublicKeyInfo` TLV, without depending on `cryptography`.

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
        issuer, validity, subject, subjectPublicKeyInfo, ... }
    """
    if not cert_der or cert_der[0] != 0x30:
        raise ValueError("not a DER SEQUENCE (expected X.509 Certificate)")
    cert_content_start, _ = _der_content_bounds(cert_der, 0)
    if cert_der[cert_content_start] != 0x30:
        raise ValueError("malformed certificate: expected tbsCertificate SEQUENCE")
    tbs_content_start, tbs_content_end = _der_content_bounds(cert_der, cert_content_start)

    pos = tbs_content_start
    if pos < tbs_content_end and cert_der[pos] == 0xA0:
        pos = _der_tlv_end(cert_der, pos)
    for _ in range(5):
        if pos >= tbs_content_end:
            raise ValueError("malformed tbsCertificate: ran out of fields before SPKI")
        pos = _der_tlv_end(cert_der, pos)
    if pos >= tbs_content_end or cert_der[pos] != 0x30:
        raise ValueError("malformed tbsCertificate: subjectPublicKeyInfo not found")
    return cert_der[pos : _der_tlv_end(cert_der, pos)]


def spki_sha256_hex(cert_der: bytes) -> str:
    return hashlib.sha256(extract_subject_public_key_info(cert_der)).hexdigest()


def verify_spki_pin(cert_der: bytes, pins: Sequence[str]) -> str:
    digest = spki_sha256_hex(cert_der)
    if pins and digest not in {p.lower() for p in pins}:
        raise PinMismatch(f"SPKI {digest} does not match any pinned key")
    return digest


def fetch_https_with_pins(url: str, pins: Sequence[str], timeout: float = 30.0) -> bytes:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FeedError(f"pinned fetch requires https: {url!r}")
    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=context)
    try:
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        conn.request("GET", path, headers={"User-Agent": "azazel-knowledge-feed-adapter"})
        response = conn.getresponse()
        body = response.read()
        if response.status >= 400:
            raise FeedError(f"HTTP {response.status} fetching {url}")
        cert_der = conn.sock.getpeercert(binary_form=True)
        verify_spki_pin(cert_der, pins)
        return body
    finally:
        conn.close()


# --- FeedAdapter -------------------------------------------------------------


class FeedAdapter(ABC):
    full_replace: bool = False

    def __init__(
        self,
        feed_id: str,
        config: Mapping[str, Any],
        intel_writer: Any,
        local_writer: Any | None = None,
        clock: Clock | None = None,
        fetch_bytes: Callable[[], bytes] | None = None,
        checkpoint_size: int = DEFAULT_CHECKPOINT_SIZE,
    ) -> None:
        self.feed_id = feed_id
        self.config = dict(config)
        self.intel_writer = intel_writer
        self.local_writer = local_writer
        self.clock = clock or SystemClock()
        self._fetch_bytes = fetch_bytes
        self.checkpoint_size = checkpoint_size

    # ---- lifecycle hooks -----------------------------------------------

    def fetch(self) -> bytes:
        if self._fetch_bytes is not None:
            return self._fetch_bytes()
        return self.default_fetch()

    def default_fetch(self) -> bytes:
        raise FeedError(
            f"{self.feed_id}: no fetch source configured "
            "(inject fetch_bytes or override default_fetch)"
        )

    @abstractmethod
    def parse(self, raw: bytes) -> Any: ...

    def validate(self, items: Any) -> Any:
        return items

    def item_count(self, items: Any) -> int:
        return len(items)

    @abstractmethod
    def apply_batch(self, batch: Any) -> int: ...

    def before_run(self) -> None:
        return None

    def after_run(self, outcome: FeedRunOutcome) -> None:
        return None

    def rate_limit_sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    # ---- writer helpers ---------------------------------------------------

    def _exec(self, writer: Any, fn: Callable[[Any], Any], priority: int = P2) -> Any:
        box: dict[str, Any] = {}

        def wrapper(conn: Any) -> None:
            box["value"] = fn(conn)

        writer.submit(priority, wrapper)
        writer.process_pending()
        return box.get("value")

    def _exec_intel(self, fn: Callable[[Any], Any], priority: int = P2) -> Any:
        return self._exec(self.intel_writer, fn, priority)

    def _exec_local(self, fn: Callable[[Any], Any], priority: int = P2) -> Any:
        if self.local_writer is None:
            raise FeedError(f"{self.feed_id}: local_writer required for this operation")
        return self._exec(self.local_writer, fn, priority)

    # ---- staged IOC swap (used by IOC-bearing adapters) --------------------

    def stage_ioc_rows(self, ioc_rows: list[IocRow], source_rows: list[IocSourceRow]) -> None:
        def txn(conn: Any) -> None:
            conn.execute("DELETE FROM _stage_ioc")
            conn.execute("DELETE FROM _stage_ioc_source")
            conn.executemany(
                "INSERT INTO _stage_ioc (type, value, first_seen, last_seen, tags) "
                "VALUES (?, ?, ?, ?, ?)",
                [(r.type, r.value, r.first_seen, r.last_seen, json.dumps(r.tags)) for r in ioc_rows],
            )
            conn.executemany(
                "INSERT INTO _stage_ioc_source (type, value, feed_id, source_confidence, "
                "first_seen, last_seen, expires_at, intel_generation, flagged_critical_infra) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        r.type,
                        r.value,
                        r.feed_id,
                        r.source_confidence,
                        r.first_seen,
                        r.last_seen,
                        r.expires_at,
                        r.intel_generation,
                        int(r.flagged_critical_infra),
                    )
                    for r in source_rows
                ],
            )

        self._exec_intel(txn)

    def _swap_staged_ioc_rows_txn(self, conn: Any) -> int:
        conn.execute(
            "INSERT INTO ioc (type, value, first_seen, last_seen, tags) "
            "SELECT type, value, first_seen, last_seen, tags FROM _stage_ioc WHERE true "
            "ON CONFLICT(type, value) DO UPDATE SET "
            "first_seen = MIN(ioc.first_seen, excluded.first_seen), "
            "last_seen = MAX(ioc.last_seen, excluded.last_seen)"
        )
        conn.execute(
            "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, "
            "last_seen, expires_at, intel_generation, flagged_critical_infra) "
            "SELECT i.ioc_id, s.feed_id, s.source_confidence, s.first_seen, s.last_seen, "
            "s.expires_at, s.intel_generation, s.flagged_critical_infra "
            "FROM _stage_ioc_source s JOIN ioc i ON i.type = s.type AND i.value = s.value "
            "WHERE true "
            "ON CONFLICT(ioc_id, feed_id) DO UPDATE SET "
            "source_confidence = excluded.source_confidence, "
            "last_seen = excluded.last_seen, "
            "expires_at = excluded.expires_at, "
            "intel_generation = excluded.intel_generation, "
            "flagged_critical_infra = excluded.flagged_critical_infra"
        )
        count = conn.execute("SELECT COUNT(*) FROM _stage_ioc_source").fetchone()[0]
        conn.execute("DELETE FROM _stage_ioc")
        conn.execute("DELETE FROM _stage_ioc_source")
        return count

    def swap_staged_ioc_rows(self) -> int:
        return self._exec_intel(self._swap_staged_ioc_rows_txn)

    def stage_and_swap_ioc(self, ioc_rows: list[IocRow], source_rows: list[IocSourceRow]) -> int:
        self.stage_ioc_rows(ioc_rows, source_rows)
        return self.swap_staged_ioc_rows()

    def _insert_ioc_cidr_rows_txn(self, conn: Any, rows: list[IocCidrRow]) -> int:
        count = 0
        for r in rows:
            conn.execute(
                "INSERT INTO ioc_cidr (tier, range_start, range_end, ioc_id, feed_id, expires_at) "
                "SELECT ?, ?, ?, i.ioc_id, ?, ? FROM ioc i WHERE i.type = ? AND i.value = ? "
                "AND true "
                "ON CONFLICT(tier, range_start, ioc_id, feed_id) DO UPDATE SET "
                "range_end = excluded.range_end, expires_at = excluded.expires_at",
                (r.tier, r.range_start, r.range_end, r.feed_id, r.expires_at, r.type, r.value),
            )
            count += 1
        return count

    def swap_staged_ioc_rows_with_cidr(self, cidr_rows: list[IocCidrRow]) -> tuple[int, int]:
        def txn(conn: Any) -> tuple[int, int]:
            source_count = self._swap_staged_ioc_rows_txn(conn)
            cidr_count = self._insert_ioc_cidr_rows_txn(conn, cidr_rows)
            return source_count, cidr_count

        return self._exec_intel(txn)

    def stage_and_swap_ioc_with_cidr(
        self, ioc_rows: list[IocRow], source_rows: list[IocSourceRow], cidr_rows: list[IocCidrRow]
    ) -> tuple[int, int]:
        self.stage_ioc_rows(ioc_rows, source_rows)
        return self.swap_staged_ioc_rows_with_cidr(cidr_rows)

    def current_intel_generation(self) -> int:
        return self._exec_intel(read_intel_generation)

    # ---- feed_state / feed_quarantine bookkeeping --------------------------

    def _select_state(self, conn: Any) -> dict[str, Any] | None:
        cur = conn.execute("SELECT * FROM feed_state WHERE feed_id = ?", (self.feed_id,))
        return _row_to_dict(cur, cur.fetchone())

    def _write_state(
        self,
        now_s: str,
        success: bool,
        checksum: str,
        item_count: int,
        cursor: dict[str, Any],
        consecutive_polls: int,
    ) -> None:
        def txn(conn: Any) -> None:
            conn.execute(
                "INSERT INTO feed_state (feed_id, cursor, last_run, last_success, item_count, "
                "checksum, enabled, consecutive_polls) VALUES (?, ?, ?, ?, ?, ?, 1, ?) "
                "ON CONFLICT(feed_id) DO UPDATE SET cursor = excluded.cursor, "
                "last_run = excluded.last_run, "
                "last_success = COALESCE(excluded.last_success, feed_state.last_success), "
                "item_count = excluded.item_count, checksum = excluded.checksum, "
                "consecutive_polls = excluded.consecutive_polls, enabled = 1",
                (
                    self.feed_id,
                    json.dumps(cursor),
                    now_s,
                    now_s if success else None,
                    item_count,
                    checksum,
                    consecutive_polls,
                ),
            )

        self._exec_intel(txn)

    def _halt(self, now_s: str, reason: str) -> None:
        def txn(conn: Any) -> None:
            conn.execute(
                "INSERT INTO feed_state (feed_id, cursor, last_run, item_count, checksum, "
                "enabled, consecutive_polls) VALUES (?, ?, ?, 0, NULL, 0, 0) "
                "ON CONFLICT(feed_id) DO UPDATE SET cursor = excluded.cursor, "
                "last_run = excluded.last_run, enabled = 0",
                (self.feed_id, json.dumps({"halt_reason": reason}), now_s),
            )

        self._exec_intel(txn)

    def _checkpoint(self, now_s: str, checksum: str, parse_cursor: int, history: list[int]) -> None:
        cursor = {"parse_cursor": parse_cursor, "volume_history": history}

        def txn(conn: Any) -> None:
            conn.execute(
                "INSERT INTO feed_state (feed_id, cursor, last_run, item_count, checksum, "
                "enabled, consecutive_polls) VALUES (?, ?, ?, ?, ?, 1, "
                "COALESCE((SELECT consecutive_polls FROM feed_state WHERE feed_id = ?), 0)) "
                "ON CONFLICT(feed_id) DO UPDATE SET cursor = excluded.cursor, "
                "last_run = excluded.last_run, item_count = excluded.item_count, "
                "checksum = excluded.checksum",
                (self.feed_id, json.dumps(cursor), now_s, parse_cursor, checksum, self.feed_id),
            )

        self._exec_intel(txn)

    def insert_quarantine(self, now_s: str, reason: str, detail: str | None = None) -> None:
        def txn(conn: Any) -> None:
            conn.execute(
                "INSERT INTO feed_quarantine (feed_id, quarantined_at, reason, detail, resolved_at) "
                "VALUES (?, ?, ?, ?, NULL)",
                (self.feed_id, now_s, reason, detail),
            )

        self._exec_local(txn)

    # ---- guards -------------------------------------------------------------

    def _is_volume_halt(self, history: list[int], new_count: int) -> bool:
        if not history:
            return False
        multiplier = float(self.config.get("volume_halt_multiplier", DEFAULT_VOLUME_HALT_MULTIPLIER))
        trailing = history[-DEFAULT_TRAILING_RUNS:]
        median = statistics.median(trailing)
        if median <= 0:
            return False
        return new_count > multiplier * median

    def _throttled(self, state: dict[str, Any] | None, now) -> bool:
        interval = self.config.get("min_interval_s")
        if not interval or not state or not state.get("last_run"):
            return False
        last_run = parse_rfc3339(state["last_run"])
        return (now - last_run).total_seconds() < float(interval)

    # ---- orchestration --------------------------------------------------

    def run(self) -> FeedRunOutcome:
        now = self.clock.query_as_of()
        now_s = to_rfc3339(now)
        state = self._exec_intel(self._select_state)

        if state is not None and not state.get("enabled", 1):
            cursor = json.loads(state["cursor"]) if state.get("cursor") else {}
            outcome = FeedRunOutcome(self.feed_id, 0, 0, "halted", cursor.get("halt_reason", "feed halted"))
            self.after_run(outcome)
            return outcome

        if self._throttled(state, now):
            outcome = FeedRunOutcome(self.feed_id, 0, 0, "throttled", "min_interval_s not elapsed")
            self.after_run(outcome)
            return outcome

        self.before_run()

        try:
            raw = self.fetch()
        except PinMismatch as exc:
            self._halt(now_s, str(exc))
            outcome = FeedRunOutcome(self.feed_id, 0, 0, "halted", str(exc))
            self.after_run(outcome)
            return outcome

        checksum = hashlib.sha256(raw).hexdigest()
        items = self.validate(self.parse(raw))
        total = self.item_count(items)

        cursor = json.loads(state["cursor"]) if state and state.get("cursor") else {}
        history = list(cursor.get("volume_history", []))
        consecutive = int(state.get("consecutive_polls", 0)) if state else 0

        if self._is_volume_halt(history, total):
            multiplier = self.config.get("volume_halt_multiplier", DEFAULT_VOLUME_HALT_MULTIPLIER)
            self.insert_quarantine(
                now_s, "volume_halt", f"item_count={total} exceeds {multiplier}x trailing median"
            )
            self._write_state(now_s, False, checksum, total, {"volume_history": history, "parse_cursor": 0}, 0)
            outcome = FeedRunOutcome(self.feed_id, total, 0, "quarantined", "volume_halt")
            self.after_run(outcome)
            return outcome

        min_polls = self.config.get("min_consecutive_polls")
        resulting_consecutive = consecutive + 1
        gated = min_polls is not None and resulting_consecutive < int(min_polls)

        if gated:
            self._write_state(
                now_s, True, checksum, total, {"volume_history": history, "parse_cursor": 0}, resulting_consecutive
            )
            outcome = FeedRunOutcome(
                self.feed_id, total, 0, "warming_up", f"{resulting_consecutive}/{min_polls} consecutive polls"
            )
            self.after_run(outcome)
            return outcome

        resume_from = cursor.get("parse_cursor", 0) if (state and state.get("checksum") == checksum) else 0
        applied, final_cursor = self._apply_items(items, resume_from, now_s, checksum, history)

        new_history = (history + [total])[-DEFAULT_TRAILING_RUNS:]
        self._write_state(
            now_s, True, checksum, total, {"volume_history": new_history, "parse_cursor": final_cursor},
            resulting_consecutive,
        )
        outcome = FeedRunOutcome(self.feed_id, total, applied, "applied")
        self.after_run(outcome)
        return outcome

    def _apply_items(
        self, items: Any, resume_from: int, now_s: str, checksum: str, history: list[int]
    ) -> tuple[int, int]:
        total = self.item_count(items)
        if self.full_replace:
            applied = self.apply_batch(items)
            self._checkpoint(now_s, checksum, total, history)
            return applied, total

        applied = 0
        idx = resume_from
        while idx < total:
            end = min(idx + self.checkpoint_size, total)
            batch = items[idx:end]
            applied += self.apply_batch(batch)
            idx = end
            self._checkpoint(now_s, checksum, idx, history)
        return applied, idx
