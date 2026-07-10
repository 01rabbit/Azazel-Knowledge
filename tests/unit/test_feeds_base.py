from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.feeds import base as feeds_base
from azazel_knowledge.feeds.base import (
    FeedAdapter,
    PinMismatch,
    extract_subject_public_key_info,
    parse_duration,
    resolve_ttl,
    spki_sha256_hex,
    verify_spki_pin,
)
from azazel_knowledge.feeds import sanity

from _feeds_support import make_intel_writer, make_local_writer

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "feeds"
NOW = datetime(2026, 7, 6, 0, 0, 0, tzinfo=timezone.utc)


class ListAdapter(FeedAdapter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.applied_items: list[int] = []
        self.apply_calls = 0
        self.fail_on_call: int | None = None

    def parse(self, raw: bytes) -> list[int]:
        return json.loads(raw)

    def apply_batch(self, batch: list[int]) -> int:
        self.apply_calls += 1
        if self.fail_on_call is not None and self.apply_calls == self.fail_on_call:
            raise RuntimeError("simulated crash mid-apply")
        self.applied_items.extend(batch)
        return len(batch)


def _make_adapter(tmp_path, payload: list[int], config: dict | None = None, **kwargs: Any) -> ListAdapter:
    intel = make_intel_writer(tmp_path)
    local = make_local_writer(tmp_path)
    adapter = ListAdapter(
        "testfeed",
        config or {},
        intel,
        local,
        clock=FixedClock(NOW),
        fetch_bytes=lambda: json.dumps(payload).encode(),
        **kwargs,
    )
    return adapter


def _feed_state(adapter: ListAdapter) -> dict | None:
    return adapter._exec_intel(adapter._select_state)


def test_der_spki_extraction_matches_openssl_pubkey():
    cert_der = (FIXTURES / "cert.der").read_bytes()
    expected_spki = (FIXTURES / "cert_spki.der").read_bytes()
    expected_pin = (FIXTURES / "cert_pin.txt").read_text().strip()

    spki = extract_subject_public_key_info(cert_der)
    assert spki == expected_spki
    assert spki_sha256_hex(cert_der) == expected_pin
    assert hashlib.sha256(spki).hexdigest() == expected_pin


def test_verify_spki_pin_accepts_matching_pin_and_empty_pin_list():
    cert_der = (FIXTURES / "cert.der").read_bytes()
    pin = (FIXTURES / "cert_pin.txt").read_text().strip()
    assert verify_spki_pin(cert_der, [pin]) == pin
    assert verify_spki_pin(cert_der, [pin.upper()]) == pin
    assert verify_spki_pin(cert_der, []) == pin


def test_verify_spki_pin_mismatch_raises():
    cert_der = (FIXTURES / "cert.der").read_bytes()
    with pytest.raises(PinMismatch):
        verify_spki_pin(cert_der, ["0" * 64])


def test_der_walker_rejects_garbage():
    with pytest.raises(ValueError):
        extract_subject_public_key_info(b"")
    with pytest.raises(ValueError):
        extract_subject_public_key_info(b"\x02\x01\x00")
    with pytest.raises(ValueError):
        extract_subject_public_key_info(b"\x30\x82")


def test_pin_mismatch_halts_feed(tmp_path):
    adapter = _make_adapter(tmp_path, [1, 2, 3])

    def bad_fetch() -> bytes:
        raise PinMismatch("SPKI deadbeef does not match any pinned key")

    adapter._fetch_bytes = bad_fetch
    outcome = adapter.run()
    assert outcome.status == "halted"

    state = _feed_state(adapter)
    assert state is not None
    assert state["enabled"] == 0

    fetch_calls = []
    adapter._fetch_bytes = lambda: fetch_calls.append(1) or b"[]"
    second = adapter.run()
    assert second.status == "halted"
    assert fetch_calls == []


def test_checkpoint_resume_after_mid_apply_crash(tmp_path):
    payload = [1, 2, 3, 4, 5]
    adapter = _make_adapter(tmp_path, payload, checkpoint_size=2)
    adapter.fail_on_call = 2

    with pytest.raises(RuntimeError):
        adapter.run()

    assert adapter.applied_items == [1, 2]
    state = _feed_state(adapter)
    cursor = json.loads(state["cursor"])
    assert cursor["parse_cursor"] == 2

    adapter.fail_on_call = None
    outcome = adapter.run()
    assert outcome.status == "applied"
    assert outcome.items_applied == 3
    assert adapter.applied_items == [1, 2, 3, 4, 5]


def test_rerun_with_same_checksum_is_idempotent(tmp_path):
    payload = [1, 2, 3]
    adapter = _make_adapter(tmp_path, payload)
    first = adapter.run()
    assert first.items_applied == 3
    second = adapter.run()
    assert second.status == "applied"
    assert second.items_applied == 0
    assert adapter.applied_items == [1, 2, 3]


def test_volume_halt_quarantines_pull(tmp_path):
    payload = list(range(100))
    adapter = _make_adapter(tmp_path, payload)

    def seed(conn: Any) -> None:
        conn.execute(
            "INSERT INTO feed_state (feed_id, cursor, item_count) VALUES (?, ?, 10)",
            ("testfeed", json.dumps({"volume_history": [10] * 7, "parse_cursor": 0})),
        )

    adapter._exec_intel(seed)

    outcome = adapter.run()
    assert outcome.status == "quarantined"
    assert outcome.reason == "volume_halt"
    assert adapter.applied_items == []

    def read_quarantine(conn: Any):
        return conn.execute(
            "SELECT feed_id, reason FROM feed_quarantine WHERE feed_id = 'testfeed'"
        ).fetchall()

    rows = adapter._exec_local(read_quarantine)
    assert len(rows) == 1
    assert rows[0][1] == "volume_halt"


def test_volume_within_bounds_is_not_halted(tmp_path):
    payload = list(range(25))
    adapter = _make_adapter(tmp_path, payload)

    def seed(conn: Any) -> None:
        conn.execute(
            "INSERT INTO feed_state (feed_id, cursor, item_count) VALUES (?, ?, 10)",
            ("testfeed", json.dumps({"volume_history": [10] * 7, "parse_cursor": 0})),
        )

    adapter._exec_intel(seed)
    outcome = adapter.run()
    assert outcome.status == "applied"
    assert outcome.items_applied == 25


def test_min_consecutive_polls_gate(tmp_path):
    payload = [1, 2]
    adapter = _make_adapter(tmp_path, payload, config={"min_consecutive_polls": 2})

    first = adapter.run()
    assert first.status == "warming_up"
    assert adapter.applied_items == []

    second = adapter.run()
    assert second.status == "applied"
    assert second.items_applied == 2


def test_stage_crash_leaves_live_tables_untouched(tmp_path):
    from azazel_knowledge.feeds.base import IocRow, IocSourceRow

    intel = make_intel_writer(tmp_path)
    local = make_local_writer(tmp_path)

    class StagingAdapter(FeedAdapter):
        def parse(self, raw: bytes) -> list[int]:
            return json.loads(raw)

        def apply_batch(self, batch: list[int]) -> int:
            ioc_rows = [IocRow("ip", "203.0.113.9", "2026-07-05T00:00:00Z", "2026-07-06T00:00:00Z")]
            source_rows = [
                IocSourceRow(
                    "ip", "203.0.113.9", self.feed_id, 80,
                    "2026-07-05T00:00:00Z", "2026-07-06T00:00:00Z", None, 0,
                )
            ]
            self.stage_ioc_rows(ioc_rows, source_rows)
            raise RuntimeError("killed between stage and swap")

    adapter = StagingAdapter(
        "stagefeed", {}, intel, local, clock=FixedClock(NOW), fetch_bytes=lambda: b"[1]"
    )
    with pytest.raises(RuntimeError):
        adapter.run()

    def read_counts(conn: Any):
        live_ioc = conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
        live_src = conn.execute("SELECT COUNT(*) FROM ioc_source").fetchone()[0]
        staged = conn.execute("SELECT COUNT(*) FROM _stage_ioc").fetchone()[0]
        return live_ioc, live_src, staged

    live_ioc, live_src, staged = adapter._exec_intel(read_counts)
    assert live_ioc == 0
    assert live_src == 0
    assert staged == 1


def test_swap_is_single_transaction_and_clears_stage(tmp_path):
    from azazel_knowledge.feeds.base import IocRow, IocSourceRow

    intel = make_intel_writer(tmp_path)

    class OkAdapter(FeedAdapter):
        def parse(self, raw: bytes) -> list[int]:
            return json.loads(raw)

        def apply_batch(self, batch: list[int]) -> int:
            ioc_rows = [IocRow("ip", "203.0.113.9", "2026-07-05T00:00:00Z", "2026-07-06T00:00:00Z")]
            source_rows = [
                IocSourceRow(
                    "ip", "203.0.113.9", self.feed_id, 80,
                    "2026-07-05T00:00:00Z", "2026-07-06T00:00:00Z", None, 0,
                )
            ]
            return self.stage_and_swap_ioc(ioc_rows, source_rows)

    adapter = OkAdapter("stagefeed", {}, intel, clock=FixedClock(NOW), fetch_bytes=lambda: b"[1]")
    outcome = adapter.run()
    assert outcome.status == "applied"
    assert outcome.items_applied == 1

    def read_counts(conn: Any):
        return (
            conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM ioc_source").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM _stage_ioc").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM _stage_ioc_source").fetchone()[0],
        )

    ioc_count, src_count, stage_ioc, stage_src = adapter._exec_intel(read_counts)
    assert (ioc_count, src_count) == (1, 1)
    assert (stage_ioc, stage_src) == (0, 0)


def test_rate_limit_min_interval_throttles(tmp_path):
    payload = [1]
    adapter = _make_adapter(tmp_path, payload, config={"min_interval_s": 3600})
    first = adapter.run()
    assert first.status == "applied"
    second = adapter.run()
    assert second.status == "throttled"


def test_parse_duration_and_resolve_ttl():
    assert parse_duration("14d") == timedelta(days=14)
    assert parse_duration("4h") == timedelta(hours=4)
    assert resolve_ttl({"ip": "14d", "default": "3d"}, "ip") == timedelta(days=14)
    assert resolve_ttl({"default": "3d"}, "url") == timedelta(days=3)
    assert resolve_ttl({"ip": "14d"}, "url") is None
    assert resolve_ttl(None, "ip") is None
    with pytest.raises(ValueError):
        parse_duration("14 days")


def test_sanity_skew_and_lengths_and_soft_hold():
    assert sanity.within_skew("2026-07-05T12:00:00Z", NOW)
    assert not sanity.within_skew("2026-07-01T00:00:00Z", NOW)
    assert not sanity.within_skew("2026-07-09T00:00:00Z", NOW)
    assert not sanity.within_skew("garbage", NOW)
    assert sanity.within_length("a" * sanity.MAX_VALUE_LENGTH)
    assert not sanity.within_length("a" * (sanity.MAX_VALUE_LENGTH + 1))
    assert sanity.within_line_length("a" * sanity.MAX_LINE_LENGTH)
    assert not sanity.within_line_length("a" * (sanity.MAX_LINE_LENGTH + 1))

    first_seen = NOW - timedelta(hours=3)
    assert sanity.soft_hold_active(first_seen, NOW)
    assert not sanity.soft_hold_active(NOW - timedelta(hours=5), NOW)
    assert sanity.soft_hold_release_at(first_seen) == first_seen + timedelta(hours=4)


def test_fetch_requires_injection_or_override(tmp_path):
    adapter = _make_adapter(tmp_path, [])
    adapter._fetch_bytes = None
    with pytest.raises(feeds_base.FeedError):
        adapter.fetch()


def test_spamhaus_asndrop_writes_asn_iocs_and_cidr_tier(tmp_path):
    from azazel_knowledge.feeds.adapters.spamhaus_asndrop import SpamhausAsnDropAdapter

    adapter = SpamhausAsnDropAdapter(
        "spamhaus_asndrop",
        {"group": "spamhaus", "ttl": {"asn": "7d"}},
        make_intel_writer(tmp_path),
        make_local_writer(tmp_path),
        clock=FixedClock(NOW),
        fetch_bytes=(FIXTURES / "spamhaus_asndrop.json").read_bytes,
    )
    outcome = adapter.run()
    assert outcome.status == "applied"

    def query(conn: Any):
        iocs = conn.execute(
            "SELECT type, value, tags FROM ioc ORDER BY value"
        ).fetchall()
        cidrs = conn.execute(
            "SELECT tier, range_start, range_end, expires_at FROM ioc_cidr ORDER BY range_start"
        ).fetchall()
        return iocs, cidrs

    iocs, cidrs = adapter._exec_intel(query)
    assert [(r[0], r[1]) for r in iocs] == [("asn", "AS64500"), ("asn", "AS64501")]
    assert "org:Bulletproof Hosting LLC" in json.loads(iocs[0][2])

    assert len(cidrs) == 2
    assert all(r[0] == "asn" for r in cidrs)
    assert cidrs[0][1] == int.from_bytes(bytes([192, 0, 2, 0]), "big")
    assert cidrs[0][2] == int.from_bytes(bytes([192, 0, 2, 255]), "big")
    assert all(r[3] == "2026-07-13T00:00:00Z" for r in cidrs)


def test_geoip_asn_loads_local_csv_with_org_tags(tmp_path):
    from azazel_knowledge.feeds.adapters.geoip_asn import GeoipAsnAdapter

    adapter = GeoipAsnAdapter(
        "geoip_asn",
        {"group": "geoip", "ttl": {"asn": "30d"}},
        make_intel_writer(tmp_path),
        make_local_writer(tmp_path),
        clock=FixedClock(NOW),
        fetch_bytes=(FIXTURES / "geoip_asn.csv").read_bytes,
    )
    outcome = adapter.run()
    assert outcome.status == "applied"

    def query(conn: Any):
        iocs = conn.execute("SELECT type, value, tags FROM ioc ORDER BY value").fetchall()
        cidrs = conn.execute("SELECT tier, range_start, range_end FROM ioc_cidr").fetchall()
        return iocs, cidrs

    iocs, cidrs = adapter._exec_intel(query)
    assert [(r[0], r[1]) for r in iocs] == [("asn", "AS64500"), ("asn", "AS64510")]
    assert "org:Example Carrier One" in json.loads(iocs[0][2])
    assert len(cidrs) == 3
    assert all(r[0] == "asn" for r in cidrs)
