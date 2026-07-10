from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from azazel_grimoire.core.clock import FixedClock, SystemClock, parse_rfc3339, to_rfc3339


def test_fixed_clock_returns_same_instant_every_call():
    dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
    clock = FixedClock(dt)
    assert clock.query_as_of() == dt
    assert clock.query_as_of() == clock.query_as_of()


def test_fixed_clock_normalizes_non_utc_to_utc():
    tz = timezone(timedelta(hours=5))
    dt = datetime(2026, 1, 1, 12, 0, tzinfo=tz)
    clock = FixedClock(dt)
    result = clock.query_as_of()
    assert result.tzinfo == timezone.utc
    assert result == dt


def test_fixed_clock_rejects_naive_datetime():
    with pytest.raises(ValueError):
        FixedClock(datetime(2026, 1, 1))


def test_system_clock_returns_aware_utc_datetime():
    clock = SystemClock()
    now = clock.query_as_of()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


def test_determinism_contract_repeated_reads_are_identical():
    fixed = FixedClock(datetime(2026, 6, 1, tzinfo=timezone.utc))
    reads = [fixed.query_as_of() for _ in range(5)]
    assert all(r == reads[0] for r in reads)


def test_parse_rfc3339_accepts_z_suffix():
    dt = parse_rfc3339("2026-01-01T00:00:00Z")
    assert dt == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_parse_rfc3339_accepts_numeric_offset():
    dt = parse_rfc3339("2026-01-01T05:00:00+05:00")
    assert dt == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_parse_rfc3339_accepts_fractional_seconds():
    dt = parse_rfc3339("2026-01-01T00:00:00.123456Z")
    assert dt.microsecond == 123456


def test_parse_rfc3339_rejects_naive_string():
    with pytest.raises(ValueError):
        parse_rfc3339("2026-01-01T00:00:00")


def test_to_rfc3339_roundtrip():
    dt = datetime(2026, 1, 1, 12, 30, 45, tzinfo=timezone.utc)
    text = to_rfc3339(dt)
    assert text == "2026-01-01T12:30:45Z"
    assert parse_rfc3339(text) == dt


def test_to_rfc3339_rejects_naive_datetime():
    with pytest.raises(ValueError):
        to_rfc3339(datetime(2026, 1, 1))


def test_to_rfc3339_converts_non_utc_offset():
    tz = timezone(timedelta(hours=-3))
    dt = datetime(2026, 1, 1, 9, 0, tzinfo=tz)
    assert to_rfc3339(dt) == "2026-01-01T12:00:00Z"
