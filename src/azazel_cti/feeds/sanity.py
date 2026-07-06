"""Per-pull sanity checks shared by feed adapters (design S6).

Stateless helpers: RFC3339 skew bounds for feed-supplied dates, max
line/value lengths, and the high-severity first-seen soft-hold (4h)
bookkeeping used to delay trusting a brand-new high-severity item until
it has survived one hold window.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from azazel_cti.core.clock import parse_rfc3339

DEFAULT_SKEW_HOURS = 48
MAX_VALUE_LENGTH = 2048
MAX_LINE_LENGTH = 8192
DEFAULT_SOFT_HOLD_HOURS = 4


def within_skew(timestamp: str, now: datetime, max_skew_hours: int = DEFAULT_SKEW_HOURS) -> bool:
    try:
        dt = parse_rfc3339(timestamp)
    except ValueError:
        return False
    return abs((now.astimezone(timezone.utc) - dt).total_seconds()) <= max_skew_hours * 3600


def within_length(value: str, max_length: int = MAX_VALUE_LENGTH) -> bool:
    return len(value) <= max_length


def within_line_length(line: str, max_length: int = MAX_LINE_LENGTH) -> bool:
    return len(line) <= max_length


def soft_hold_active(first_seen: datetime, now: datetime, hold_hours: int = DEFAULT_SOFT_HOLD_HOURS) -> bool:
    return (now.astimezone(timezone.utc) - first_seen.astimezone(timezone.utc)) < timedelta(hours=hold_hours)


def soft_hold_release_at(first_seen: datetime, hold_hours: int = DEFAULT_SOFT_HOLD_HOURS) -> datetime:
    return first_seen.astimezone(timezone.utc) + timedelta(hours=hold_hours)
