"""Deterministic time source for the scoring pipeline.

The scoring determinism contract (design S5) requires that `query_as_of`
is captured exactly once at handler entry and threaded through every
freshness/promotion/corroboration evaluation performed while answering
that request. `Clock` is the seam that makes this possible in production
(`SystemClock`) and reproducible in tests (`FixedClock`).
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone

_RFC3339_FRACTION_RE = re.compile(r"\.(\d+)")


class Clock(ABC):
    """Abstraction over "now" for the query path."""

    @abstractmethod
    def query_as_of(self) -> datetime:
        """Return the aware-UTC instant this call/request is pinned to."""
        raise NotImplementedError


class SystemClock(Clock):
    """Reads the real wall clock, once per call."""

    def query_as_of(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock(Clock):
    """Returns a fixed, caller-supplied instant. For tests and replay."""

    def __init__(self, dt: datetime) -> None:
        if dt.tzinfo is None:
            raise ValueError("FixedClock requires an aware datetime")
        self._dt = dt.astimezone(timezone.utc)

    def query_as_of(self) -> datetime:
        return self._dt


def parse_rfc3339(value: str) -> datetime:
    """Parse an RFC3339 timestamp into an aware UTC datetime.

    Accepts a trailing 'Z' as well as explicit numeric offsets, and
    fractional seconds of any precision.
    """
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"RFC3339 timestamp must carry a timezone offset: {value!r}")
    return dt.astimezone(timezone.utc)


def to_rfc3339(dt: datetime) -> str:
    """Serialize an aware datetime as RFC3339 UTC with a literal 'Z' suffix."""
    if dt.tzinfo is None:
        raise ValueError("to_rfc3339 requires an aware datetime")
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.isoformat().replace("+00:00", "Z")
