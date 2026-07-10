"""Per-entity event cap bookkeeping (design S5 history component).

`BurstGuard` enforces the `history.burst_cap` rule (`config/scoring.yaml`
default: 500 events per rolling window per `entity_key`). Over-cap events
are still stored in `observation` -- nothing is dropped -- but the drainer
marks them `excluded_from_stats` so `observation_stats` and the `history`
scoring component never reward burst flooding.

This is in-process, best-effort bookkeeping: it resets on worker restart.
That is an accepted simplification (the cap is a stats-fairness heuristic,
not a security control); durability lives in the `observation` rows and
`observation_stats` themselves, not here.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime

DEFAULT_CAP = 500
DEFAULT_WINDOW_S = 3600.0


class BurstGuard:
    def __init__(self, cap: int = DEFAULT_CAP, window_s: float = DEFAULT_WINDOW_S) -> None:
        self.cap = cap
        self.window_s = window_s
        self._windows: dict[bytes, deque[float]] = {}
        self._lock = threading.Lock()

    def check_and_record(self, entity_key: bytes, observed_at: datetime) -> bool:
        """Record one event for `entity_key` at `observed_at`.

        Returns True if the event is within cap for its rolling window,
        False if it is the (cap+1)th or later event in that window --
        callers must still store the event but mark it excluded from
        stats aggregation.
        """
        ts = observed_at.timestamp()
        with self._lock:
            bucket = self._windows.setdefault(entity_key, deque())
            cutoff = ts - self.window_s
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            within_cap = len(bucket) < self.cap
            bucket.append(ts)
            return within_cap

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
