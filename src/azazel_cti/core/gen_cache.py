"""Byte-capped LRU cache for per-worker query-path caching (design F-11).

Each API worker owns one `GenCache` capped at 64 MiB by default (3
workers x 64 MiB = 192 MiB, replacing the larger duplication flagged in
design round 5). Cache entries are namespaced by intel generation --
callers key entries as `f"{generation}:{rest}"` -- so that a generation
swap can drop exactly the stale entries via `clear_generation` without
a full flush.
"""

from __future__ import annotations

import sys
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable

DEFAULT_CAPACITY_BYTES = 64 * 1024 * 1024


def default_size_estimator(value: Any) -> int:
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return sys.getsizeof(value)


@dataclass(frozen=True)
class CacheStats:
    hits: int
    misses: int
    evictions: int
    bytes: int
    entries: int
    capacity_bytes: int


class GenCache:
    """Thread-safe, byte-capped LRU keyed by opaque string keys."""

    def __init__(
        self,
        capacity_bytes: int = DEFAULT_CAPACITY_BYTES,
        size_estimator: Callable[[Any], int] | None = None,
    ) -> None:
        if capacity_bytes <= 0:
            raise ValueError("capacity_bytes must be positive")
        self._capacity = capacity_bytes
        self._size_estimator = size_estimator or default_size_estimator
        self._lock = threading.Lock()
        self._entries: "OrderedDict[str, tuple[Any, int]]" = OrderedDict()
        self._bytes = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return default
            value, size = entry
            self._entries.move_to_end(key)
            self._hits += 1
            return value

    def put(self, key: str, value: Any) -> None:
        size = self._size_estimator(value)
        if size < 0:
            raise ValueError("size estimator returned a negative size")
        with self._lock:
            existing = self._entries.pop(key, None)
            if existing is not None:
                self._bytes -= existing[1]
            self._entries[key] = (value, size)
            self._bytes += size
            self._evict_to_capacity()

    def _evict_to_capacity(self) -> None:
        while self._bytes > self._capacity and self._entries:
            _, (_, size) = self._entries.popitem(last=False)
            self._bytes -= size
            self._evictions += 1

    def clear_generation(self, generation: str) -> int:
        prefix = f"{generation}:"
        with self._lock:
            stale_keys = [key for key in self._entries if key.startswith(prefix)]
            for key in stale_keys:
                _, size = self._entries.pop(key)
                self._bytes -= size
            return len(stale_keys)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._bytes = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._entries

    def stats(self) -> CacheStats:
        with self._lock:
            return CacheStats(
                hits=self._hits,
                misses=self._misses,
                evictions=self._evictions,
                bytes=self._bytes,
                entries=len(self._entries),
                capacity_bytes=self._capacity,
            )
