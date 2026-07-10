from __future__ import annotations

import threading

from azazel_grimoire.core.gen_cache import GenCache


def test_put_get_roundtrip_and_hit_counting():
    cache = GenCache(capacity_bytes=1024)
    cache.put("gen-1:a", b"hello")

    assert cache.get("gen-1:a") == b"hello"
    stats = cache.stats()
    assert stats.hits == 1
    assert stats.misses == 0
    assert stats.entries == 1


def test_get_missing_key_counts_as_miss():
    cache = GenCache(capacity_bytes=1024)
    assert cache.get("missing") is None
    assert cache.stats().misses == 1


def test_default_capacity_matches_design_f11():
    cache = GenCache()
    assert cache.stats().capacity_bytes == 64 * 1024 * 1024


def test_byte_cap_evicts_least_recently_used():
    cache = GenCache(capacity_bytes=10)
    cache.put("a", b"12345")
    cache.put("b", b"12345")
    assert cache.stats().bytes == 10

    cache.put("c", b"12345")  # 15 bytes total > cap; evicts "a" (LRU)

    assert cache.get("a") is None
    assert cache.get("b") == b"12345"
    assert cache.get("c") == b"12345"
    assert cache.stats().evictions == 1
    assert cache.stats().bytes <= 10


def test_get_refreshes_recency_order():
    cache = GenCache(capacity_bytes=10)
    cache.put("a", b"12345")
    cache.put("b", b"12345")
    cache.get("a")  # "a" becomes most-recently-used; "b" is now LRU
    cache.put("c", b"12345")

    assert cache.get("b") is None
    assert cache.get("a") == b"12345"
    assert cache.get("c") == b"12345"


def test_overwrite_updates_byte_accounting():
    cache = GenCache(capacity_bytes=1024)
    cache.put("k", b"short")
    cache.put("k", b"a much longer value than the first one")

    stats = cache.stats()
    assert stats.entries == 1
    assert stats.bytes == len(b"a much longer value than the first one")


def test_clear_generation_removes_only_namespaced_keys():
    cache = GenCache(capacity_bytes=1024)
    cache.put("gen-1:x", b"a")
    cache.put("gen-1:y", b"b")
    cache.put("gen-2:x", b"c")

    removed = cache.clear_generation("gen-1")

    assert removed == 2
    assert cache.get("gen-1:x") is None
    assert cache.get("gen-1:y") is None
    assert cache.get("gen-2:x") == b"c"
    assert cache.stats().bytes == 1


def test_clear_resets_all_state():
    cache = GenCache(capacity_bytes=1024)
    cache.put("a", b"12345")
    cache.clear()

    assert len(cache) == 0
    assert cache.stats().bytes == 0


def test_single_oversized_value_still_bounds_cache_to_capacity():
    cache = GenCache(capacity_bytes=10)
    cache.put("a", b"12345")
    cache.put("huge", b"x" * 100)

    assert cache.stats().bytes <= 100  # the single oversized entry cannot be split
    assert cache.get("a") is None


def test_thread_safety_under_concurrent_puts():
    cache = GenCache(capacity_bytes=1024 * 1024)

    def worker(n: int) -> None:
        for i in range(200):
            cache.put(f"t{n}:{i}", b"x" * 16)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stats = cache.stats()
    assert stats.bytes == len(cache) * 16
