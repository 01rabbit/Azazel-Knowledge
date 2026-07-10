from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from azazel_grimoire.core.clock import FixedClock
from azazel_grimoire.feeds.adapters.kev import KevAdapter
from azazel_grimoire.feeds.base import FeedError

from _feeds_support import make_intel_writer

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "feeds"
NOW = datetime(2026, 7, 6, 0, 0, 0, tzinfo=timezone.utc)


def _make_adapter(tmp_path, fixture_name: str) -> KevAdapter:
    intel = make_intel_writer(tmp_path)
    fixture = FIXTURES / fixture_name
    return KevAdapter(
        "cisa_kev",
        {"kind": "cisa_kev", "group": "cisa"},
        intel,
        clock=FixedClock(NOW),
        fetch_bytes=fixture.read_bytes,
    )


def _read_kev(adapter: KevAdapter) -> list[tuple]:
    def query(conn: Any):
        return conn.execute(
            "SELECT cve_id, catalog_version, date_added, vendor_project FROM kev ORDER BY cve_id"
        ).fetchall()

    return adapter._exec_intel(query)


def test_kev_import_populates_catalog(tmp_path):
    adapter = _make_adapter(tmp_path, "kev_catalog.json")
    outcome = adapter.run()
    assert outcome.status == "applied"
    assert outcome.items_applied == 3

    rows = _read_kev(adapter)
    assert [r[0] for r in rows] == ["CVE-2023-9999", "CVE-2024-0001", "CVE-2025-1111"]
    assert all(r[1] == "2026.07.01" for r in rows)
    by_id = {r[0]: r for r in rows}
    assert by_id["CVE-2024-0001"][2] == "2026-06-15"
    assert by_id["CVE-2024-0001"][3] == "ExampleVendor"


def test_kev_full_replace_swaps_catalog_version(tmp_path):
    adapter = _make_adapter(tmp_path, "kev_catalog.json")
    adapter.run()

    adapter._fetch_bytes = (FIXTURES / "kev_catalog_v2.json").read_bytes
    outcome = adapter.run()
    assert outcome.status == "applied"

    rows = _read_kev(adapter)
    assert [r[0] for r in rows] == ["CVE-2026-2222"]
    assert rows[0][1] == "2026.07.05"


def test_kev_never_touches_ioc_tables(tmp_path):
    adapter = _make_adapter(tmp_path, "kev_catalog.json")
    adapter.run()

    def query(conn: Any):
        return (
            conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM ioc_source").fetchone()[0],
        )

    ioc_count, source_count = adapter._exec_intel(query)
    assert (ioc_count, source_count) == (0, 0)


def test_kev_missing_catalog_version_is_an_error(tmp_path):
    adapter = _make_adapter(tmp_path, "kev_catalog.json")
    adapter._fetch_bytes = lambda: json.dumps({"vulnerabilities": []}).encode()
    with pytest.raises(FeedError):
        adapter.run()


def test_kev_skips_incomplete_and_oversized_entries(tmp_path):
    adapter = _make_adapter(tmp_path, "kev_catalog.json")
    document = {
        "catalogVersion": "2026.07.06",
        "vulnerabilities": [
            {"cveID": "CVE-2026-0001", "dateAdded": "2026-07-06"},
            {"cveID": "CVE-2026-0002"},
            {"dateAdded": "2026-07-06"},
            {"cveID": "CVE-2026-0003", "dateAdded": "2026-07-06", "shortDescription": "x" * 5000},
        ],
    }
    parsed = adapter.parse(json.dumps(document).encode())
    valid = adapter.validate(parsed)
    assert [row["cve_id"] for row in valid] == ["CVE-2026-0001"]
