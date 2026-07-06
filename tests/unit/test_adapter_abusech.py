from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from azazel_cti.core.clock import FixedClock
from azazel_cti.feeds.adapters.malwarebazaar import MalwarebazaarAdapter
from azazel_cti.feeds.adapters.threatfox import ThreatfoxAdapter
from azazel_cti.feeds.adapters.urlhaus import UrlhausAdapter
from azazel_cti.normalize.exclusions import ExclusionPolicy

from _feeds_support import make_intel_writer, make_local_writer

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "feeds"
NOW = datetime(2026, 7, 6, 0, 0, 0, tzinfo=timezone.utc)

URLHAUS_CONFIG = {
    "group": "abusech",
    "source_confidence": 85,
    "ttl": {"ip": "14d", "domain": "14d", "url": "30d", "hash": "365d"},
}
MALWAREBAZAAR_CONFIG = {"group": "abusech", "source_confidence": 80, "ttl": {"sha256": "365d"}}
THREATFOX_CONFIG = {
    "group": "abusech",
    "source_confidence": {"cap": 90},
    "ttl": {"ip": "14d", "domain": "14d", "url": "30d"},
}


def _read_sources(adapter) -> dict[tuple[str, str], dict[str, Any]]:
    def query(conn: Any):
        return conn.execute(
            "SELECT i.type, i.value, i.tags, s.source_confidence, s.expires_at, "
            "s.flagged_critical_infra FROM ioc i JOIN ioc_source s ON s.ioc_id = i.ioc_id"
        ).fetchall()

    rows = adapter._exec_intel(query)
    return {
        (r[0], r[1]): {
            "tags": json.loads(r[2]),
            "source_confidence": r[3],
            "expires_at": r[4],
            "flagged_critical_infra": r[5],
        }
        for r in rows
    }


def _quarantine_rows(adapter) -> list[tuple]:
    def query(conn: Any):
        return conn.execute("SELECT feed_id, reason, detail FROM feed_quarantine").fetchall()

    return adapter._exec_local(query)


def _urlhaus(tmp_path, policy: ExclusionPolicy | None = None) -> UrlhausAdapter:
    return UrlhausAdapter(
        "urlhaus",
        URLHAUS_CONFIG,
        make_intel_writer(tmp_path),
        make_local_writer(tmp_path),
        clock=FixedClock(NOW),
        fetch_bytes=(FIXTURES / "urlhaus_recent.csv").read_bytes,
        exclusion_policy=policy or ExclusionPolicy.empty(),
    )


def test_urlhaus_normalizes_and_upserts(tmp_path):
    adapter = _urlhaus(tmp_path)
    outcome = adapter.run()
    assert outcome.status == "applied"

    entries = _read_sources(adapter)
    assert ("url", "http://malware.example.com/payload.exe") in entries
    assert ("url", "http://evil.example.org/stage2") in entries
    assert not any(v == "not-a-url" for _, v in entries)

    url_entry = entries[("url", "http://malware.example.com/payload.exe")]
    assert url_entry["source_confidence"] == 85
    assert url_entry["expires_at"] == "2026-08-05T00:00:00Z"


def test_urlhaus_derived_hosts_are_discounted_and_tagged(tmp_path):
    adapter = _urlhaus(tmp_path)
    adapter.run()
    entries = _read_sources(adapter)

    derived_domain = entries[("domain", "malware.example.com")]
    assert derived_domain["source_confidence"] == 51
    assert "derived-host" in derived_domain["tags"]
    assert derived_domain["flagged_critical_infra"] == 0

    derived_ip = entries[("ip", "45.155.205.233")]
    assert derived_ip["source_confidence"] == 51
    assert "derived-host" in derived_ip["tags"]


def test_urlhaus_drops_bogon_derived_hosts(tmp_path):
    adapter = _urlhaus(tmp_path)
    adapter.run()
    entries = _read_sources(adapter)
    assert ("url", "http://10.0.0.5/internal.exe") in entries
    assert ("ip", "10.0.0.5") not in entries


def test_urlhaus_derived_host_never_flagged_critical_infra(tmp_path):
    policy = ExclusionPolicy([], [{"cidr": "45.155.205.0/24", "label": "hospital"}])
    adapter = _urlhaus(tmp_path, policy)
    adapter.run()
    entries = _read_sources(adapter)
    assert ("ip", "45.155.205.233") not in entries
    assert all(v["flagged_critical_infra"] == 0 for v in entries.values())


def test_malwarebazaar_hash_dump(tmp_path):
    adapter = MalwarebazaarAdapter(
        "malwarebazaar",
        MALWAREBAZAAR_CONFIG,
        make_intel_writer(tmp_path),
        make_local_writer(tmp_path),
        clock=FixedClock(NOW),
        fetch_bytes=(FIXTURES / "malwarebazaar_sha256.csv").read_bytes,
    )
    outcome = adapter.run()
    assert outcome.status == "applied"
    assert outcome.items_applied == 3

    entries = _read_sources(adapter)
    assert ("sha256", "a" * 64) in entries
    assert ("sha256", "b" * 64) in entries
    assert all(t == "sha256" for t, _ in entries)

    entry = entries[("sha256", "a" * 64)]
    assert entry["source_confidence"] == 80
    assert entry["expires_at"] == "2027-07-06T00:00:00Z"


def _threatfox(tmp_path, policy: ExclusionPolicy | None = None) -> ThreatfoxAdapter:
    return ThreatfoxAdapter(
        "threatfox",
        THREATFOX_CONFIG,
        make_intel_writer(tmp_path),
        make_local_writer(tmp_path),
        clock=FixedClock(NOW),
        fetch_bytes=(FIXTURES / "threatfox_export.json").read_bytes,
        exclusion_policy=policy or ExclusionPolicy.empty(),
    )


def test_threatfox_confidence_cap(tmp_path):
    adapter = _threatfox(tmp_path)
    adapter.run()
    entries = _read_sources(adapter)

    capped = entries[("ip", "91.219.29.81")]
    assert capped["source_confidence"] == 90

    uncapped = entries[("domain", "bad.example.net")]
    assert uncapped["source_confidence"] == 75


def test_threatfox_rejects_bogon_ips(tmp_path):
    adapter = _threatfox(tmp_path)
    adapter.run()
    entries = _read_sources(adapter)
    assert ("ip", "127.0.0.1") not in entries


def test_threatfox_derived_host_discount(tmp_path):
    adapter = _threatfox(tmp_path)
    adapter.run()
    entries = _read_sources(adapter)

    url_entry = entries[("url", "http://dropper.example.io/x.bin")]
    assert url_entry["source_confidence"] == 50

    derived = entries[("domain", "dropper.example.io")]
    assert derived["source_confidence"] == 30
    assert "derived-host" in derived["tags"]


def test_threatfox_accepts_hashes(tmp_path):
    adapter = _threatfox(tmp_path)
    adapter.run()
    entries = _read_sources(adapter)
    assert ("sha256", "d" * 64) in entries


def test_threatfox_critical_infra_flag_and_quarantine(tmp_path):
    policy = ExclusionPolicy([], [{"cidr": "91.219.29.0/24", "label": "water-plant"}])
    adapter = _threatfox(tmp_path, policy)
    adapter.run()
    entries = _read_sources(adapter)

    flagged = entries[("ip", "91.219.29.81")]
    assert flagged["flagged_critical_infra"] == 1

    rows = _quarantine_rows(adapter)
    assert any(r[1] == "critical_infra" and "91.219.29.81" in r[2] for r in rows)


def test_threatfox_rejects_own_infrastructure(tmp_path):
    policy = ExclusionPolicy(["91.219.29.0/24"], [])
    adapter = _threatfox(tmp_path, policy)
    adapter.run()
    entries = _read_sources(adapter)
    assert ("ip", "91.219.29.81") not in entries
    assert ("domain", "bad.example.net") in entries


def test_abusech_min_consecutive_polls_gate_applies(tmp_path):
    config = dict(THREATFOX_CONFIG)
    config["min_consecutive_polls"] = 2
    adapter = ThreatfoxAdapter(
        "threatfox",
        config,
        make_intel_writer(tmp_path),
        make_local_writer(tmp_path),
        clock=FixedClock(NOW),
        fetch_bytes=(FIXTURES / "threatfox_export.json").read_bytes,
        exclusion_policy=ExclusionPolicy.empty(),
    )
    first = adapter.run()
    assert first.status == "warming_up"
    assert _read_sources(adapter) == {}

    second = adapter.run()
    assert second.status == "applied"
    assert _read_sources(adapter) != {}
