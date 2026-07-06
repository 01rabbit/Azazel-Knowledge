from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from azazel_cti.core.clock import FixedClock
from azazel_cti.core.config import TrackedConfigLoader
from azazel_cti.correlate.campaign import match_campaign
from azazel_cti.correlate.pipeline import (
    AdvisoryResult,
    ContextRequest,
    ContextRequestTooLarge,
    ContextTimeout,
    Entity,
    run_context,
)
from azazel_cti.db import generations
from azazel_cti.db.repository import Repository, apply_migrations, entity_key

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"
LOADER = TrackedConfigLoader(REPO_CONFIG)

QUERY_AS_OF = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)
CLOCK = FixedClock(QUERY_AS_OF)
NOW = "2026-07-06T11:59:30Z"


def _make_local_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    conn.execute(
        "INSERT INTO local_meta (key, value) VALUES ('local_generation', '3')"
    )
    conn.execute(
        "INSERT INTO local_meta (key, value) VALUES ('stats_generation', '7')"
    )
    conn.commit()
    conn.close()


def _make_intel_generation(data_db_dir: Path, n: int) -> Path:
    intel_path = generations.build_next_generation(data_db_dir)
    conn = sqlite3.connect(intel_path)
    apply_migrations(conn, "intel")
    rows = [
        (1, "ip", "203.0.113.7", "2026-06-01T00:00:00Z", "2026-07-02T00:00:00Z", 80.0),
        (2, "ip", "198.51.100.9", "2026-06-01T00:00:00Z", "2026-07-02T00:00:00Z", 40.0),
        (3, "domain", "evil.example.com", "2026-06-01T00:00:00Z", "2026-07-04T00:00:00Z", 70.0),
        (4, "asn", "AS64500", "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", 80.0),
        (5, "ip", "192.0.2.99", "2026-06-01T00:00:00Z", "2026-07-02T00:00:00Z", 55.0),
    ]
    for ioc_id, type_, value, first, last, agg in rows:
        conn.execute(
            "INSERT INTO ioc (ioc_id, type, value, first_seen, last_seen, "
            "agg_raw_confidence, agg_computed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ioc_id, type_, value, first, last, agg, last),
        )
    sources = [
        (1, "urlhaus", 85),
        (1, "threatfox", 80),
        (3, "urlhaus", 85),
        (4, "spamhaus_asndrop", 90),
        (5, "urlhaus", 85),
    ]
    for ioc_id, feed_id, confidence in sources:
        conn.execute(
            "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, "
            "first_seen, last_seen, intel_generation) VALUES "
            "(?, ?, ?, '2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 1)",
            (ioc_id, feed_id, confidence),
        )
    # 192.0.2.0/24 containment range referencing ioc 5
    conn.execute(
        "INSERT INTO ioc_cidr (tier, range_start, range_end, ioc_id, feed_id) "
        "VALUES ('/24', ?, ?, 5, 'urlhaus')",
        (int.from_bytes(bytes([192, 0, 2, 0]), "big"),
         int.from_bytes(bytes([192, 0, 2, 255]), "big")),
    )
    conn.execute(
        "INSERT INTO kev (cve_id, catalog_version, date_added) VALUES "
        "('CVE-2024-0001', 'v1', '2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO stats_meta (key, value) VALUES ('intel_generation', ?)",
        (str(n),),
    )
    conn.commit()
    conn.close()
    generations.swap_current(data_db_dir, n)
    return intel_path


def _seed_local_stats(local_db_path: Path, key: bytes, *, updated_at: str = NOW,
                      event_count: int = 14, trend: float = 0.3) -> None:
    conn = sqlite3.connect(local_db_path)
    conn.execute(
        "INSERT INTO observation_stats (entity_key, window_start, window_end, "
        "event_count, trend, stats_generation, updated_at) VALUES "
        "(?, '2026-07-05T00:00:00Z', '2026-07-06T00:00:00Z', ?, ?, 7, ?)",
        (key, event_count, trend, updated_at),
    )
    conn.execute(
        "INSERT INTO reputation (entity_key, score, updated_at) VALUES (?, 55.0, ?)",
        (key, updated_at),
    )
    conn.commit()
    conn.close()


@pytest.fixture()
def env(tmp_path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    _make_intel_generation(data_db_dir, 1)
    repo = Repository(local_db_path, data_db_dir, pool_size=2)
    yield repo, local_db_path
    repo.close()


def _request(**overrides) -> ContextRequest:
    base = dict(
        entities=[Entity("ip", "203.0.113.7")],
        event={
            "kind": "eve_alert",
            "event_types": ["eve_alert"],
            "alert": {"category": "scan"},
            "cves": ["CVE-2024-0001"],
            "asn": "64500",
        },
        edge_id="edge-1",
        actor_key="actor-1",
    )
    base.update(overrides)
    return ContextRequest(**base)


def _canonical(result: AdvisoryResult) -> str:
    return json.dumps(
        {
            "threat_score": result.threat_score,
            "confidence": result.confidence,
            "reason": list(result.reason),
            "confidence_reason": list(result.confidence_reason),
            "recommendation": result.recommendation,
            "threat_context": result.threat_context,
            "source_freshness": result.source_freshness,
            "multi_ioc_scope": result.multi_ioc_scope,
            "content_hash": result.content_hash,
            "determinism": result.determinism,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def test_full_context_answer_shape(env):
    repo, local_db_path = env
    _seed_local_stats(local_db_path, entity_key("ip", "203.0.113.7"))

    result = run_context(repo, LOADER, _request(), CLOCK)

    assert [l["component"] for l in result.reason] == [
        "ioc_match", "history", "attack_map", "campaign", "geo_asn", "cve_exploited",
    ]
    assert result.threat_score > 0
    assert result.confidence > 0
    assert result.multi_ioc_scope["matched_count"] == 1
    assert result.multi_ioc_scope["primary_ioc_id"] == 1
    assert result.threat_context["history"]["prior_observations"] == 14
    assert result.recommendation["action"] in {
        "isolate", "throttle", "redirect", "observe"
    }
    assert "advisory" in result.advisory_notice.lower()
    assert result.determinism["stats_generation"] == 7
    assert result.determinism["local_generation"] == 3
    assert result.determinism["intel_generation"] == 1

    by_name = {l["component"]: l for l in result.reason}
    assert by_name["cve_exploited"]["contribution"] > 0
    assert by_name["geo_asn"]["contribution"] > 0
    assert by_name["attack_map"]["contribution"] > 0
    assert by_name["campaign"]["contribution"] == 0  # no campaign tables


def test_pipeline_determinism_three_runs_byte_identical_except_advisory_id(env):
    repo, local_db_path = env
    _seed_local_stats(local_db_path, entity_key("ip", "203.0.113.7"))

    results = [run_context(repo, LOADER, _request(), CLOCK) for _ in range(3)]
    canonicals = [_canonical(r) for r in results]
    assert canonicals[0] == canonicals[1] == canonicals[2]
    assert len({r.advisory_id for r in results}) == 3
    assert len({r.content_hash for r in results}) == 1


def test_different_query_as_of_changes_output(env):
    repo, local_db_path = env
    a = run_context(repo, LOADER, _request(), CLOCK)
    later = FixedClock(datetime(2026, 8, 6, 12, 0, 0, tzinfo=timezone.utc))
    b = run_context(repo, LOADER, _request(), later)
    assert a.content_hash != b.content_hash
    line_a = next(l for l in a.reason if l["component"] == "ioc_match")
    line_b = next(l for l in b.reason if l["component"] == "ioc_match")
    assert line_a["freshness"] != line_b["freshness"]


def test_deadline_exceeded_raises_context_timeout_with_no_partial_result(env):
    repo, _ = env
    with pytest.raises(ContextTimeout):
        run_context(
            repo, LOADER, _request(), CLOCK, deadline=time.monotonic() - 1.0
        )


def test_entity_cap_enforced(env):
    repo, _ = env
    entities = [Entity("ip", f"10.0.{i // 256}.{i % 256}") for i in range(65)]
    with pytest.raises(ContextRequestTooLarge):
        run_context(repo, LOADER, _request(entities=entities), CLOCK)


def test_multi_ioc_primary_is_argmax_conf_times_freshness(env):
    repo, _ = env
    request = _request(
        entities=[Entity("ip", "203.0.113.7"), Entity("ip", "198.51.100.9")]
    )
    result = run_context(repo, LOADER, request, CLOCK)
    assert result.multi_ioc_scope["matched_count"] == 2
    assert result.multi_ioc_scope["primary_ioc_id"] == 1  # agg 80 beats 40


def test_multi_ioc_tie_breaks_by_entity_key_asc(tmp_path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    intel_path = generations.build_next_generation(data_db_dir)
    conn = sqlite3.connect(intel_path)
    apply_migrations(conn, "intel")
    for ioc_id, value in ((1, "203.0.113.7"), (2, "198.51.100.9")):
        conn.execute(
            "INSERT INTO ioc (ioc_id, type, value, first_seen, last_seen, "
            "agg_raw_confidence) VALUES (?, 'ip', ?, '2026-06-01T00:00:00Z', "
            "'2026-07-02T00:00:00Z', 80.0)",
            (ioc_id, value),
        )
    conn.commit()
    conn.close()
    generations.swap_current(data_db_dir, 1)

    keys = {
        1: entity_key("ip", "203.0.113.7").hex(),
        2: entity_key("ip", "198.51.100.9").hex(),
    }
    expected = min(keys, key=lambda ioc_id: keys[ioc_id])

    repo = Repository(local_db_path, data_db_dir, pool_size=1)
    try:
        request = _request(
            entities=[Entity("ip", "203.0.113.7"), Entity("ip", "198.51.100.9")],
            event={},
        )
        result = run_context(repo, LOADER, request, CLOCK)
        assert result.multi_ioc_scope["primary_ioc_id"] == expected
    finally:
        repo.close()


def test_cidr_containment_match(env):
    repo, _ = env
    request = _request(entities=[Entity("ip", "192.0.2.50")], event={})
    result = run_context(repo, LOADER, request, CLOCK)
    assert result.multi_ioc_scope["matched_count"] == 1
    match = result.threat_context["ioc_matches"][0]
    assert match["match_tier"] == "cidr_/24"
    assert match["value"] == "192.0.2.99"


def test_domain_suffix_walk(env):
    repo, _ = env
    request = _request(
        entities=[Entity("domain", "deep.sub.evil.example.com")], event={}
    )
    result = run_context(repo, LOADER, request, CLOCK)
    assert result.multi_ioc_scope["matched_count"] == 1
    match = result.threat_context["ioc_matches"][0]
    assert match["value"] == "evil.example.com"
    assert match["match_tier"] == "domain_suffix"


def test_no_match_still_emits_complete_reason(env):
    repo, _ = env
    request = _request(entities=[Entity("ip", "172.16.99.99")], event={})
    result = run_context(repo, LOADER, request, CLOCK)
    assert result.multi_ioc_scope["matched_count"] == 0
    assert result.multi_ioc_scope["primary_ioc_id"] is None
    assert len(result.reason) == 6
    assert all(l["contribution"] == 0 for l in result.reason)
    assert len(result.confidence_reason) == 4
    cve = next(l for l in result.reason if l["component"] == "cve_exploited")
    assert cve["applicable"] is False


def test_stale_stats_force_history_and_local_corroboration(env):
    repo, local_db_path = env
    _seed_local_stats(
        local_db_path,
        entity_key("ip", "203.0.113.7"),
        updated_at="2026-07-06T11:00:00Z",  # 59 min before query_as_of
    )
    result = run_context(repo, LOADER, _request(), CLOCK)
    history = next(l for l in result.reason if l["component"] == "history")
    assert history["contribution"] == 0
    assert "max_staleness_s" in history["detail"]
    local = next(
        l
        for l in result.confidence_reason
        if l["component"] == "local_corroboration"
    )
    assert local["contribution"] == 0


def test_burst_guard_excludes_over_cap_events(env):
    repo, local_db_path = env
    _seed_local_stats(
        local_db_path,
        entity_key("ip", "203.0.113.7"),
        event_count=700,
    )
    result = run_context(repo, LOADER, _request(), CLOCK)
    history = next(l for l in result.reason if l["component"] == "history")
    assert "burst_excluded 200" in history["detail"]
    assert result.threat_context["history"]["prior_observations"] == 700


def test_untagged_asn_yields_zero_geo_contribution(env):
    repo, _ = env
    request = _request(
        event={"kind": "flow", "asn": "65001"},
        entities=[Entity("ip", "203.0.113.7")],
    )
    result = run_context(repo, LOADER, request, CLOCK)
    geo = next(l for l in result.reason if l["component"] == "geo_asn")
    assert geo["contribution"] == 0
    assert "AS65001" in geo["detail"]


def test_attack_map_line_discloses_rules_scanned(env):
    repo, _ = env
    result = run_context(repo, LOADER, _request(), CLOCK)
    attack = next(l for l in result.reason if l["component"] == "attack_map")
    assert "rules_scanned 6/6" in attack["detail"]
    assert result.threat_context["attack_mapping"] == [{"technique": "T1595.002"}]


def test_campaign_absent_tables_degrade_to_zero(env):
    repo, _ = env
    with repo.connection() as conn:
        result = match_campaign(
            conn, [entity_key("ip", "203.0.113.7")], ["T1595.002"], QUERY_AS_OF
        )
    assert result.matched is False
    assert result.ioc_overlap == 0.0


def test_campaign_tables_present_produce_match(tmp_path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    intel_path = _make_intel_generation(data_db_dir, 1)

    key = entity_key("ip", "203.0.113.7")
    conn = sqlite3.connect(intel_path)
    conn.execute(
        "CREATE TABLE campaign (campaign_id TEXT PRIMARY KEY, name TEXT, "
        "actor TEXT, last_seen TEXT)"
    )
    conn.execute(
        "CREATE TABLE campaign_ioc (campaign_id TEXT, entity_key BLOB)"
    )
    conn.execute(
        "CREATE TABLE campaign_technique (campaign_id TEXT, technique_id TEXT)"
    )
    conn.execute(
        "INSERT INTO campaign VALUES ('c1', 'OpTest', 'APT-00', "
        "'2026-07-01T00:00:00Z')"
    )
    conn.execute("INSERT INTO campaign_ioc VALUES ('c1', ?)", (key,))
    conn.execute("INSERT INTO campaign_technique VALUES ('c1', 'T1595.002')")
    conn.commit()
    conn.close()

    repo = Repository(local_db_path, data_db_dir, pool_size=1)
    try:
        result = run_context(repo, LOADER, _request(), CLOCK)
        campaign_line = next(
            l for l in result.reason if l["component"] == "campaign"
        )
        assert campaign_line["contribution"] > 0
        assert result.threat_context["campaign"]["name"] == "OpTest"
        assert result.threat_context["campaign"]["actor"] == "APT-00"
    finally:
        repo.close()


def test_invalid_entities_are_dropped_not_fatal(env):
    repo, _ = env
    request = _request(
        entities=[Entity("ip", "not-an-ip"), Entity("ip", "203.0.113.7")],
        event={},
    )
    result = run_context(repo, LOADER, request, CLOCK)
    assert result.multi_ioc_scope["matched_count"] == 1


def test_rejected_alternatives_carry_actual_numbers(env):
    repo, _ = env
    request = _request(entities=[Entity("ip", "172.16.99.99")], event={})
    result = run_context(repo, LOADER, request, CLOCK)
    assert result.recommendation["action"] == "observe"
    rejected = result.recommendation["rejected_alternatives"]
    assert {r["action"] for r in rejected} == {"isolate", "throttle", "redirect"}
    for r in rejected:
        assert str(result.threat_score) in r["why_not"] or str(
            result.confidence
        ) in r["why_not"]
