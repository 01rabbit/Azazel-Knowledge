from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from _api_support import add_api_client, auth_header, make_client
from azazel_cti.core.clock import FixedClock
from azazel_cti.core.config import TrackedConfigLoader
from azazel_cti.correlate.pipeline import ContextRequest, Entity, run_context
from azazel_cti.db import generations
from azazel_cti.db.behavior import behavior_pattern_id
from azazel_cti.db.repository import Repository, apply_migrations, entity_key

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"
LOADER = TrackedConfigLoader(REPO_CONFIG)
QUERY_AS_OF = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)
CLOCK = FixedClock(QUERY_AS_OF)
LIMITATIONS = [
    "Behavioral similarity is not attribution.",
    "AI usage is not directly proven.",
    "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter.",
]
POSTURE_MAP = {
    "simple_scanner": "observe",
    "scripted_automation": "delay",
    "adaptive_probe": "delay",
    "decoy_engaged": "decoy",
    "disengaged_after_friction": "no_change",
    "unknown": "unknown",
}


def _make_local_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    conn.execute("INSERT INTO local_meta (key, value) VALUES ('local_generation', '3')")
    conn.execute("INSERT INTO local_meta (key, value) VALUES ('stats_generation', '7')")
    conn.commit()
    conn.close()


def _make_intel_generation(data_db_dir: Path, n: int = 1) -> None:
    intel_path = generations.build_next_generation(data_db_dir)
    conn = sqlite3.connect(intel_path)
    apply_migrations(conn, "intel")
    conn.execute(
        "INSERT INTO ioc (ioc_id, type, value, first_seen, last_seen, agg_raw_confidence, agg_computed_at) "
        "VALUES (1, 'ip', '203.0.113.7', '2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 80.0, '2026-07-02T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, intel_generation) "
        "VALUES (1, 'urlhaus', 85, '2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 1)"
    )
    conn.execute(
        "INSERT INTO kev (cve_id, catalog_version, date_added) VALUES "
        "('CVE-2024-0001', 'v1', '2026-01-01T00:00:00Z')"
    )
    conn.execute("INSERT INTO stats_meta (key, value) VALUES ('intel_generation', ?)", (str(n),))
    conn.commit()
    conn.close()
    generations.swap_current(data_db_dir, n)


def _seed_local_stats(local_db_path: Path) -> None:
    key = entity_key("ip", "203.0.113.7")
    conn = sqlite3.connect(local_db_path)
    conn.execute(
        "INSERT INTO observation_stats (entity_key, window_start, window_end, event_count, trend, stats_generation, updated_at) "
        "VALUES (?, '2026-07-05T00:00:00Z', '2026-07-06T00:00:00Z', 14, 0.3, 7, '2026-07-06T11:59:30Z')",
        (key,),
    )
    conn.execute(
        "INSERT INTO reputation (entity_key, score, updated_at) VALUES (?, 55.0, '2026-07-06T11:59:30Z')",
        (key,),
    )
    conn.commit()
    conn.close()


def _seed_behavioral_pattern(
    local_db_path: Path,
    *,
    actor_key_value: str = "actor-1",
    behavior_class: str = "adaptive_probe",
    confidence: int = 68,
    novelty_score: int = 28,
    repeatability_score: int = 0,
    similarity: float = 0.84,
    repeatability: int = 72,
) -> str:
    conn = sqlite3.connect(local_db_path)
    conn.execute(
        """
        INSERT INTO observation (
            event_id, edge_id, kind, observed_at, entity_key, entities, raw, created_at
        ) VALUES (
            'evt-1', 'edge-1', 'http', '2026-07-06T00:00:00.000Z', NULL,
            '["203.0.113.7"]', '{"path":"/login"}', '2026-07-06T00:00:00.000Z'
        )
        """
    )
    conn.execute(
        """
        INSERT INTO reaction (
            edge_id, actor_key, action_applied, applied_at, reaction,
            reaction_window_s, events_in_window, classifier, classifier_version,
            evidence_refs, evidence_modality_count, trust_tier, advisory_id,
            advisory_linkage, created_at
        ) VALUES (
            'edge-1', ?, 'throttle', '2026-07-06T00:00:01.000Z', 'shifted_port',
            60, 3, 'ladder-v1', '1', '[1]', 1, 'provisional', NULL, 'none',
            '2026-07-06T00:00:01.000Z'
        )
        """,
        (actor_key_value,),
    )
    observation_id = conn.execute("SELECT observation_id FROM observation").fetchone()[0]
    reaction_id = conn.execute("SELECT reaction_id FROM reaction").fetchone()[0]
    pattern_id = behavior_pattern_id(
        "edge-1",
        actor_key_value,
        "2026-07-06T00:00:00.000Z",
        "2026-07-06T00:10:00.000Z",
        "bpg-1",
    )
    conn.execute(
        """
        INSERT INTO behavior_pattern (
            pattern_id, behavior_generation, version, actor_key, actor_cluster_key,
            edge_id, observation_start, observation_end, action_applied,
            reaction_sequence, reaction_window_s, behavior_class, confidence,
            novelty_score, repeatability_score, suspected_stage, related_iocs,
            related_ttps, generated_at, generator_version, behavior_config_hash, provenance
        ) VALUES (
            ?, 7, 1, ?, 'cluster-1', 'edge-1', '2026-07-06T00:00:00.000Z',
            '2026-07-06T00:10:00.000Z', 'throttle', '["shifted_port","followed_decoy"]',
            60, ?, ?, ?, ?, 'reconnaissance', '["203.0.113.7"]', '["T1595"]',
            '2026-07-06T00:10:01.000Z', 'bpg-1', 'cfg-1', '{"builder":"unit"}'
        )
        """,
        (
            pattern_id,
            actor_key_value,
            behavior_class,
            confidence,
            novelty_score,
            repeatability_score,
        ),
    )
    conn.execute(
        """
        INSERT INTO behavior_pattern_evidence (
            pattern_id, behavior_generation, evidence_type, evidence_id, role
        ) VALUES (?, 7, 'observation', ?, 'supporting')
        """,
        (pattern_id, str(observation_id)),
    )
    conn.execute(
        """
        INSERT INTO behavior_pattern_evidence (
            pattern_id, behavior_generation, evidence_type, evidence_id, role
        ) VALUES (?, 7, 'reaction', ?, 'source')
        """,
        (pattern_id, str(reaction_id)),
    )
    conn.execute(
        """
        INSERT INTO behavior_pattern_similarity (
            pattern_id, behavior_generation, other_pattern_id, similarity,
            repeatability, shared_features, differences, evidence_refs
        ) VALUES (?, 7, 'bp-prior', ?, ?, '["same-action"]', '["new-decoy"]', '["1","2"]')
        """,
        (pattern_id, similarity, repeatability),
    )
    conn.execute(
        "INSERT OR REPLACE INTO behavior_meta (key, value) VALUES ('current_behavior_generation', '7')"
    )
    conn.commit()
    conn.close()
    return pattern_id


def _request(actor_key_value: str = "actor-1") -> ContextRequest:
    return ContextRequest(
        entities=[Entity("ip", "203.0.113.7")],
        event={
            "kind": "eve_alert",
            "event_types": ["eve_alert"],
            "alert": {"category": "scan"},
            "cves": ["CVE-2024-0001"],
            "asn": "64500",
        },
        edge_id="edge-1",
        actor_key=actor_key_value,
    )


@pytest.fixture()
def env(tmp_path: Path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    _make_intel_generation(data_db_dir)
    _seed_local_stats(local_db_path)
    repo = Repository(local_db_path, data_db_dir, pool_size=2)
    yield repo, local_db_path
    repo.close()


def test_behavioral_cti_block_present_for_matching_actor(env) -> None:
    repo, local_db_path = env
    pattern_id = _seed_behavioral_pattern(local_db_path)

    result = run_context(repo, LOADER, _request(), CLOCK)

    behavioral = result.threat_context["behavioral_cti"]
    assert behavioral == {
        "behavior_seen_before": True,
        "behavior_class": "adaptive_probe",
        "pattern_id": pattern_id,
        "similarity": 0.84,
        "repeatability_score": 72,
        "novelty_score": 28,
        "suggested_posture": "delay",
        "confidence": 68,
        "evidence_refs": ["obs-1", "rxn-1"],
        "explanation_short": (
            "Observed adaptive probe behavior matched a stored pattern with "
            "precomputed similarity 0.84 and linked evidence."
        ),
        "limitations": LIMITATIONS,
        "behavior_generation": 7,
        "generator_version": "bpg-1",
        "behavior_config_hash": "cfg-1",
    }


def test_behavioral_cti_omitted_when_actor_does_not_match_and_context_is_unchanged(env) -> None:
    repo, local_db_path = env
    baseline = run_context(repo, LOADER, _request(), CLOCK)

    _seed_behavioral_pattern(local_db_path, actor_key_value="actor-2")
    result = run_context(repo, LOADER, _request(), CLOCK)

    assert "behavioral_cti" not in result.threat_context
    assert result.threat_context == baseline.threat_context
    assert result.threat_score == baseline.threat_score
    assert result.confidence == baseline.confidence
    assert result.reason == baseline.reason
    assert result.confidence_reason == baseline.confidence_reason
    assert result.advisory_notice == baseline.advisory_notice
    assert result.content_hash == baseline.content_hash


@pytest.mark.parametrize(
    ("behavior_class", "expected_posture"),
    list(POSTURE_MAP.items()),
)
def test_behavioral_cti_suggested_posture_uses_deterministic_mapping(
    env, behavior_class: str, expected_posture: str
) -> None:
    repo, local_db_path = env
    _seed_behavioral_pattern(local_db_path, behavior_class=behavior_class)

    result = run_context(repo, LOADER, _request(), CLOCK)

    behavioral = result.threat_context["behavioral_cti"]
    assert behavioral["suggested_posture"] == expected_posture
    assert behavioral["suggested_posture"] in set(POSTURE_MAP.values())
    assert "action" not in behavioral


def test_behavioral_cti_is_additive_and_preserves_scored_fields(env) -> None:
    repo, local_db_path = env
    baseline = run_context(repo, LOADER, _request(), CLOCK)
    _seed_behavioral_pattern(local_db_path)

    result = run_context(repo, LOADER, _request(), CLOCK)

    assert result.threat_score == baseline.threat_score
    assert result.confidence == baseline.confidence
    assert result.reason == baseline.reason
    assert result.confidence_reason == baseline.confidence_reason
    assert result.advisory_notice == baseline.advisory_notice
    assert result.content_hash == baseline.content_hash
    assert result.threat_context["ioc_matches"] == baseline.threat_context["ioc_matches"]
    assert result.threat_context["campaign"] == baseline.threat_context["campaign"]
    assert result.threat_context["attack_mapping"] == baseline.threat_context["attack_mapping"]
    assert result.threat_context["pattern_match"] == baseline.threat_context["pattern_match"]
    assert result.threat_context["history"] == baseline.threat_context["history"]


def test_behavioral_cti_lookup_error_is_omitted_and_context_api_still_returns_200(tmp_path: Path) -> None:
    client, _, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])

    def _boom(*args, **kwargs):
        raise sqlite3.OperationalError("behavior lookup failed")

    client.app.state.repo.get_behavior_patterns = _boom
    resp = client.post(
        "/v1/context",
        json={
            "entities": [{"type": "ip", "value": "203.0.113.7"}],
            "event": {"kind": "eve_alert", "event_types": ["eve_alert"], "cves": ["CVE-2024-0001"]},
            "edge_id": "edge-1",
            "actor_key": "actor-1",
        },
        headers=auth_header(token),
    )

    assert resp.status_code == 200
    body = resp.json()
    assert "behavioral_cti" not in body["threat_context"]
    assert body["reason"]
    assert body["confidence_reason"]
    assert "threat_score" in body
    assert "confidence" in body


def test_behavioral_cti_subdeadline_expiry_omits_block_and_context_api_still_returns_200(
    tmp_path: Path,
) -> None:
    client, _, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    _seed_behavioral_pattern(local_db_path)
    original = client.app.state.repo.get_behavior_patterns

    def _slow(*args, **kwargs):
        time.sleep(0.03)
        return original(*args, **kwargs)

    client.app.state.repo.get_behavior_patterns = _slow
    resp = client.post(
        "/v1/context",
        json={
            "entities": [{"type": "ip", "value": "203.0.113.7"}],
            "event": {"kind": "eve_alert", "event_types": ["eve_alert"], "cves": ["CVE-2024-0001"]},
            "edge_id": "edge-1",
            "actor_key": "actor-1",
        },
        headers=auth_header(token),
    )

    assert resp.status_code == 200
    body = resp.json()
    assert "behavioral_cti" not in body["threat_context"]
    assert body["reason"]
    assert body["confidence_reason"]
    assert body["advisory_notice"] == LIMITATIONS[-1]


def test_behavior_pattern_lookup_uses_actor_generation_index(tmp_path: Path) -> None:
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")

    plan_rows = conn.execute(
        """
        EXPLAIN QUERY PLAN
        SELECT pattern_id, behavior_generation, version, actor_key, actor_cluster_key,
               edge_id, observation_start, observation_end, action_applied, reaction_sequence,
               reaction_window_s, behavior_class, confidence, novelty_score,
               repeatability_score, suspected_stage, related_iocs, related_ttps,
               generated_at, generator_version, behavior_config_hash, provenance
        FROM behavior_pattern
        WHERE actor_key = ? AND behavior_generation = ?
        ORDER BY observation_start ASC, pattern_id ASC
        """,
        ("actor-1", 7),
    ).fetchall()

    details = " | ".join(str(row[3]) for row in plan_rows)
    conn.close()
    assert "idx_behavior_pattern_actor" in details
    assert "SCAN behavior_pattern" not in details
