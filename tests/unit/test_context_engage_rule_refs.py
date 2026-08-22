"""`engage_refs` / `rule_refs` advisory sub-context tests (#60/#61 usage seam).

Covers both layers:

* the pure, deterministic lookup functions in
  `correlate.engage_rule_refs` against a directly-attached intel DB
  (case-normalization, match-gating, determinism, rule-identity-only), and
* the `POST /v1/context` wire contract end to end through the same
  `_api_support` harness the rest of `tests/unit/test_api_context.py` uses.

Also proves the ADR-0012/ADR-0013 determinism boundary directly: seeding
the new intel-tier tables never perturbs `run_context`'s
`threat_score`/`confidence`/`reason`/`content_hash`, because `run_context`
itself never reads them -- the enrichment is wired in only at the router,
strictly after scoring has already produced its `AdvisoryResult`.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.core.config import TrackedConfigLoader
from azazel_knowledge.correlate.engage_rule_refs import (
    MAX_RULE_REFS,
    canonicalize_technique,
    lookup_engage_refs,
    lookup_rule_refs,
)
from azazel_knowledge.correlate.pipeline import ContextRequest, Entity, run_context
from azazel_knowledge.db import generations
from azazel_knowledge.db.repository import Repository, apply_migrations

from _api_support import add_api_client, auth_header, make_client

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"
LOADER = TrackedConfigLoader(REPO_CONFIG)
QUERY_AS_OF = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)
CLOCK = FixedClock(QUERY_AS_OF)

# `alert.category: scan` matches attack-map.yaml's `network_scan` rule ->
# technique T1595.002 (mirrors test_pipeline.py's own event and the
# docs/api.md `attack_mapping` example).
_SCAN_EVENT = {
    "kind": "eve_alert",
    "event_types": ["eve_alert"],
    "alert": {"category": "scan"},
}


# --------------------------------------------------------------------------
# Low-level intel DB seeding helpers (raw sqlite3, mirrors _api_support.py /
# test_pipeline.py's own seeding style).
# --------------------------------------------------------------------------


def _fresh_intel_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    apply_migrations(conn, "intel")
    conn.commit()
    conn.close()


def _attach(intel_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("ATTACH DATABASE ? AS intel", (str(intel_path),))
    return conn


def _seed_engage(
    intel_path: Path, rows: list[tuple[str, str, str, str]]
) -> None:
    """rows: (activity_id, name, approach, technique_id)."""
    conn = sqlite3.connect(intel_path)
    for activity_id, name, approach, technique_id in rows:
        conn.execute(
            "INSERT OR IGNORE INTO engage_activity "
            "(activity_id, name, approach, engage_version) VALUES (?, ?, ?, 'v1')",
            (activity_id, name, approach),
        )
        conn.execute(
            "INSERT INTO engage_attack_map "
            "(technique_id, activity_id, engage_version) VALUES (?, ?, 'v1')",
            (technique_id, activity_id),
        )
    conn.commit()
    conn.close()


def _seed_sigma(
    intel_path: Path, rows: list[tuple[str, str, list[str], str]]
) -> None:
    """rows: (rule_uid, title, attack_refs, source_url)."""
    conn = sqlite3.connect(intel_path)
    for rule_uid, title, attack_refs, source_url in rows:
        conn.execute(
            "INSERT INTO sigma_rule_corpus "
            "(rule_uid, title, raw_yaml, tags, attack_refs, license, source_url, "
            "corpus_version) VALUES (?, ?, ?, '[]', ?, 'DRL 1.1', ?, 'v1')",
            (rule_uid, title, f"title: {title}\n", json.dumps(attack_refs), source_url),
        )
    conn.commit()
    conn.close()


def _seed_yara(
    intel_path: Path, rows: list[tuple[str, list[str], str]]
) -> None:
    """rows: (rule_name, attack_refs, source_url)."""
    conn = sqlite3.connect(intel_path)
    for rule_name, attack_refs, source_url in rows:
        conn.execute(
            "INSERT INTO yara_rule_corpus "
            "(rule_name, raw_text, attack_refs, license, source_url, corpus_version) "
            "VALUES (?, ?, ?, 'Unrestricted', ?, 'v1')",
            (rule_name, f"rule {rule_name} {{ condition: true }}", json.dumps(attack_refs), source_url),
        )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# canonicalize_technique
# --------------------------------------------------------------------------


def test_canonicalize_technique_forms():
    assert canonicalize_technique("T1059.001") == "T1059.001"
    assert canonicalize_technique("attack.t1059.001") == "T1059.001"
    assert canonicalize_technique("ATTACK.T1059.001") == "T1059.001"
    assert canonicalize_technique("t1105") == "T1105"
    assert canonicalize_technique("T1105") == "T1105"
    assert canonicalize_technique("attack.t1105") == "T1105"


def test_canonicalize_technique_empty_and_none():
    assert canonicalize_technique(None) is None
    assert canonicalize_technique("") is None
    assert canonicalize_technique("   ") is None


# --------------------------------------------------------------------------
# lookup_engage_refs
# --------------------------------------------------------------------------


def test_lookup_engage_refs_match_and_sort(tmp_path):
    intel_path = tmp_path / "intel.db"
    _fresh_intel_db(intel_path)
    _seed_engage(
        intel_path,
        [
            ("EAC0009", "Network Analysis", "Understand", "T1595.002"),
            ("EAC0002", "Application Diversity Monitoring", "Detect", "T1595.002"),
            ("EAC0001", "Air Gapping", "Isolate", "T1071.001"),
        ],
    )
    conn = _attach(intel_path)
    refs = lookup_engage_refs(conn, ["T1595.002"])
    assert refs == [
        {"technique": "T1595.002", "activity_id": "EAC0002", "name": "Application Diversity Monitoring", "approach": "Detect"},
        {"technique": "T1595.002", "activity_id": "EAC0009", "name": "Network Analysis", "approach": "Understand"},
    ]


def test_lookup_engage_refs_match_gating_unrelated_technique(tmp_path):
    intel_path = tmp_path / "intel.db"
    _fresh_intel_db(intel_path)
    _seed_engage(intel_path, [("EAC0001", "Air Gapping", "Isolate", "T1071.001")])
    conn = _attach(intel_path)
    assert lookup_engage_refs(conn, ["T1595.002"]) == []
    assert lookup_engage_refs(conn, []) == []


def test_lookup_engage_refs_empty_tables_returns_empty(tmp_path):
    intel_path = tmp_path / "intel.db"
    _fresh_intel_db(intel_path)
    conn = _attach(intel_path)
    assert lookup_engage_refs(conn, ["T1595.002"]) == []


def test_lookup_engage_refs_absent_table_fails_open(tmp_path):
    # No migrations applied at all -> engage_attack_map does not exist.
    intel_path = tmp_path / "intel.db"
    intel_path.parent.mkdir(parents=True, exist_ok=True)
    sqlite3.connect(intel_path).close()
    conn = _attach(intel_path)
    assert lookup_engage_refs(conn, ["T1595.002"]) == []


# --------------------------------------------------------------------------
# lookup_rule_refs
# --------------------------------------------------------------------------


def test_lookup_rule_refs_case_normalization(tmp_path):
    intel_path = tmp_path / "intel.db"
    _fresh_intel_db(intel_path)
    _seed_sigma(
        intel_path,
        [("sig-1", "Suspicious PowerShell", ["attack.t1059.001", "attack.execution"], "https://sigmahq/sig-1")],
    )
    _seed_yara(
        intel_path,
        [
            ("Yara_Upper", ["T1059.001"], "https://example/yara-upper"),
            ("Yara_Lower", ["t1059.001"], "https://example/yara-lower"),
        ],
    )
    conn = _attach(intel_path)
    refs = lookup_rule_refs(conn, ["T1059.001"])
    assert refs == [
        {"technique": "T1059.001", "rule_type": "sigma", "rule_id": "sig-1", "title": "Suspicious PowerShell", "source_url": "https://sigmahq/sig-1"},
        {"technique": "T1059.001", "rule_type": "yara", "rule_id": "Yara_Lower", "title": None, "source_url": "https://example/yara-lower"},
        {"technique": "T1059.001", "rule_type": "yara", "rule_id": "Yara_Upper", "title": None, "source_url": "https://example/yara-upper"},
    ]


def test_lookup_rule_refs_match_gating(tmp_path):
    intel_path = tmp_path / "intel.db"
    _fresh_intel_db(intel_path)
    _seed_sigma(intel_path, [("sig-1", "Unrelated Rule", ["attack.t1003"], "https://sigmahq/sig-1")])
    _seed_yara(intel_path, [("Yara_1", ["attack.t1105"], "https://example/yara-1")])
    conn = _attach(intel_path)
    assert lookup_rule_refs(conn, ["T1059.001"]) == []
    assert lookup_rule_refs(conn, []) == []


def test_lookup_rule_refs_never_includes_rule_body(tmp_path):
    intel_path = tmp_path / "intel.db"
    _fresh_intel_db(intel_path)
    _seed_sigma(intel_path, [("sig-1", "Rule Title", ["attack.t1595.002"], "https://sigmahq/sig-1")])
    _seed_yara(intel_path, [("Yara_1", ["attack.t1595.002"], "https://example/yara-1")])
    conn = _attach(intel_path)
    refs = lookup_rule_refs(conn, ["T1595.002"])
    assert refs
    banned = {"raw_yaml", "raw_text", "condition", "condition_summary", "tags", "meta", "log_source"}
    for ref in refs:
        assert set(ref) == {"technique", "rule_type", "rule_id", "title", "source_url"}
        assert not (set(ref) & banned)


def test_lookup_rule_refs_empty_and_absent_tables_fail_open(tmp_path):
    intel_path = tmp_path / "intel.db"
    _fresh_intel_db(intel_path)
    conn = _attach(intel_path)
    assert lookup_rule_refs(conn, ["T1595.002"]) == []

    intel_path_absent = tmp_path / "absent_intel.db"
    intel_path_absent.parent.mkdir(parents=True, exist_ok=True)
    sqlite3.connect(intel_path_absent).close()
    conn2 = _attach(intel_path_absent)
    assert lookup_rule_refs(conn2, ["T1595.002"]) == []


def test_lookup_rule_refs_deterministic_cap(tmp_path):
    intel_path = tmp_path / "intel.db"
    _fresh_intel_db(intel_path)
    rows = [
        (f"sig-{i:03d}", f"Rule {i}", ["attack.t1595.002"], f"https://sigmahq/sig-{i:03d}")
        for i in range(MAX_RULE_REFS + 5)
    ]
    _seed_sigma(intel_path, rows)
    conn = _attach(intel_path)
    refs = lookup_rule_refs(conn, ["T1595.002"])
    assert len(refs) == MAX_RULE_REFS
    ids = [r["rule_id"] for r in refs]
    assert ids == sorted(ids)


def test_lookups_are_deterministic_across_repeated_calls(tmp_path):
    intel_path = tmp_path / "intel.db"
    _fresh_intel_db(intel_path)
    _seed_engage(intel_path, [("EAC0009", "Network Analysis", "Understand", "T1595.002")])
    _seed_sigma(intel_path, [("sig-1", "Rule Title", ["attack.t1595.002"], "https://sigmahq/sig-1")])
    _seed_yara(intel_path, [("Yara_1", ["T1595.002"], "https://example/yara-1")])
    conn = _attach(intel_path)

    engage_calls = [lookup_engage_refs(conn, ["T1595.002"]) for _ in range(3)]
    rule_calls = [lookup_rule_refs(conn, ["T1595.002"]) for _ in range(3)]
    assert engage_calls[0] == engage_calls[1] == engage_calls[2]
    assert rule_calls[0] == rule_calls[1] == rule_calls[2]


# --------------------------------------------------------------------------
# Determinism/scoring boundary: run_context is byte-identical whether or not
# the new intel-tier tables carry rows (ADR-0012/ADR-0013 §Determinism
# handling; must NOT touch scoring/the 7-tuple/content_hash).
# --------------------------------------------------------------------------


def _make_local_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    conn.execute("INSERT INTO local_meta (key, value) VALUES ('local_generation', '3')")
    conn.execute("INSERT INTO local_meta (key, value) VALUES ('stats_generation', '7')")
    conn.commit()
    conn.close()


def _make_intel_generation(data_db_dir: Path, n: int) -> Path:
    intel_path = generations.build_next_generation(data_db_dir)
    conn = sqlite3.connect(intel_path)
    apply_migrations(conn, "intel")
    conn.execute(
        "INSERT INTO stats_meta (key, value) VALUES ('intel_generation', ?)", (str(n),)
    )
    conn.commit()
    conn.close()
    generations.swap_current(data_db_dir, n)
    return intel_path


def _canonical(result) -> str:
    return json.dumps(
        {
            "threat_score": result.threat_score,
            "confidence": result.confidence,
            "reason": list(result.reason),
            "confidence_reason": list(result.confidence_reason),
            "content_hash": result.content_hash,
            "determinism": result.determinism,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def test_run_context_byte_identical_with_and_without_engage_rule_tables(tmp_path):
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    _make_local_db(local_db_path)
    intel_path = _make_intel_generation(data_db_dir, 1)
    repo = Repository(local_db_path, data_db_dir, pool_size=2)
    request = ContextRequest(
        entities=[Entity("ip", "203.0.113.7")],
        event=_SCAN_EVENT,
        edge_id="edge-1",
        actor_key="actor-1",
    )

    before = run_context(repo, LOADER, request, CLOCK)
    assert "T1595.002" in [m["technique"] for m in before.threat_context["attack_mapping"]]

    # Seed the new intel-tier tables in place, same generation, no swap.
    _seed_engage(intel_path, [("EAC0009", "Network Analysis", "Understand", "T1595.002")])
    _seed_sigma(intel_path, [("sig-1", "Rule Title", ["attack.t1595.002"], "https://sigmahq/sig-1")])
    _seed_yara(intel_path, [("Yara_1", ["T1595.002"], "https://example/yara-1")])
    repo.close()
    repo = Repository(local_db_path, data_db_dir, pool_size=2)

    after = run_context(repo, LOADER, request, CLOCK)
    repo.close()

    assert _canonical(before) == _canonical(after)


# --------------------------------------------------------------------------
# API-level: POST /v1/context wire contract.
# --------------------------------------------------------------------------


def _context_body(**overrides):
    body = {
        "entities": [{"type": "ip", "value": "203.0.113.7"}],
        "event": dict(_SCAN_EVENT),
        "edge_id": "edge-1",
        "actor_key": "actor-1",
    }
    body.update(overrides)
    return body


def test_context_api_empty_feeds_returns_empty_refs(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["engage_refs"] == []
    assert body["rule_refs"] == []


def test_context_api_returns_matched_engage_and_rule_refs(tmp_path):
    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    intel_path = generations.intel_db_path(data_db_dir, 1)
    _seed_engage(
        intel_path,
        [
            ("EAC0009", "Network Analysis", "Understand", "T1595.002"),
            ("EAC0001", "Air Gapping", "Isolate", "T1071.001"),  # unrelated -- must not appear
        ],
    )
    _seed_sigma(
        intel_path,
        [
            ("sig-1", "Suspicious Port Scan", ["attack.t1595.002"], "https://sigmahq/sig-1"),
            ("sig-2", "Unrelated Rule", ["attack.t1003"], "https://sigmahq/sig-2"),  # must not appear
        ],
    )
    _seed_yara(
        intel_path,
        [("APT_Scanner_Tool", ["T1595.002"], "https://example/yara-1")],
    )

    token = add_api_client(local_db_path, "edge1", ["query"])
    resp1 = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert resp1.status_code == 200
    body1 = resp1.json()

    assert body1["engage_refs"] == [
        {"technique": "T1595.002", "activity_id": "EAC0009", "name": "Network Analysis", "approach": "Understand"}
    ]
    assert body1["rule_refs"] == [
        {"technique": "T1595.002", "rule_type": "sigma", "rule_id": "sig-1", "title": "Suspicious Port Scan", "source_url": "https://sigmahq/sig-1"},
        {"technique": "T1595.002", "rule_type": "yara", "rule_id": "APT_Scanner_Tool", "title": None, "source_url": "https://example/yara-1"},
    ]

    # Determinism: a second call yields identical engage_refs/rule_refs (and
    # identical score/reason -- only advisory_id/advisory-chain fields vary).
    resp2 = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    body2 = resp2.json()
    assert body2["engage_refs"] == body1["engage_refs"]
    assert body2["rule_refs"] == body1["rule_refs"]
    assert body2["threat_score"] == body1["threat_score"]
    assert body2["confidence"] == body1["confidence"]
    assert body2["reason"] == body1["reason"]
    assert body1["advisory_id"] != body2["advisory_id"]


def test_context_api_no_matching_technique_yields_empty_refs(tmp_path):
    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    intel_path = generations.intel_db_path(data_db_dir, 1)
    # Seeded only for an unrelated technique; the scan event maps to
    # T1595.002, so neither list should surface these rows.
    _seed_engage(intel_path, [("EAC0001", "Air Gapping", "Isolate", "T1071.001")])
    _seed_sigma(intel_path, [("sig-1", "Unrelated", ["attack.t1071.001"], "https://sigmahq/sig-1")])

    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["engage_refs"] == []
    assert body["rule_refs"] == []


def test_context_api_advisory_only_invariant_holds_with_refs_present(tmp_path):
    from azazel_knowledge.api.contracts import assert_response_advisory_only

    client, settings, local_db_path, data_db_dir = make_client(tmp_path)
    intel_path = generations.intel_db_path(data_db_dir, 1)
    _seed_engage(intel_path, [("EAC0009", "Network Analysis", "Understand", "T1595.002")])
    _seed_sigma(intel_path, [("sig-1", "Rule Title", ["attack.t1595.002"], "https://sigmahq/sig-1")])

    token = add_api_client(local_db_path, "edge1", ["query"])
    resp = client.post("/v1/context", json=_context_body(), headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["engage_refs"]
    assert body["rule_refs"]
    # Must not raise: no directive-shaped field anywhere, including inside
    # the newly-added engage_refs/rule_refs lists.
    assert_response_advisory_only(body)
