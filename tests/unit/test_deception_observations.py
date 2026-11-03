"""AZ-06 deception-observation ingest + effectiveness advisory (ADR-0011).

Covers the honesty-ladder ingest path and the deterministic effectiveness
advisory output against the Absolute Constraints: F-1 immutability / rows never
decrease, deterministic byte-identical replay, advisory-only response guard,
untrusted-input containment, and fail-closed timeout/audit.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from _api_support import (
    QUERY_AS_OF,
    add_api_client,
    auth_header,
    make_client,
)
from azazel_knowledge.audit.logger import AuditUnavailable
from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.db.repository import apply_migrations
from azazel_knowledge.db.writer import PrioritySingleWriterQueue
from azazel_knowledge.ingest.drain import drain_endpoint
from azazel_knowledge.ingest.spool import SpoolWriter
from azazel_knowledge.ingest.validators import validate_deception_observation_line

NOW = QUERY_AS_OF
OBSERVED_AT = QUERY_AS_OF.isoformat().replace("+00:00", "Z")
ENDPOINT = "deception-observations"


# --------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------


def _obs(observation_id: str, klass: str, surface: str, **overrides) -> dict:
    body = {
        "observation_id": observation_id,
        "environment_id": "env-1",
        "package_id": "pkg-1",
        "node_id": "node-1",
        "observed_at": OBSERVED_AT,
        "observation_class": klass,
        "surface": surface,
        "metadata": {"edge_id": "edge-pi4-07", "actor_key": "ip:203.0.113.9"},
    }
    body.update(overrides)
    return body


def _make_writer(tmp_path: Path) -> PrioritySingleWriterQueue:
    db_path = tmp_path / "local.db"
    conn = sqlite3.connect(db_path)
    apply_migrations(conn, "local")
    conn.close()
    writer = PrioritySingleWriterQueue(db_path, tmp_path / "writer.lock")
    writer.open()
    return writer


def _count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM deception_observation").fetchone()[0]


# --------------------------------------------------------------------------
# migration: F-1 immutability + rows never decrease
# --------------------------------------------------------------------------


def _insert_row(conn: sqlite3.Connection, uid: str = "o1") -> None:
    conn.execute(
        "INSERT INTO deception_observation (observation_uid, environment_id, package_id, "
        "node_id, observed_at, observation_class, surface, confounder_tags, evidence_refs, "
        "raw, created_at) VALUES (?, 'env-1', 'pkg-1', 'node-1', ?, 'interaction', 'service', "
        "'[]', '[]', '{}', ?)",
        (uid, OBSERVED_AT, OBSERVED_AT),
    )
    conn.commit()


def test_deception_observation_immutable_on_update(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    _insert_row(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE deception_observation SET surface = 'port' WHERE observation_uid = 'o1'"
        )


def test_deception_observation_immutable_on_delete(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    _insert_row(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM deception_observation WHERE observation_uid = 'o1'")


def test_local_migration_chain_includes_0005_and_is_idempotent(tmp_path):
    conn = sqlite3.connect(tmp_path / "local.db")
    assert apply_migrations(conn, "local") == [
        "0001_init",
        "0002_behavior",
        "0003_reaction_ext",
        "0004_deception_observation",
        "0005_outcome_evidence_v0",
        "0006_defensive_state_observation",
        "0007_engagement_event",
        "0008_deception_outcome_envelope",
    ]
    assert apply_migrations(conn, "local") == []


def test_rows_never_decrease_across_redrain_and_overlap(tmp_path):
    """Re-draining a batch is a no-op, and an overlapping uid dedupes rather
    than duplicating or deleting -- the row count only ever grows (F-1)."""
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        spool.write_batch(ENDPOINT, "c1", [json.dumps(_obs("o1", "interaction", "service")),
                                           json.dumps(_obs("o2", "reaction", "file", reaction_kind="read"))])
        s1 = drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))
        assert (s1.lines_valid, _count(writer._conn)) == (2, 2)

        # Re-drain: the batch is marked drained, nothing reprocessed.
        s2 = drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))
        assert s2.batches_drained == 0
        assert _count(writer._conn) == 2

        # New batch overlapping o2 + adding o3: o2 dedupes, count grows only.
        spool.write_batch(ENDPOINT, "c1", [json.dumps(_obs("o2", "reaction", "file", reaction_kind="read")),
                                           json.dumps(_obs("o3", "outcome", "document"))])
        s3 = drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))
        assert s3.duplicates_skipped == 1
        assert _count(writer._conn) == 3
    finally:
        writer.close()


# --------------------------------------------------------------------------
# validator (framework-free structural mirror of InteractionObservation)
# --------------------------------------------------------------------------


def test_validator_accepts_full_observation():
    ok, result = validate_deception_observation_line(
        json.dumps(
            _obs(
                "o1",
                "outcome",
                "credential_lure",
                reaction_kind="authenticate",
                lure_id="cred-7",
                dwell_ms=1200,
                attempt_count=3,
                confounder_tags=["scanner_noise"],
                runtime_context={
                    "selected_tier": "lite",
                    "architecture": "arm64",
                    "runtime_adapter": "docker_compose",
                    "omitted_components": ["db-decoy"],
                    "resource_saturation": {"cpu": 0.9},
                },
                evidence_refs=["ev-1"],
            )
        ),
        now=NOW,
    )
    assert ok is True
    assert result["observation_uid"] == "o1"
    assert result["edge_id"] == "edge-pi4-07"
    assert result["actor_key"] == "ip:203.0.113.9"
    assert result["confounder_tags"] == ["scanner_noise"]
    assert result["runtime_context"]["omitted_components"] == ["db-decoy"]


def test_validator_rejects_belief_field_anywhere():
    """Honesty invariant: a belief/verdict/effectiveness field on a fact-only
    observation is rejected -- interaction does not prove attacker belief."""
    line = json.dumps(_obs("o1", "interaction", "service", metadata={"belief": "high"}))
    ok, err = validate_deception_observation_line(line, now=NOW)
    assert ok is False
    assert "belief" in err


def test_validator_rejects_interaction_with_reaction_kind():
    line = json.dumps(_obs("o1", "interaction", "service", reaction_kind="read"))
    ok, err = validate_deception_observation_line(line, now=NOW)
    assert ok is False
    assert "interaction" in err


def test_validator_rejects_unknown_enum_and_bounds_strings():
    ok, err = validate_deception_observation_line(
        json.dumps(_obs("o1", "interaction", "teleporter")), now=NOW
    )
    assert ok is False and "surface" in err

    huge = "A" * (4096 + 1)
    ok, err = validate_deception_observation_line(
        json.dumps(_obs("o1", "interaction", "service", lure_id=huge)), now=NOW
    )
    assert ok is False and "lure_id" in err


def test_untrusted_string_content_is_contained_not_executed(tmp_path):
    """An attacker-authored string in a field is stored as opaque data and does
    not break the drain or leak out of its field."""
    spool = SpoolWriter(tmp_path / "ingest")
    writer = _make_writer(tmp_path)
    try:
        nasty = "'; DROP TABLE deception_observation;-- {{7*7}} $(rm -rf /)"
        line = json.dumps(_obs("o1", "reaction", "file", reaction_kind="read", lure_id=nasty))
        spool.write_batch(ENDPOINT, "c1", [line])
        stats = drain_endpoint(ENDPOINT, spool, writer, clock=FixedClock(NOW))
        assert stats.lines_valid == 1
        # table still present, row stored verbatim, nothing executed.
        stored = writer._conn.execute(
            "SELECT lure_id FROM deception_observation WHERE observation_uid = 'o1'"
        ).fetchone()[0]
        assert stored == nasty
    finally:
        writer.close()


# --------------------------------------------------------------------------
# ingest endpoint: fire-and-forget, envelope enforcement, caps
# --------------------------------------------------------------------------


def test_post_legacy_jsonl_is_fire_and_forget(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    good = json.dumps(_obs("o1", "interaction", "service"))
    # A single bare item and an unparseable line both 202 (quarantined at drain).
    r1 = client.post(
        "/v1/deception-observations", content=(good + "\n").encode(), headers=auth_header(token)
    )
    r2 = client.post(
        "/v1/deception-observations", content=b"not json at all\n", headers=auth_header(token)
    )
    assert r1.status_code == 202 and r2.status_code == 202


def test_post_envelope_flattens_items_to_spool(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    envelope = {
        "environment_id": "env-1",
        "items": [_obs("o1", "interaction", "service"), _obs("o2", "reaction", "file", reaction_kind="read")],
    }
    resp = client.post("/v1/deception-observations", json=envelope, headers=auth_header(token))
    assert resp.status_code == 202
    files = list((settings.spool_root / ENDPOINT).glob("*.jsonl"))
    assert len(files) == 1
    lines = [l for l in files[0].read_text().splitlines() if l.strip()]
    assert {json.loads(l)["observation_id"] for l in lines} == {"o1", "o2"}


def test_post_envelope_violation_fails_closed_422(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    # interaction carrying reaction_kind is a Fabric model violation.
    bad = {"environment_id": "env-1", "items": [_obs("o1", "interaction", "service", reaction_kind="read")]}
    resp = client.post("/v1/deception-observations", json=bad, headers=auth_header(token))
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "ingest_batch_invalid"


def test_post_envelope_belief_field_fails_closed_422(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    bad = {"environment_id": "env-1", "items": [_obs("o1", "reaction", "file", reaction_kind="read", metadata={"deceived": True})]}
    resp = client.post("/v1/deception-observations", json=bad, headers=auth_header(token))
    assert resp.status_code == 422


def test_post_requires_ingest_scope(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "reader1", ["read"])
    resp = client.post(
        "/v1/deception-observations",
        content=json.dumps(_obs("o1", "interaction", "service")).encode(),
        headers=auth_header(token),
    )
    assert resp.status_code == 403


def test_post_batch_too_large_413(tmp_path):
    from azazel_knowledge.api import limits

    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    body = b"x" * (limits.INGEST_BATCH_MAX_BYTES + 1)
    resp = client.post("/v1/deception-observations", content=body, headers=auth_header(token))
    assert resp.status_code == 413


def test_malformed_line_quarantined_at_drain_not_at_accept(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    good = json.dumps(_obs("o1", "interaction", "service"))
    bad = json.dumps(_obs("o2", "interaction", "bogus_surface"))
    resp = client.post(
        "/v1/deception-observations",
        content=(good + "\n" + bad + "\n").encode(),
        headers=auth_header(token),
    )
    assert resp.status_code == 202  # never failed at accept
    writer = _make_writer_for(settings.local_db_path, tmp_path)
    try:
        stats = drain_endpoint(
            ENDPOINT, SpoolWriter(settings.spool_root), writer, clock=FixedClock(NOW)
        )
        assert stats.lines_valid == 1 and stats.lines_invalid == 1
    finally:
        writer.close()


def _make_writer_for(db_path: Path, tmp_path: Path) -> PrioritySingleWriterQueue:
    writer = PrioritySingleWriterQueue(db_path, tmp_path / "w2.lock")
    writer.open()
    return writer


# --------------------------------------------------------------------------
# effectiveness advisory: determinism, boundary, fail-closed
# --------------------------------------------------------------------------


def _seed_and_client(tmp_path: Path, items: list[dict]):
    client, settings, local_db_path, _ = make_client(tmp_path)
    ingest_tok = add_api_client(local_db_path, "edge1", ["ingest"])
    read_tok = add_api_client(local_db_path, "reader1", ["read"])
    client.post(
        "/v1/deception-observations",
        json={"environment_id": "env-1", "items": items},
        headers=auth_header(ingest_tok),
    )
    writer = _make_writer_for(settings.local_db_path, tmp_path)
    try:
        drain_endpoint(ENDPOINT, SpoolWriter(settings.spool_root), writer, clock=FixedClock(NOW))
    finally:
        writer.close()
    return client, settings, read_tok


def test_advisory_deterministic_byte_identical_replay(tmp_path):
    items = [
        _obs("o1", "interaction", "service"),
        _obs("o2", "reaction", "credential_lure", reaction_kind="authenticate"),
        _obs("o3", "outcome", "file", reaction_kind="exfiltrate"),
    ]
    client, settings, read_tok = _seed_and_client(tmp_path, items)
    r1 = client.get("/v1/deception-effectiveness?environment_id=env-1", headers=auth_header(read_tok))
    r2 = client.get("/v1/deception-effectiveness?environment_id=env-1", headers=auth_header(read_tok))
    assert r1.status_code == r2.status_code == 200
    # Same 7-tuple inputs -> byte-identical advisory, advisory_id included.
    assert json.dumps(r1.json(), sort_keys=True) == json.dumps(r2.json(), sort_keys=True)


def test_advisory_is_advisory_only_and_non_executable(tmp_path):
    client, settings, read_tok = _seed_and_client(
        tmp_path, [_obs("o1", "reaction", "file", reaction_kind="read")]
    )
    body = client.get(
        "/v1/deception-effectiveness?environment_id=env-1", headers=auth_header(read_tok)
    ).json()
    assert body["authority"] == "advisory_only"
    assert body["executable"] is False
    # No directive/belief/verdict field anywhere.
    flat = json.dumps(body).lower()
    for banned in ("must_execute", "override", "firewall_rule", "attacker_believed", "is_effective"):
        assert banned not in flat


def test_advisory_never_claims_belief_lists_it_unknown(tmp_path):
    client, settings, read_tok = _seed_and_client(
        tmp_path, [_obs("o1", "reaction", "credential_lure", reaction_kind="authenticate")]
    )
    body = client.get(
        "/v1/deception-effectiveness?environment_id=env-1", headers=auth_header(read_tok)
    ).json()
    assert any("belief" in u for u in body["unknowns"])
    assert "not asserted" in body["assessment"]


def test_advisory_separates_narrative_from_capacity(tmp_path):
    """Omitted components + saturation surface as counter-evidence, not as a
    narrative-failure claim (docs/azazel-deception-effectiveness.md)."""
    items = [
        _obs("o1", "interaction", "service", confounder_tags=["host_capacity"]),
        _obs(
            "o2",
            "outcome",
            "file",
            reaction_kind="read",
            runtime_context={
                "selected_tier": "lite",
                "architecture": "arm64",
                "runtime_adapter": "docker_compose",
                "omitted_components": ["db-decoy", "smtp-decoy"],
                "resource_saturation": {"cpu": 0.95},
            },
        ),
    ]
    client, settings, read_tok = _seed_and_client(tmp_path, items)
    body = client.get(
        "/v1/deception-effectiveness?environment_id=env-1", headers=auth_header(read_tok)
    ).json()
    ce = " ".join(body["counter_evidence"])
    assert "host_capacity" in ce
    assert "omitted optional components" in ce
    assert "capacity confounder" in ce
    assert any("capacity effect not separable" in u for u in body["unknowns"])


def test_advisory_reports_insufficient_evidence(tmp_path):
    client, settings, read_tok = _seed_and_client(
        tmp_path, [_obs("o1", "interaction", "service")]
    )
    body = client.get(
        "/v1/deception-effectiveness?environment_id=env-1", headers=auth_header(read_tok)
    ).json()
    assert any("insufficient evidence" in u for u in body["unknowns"])


def test_advisory_empty_environment_is_insufficient(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    read_tok = add_api_client(local_db_path, "reader1", ["read"])
    body = client.get(
        "/v1/deception-effectiveness?environment_id=env-none&package_id=pkg-x",
        headers=auth_header(read_tok),
    ).json()
    assert body["observation_refs"] == []
    assert body["package_id"] == "pkg-x"
    assert any("insufficient evidence" in u for u in body["unknowns"])


def test_advisory_requires_read_scope(tmp_path):
    client, settings, local_db_path, _ = make_client(tmp_path)
    token = add_api_client(local_db_path, "edge1", ["ingest"])
    resp = client.get(
        "/v1/deception-effectiveness?environment_id=env-1", headers=auth_header(token)
    )
    assert resp.status_code == 403


def test_advisory_fail_closed_on_timeout(tmp_path, monkeypatch):
    from azazel_knowledge.correlate.deception_effectiveness import DeceptionEffectivenessTimeout

    client, settings, read_tok = _seed_and_client(
        tmp_path, [_obs("o1", "interaction", "service")]
    )

    def _boom(*a, **k):
        raise DeceptionEffectivenessTimeout("forced")

    monkeypatch.setattr(
        "azazel_knowledge.api.routers.deception.summarize_effectiveness", _boom
    )
    resp = client.get(
        "/v1/deception-effectiveness?environment_id=env-1", headers=auth_header(read_tok)
    )
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "context_timeout"


def test_advisory_fail_closed_on_audit_unavailable(tmp_path):
    client, settings, read_tok = _seed_and_client(
        tmp_path, [_obs("o1", "interaction", "service")]
    )

    class _RaisingAudit:
        healthy = False

        def append(self, event):
            raise AuditUnavailable("chain down")

    client.app.state.audit = _RaisingAudit()
    resp = client.get(
        "/v1/deception-effectiveness?environment_id=env-1", headers=auth_header(read_tok)
    )
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "audit_unavailable"


# --------------------------------------------------------------------------
# static: the new router opens no write-mode SQLite path
# --------------------------------------------------------------------------


def test_new_router_has_no_write_sql():
    router_path = (
        Path(__file__).resolve().parents[2]
        / "src" / "azazel_knowledge" / "api" / "routers" / "deception.py"
    )
    text = router_path.read_text(encoding="utf-8")
    assert not re.search(r"\b(INSERT|UPDATE|DELETE|executemany|executescript)\b", text, re.IGNORECASE)
    assert "sqlite3.connect" not in text