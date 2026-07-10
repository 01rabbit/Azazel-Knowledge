from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from export_research_dataset import (  # noqa: E402
    build_manifest,
    export_reactions,
    pseudonymize_actor_key,
    run_export,
    write_jsonl,
)

from azazel_knowledge.db.repository import apply_migrations  # noqa: E402
from azazel_knowledge.reactions import classifier  # noqa: E402

NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)
SITE_KEY = b"site-secret-key-material"


def _make_conn(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "local.db")
    apply_migrations(conn, "local")
    return conn


def _seed_reactions(conn) -> None:
    for i in range(3):
        classifier.ingest_reaction(
            conn,
            {
                "edge_id": "edge-1",
                "actor_key": f"203.0.113.{i}",
                "action_applied": "throttle",
                "applied_at": "2026-07-06T11:00:00Z",
                "reaction": "continued_scanning",
                "reaction_window_s": 60,
                "evidence_refs": ["ev-1"],
                "advisory_id": None,
            },
            now=NOW,
        )
    conn.commit()


def test_pseudonymize_actor_key_is_deterministic_and_hides_raw_value():
    a = pseudonymize_actor_key(SITE_KEY, "203.0.113.9")
    b = pseudonymize_actor_key(SITE_KEY, "203.0.113.9")
    c = pseudonymize_actor_key(SITE_KEY, "203.0.113.10")
    assert a == b
    assert a != c
    assert len(a) == 16
    assert "203.0.113.9" not in a


def test_export_reactions_never_contains_raw_actor_key(tmp_path):
    conn = _make_conn(tmp_path)
    _seed_reactions(conn)

    rows = export_reactions(conn, site_key=SITE_KEY)
    assert len(rows) == 3
    for row in rows:
        assert row["actor_key"] != "203.0.113.0"
        assert "." not in row["actor_key"]
        assert len(row["actor_key"]) == 16


def test_export_reactions_is_deterministically_ordered(tmp_path):
    conn = _make_conn(tmp_path)
    _seed_reactions(conn)

    first = export_reactions(conn, site_key=SITE_KEY)
    second = export_reactions(conn, site_key=SITE_KEY)
    assert [r["reaction_id"] for r in first] == [r["reaction_id"] for r in second]
    assert [r["reaction_id"] for r in first] == sorted(r["reaction_id"] for r in first)


def test_write_jsonl_produces_one_sorted_json_object_per_line(tmp_path):
    rows = [{"b": 2, "a": 1}, {"b": 4, "a": 3}]
    out_path = tmp_path / "out.jsonl"
    write_jsonl(out_path, rows)

    lines = out_path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"a": 1, "b": 2}
    assert list(json.loads(lines[0]).keys()) == ["a", "b"]


def test_build_manifest_records_sha256_and_row_count(tmp_path):
    conn = _make_conn(tmp_path)
    _seed_reactions(conn)
    out_path = tmp_path / "out.jsonl"
    write_jsonl(out_path, export_reactions(conn, site_key=SITE_KEY))

    manifest = build_manifest(
        out_path, conn=conn, generated_at="2026-07-06T12:00:00Z", row_count=3
    )
    assert manifest["row_count"] == 3
    assert len(manifest["sha256"]) == 64
    assert "ambiguous_linkage_rate" in manifest


def test_run_export_writes_jsonl_and_manifest_files(tmp_path):
    conn = _make_conn(tmp_path)
    _seed_reactions(conn)
    conn.close()

    out_path = tmp_path / "export.jsonl"
    site_key_path = tmp_path / "site.key"
    site_key_path.write_bytes(SITE_KEY)

    manifest = run_export(
        local_db_path=tmp_path / "local.db", out_path=out_path, site_key=SITE_KEY
    )
    assert out_path.is_file()
    manifest_path = tmp_path / "export.jsonl.manifest.json"
    assert manifest_path.is_file()
    loaded_manifest = json.loads(manifest_path.read_text())
    assert loaded_manifest["row_count"] == manifest["row_count"] == 3

    for line in out_path.read_text().splitlines():
        record = json.loads(line)
        assert "." not in record["actor_key"]
