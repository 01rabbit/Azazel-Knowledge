from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = REPO_ROOT / "tools" / "bench"
if str(BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(BENCH_DIR))

import _common
import availability_run
import capacity_run
import cold_read
import synth_dataset


def _manifest_path(tmp_path: Path) -> Path:
    return tmp_path / "bench-results" / "dataset-manifest.json"


def test_synth_dataset_creates_generation_and_search_hit(tmp_path):
    root = tmp_path / "scratch"
    manifest_path = _manifest_path(tmp_path)
    manifest = synth_dataset.generate_dataset(root, 0.00002, synth_dataset.DEFAULT_SEED, manifest_path)

    current = root / "data" / "db" / "current"
    assert current.is_symlink()
    assert manifest["generation"] == 1

    app, _, paths = _common.build_client(root, context_deadline_ms=10**9)
    token = _common.add_query_client(paths.local_db_path)
    sample = manifest["search_samples"][0]
    with TestClient(app) as client:
        response = client.post("/v1/ioc/search", json=sample, headers=_common.auth_header(token))
    assert response.status_code == 200
    assert response.json()["match"] is True


def test_capacity_run_emits_gates_and_breaker_disabled(tmp_path):
    root = tmp_path / "scratch"
    manifest_path = _manifest_path(tmp_path)
    synth_dataset.generate_dataset(root, 0.00002, synth_dataset.DEFAULT_SEED, manifest_path)

    payload = capacity_run.run_capacity(
        root=root,
        manifest_path=manifest_path,
        requests=8,
        warmup=2,
        label="test-capacity",
        stamp="s1",
    )

    assert "gates" in payload
    assert payload["breaker_disabled"] is True
    assert payload["context_deadline_ms"] == capacity_run.HUGE_DEADLINE_MS
    assert "pass" in payload
    assert "authoritative" in payload


def test_availability_run_emits_phase_rates(tmp_path):
    root = tmp_path / "scratch"
    manifest_path = _manifest_path(tmp_path)
    synth_dataset.generate_dataset(root, 0.00002, synth_dataset.DEFAULT_SEED, manifest_path)

    payload = availability_run.run_availability(
        root=root,
        manifest_path=manifest_path,
        duration_s=None,
        requests=12,
        concurrency=2,
        label="test-availability",
        stamp="s2",
    )

    assert "baseline" in payload
    assert "double_load" in payload
    assert "breaker_rate" in payload["baseline"]
    assert "breaker_rate" in payload["double_load"]
    assert "gates" in payload


def test_cold_read_platform_behavior(tmp_path):
    root = tmp_path / "scratch"
    manifest_path = _manifest_path(tmp_path)
    synth_dataset.generate_dataset(root, 0.00002, synth_dataset.DEFAULT_SEED, manifest_path)

    payload = cold_read.run_cold_read(root, manifest_path, "test-cold", "s3")

    if not _common.fadvise_available():
        assert payload["skipped"] is True
        assert payload["authoritative"] is False
        assert payload["reason"] == "posix_fadvise unavailable (not Linux)"
    else:
        assert payload["skipped"] is False
        assert "leaf_read_ms" in payload
        assert "worst_case_context_ms" in payload


def test_synth_dataset_large_scale_preserves_ioc_uniqueness(tmp_path: Path) -> None:
    root = tmp_path / "scratch"
    manifest_path = _manifest_path(tmp_path)
    manifest = synth_dataset.generate_dataset(root, 0.002, synth_dataset.DEFAULT_SEED, manifest_path)

    db_path = Path(manifest["intel_db_path"])
    conn = sqlite3.connect(db_path)
    try:
        count = int(conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0])
        distinct_pairs = int(
            conn.execute("SELECT COUNT(DISTINCT type || ':' || value) FROM ioc").fetchone()[0]
        )
    finally:
        conn.close()

    assert count == 20_000
    assert count == int(manifest["count"])
    assert distinct_pairs == count
