"""Shared fixtures for the `api`/`taxii` test suite.

Mirrors the seeding pattern in `test_pipeline.py` (raw `sqlite3` +
`apply_migrations`, one intel generation dir, `generations.swap_current`)
but adds an `api_client` row per test client and wires everything
through `azazel_cti.api.app.create_app`.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from azazel_cti.api.app import Settings, create_app
from azazel_cti.core.clock import FixedClock
from azazel_cti.db import generations
from azazel_cti.db.repository import apply_migrations
from azazel_cti.security.auth import mint_token

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"
QUERY_AS_OF = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)


def make_local_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    apply_migrations(conn, "local")
    conn.execute("INSERT INTO local_meta (key, value) VALUES ('local_generation', '3')")
    conn.execute("INSERT INTO local_meta (key, value) VALUES ('stats_generation', '7')")
    conn.commit()
    conn.close()


def add_api_client(local_db_path: Path, key_id: str, scopes: list[str], enabled: bool = True) -> str:
    token, token_hash = mint_token(key_id)
    conn = sqlite3.connect(local_db_path)
    conn.execute(
        "INSERT INTO api_client (key_id, token_sha256, scopes, quota_bytes, enabled, created_at) "
        "VALUES (?, ?, ?, NULL, ?, ?)",
        (key_id, token_hash, json.dumps(scopes), 1 if enabled else 0, QUERY_AS_OF.isoformat()),
    )
    conn.commit()
    conn.close()
    return token


def make_intel_generation(data_db_dir: Path, n: int = 1) -> Path:
    intel_path = generations.build_next_generation(data_db_dir)
    conn = sqlite3.connect(intel_path)
    apply_migrations(conn, "intel")
    conn.execute(
        "INSERT INTO ioc (ioc_id, type, value, first_seen, last_seen, "
        "agg_raw_confidence, agg_computed_at) VALUES "
        "(1, 'ip', '203.0.113.7', '2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 80.0, "
        "'2026-07-02T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
        "intel_generation) VALUES (1, 'urlhaus', 85, '2026-06-01T00:00:00Z', "
        "'2026-07-02T00:00:00Z', 1)"
    )
    conn.execute(
        "INSERT INTO kev (cve_id, catalog_version, date_added) VALUES "
        "('CVE-2024-0001', 'v1', '2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO stats_meta (key, value) VALUES ('intel_generation', ?)", (str(n),)
    )
    conn.execute(
        "INSERT INTO feed_state (feed_id, last_run, last_success, item_count, enabled, "
        "consecutive_polls) VALUES ('urlhaus', '2026-07-06T00:00:00Z', "
        "'2026-07-05T00:00:00Z', 10, 1, 5)"
    )
    conn.commit()
    conn.close()
    generations.swap_current(data_db_dir, n)
    return intel_path


def build_app(
    tmp_path: Path, *, warm: bool = True, deadline_ms: int | None = None
) -> tuple[Any, Settings, Path, Path]:
    data_db_dir = tmp_path / "data" / "db"
    local_db_path = tmp_path / "data" / "local.db"
    spool_root = tmp_path / "var" / "ingest"
    audit_dir = tmp_path / "var" / "audit" / "api"

    make_local_db(local_db_path)
    if warm:
        make_intel_generation(data_db_dir, 1)
    else:
        data_db_dir.mkdir(parents=True, exist_ok=True)

    settings = Settings(
        config_dir=CONFIG_DIR,
        local_db_path=local_db_path,
        data_db_dir=data_db_dir,
        spool_root=spool_root,
        audit_dir=audit_dir,
        proc_id="test-proc",
        boot_id="test-boot",
        clock=FixedClock(QUERY_AS_OF),
        pool_size=2,
        context_deadline_ms=deadline_ms,
    )
    app = create_app(settings)
    return app, settings, local_db_path, data_db_dir


def make_client(tmp_path: Path, **kwargs: Any) -> tuple[TestClient, Settings, Path, Path]:
    app, settings, local_db_path, data_db_dir = build_app(tmp_path, **kwargs)
    client = TestClient(app)
    return client, settings, local_db_path, data_db_dir


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
