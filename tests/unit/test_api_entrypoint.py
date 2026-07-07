from __future__ import annotations

import importlib
import os
import sqlite3
import sys
from pathlib import Path

from _api_support import add_api_client, auth_header
from fastapi import FastAPI
from fastapi.testclient import TestClient

from azazel_cti.api.app import create_app, settings_from_env
from azazel_cti.worker import WorkerPaths, ensure_intel_generation, ensure_local_db


def test_module_exposes_asgi_app(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AZAZEL_ROOT", raising=False)
    monkeypatch.delenv("AZAZEL_CONFIG_DIR", raising=False)

    module = importlib.reload(
        sys.modules.get("azazel_cti.api.app")
        or importlib.import_module("azazel_cti.api.app")
    )

    assert isinstance(module.app, FastAPI)
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "var").exists()


def test_settings_from_env_uses_root(tmp_path, monkeypatch):
    expected = WorkerPaths.from_root(tmp_path)

    settings = settings_from_env(root=tmp_path)
    assert settings.local_db_path == expected.local_db_path
    assert settings.data_db_dir == expected.data_db_dir
    assert settings.spool_root == expected.ingest_root
    assert settings.audit_dir == expected.audit_dir
    assert settings.secrets_dir == expected.secrets_dir
    assert settings.config_dir == expected.config_dir
    assert settings.context_deadline_ms is None

    monkeypatch.setenv("AZAZEL_ROOT", os.fspath(tmp_path))
    env_settings = settings_from_env()
    assert env_settings.local_db_path == expected.local_db_path
    assert env_settings.data_db_dir == expected.data_db_dir
    assert env_settings.spool_root == expected.ingest_root
    assert env_settings.audit_dir == expected.audit_dir
    assert env_settings.secrets_dir == expected.secrets_dir
    assert env_settings.config_dir == expected.config_dir


def test_app_from_env_serves_health(tmp_path, monkeypatch):
    repo_config = Path(__file__).resolve().parents[2] / "config"
    paths = WorkerPaths.from_root(tmp_path, config_dir=repo_config)

    ensure_local_db(paths.local_db_path)
    ensure_intel_generation(paths.data_db_dir)

    conn = sqlite3.connect(paths.local_db_path)
    try:
        conn.execute("INSERT INTO local_meta (key, value) VALUES ('local_generation', '3')")
        conn.execute("INSERT INTO local_meta (key, value) VALUES ('stats_generation', '7')")
        conn.commit()
    finally:
        conn.close()

    paths.secrets_dir.mkdir(parents=True, exist_ok=True)
    paths.node_signing_key_path.write_bytes(b"\x90\x00binary-ed25519-key")
    (paths.secrets_dir / "api_token").write_text("text-secret", encoding="utf-8")

    token = add_api_client(paths.local_db_path, "reader1", ["read"])
    monkeypatch.setenv("AZAZEL_ROOT", os.fspath(tmp_path))
    monkeypatch.setenv("AZAZEL_CONFIG_DIR", os.fspath(repo_config))

    with TestClient(create_app(settings_from_env())) as client:
        response = client.get("/v1/health", headers=auth_header(token))

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["cache_state"] == "warm"
    assert body["audit_writer_ok"] is True
