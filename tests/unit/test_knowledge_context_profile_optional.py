from __future__ import annotations

import builtins
import importlib.util

import pytest

from azazel_knowledge.api.app import Settings, create_app


def test_candidate_endpoint_is_not_mounted_without_fabric_profile(monkeypatch, tmp_path):
    original_find_spec = importlib.util.find_spec

    def find_spec(name, *args, **kwargs):
        if name == "azazel_fabric.knowledge_context":
            return None
        return original_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)
    app = create_app(
        Settings(
            config_dir=tmp_path / "config",
            local_db_path=tmp_path / "local.db",
            data_db_dir=tmp_path / "generations",
            spool_root=tmp_path / "spool",
            audit_dir=tmp_path / "audit",
        ),
        eager_runtime=False,
    )

    assert not any(
        getattr(route, "path", None) == "/v1/knowledge-context"
        for route in app.routes
    )


@pytest.mark.parametrize(
    "import_error",
    [ImportError, RuntimeError, TypeError, ValueError, AttributeError, KeyError],
)
def test_incompatible_fabric_context_does_not_break_ordinary_routes(
    monkeypatch, tmp_path, import_error
):
    original_import = builtins.__import__
    original_find_spec = importlib.util.find_spec

    def find_spec(name, *args, **kwargs):
        if name == "azazel_fabric.knowledge_context":
            return object()
        return original_find_spec(name, *args, **kwargs)

    def broken_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "azazel_knowledge.api.routers" and "knowledge_context" in fromlist:
            raise import_error("simulated incompatible Fabric contract")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)
    monkeypatch.setattr(builtins, "__import__", broken_import)
    app = create_app(
        Settings(
            config_dir=tmp_path / "config",
            local_db_path=tmp_path / "local.db",
            data_db_dir=tmp_path / "generations",
            spool_root=tmp_path / "spool",
            audit_dir=tmp_path / "audit",
        ),
        eager_runtime=False,
    )

    paths = app.openapi()["paths"]
    assert "/v1/context" in paths
    assert "/v1/knowledge-context" not in paths


def test_missing_fabric_package_does_not_break_ordinary_routes(monkeypatch, tmp_path):
    original_find_spec = importlib.util.find_spec

    def find_spec(name, *args, **kwargs):
        if name == "azazel_fabric.knowledge_context":
            raise ModuleNotFoundError("azazel_fabric is not installed")
        return original_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)
    app = create_app(
        Settings(
            config_dir=tmp_path / "config",
            local_db_path=tmp_path / "local.db",
            data_db_dir=tmp_path / "generations",
            spool_root=tmp_path / "spool",
            audit_dir=tmp_path / "audit",
        ),
        eager_runtime=False,
    )

    paths = app.openapi()["paths"]
    assert "/v1/context" in paths
    assert "/v1/knowledge-context" not in paths
