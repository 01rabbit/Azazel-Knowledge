from __future__ import annotations

import importlib.util

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
