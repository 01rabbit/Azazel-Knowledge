from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from azazel_knowledge.core.config import ConfigError, QUERY_PATH_FILES, TrackedConfigLoader

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"


def _copy_config(tmp_path: Path) -> Path:
    dest = tmp_path / "config"
    shutil.copytree(REPO_CONFIG, dest)
    return dest


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _dump_yaml(path: Path, document: dict) -> None:
    path.write_text(yaml.safe_dump(document))


def test_repo_config_loads_and_validates():
    loader = TrackedConfigLoader(REPO_CONFIG)
    assert abs(sum(loader.weights().values()) - 1.0) < 1e-9
    assert abs(sum(loader.confidence_weights().values()) - 1.0) < 1e-9
    assert loader.deadline_ms() == 220
    assert loader.max_staleness_s() == 120
    assert loader.shadow_scoring()["enabled"] is False


def test_bad_weights_sum_rejected(tmp_path):
    config_dir = _copy_config(tmp_path)
    scoring_path = config_dir / "scoring.yaml"
    document = _load_yaml(scoring_path)
    document["weights"]["ioc_match"] = 0.99
    _dump_yaml(scoring_path, document)

    with pytest.raises(ConfigError, match="weights"):
        TrackedConfigLoader(config_dir)


def test_bad_confidence_weights_sum_rejected(tmp_path):
    config_dir = _copy_config(tmp_path)
    scoring_path = config_dir / "scoring.yaml"
    document = _load_yaml(scoring_path)
    document["confidence_weights"]["source_count"] = 0.99
    _dump_yaml(scoring_path, document)

    with pytest.raises(ConfigError, match="confidence_weights"):
        TrackedConfigLoader(config_dir)


def test_weights_sum_within_tolerance_is_accepted(tmp_path):
    config_dir = _copy_config(tmp_path)
    scoring_path = config_dir / "scoring.yaml"
    document = _load_yaml(scoring_path)
    document["weights"]["ioc_match"] = 0.30 + 1e-10
    _dump_yaml(scoring_path, document)

    TrackedConfigLoader(config_dir)  # must not raise


def test_config_hash_stable_across_loads():
    first = TrackedConfigLoader(REPO_CONFIG)
    second = TrackedConfigLoader(REPO_CONFIG)
    assert first.config_hash == second.config_hash
    assert len(first.config_hash) == 64


def test_config_hash_unaffected_by_non_query_path_file(tmp_path):
    config_dir = _copy_config(tmp_path)
    baseline = TrackedConfigLoader(config_dir).config_hash

    (config_dir / "unrelated.yaml").write_text("some: value\n")

    assert TrackedConfigLoader(config_dir).config_hash == baseline


@pytest.mark.parametrize("filename", QUERY_PATH_FILES)
def test_config_hash_changes_when_query_path_file_changes(tmp_path, filename):
    config_dir = _copy_config(tmp_path)
    baseline = TrackedConfigLoader(config_dir).config_hash

    target = config_dir / filename
    document = _load_yaml(target) or {}
    document["__test_marker__"] = True
    _dump_yaml(target, document)

    changed = TrackedConfigLoader(config_dir).config_hash
    assert changed != baseline


def test_reaction_adjustments_mode_active_rejected(tmp_path):
    config_dir = _copy_config(tmp_path)
    scoring_path = config_dir / "scoring.yaml"
    document = _load_yaml(scoring_path)
    document["research"]["shadow_scoring"]["reaction_adjustments"]["mode"] = "active"
    _dump_yaml(scoring_path, document)

    with pytest.raises(ConfigError, match="shadow"):
        TrackedConfigLoader(config_dir)


def test_reaction_adjustments_enabled_true_with_active_mode_rejected(tmp_path):
    config_dir = _copy_config(tmp_path)
    scoring_path = config_dir / "scoring.yaml"
    document = _load_yaml(scoring_path)
    document["research"]["shadow_scoring"]["enabled"] = True
    document["research"]["shadow_scoring"]["reaction_adjustments"]["mode"] = "active"
    _dump_yaml(scoring_path, document)

    with pytest.raises(ConfigError, match="shadow"):
        TrackedConfigLoader(config_dir)


def test_reaction_adjustments_missing_block_is_allowed(tmp_path):
    config_dir = _copy_config(tmp_path)
    scoring_path = config_dir / "scoring.yaml"
    document = _load_yaml(scoring_path)
    del document["research"]["shadow_scoring"]["reaction_adjustments"]
    _dump_yaml(scoring_path, document)

    loader = TrackedConfigLoader(config_dir)
    assert loader.shadow_scoring().get("reaction_adjustments") is None


def test_missing_scoring_yaml_rejected(tmp_path):
    config_dir = _copy_config(tmp_path)
    (config_dir / "scoring.yaml").unlink()

    with pytest.raises(ConfigError):
        TrackedConfigLoader(config_dir)
