from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from textwrap import dedent


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "docs-sync-check.py"

_SPEC = importlib.util.spec_from_file_location("docs_sync_check", MODULE_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
docs_sync_check = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = docs_sync_check
_SPEC.loader.exec_module(docs_sync_check)


def _write_config(config_dir: Path) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "scoring.yaml").write_text(
        dedent(
            """
            weights:
              ioc_match: 0.30
              history: 0.20
              attack_map: 0.15
              cve_exploited: 0.15
              campaign: 0.10
              geo_asn: 0.10
            freshness:
              half_life_days: 30
              floor: 0.2
            confidence_weights:
              source_count: 0.30
              source_independence: 0.30
              source_freshness: 0.25
              local_corroboration: 0.15
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def _write_docs(
    docs_dir: Path,
    *,
    scoring_weights: dict[str, float],
    freshness_line: str = "Default half-life 30 days, floor 0.2.",
    reason_weights: dict[str, float] | None = None,
) -> None:
    docs_dir.mkdir(parents=True, exist_ok=True)
    scoring_rows = "\n".join(
        f"| {component} | {weight:.2f} | source |"
        for component, weight in scoring_weights.items()
    )
    (docs_dir / "scoring.md").write_text(
        dedent(
            f"""
            # Deterministic scoring

            | Component | Weight | Source |
            |---|---|---|
            {scoring_rows}

            {freshness_line}
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    if reason_weights is None:
        reason_weights = {
            "ioc_match": 0.30,
            "history": 0.20,
            "attack_map": 0.15,
            "campaign": 0.10,
            "geo_asn": 0.10,
        }
    reason_rows = ",\n".join(
        dedent(
            f"""
            {{ "component": "{component}", "weight": {weight:.2f}, "contribution": 1, "detail": "x" }}
            """
        ).strip()
        for component, weight in reason_weights.items()
    )
    (docs_dir / "api.md").write_text(
        dedent(
            f"""
            # API

            ```json
            {{
              "reason": [
                {reason_rows}
              ]
            }}
            ```
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def _write_allowlist(path: Path, entries: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["known_diffs:"]
    for entry in entries:
        lines.extend(
            [
                f"  - doc: {entry['doc']}",
                f"    check: {entry['check']}",
                f"    key: {entry['key']}",
                f"    reason: {entry['reason']!r}",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _matching_weights() -> dict[str, float]:
    return {
        "ioc_match": 0.30,
        "history": 0.20,
        "attack_map": 0.15,
        "cve_exploited": 0.15,
        "campaign": 0.10,
        "geo_asn": 0.10,
    }


def test_repo_passes_with_shipped_allowlist():
    result = docs_sync_check.run_check(
        REPO_ROOT / "config",
        REPO_ROOT / "docs",
        REPO_ROOT / "tools" / "docs-sync-allowlist.yaml",
    )
    assert result.exit_code == 0
    assert result.mismatches == []
    assert len([warning for warning in result.warnings if warning.kind == "allowlisted"]) == 7


def test_unallowlisted_weight_mismatch_fails(tmp_path):
    config_dir = tmp_path / "config"
    docs_dir = tmp_path / "docs"
    allowlist_path = tmp_path / "tools" / "allowlist.yaml"
    _write_config(config_dir)
    weights = _matching_weights()
    weights["ioc_match"] = 0.35
    _write_docs(docs_dir, scoring_weights=weights)
    _write_allowlist(allowlist_path, [])

    result = docs_sync_check.run_check(config_dir, docs_dir, allowlist_path)
    assert result.exit_code == 1
    assert ("docs/scoring.md", "weights_table", "ioc_match") in {
        (mismatch.doc, mismatch.check, mismatch.key) for mismatch in result.mismatches
    }


def test_allowlist_downgrades_to_warning(tmp_path):
    config_dir = tmp_path / "config"
    docs_dir = tmp_path / "docs"
    allowlist_path = tmp_path / "tools" / "allowlist.yaml"
    _write_config(config_dir)
    weights = _matching_weights()
    weights["ioc_match"] = 0.35
    _write_docs(docs_dir, scoring_weights=weights)
    _write_allowlist(
        allowlist_path,
        [
            {
                "doc": "docs/scoring.md",
                "check": "weights_table",
                "key": "ioc_match",
                "reason": "S12/F-15/T3 pending",
            }
        ],
    )

    result = docs_sync_check.run_check(config_dir, docs_dir, allowlist_path)
    assert result.exit_code == 0
    assert result.mismatches == []
    assert ("docs/scoring.md", "weights_table", "ioc_match") in {
        (warning.doc, warning.check, warning.key) for warning in result.warnings
    }


def test_empty_allowlist_escalates_current_drift(tmp_path):
    allowlist_path = tmp_path / "tools" / "allowlist.yaml"
    _write_allowlist(allowlist_path, [])
    result = docs_sync_check.run_check(REPO_ROOT / "config", REPO_ROOT / "docs", allowlist_path)
    assert result.exit_code == 1
    assert len(result.mismatches) == 7


def test_matching_docs_pass(tmp_path):
    config_dir = tmp_path / "config"
    docs_dir = tmp_path / "docs"
    allowlist_path = tmp_path / "tools" / "allowlist.yaml"
    _write_config(config_dir)
    _write_docs(docs_dir, scoring_weights=_matching_weights())
    _write_allowlist(allowlist_path, [])

    result = docs_sync_check.run_check(config_dir, docs_dir, allowlist_path)
    assert result.exit_code == 0
    assert result.mismatches == []
    assert result.warnings == []


def test_freshness_mismatch_detected(tmp_path):
    config_dir = tmp_path / "config"
    docs_dir = tmp_path / "docs"
    allowlist_path = tmp_path / "tools" / "allowlist.yaml"
    _write_config(config_dir)
    _write_docs(
        docs_dir,
        scoring_weights=_matching_weights(),
        freshness_line="Default half-life 20 days, floor 0.2.",
    )
    _write_allowlist(allowlist_path, [])

    result = docs_sync_check.run_check(config_dir, docs_dir, allowlist_path)
    assert result.exit_code == 1
    assert ("docs/scoring.md", "freshness", "half_life_days") in {
        (mismatch.doc, mismatch.check, mismatch.key) for mismatch in result.mismatches
    }


def test_stale_allowlist_entry_warns(tmp_path):
    config_dir = tmp_path / "config"
    docs_dir = tmp_path / "docs"
    allowlist_path = tmp_path / "tools" / "allowlist.yaml"
    _write_config(config_dir)
    _write_docs(docs_dir, scoring_weights=_matching_weights())
    _write_allowlist(
        allowlist_path,
        [
            {
                "doc": "docs/scoring.md",
                "check": "weights_table",
                "key": "ioc_match",
                "reason": "S12/F-15/T3 pending",
            }
        ],
    )

    result = docs_sync_check.run_check(config_dir, docs_dir, allowlist_path)
    assert result.exit_code == 0
    assert len(result.warnings) == 1
    assert result.warnings[0].kind == "stale"


def test_api_reason_weight_mismatch_detected(tmp_path):
    config_dir = tmp_path / "config"
    docs_dir = tmp_path / "docs"
    allowlist_path = tmp_path / "tools" / "allowlist.yaml"
    _write_config(config_dir)
    reason_weights = {
        "ioc_match": 0.35,
        "history": 0.20,
        "attack_map": 0.15,
        "campaign": 0.10,
        "geo_asn": 0.10,
    }
    _write_docs(docs_dir, scoring_weights=_matching_weights(), reason_weights=reason_weights)
    _write_allowlist(allowlist_path, [])

    result = docs_sync_check.run_check(config_dir, docs_dir, allowlist_path)
    assert result.exit_code == 1
    assert ("docs/api.md", "reason_example", "ioc_match") in {
        (mismatch.doc, mismatch.check, mismatch.key) for mismatch in result.mismatches
    }
