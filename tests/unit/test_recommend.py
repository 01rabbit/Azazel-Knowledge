from __future__ import annotations

import inspect
import json
from pathlib import Path

from azazel_grimoire.core.config import TrackedConfigLoader
from azazel_grimoire.recommend import select
from azazel_grimoire.recommend.select import recommend

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config"
BANDS = TrackedConfigLoader(REPO_CONFIG).action_bands()


def test_first_match_wins_isolate():
    result = recommend(90.0, 80.0, BANDS)
    assert result["action"] == "isolate"
    assert result["rejected_alternatives"] == []


def test_throttle_band_reports_isolate_rejection_with_numbers():
    result = recommend(70.0, 60.0, BANDS)
    assert result["action"] == "throttle"
    rejected = result["rejected_alternatives"]
    assert len(rejected) == 1
    assert rejected[0]["action"] == "isolate"
    assert "70.0" in rejected[0]["why_not"]
    assert "85" in rejected[0]["why_not"]
    assert "60.0" in rejected[0]["why_not"]
    assert "70" in rejected[0]["why_not"]


def test_redirect_band():
    result = recommend(50.0, 45.0, BANDS)
    assert result["action"] == "redirect"
    assert {r["action"] for r in result["rejected_alternatives"]} == {
        "isolate",
        "throttle",
    }


def test_default_observe_reports_all_stronger_bands():
    result = recommend(10.0, 5.0, BANDS)
    assert result["action"] == "observe"
    rejected = result["rejected_alternatives"]
    assert [r["action"] for r in rejected] == ["isolate", "throttle", "redirect"]
    for r in rejected:
        assert "10.0" in r["why_not"]
        assert "5.0" in r["why_not"]


def test_why_not_states_only_the_predicates_that_actually_failed():
    # score passes throttle's 60 but confidence fails its 50
    result = recommend(65.0, 20.0, BANDS)
    assert result["action"] == "observe"
    throttle = next(
        r for r in result["rejected_alternatives"] if r["action"] == "throttle"
    )
    assert "confidence 20.0 < required 50" in throttle["why_not"]
    assert "score" not in throttle["why_not"]


def test_high_score_low_confidence_never_isolates():
    result = recommend(100.0, 0.0, BANDS)
    assert result["action"] == "observe"
    isolate = next(
        r for r in result["rejected_alternatives"] if r["action"] == "isolate"
    )
    assert "confidence 0.0 < required 70" in isolate["why_not"]


def test_recommendation_shape_is_pure_data():
    result = recommend(70.0, 60.0, BANDS)
    assert set(result) == {
        "action",
        "rule",
        "delay_profile",
        "decoy",
        "rejected_alternatives",
    }
    json.dumps(result)  # must be plain serializable data


def test_recommend_is_pure_function_of_score_confidence_config():
    a = recommend(42.0, 33.0, BANDS)
    b = recommend(42.0, 33.0, BANDS)
    assert a == b
    assert a is not b


def test_recommend_reads_no_reaction_data():
    signature = inspect.signature(recommend)
    assert list(signature.parameters) == ["score", "confidence", "action_bands"]
    module_source = inspect.getsource(select)
    assert "azazel_grimoire.reactions" not in module_source
    assert "sqlite" not in module_source.lower()
    assert "repository" not in module_source.lower()


def test_no_default_band_falls_back_to_observe():
    bands = [
        {"name": "isolate", "condition": {"score_gte": 85, "confidence_gte": 70}}
    ]
    result = recommend(10.0, 10.0, bands)
    assert result["action"] == "observe"
    assert result["rule"] is None
    assert len(result["rejected_alternatives"]) == 1


def test_boundary_is_inclusive_gte():
    result = recommend(85.0, 70.0, BANDS)
    assert result["action"] == "isolate"
    result = recommend(84.999, 70.0, BANDS)
    assert result["action"] == "throttle"
