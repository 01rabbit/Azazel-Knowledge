from __future__ import annotations

from pathlib import Path

from azazel_knowledge.normalize.cross_feed_check import CrossFeedCheck, CrossFeedDecision


def _make_check(tmp_path: Path, **kwargs) -> CrossFeedCheck:
    return CrossFeedCheck(tmp_path / "cross_feed_state.json", **kwargs)


def test_baseline_builds_up_and_stays_ok(tmp_path: Path):
    check = _make_check(tmp_path, min_baseline_runs=5)
    for i in range(6):
        result = check.check("urlhaus", {f"v{i}"})
        assert result.decision is CrossFeedDecision.OK


def test_no_quarantine_before_min_baseline_runs(tmp_path: Path):
    check = _make_check(tmp_path, min_baseline_runs=5)
    check.check("threatfox", {"a"})
    check.check("threatfox", {"a"})
    result = check.check("threatfox", {"a", "b", "c", "d", "e", "f", "g", "h"})
    assert result.decision is CrossFeedDecision.OK


def test_quarantine_trips_after_deviation(tmp_path: Path):
    state_path = tmp_path / "state.json"
    check = CrossFeedCheck(state_path, min_baseline_runs=5, sigma_threshold=3.0)

    for i in range(6):
        result = check.check("urlhaus", {f"stable-{i}-{j}" for j in range(10)})
        assert result.decision is CrossFeedDecision.OK

    check.check("malwarebazaar", {"shared-1", "shared-2"})

    anomalous_novel = {"shared-1", "shared-2"}
    result = check.check("urlhaus", anomalous_novel)
    assert result.decision is CrossFeedDecision.QUARANTINE
    assert result.baseline_n >= 5
    assert result.z_score is not None
    assert result.z_score > 3.0


def test_deterministic_given_same_state(tmp_path: Path):
    state_path = tmp_path / "state.json"
    check_a = CrossFeedCheck(state_path, min_baseline_runs=5)
    for i in range(5):
        check_a.check("urlhaus", {f"x{i}"})

    check_b = CrossFeedCheck(state_path, min_baseline_runs=5)
    result_b = check_b.check("urlhaus", {"y0"})

    check_c = CrossFeedCheck(state_path, min_baseline_runs=5)
    check_c_state = check_c._load()
    assert "urlhaus" in check_c_state["feeds"]
    assert result_b.baseline_n == 5


def test_empty_novel_set_zero_overlap(tmp_path: Path):
    check = _make_check(tmp_path)
    result = check.check("urlhaus", set())
    assert result.overlap_fraction == 0.0
    assert result.decision is CrossFeedDecision.OK


def test_state_persists_across_instances(tmp_path: Path):
    state_path = tmp_path / "state.json"
    check1 = CrossFeedCheck(state_path, min_baseline_runs=5)
    check1.check("urlhaus", {"a", "b"})
    check2 = CrossFeedCheck(state_path, min_baseline_runs=5)
    state = check2._load()
    assert len(state["feeds"]["urlhaus"]["baseline"]) == 1
