from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class CrossFeedDecision(Enum):
    OK = "ok"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class CrossFeedResult:
    decision: CrossFeedDecision
    overlap_fraction: float
    baseline_mean: float
    baseline_std: float
    baseline_n: int
    z_score: float | None


class CrossFeedCheck:
    def __init__(
        self,
        state_path: str | Path,
        baseline_window: int = 20,
        sibling_window: int = 5,
        sigma_threshold: float = 3.0,
        min_baseline_runs: int = 5,
    ) -> None:
        self._state_path = Path(state_path)
        self._baseline_window = baseline_window
        self._sibling_window = sibling_window
        self._sigma_threshold = sigma_threshold
        self._min_baseline_runs = min_baseline_runs

    def _load(self) -> dict:
        if not self._state_path.exists():
            return {"feeds": {}}
        with self._state_path.open("r") as fh:
            return json.load(fh)

    def _save(self, state: dict) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
        with tmp_path.open("w") as fh:
            json.dump(state, fh, sort_keys=True)
        tmp_path.replace(self._state_path)

    def check(self, feed_id: str, novel_values: set[str]) -> CrossFeedResult:
        state = self._load()
        feeds = state.setdefault("feeds", {})

        sibling_values: set[str] = set()
        for other_id, other_state in feeds.items():
            if other_id == feed_id:
                continue
            for run in other_state.get("recent_sets", []):
                sibling_values.update(run)

        if novel_values:
            overlap_fraction = len(novel_values & sibling_values) / len(novel_values)
        else:
            overlap_fraction = 0.0

        feed_state = feeds.setdefault(feed_id, {"recent_sets": [], "baseline": []})
        baseline: list[float] = feed_state["baseline"]
        n = len(baseline)

        decision = CrossFeedDecision.OK
        mean = 0.0
        std = 0.0
        z_score: float | None = None

        if n >= self._min_baseline_runs:
            mean = statistics.fmean(baseline)
            std = statistics.pstdev(baseline)
            if std > 0:
                z_score = (overlap_fraction - mean) / std
            else:
                z_score = 0.0 if overlap_fraction == mean else float("inf")
            if z_score > self._sigma_threshold:
                decision = CrossFeedDecision.QUARANTINE

        if decision is CrossFeedDecision.OK:
            baseline.append(overlap_fraction)
            if len(baseline) > self._baseline_window:
                del baseline[: len(baseline) - self._baseline_window]
            feed_state["recent_sets"].append(sorted(novel_values))
            if len(feed_state["recent_sets"]) > self._sibling_window:
                del feed_state["recent_sets"][: len(feed_state["recent_sets"]) - self._sibling_window]
            self._save(state)

        return CrossFeedResult(
            decision=decision,
            overlap_fraction=overlap_fraction,
            baseline_mean=mean,
            baseline_std=std,
            baseline_n=n,
            z_score=z_score,
        )
