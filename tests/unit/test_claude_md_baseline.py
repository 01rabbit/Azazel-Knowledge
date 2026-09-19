"""The test baseline written in CLAUDE.md must match the suite it describes.

CLAUDE.md's adversarial review checklist requires that a PR not reduce the
test count, and its git discipline names a baseline to check against. That
guard is only as good as the number: a baseline **below** the real count
passes while tests are missing, and says nothing. The number has gone stale
three times (487 -> 714 -> 819 -> 821), each time caught only because someone
happened to run the suite and compare by hand.

`tools/docs-sync-check.py` is the repository's drift checker, but it cannot
own this one: it is a pure parser over `config/` and `docs/`, and the real
test count is knowable only by collecting the suite. So the check lives where
the number comes from.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

CLAUDE_MD = Path(__file__).resolve().parents[2] / "CLAUDE.md"

#: Every place CLAUDE.md states the baseline, with the section it sits in so a
#: failure names where to look rather than just which regex missed.
BASELINE_SITES = (
    (r"テスト(\d+)本\(基準線\)", "git 規律"),
    (r"基準線 (\d+) passed", "検証コマンド"),
    (r"`tests/unit/`\((\d+)\)", "リポジトリ地図"),
)


def _baseline_values() -> dict[str, int]:
    text = CLAUDE_MD.read_text(encoding="utf-8")
    found: dict[str, int] = {}
    for pattern, section in BASELINE_SITES:
        match = re.search(pattern, text)
        assert match is not None, (
            f"CLAUDE.md no longer states the test baseline in its {section} section "
            f"(pattern {pattern!r} did not match). Either the baseline was removed -- "
            f"which drops the guard -- or the wording moved and this check must follow it."
        )
        found[section] = int(match.group(1))
    return found


def test_every_statement_of_the_baseline_agrees():
    """Three places carry the number; updating one and not the others is the
    failure mode that has actually happened."""
    values = _baseline_values()
    assert len(set(values.values())) == 1, (
        f"CLAUDE.md states different baselines in different sections: {values}"
    )


def test_baseline_is_not_below_the_real_test_count(request: pytest.FixtureRequest):
    """A baseline below reality is the direction that silently disables the guard.

    Only that direction is asserted. A run over part of the suite selects fewer
    tests than the baseline by design, and this test cannot tell that apart from
    deleted tests, so asserting equality would fail on every
    `pytest tests/unit/test_one_file.py`. Too-low is the dangerous direction: it
    is the one under which "the test count did not decrease" stays true while
    tests are gone.
    """
    selected = request.session.testscollected
    baseline = min(_baseline_values().values())
    assert selected <= baseline, (
        f"CLAUDE.md's baseline is {baseline} but this run selected {selected} tests. "
        f"The baseline is stale and low, so the 'tests did not decrease' check in the "
        f"adversarial review checklist would pass with up to {selected - baseline} "
        f"tests deleted. Update every site listed in BASELINE_SITES."
    )
