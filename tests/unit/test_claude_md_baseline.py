"""The test baseline written in the instruction documents must match the suite.

CLAUDE.md's adversarial review checklist requires that a PR not reduce the
test count, and its git discipline names a baseline to check against. That
guard is only as good as the number: a baseline **below** the real count
passes while tests are missing, and says nothing. The number has gone stale
four times (487 -> 714 -> 819 -> 821 -> 859), each time caught only because
someone happened to run the suite and compare by hand.

Three documents state it, and they state it to three different audiences:

* `CLAUDE.md` -- the commander's own discipline, and the **single source**.
* `docs/development-guide.md` -- the development instruction book, which used
  to claim the single-source role for itself.
* `AGENTS.md` -- read automatically by the Codex implementer in its worktree,
  where the number backs the instruction "do not reduce the test count".

They drifted apart exactly as one would expect once two of them claimed to be
authoritative: 859 / 591 / 487 at the same commit. The `AGENTS.md` copy was
the damaging one -- 372 tests could have been deleted with its rule still
satisfied. So the check covers all three documents, not just CLAUDE.md, and
the documents now name CLAUDE.md as the one place the value is decided.

`tools/docs-sync-check.py` is the repository's drift checker, but it cannot
own this one: it is a pure parser over `config/` and `docs/`, and the real
test count is knowable only by collecting the suite. So the check lives where
the number comes from.

Each site is matched by a pattern anchored to the prose around it rather than
by a bare search for digits. A pattern that stops matching fails loudly, which
is the point: deleting the sentence that carries the baseline would otherwise
disable the guard silently, and that is indistinguishable from the drift this
test exists to catch.
"""

from __future__ import annotations

import re
import os
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Every place the baseline is stated, keyed by document and by the section it
#: sits in, so a failure names where to look rather than just which regex
#: missed. `CLAUDE.md` is the single source; the other two restate it and are
#: held to it here.
BASELINE_SITES: tuple[tuple[str, str, str], ...] = (
    ("CLAUDE.md", "git 規律", r"テスト(\d+)本\(基準線\)"),
    ("CLAUDE.md", "検証コマンド", r"基準線 (\d+) passed"),
    ("CLAUDE.md", "リポジトリ地図", r"`tests/unit/`\((\d+)\)"),
    ("docs/development-guide.md", "§0 現状分析(基準線の推移)", r"\*\*現在 = (\d+)\*\*"),
    ("AGENTS.md", "セットアップ / 検証", r"完了条件\(基準線 (\d+) 本\)"),
    ("AGENTS.md", "コード規約", r"テスト数を減らさない\*\*\(基準線 (\d+) 本\)"),
)


def _baseline_values() -> dict[str, int]:
    found: dict[str, int] = {}
    for document, section, pattern in BASELINE_SITES:
        path = REPO_ROOT / document
        text = path.read_text(encoding="utf-8")
        match = re.search(pattern, text)
        assert match is not None, (
            f"{document} no longer states the test baseline in its {section} section "
            f"(pattern {pattern!r} did not match). Either the baseline was removed -- "
            f"which drops the guard -- or the wording moved and this check must follow it."
        )
        found[f"{document} ({section})"] = int(match.group(1))
    return found


def test_every_statement_of_the_baseline_agrees():
    """Six places across three documents carry the number; updating one and
    not the others is the failure mode that has actually happened."""
    values = _baseline_values()
    assert len(set(values.values())) == 1, (
        f"The instruction documents state different baselines: {values}. "
        f"CLAUDE.md is the single source -- docs/development-guide.md and AGENTS.md "
        f"restate it and must be updated in the same diff."
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
    values = _baseline_values()
    baseline = min(values.values())
    stale = sorted(site for site, value in values.items() if value == baseline)
    require_full_candidate_suite = (
        os.environ.get("AZAZEL_REQUIRE_FULL_CANDIDATE_SUITE") == "1"
        and importlib.util.find_spec("azazel_fabric.knowledge_context") is not None
    )
    if require_full_candidate_suite:
        assert selected == baseline, (
            f"The candidate CI suite must collect exactly {baseline} tests, but selected "
            f"{selected}. Check candidate test skips and update every baseline site only "
            "when the full candidate suite intentionally changes."
        )
        return
    assert selected <= baseline, (
        f"The lowest stated baseline is {baseline} ({', '.join(stale)}) but this run "
        f"selected {selected} tests. The baseline is stale and low, so the 'tests did "
        f"not decrease' check in the adversarial review checklist would pass with up to "
        f"{selected - baseline} tests deleted. Update every site listed in BASELINE_SITES."
    )
