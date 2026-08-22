"""Static contract (ADR-0013, #61): the YARA/Sigma rule-corpus adapters
store rule text and metadata as inert knowledge and never gain a rule
-execution path. Enforced the same way `test_api_static.py` enforces its
"no write SQL in api/" contract: grep the adapter modules (and
`pyproject.toml`, which must stay dependency-unchanged) for the tokens a
rule-execution dependency would introduce, and for a `.compile(`/`.match(`
call shape that would only appear if rule content were being compiled or
matched as an executable pattern -- the adapters' own stdlib-`re`
metadata extraction never precompiles a pattern object or calls `.match(`,
so this shape is unambiguous today and stays that way.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTERS_DIR = REPO_ROOT / "src" / "azazel_knowledge" / "feeds" / "adapters"
SIGMA_ADAPTER = ADAPTERS_DIR / "sigma_corpus.py"
YARA_ADAPTER = ADAPTERS_DIR / "yara_corpus.py"
PYPROJECT = REPO_ROOT / "pyproject.toml"

_FORBIDDEN_TOKENS = ("yara-python", "import yara", "pysigma", "sigma_correlation")
_EXECUTION_CALL_RE = re.compile(r"\.compile\(|\.match\(")


def _non_comment_lines(path: Path) -> list[tuple[int, str]]:
    lines = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip().startswith("#"):
            continue
        lines.append((line_no, line))
    return lines


def _scan(path: Path) -> list[str]:
    offenders: list[str] = []
    for line_no, line in _non_comment_lines(path):
        for token in _FORBIDDEN_TOKENS:
            if token in line:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{line_no}: forbidden token {token!r}: {line.strip()}")
        if _EXECUTION_CALL_RE.search(line):
            offenders.append(
                f"{path.relative_to(REPO_ROOT)}:{line_no}: forbidden .compile(/.match( call: {line.strip()}"
            )
    return offenders


def test_sigma_adapter_exists_and_subclasses_feed_adapter():
    assert SIGMA_ADAPTER.is_file()
    text = SIGMA_ADAPTER.read_text(encoding="utf-8")
    assert "class SigmaCorpusAdapter(FeedAdapter)" in text
    assert "full_replace = True" in text


def test_yara_adapter_exists_and_subclasses_feed_adapter():
    assert YARA_ADAPTER.is_file()
    text = YARA_ADAPTER.read_text(encoding="utf-8")
    assert "class YaraCorpusAdapter(FeedAdapter)" in text
    assert "full_replace = True" in text


def test_sigma_adapter_has_no_rule_execution_path():
    offenders = _scan(SIGMA_ADAPTER)
    assert not offenders, "forbidden rule-execution pattern(s) found:\n" + "\n".join(offenders)


def test_yara_adapter_has_no_rule_execution_path():
    offenders = _scan(YARA_ADAPTER)
    assert not offenders, "forbidden rule-execution pattern(s) found:\n" + "\n".join(offenders)


def test_pyproject_has_no_rule_execution_dependency():
    offenders = _scan(PYPROJECT)
    assert not offenders, "forbidden rule-execution pattern(s) found:\n" + "\n".join(offenders)
