from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "ops" / "install-pi.sh"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PATH"] = os.environ.get("PATH", "")
    return subprocess.run(
        [str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        env=env,
    )


def test_install_pi_script_is_executable_and_parses_in_bash() -> None:
    mode = _SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR

    result = subprocess.run(
        ["bash", "-n", str(_SCRIPT)],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr


def test_install_pi_help_prints_usage() -> None:
    result = _run("--help")
    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert "--root DIR" in result.stdout
    assert "--check, --dry-run" in result.stdout


def test_install_pi_check_is_preflight_only_and_has_no_root_side_effects(tmp_path: Path) -> None:
    root = tmp_path / "node-root"

    result = _run("--check", "--root", str(root), "--skip-thermal")

    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "preflight completed; --check requested" in result.stdout
    assert not root.exists()


def test_install_pi_requires_yes_for_destructive_commands() -> None:
    text = _SCRIPT.read_text(encoding="utf-8")

    assert 'if [[ -n "${SECRETS_DEVICE}${DATA_DEVICE}" ]] && [[ "${AUTO_YES}" -ne 1 ]]; then' in text
    assert 'fail "refusing destructive device formatting without --yes"' in text
    assert "cryptsetup luksFormat" in text
    assert "mkfs.ext4" in text
