from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "ops" / "install-pi.sh"
_SYSTEMD_TEMPLATE = _REPO_ROOT / "ops" / "azazel-grimoire.service"


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
    assert "--install-systemd" in result.stdout
    assert "--edge-addr IP" in result.stdout
    assert "--mgmt-ip IP" in result.stdout


def test_install_pi_check_is_preflight_only_and_has_no_root_side_effects(tmp_path: Path) -> None:
    root = tmp_path / "node-root"

    result = _run("--check", "--root", str(root), "--skip-thermal")

    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "preflight completed; --check requested" in result.stdout
    assert not root.exists()


def test_install_pi_check_previews_systemd_unit_without_writing_etc(tmp_path: Path) -> None:
    root = tmp_path / "node-root"

    result = _run(
        "--check",
        "--root",
        str(root),
        "--skip-thermal",
        "--install-systemd",
    )

    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "systemd unit preview: /etc/systemd/system/azazel-grimoire.service" in result.stdout
    assert "RequiresMountsFor=" in result.stdout
    assert "WorkingDirectory=" in result.stdout
    assert "ExecStart=" in result.stdout
    assert not Path("/etc/systemd/system/azazel-grimoire.service").exists()


def test_install_pi_check_edge_addr_validation_is_config_only(tmp_path: Path) -> None:
    root = tmp_path / "node-root"

    inside = _run(
        "--check",
        "--root",
        str(root),
        "--skip-thermal",
        "--edge-addr",
        "203.0.113.10",
    )
    assert inside.returncode == 0, f"stdout={inside.stdout!r} stderr={inside.stderr!r}"
    assert "MGMT_SEGMENT from ops/nftables.conf: 203.0.113.0/24" in inside.stdout
    assert "edge address 203.0.113.10 is within MGMT_SEGMENT 203.0.113.0/24" in inside.stdout
    assert "check-only mode: skipping live curl against" in inside.stdout

    outside = _run(
        "--check",
        "--root",
        str(root),
        "--skip-thermal",
        "--edge-addr",
        "10.0.0.1",
    )
    assert outside.returncode == 0, f"stdout={outside.stdout!r} stderr={outside.stderr!r}"
    assert "edge address 10.0.0.1 is outside MGMT_SEGMENT 203.0.113.0/24; nftables would drop it" in outside.stderr


def test_install_pi_requires_yes_for_destructive_commands() -> None:
    text = _SCRIPT.read_text(encoding="utf-8")

    assert 'if [[ -n "${SECRETS_DEVICE}${DATA_DEVICE}" ]] && [[ "${AUTO_YES}" -ne 1 ]]; then' in text
    assert 'fail "refusing destructive device formatting without --yes"' in text
    assert "cryptsetup luksFormat" in text
    assert "mkfs.ext4" in text


def test_systemd_template_contains_required_placeholders() -> None:
    text = _SYSTEMD_TEMPLATE.read_text(encoding="utf-8")

    assert "__ROOT_DIR__" in text
    assert "__REPO_DIR__" in text
    assert "__COMPOSE_FILE__" in text
    assert "__DOCKER__" in text
    assert "RequiresMountsFor=__ROOT_DIR__" in text
    assert "WantedBy=multi-user.target" in text
