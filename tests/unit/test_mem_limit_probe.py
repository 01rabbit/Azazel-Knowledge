from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "mem_limit_probe.py"

_SPEC = importlib.util.spec_from_file_location("mem_limit_probe", MODULE_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
mem_limit_probe = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = mem_limit_probe
_SPEC.loader.exec_module(mem_limit_probe)


def test_probe_non_linux_skips_with_reason():
    if sys.platform.startswith("linux"):
        return

    result = mem_limit_probe.probe(reserve_mb=8, touch_mb=2, label="unit", stamp="case-1")

    assert result.skipped is True
    assert result.authoritative is False
    assert result.reason == "Linux /proc + cgroup required"
    assert "Linux" in result.note


def test_probe_linux_collects_expected_fields():
    if not sys.platform.startswith("linux"):
        return

    result = mem_limit_probe.probe(reserve_mb=8, touch_mb=2, label="unit", stamp="case-2")
    payload = json.loads(json.dumps(mem_limit_probe.asdict(result), sort_keys=True))

    assert result.skipped is False
    assert result.authoritative is True
    assert isinstance(result.vm_size_kb, int) and result.vm_size_kb > 0
    assert isinstance(result.vm_rss_kb, int) and result.vm_rss_kb > 0
    assert isinstance(result.vm_data_kb, int) and result.vm_data_kb >= 0
    assert result.gap.address_space_delta_kb >= 8 * 1024
    assert result.gap.rss_delta_kb >= 0
    assert payload["label"] == "unit"
    assert payload["stamp"] == "case-2"
    assert set(payload) == {
        "authoritative",
        "cgroup",
        "gap",
        "label",
        "note",
        "platform",
        "reason",
        "rlimit_as_hard",
        "rlimit_as_soft",
        "skipped",
        "stamp",
        "vm_data_kb",
        "vm_rss_kb",
        "vm_size_kb",
    }
    assert set(payload["gap"]) == {
        "address_space_delta_kb",
        "reserved_kb",
        "rss_delta_kb",
        "touched_kb",
        "vmsize_minus_rss_kb",
    }
    assert set(payload["cgroup"]) == {
        "available",
        "memory_current",
        "memory_max",
        "path",
        "reason",
    }


def test_main_writes_json_out_file(tmp_path):
    out_path = tmp_path / "probe.json"

    exit_code = mem_limit_probe.main(
        [
            "--reserve-mb",
            "8",
            "--touch-mb",
            "2",
            "--label",
            "cli",
            "--stamp",
            "sample",
            "--json-out",
            str(out_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["label"] == "cli"
    assert payload["stamp"] == "sample"
    assert "gap" in payload
