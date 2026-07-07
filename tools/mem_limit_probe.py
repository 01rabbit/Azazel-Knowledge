#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import mmap
import os
import resource
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


PROC_STATUS_PATH = Path("/proc/self/status")
PROC_CGROUP_PATH = Path("/proc/self/cgroup")
CGROUP_ROOT = Path("/sys/fs/cgroup")
LINUX_REQUIRED_REASON = "Linux /proc + cgroup required"


@dataclass(frozen=True)
class CgroupInfo:
    available: bool
    memory_max: int | str | None
    memory_current: int | None
    path: str | None
    reason: str | None


@dataclass(frozen=True)
class GapInfo:
    address_space_delta_kb: int
    rss_delta_kb: int
    vmsize_minus_rss_kb: int
    reserved_kb: int
    touched_kb: int


@dataclass(frozen=True)
class ProbeResult:
    platform: str
    authoritative: bool
    skipped: bool
    reason: str | None
    label: str | None
    stamp: str | None
    vm_size_kb: int | None
    vm_rss_kb: int | None
    vm_data_kb: int | None
    rlimit_as_soft: int | None
    rlimit_as_hard: int | None
    cgroup: CgroupInfo
    gap: GapInfo
    note: str


def _parse_kb_field(raw: str) -> int:
    parts = raw.split()
    if not parts:
        raise ValueError(f"invalid status field: {raw!r}")
    return int(parts[0])


def _read_proc_status() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in PROC_STATUS_PATH.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"VmSize", "VmRSS", "VmData"}:
            values[key] = _parse_kb_field(value.strip())
    missing = {"VmSize", "VmRSS", "VmData"} - values.keys()
    if missing:
        raise RuntimeError(f"missing proc status keys: {sorted(missing)}")
    return values


def _read_limit_value(path: Path) -> int | str | None:
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    if raw == "max":
        return raw
    return int(raw)


def _cgroup_memory_dir() -> Path | None:
    if not (CGROUP_ROOT / "cgroup.controllers").exists():
        return None
    if not PROC_CGROUP_PATH.exists():
        return None
    for line in PROC_CGROUP_PATH.read_text(encoding="utf-8").splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        hierarchy, controllers, relative_path = parts
        if hierarchy == "0" and controllers == "":
            trimmed = relative_path.lstrip("/")
            return CGROUP_ROOT / trimmed if trimmed else CGROUP_ROOT
    return None


def _read_cgroup_info() -> CgroupInfo:
    memory_dir = _cgroup_memory_dir()
    if memory_dir is None:
        return CgroupInfo(
            available=False,
            memory_max=None,
            memory_current=None,
            path=None,
            reason="cgroup v2 memory controller unavailable",
        )

    memory_max_path = memory_dir / "memory.max"
    memory_current_path = memory_dir / "memory.current"
    if not (memory_max_path.exists() and memory_current_path.exists()):
        return CgroupInfo(
            available=False,
            memory_max=None,
            memory_current=None,
            path=str(memory_dir),
            reason="cgroup v2 memory files unavailable",
        )

    memory_max = _read_limit_value(memory_max_path)
    memory_current = _read_limit_value(memory_current_path)
    return CgroupInfo(
        available=True,
        memory_max=memory_max,
        memory_current=memory_current if isinstance(memory_current, int) else None,
        path=str(memory_dir),
        reason=None,
    )


def _rlimit_value(value: int) -> int | None:
    return None if value == resource.RLIM_INFINITY else int(value)


def _touch_mapping(mapping: mmap.mmap, touch_bytes: int) -> None:
    if touch_bytes <= 0:
        return
    page_size = max(1, mmap.PAGESIZE)
    limit = min(len(mapping), touch_bytes)
    for offset in range(0, limit, page_size):
        mapping[offset] = 1
    if limit and (limit - 1) % page_size:
        mapping[limit - 1] = 1


def _unsupported_result(label: str | None, stamp: str | None, reason: str) -> ProbeResult:
    return ProbeResult(
        platform=sys.platform,
        authoritative=False,
        skipped=True,
        reason=reason,
        label=label,
        stamp=stamp,
        vm_size_kb=None,
        vm_rss_kb=None,
        vm_data_kb=None,
        rlimit_as_soft=None,
        rlimit_as_hard=None,
        cgroup=CgroupInfo(
            available=False,
            memory_max=None,
            memory_current=None,
            path=None,
            reason=reason,
        ),
        gap=GapInfo(
            address_space_delta_kb=0,
            rss_delta_kb=0,
            vmsize_minus_rss_kb=0,
            reserved_kb=0,
            touched_kb=0,
        ),
        note=reason,
    )


def probe(
    *,
    reserve_mb: int = 256,
    touch_mb: int = 32,
    label: str | None = None,
    stamp: str | None = None,
) -> ProbeResult:
    if reserve_mb < 0:
        raise ValueError("reserve_mb must be >= 0")
    if touch_mb < 0:
        raise ValueError("touch_mb must be >= 0")
    if touch_mb > reserve_mb:
        raise ValueError("touch_mb must be <= reserve_mb")

    if not sys.platform.startswith("linux"):
        return _unsupported_result(label, stamp, LINUX_REQUIRED_REASON)
    if not PROC_STATUS_PATH.exists():
        return _unsupported_result(label, stamp, LINUX_REQUIRED_REASON)

    before = _read_proc_status()
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_AS)
    cgroup = _read_cgroup_info()

    reserve_bytes = reserve_mb * 1024 * 1024
    touch_bytes = touch_mb * 1024 * 1024
    mapping: mmap.mmap | None = None
    try:
        if reserve_bytes > 0:
            mapping = mmap.mmap(-1, reserve_bytes, access=mmap.ACCESS_WRITE)
            _touch_mapping(mapping, touch_bytes)
        after = _read_proc_status()
    finally:
        if mapping is not None:
            mapping.close()

    address_space_delta_kb = max(0, after["VmSize"] - before["VmSize"])
    rss_delta_kb = max(0, after["VmRSS"] - before["VmRSS"])
    vmsize_minus_rss_kb = max(0, after["VmSize"] - after["VmRSS"])

    note = (
        "RLIMIT_AS measures VmSize while cgroup memory.max measures resident memory. "
        f"This probe reserved {reserve_mb} MB of anonymous address space and touched {touch_mb} MB; "
        f"VmSize grew by {address_space_delta_kb // 1024} MB while VmRSS grew by {rss_delta_kb // 1024} MB."
    )

    return ProbeResult(
        platform=sys.platform,
        authoritative=True,
        skipped=False,
        reason=None,
        label=label,
        stamp=stamp,
        vm_size_kb=after["VmSize"],
        vm_rss_kb=after["VmRSS"],
        vm_data_kb=after["VmData"],
        rlimit_as_soft=_rlimit_value(soft_limit),
        rlimit_as_hard=_rlimit_value(hard_limit),
        cgroup=cgroup,
        gap=GapInfo(
            address_space_delta_kb=address_space_delta_kb,
            rss_delta_kb=rss_delta_kb,
            vmsize_minus_rss_kb=vmsize_minus_rss_kb,
            reserved_kb=reserve_mb * 1024,
            touched_kb=touch_mb * 1024,
        ),
        note=note,
    )


def _result_to_json(result: ProbeResult) -> str:
    return json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reserve-mb", type=int, default=256)
    parser.add_argument("--touch-mb", type=int, default=32)
    parser.add_argument("--label")
    parser.add_argument("--stamp")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)

    result = probe(
        reserve_mb=args.reserve_mb,
        touch_mb=args.touch_mb,
        label=args.label,
        stamp=args.stamp,
    )
    payload = _result_to_json(result)
    print(payload)
    if args.json_out is not None:
        args.json_out.write_text(payload + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
