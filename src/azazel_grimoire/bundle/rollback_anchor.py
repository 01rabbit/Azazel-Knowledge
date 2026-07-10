"""Anti-rollback authority: `trust/state.toml` (design F-7).

`last_imported_version` is the sole source of truth for anti-rollback and
lives outside the data partition (the design places it on the LUKS
secrets partition alongside `anchors.toml`). `local.db:bundle_state` is
only ever a convenience mirror -- nothing in this module reads it, so
restoring an old data-partition snapshot together with an old
`bundle_state` row cannot resurrect a rolled-back version as long as
`state.toml` itself is not also rolled back.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


class IntegrityAlert(Exception):
    pass


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


@dataclass(frozen=True)
class RollbackState:
    last_imported_version: int = 0
    last_import_at: str | None = None
    last_bundle_sha256: str | None = None
    needs_full_rebaseline: bool = False


def read_state(state_path: str | Path) -> RollbackState:
    path = Path(state_path)
    if not path.exists():
        return RollbackState()
    with path.open("rb") as fh:
        doc = tomllib.load(fh)
    return RollbackState(
        last_imported_version=int(doc.get("last_imported_version", 0)),
        last_import_at=doc.get("last_import_at"),
        last_bundle_sha256=doc.get("last_bundle_sha256"),
        needs_full_rebaseline=bool(doc.get("needs_full_rebaseline", False)),
    )


def _dump_state(state: RollbackState) -> str:
    lines = [f"last_imported_version = {int(state.last_imported_version)}"]
    if state.last_import_at is not None:
        lines.append(f"last_import_at = {_toml_string(state.last_import_at)}")
    if state.last_bundle_sha256 is not None:
        lines.append(f"last_bundle_sha256 = {_toml_string(state.last_bundle_sha256)}")
    lines.append(f"needs_full_rebaseline = {'true' if state.needs_full_rebaseline else 'false'}")
    return "\n".join(lines) + "\n"


def write_state(state_path: str | Path, state: RollbackState) -> None:
    path = Path(state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    text = _dump_state(state)
    with tmp_path.open("w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, path)
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def record_import(
    state_path: str | Path,
    *,
    bundle_version: int,
    imported_at: str,
    bundle_sha256: str,
    needs_full_rebaseline: bool = False,
) -> RollbackState:
    new_state = RollbackState(
        last_imported_version=bundle_version,
        last_import_at=imported_at,
        last_bundle_sha256=bundle_sha256,
        needs_full_rebaseline=needs_full_rebaseline,
    )
    write_state(state_path, new_state)
    return new_state


def mark_needs_full_rebaseline(state_path: str | Path, flag: bool = True) -> RollbackState:
    current = read_state(state_path)
    new_state = RollbackState(
        last_imported_version=current.last_imported_version,
        last_import_at=current.last_import_at,
        last_bundle_sha256=current.last_bundle_sha256,
        needs_full_rebaseline=flag,
    )
    write_state(state_path, new_state)
    return new_state


def detect_version_gap(
    prev_version: int,
    new_version: int,
    prev_sha256: str | None = None,
    new_sha256: str | None = None,
) -> str:
    """Classify a version transition against the anti-rollback watermark.

    Returns "ok" for the expected +1 step, "integrity_check" for a
    same-version transition whose content hash disagrees with the last
    recorded one (a crash-mid-swap symptom the caller should
    investigate but need not treat as an attack), and raises
    `IntegrityAlert` (fail closed) for anything else -- rollback
    attempts or unexplained multi-version jumps.
    """
    gap = new_version - prev_version
    if gap == 1:
        return "ok"
    if gap == 0 and prev_sha256 is not None and new_sha256 is not None and prev_sha256 != new_sha256:
        return "integrity_check"
    raise IntegrityAlert(
        f"unexplained version gap: prev={prev_version} new={new_version} (gap={gap})"
    )
