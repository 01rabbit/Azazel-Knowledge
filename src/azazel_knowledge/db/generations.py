from __future__ import annotations

import os
import shutil
import sqlite3
from pathlib import Path

GEN_DIR_PREFIX = "gen-"
CURRENT_LINK_NAME = "current"
INTEL_DB_NAME = "intel.db"


def generation_dir(data_db_dir: Path, n: int) -> Path:
    return Path(data_db_dir) / f"{GEN_DIR_PREFIX}{n}"


def intel_db_path(data_db_dir: Path, n: int) -> Path:
    return generation_dir(data_db_dir, n) / INTEL_DB_NAME


def _all_generation_numbers(data_db_dir: Path) -> list[int]:
    data_db_dir = Path(data_db_dir)
    if not data_db_dir.is_dir():
        return []
    numbers = []
    for entry in data_db_dir.iterdir():
        if entry.is_dir() and entry.name.startswith(GEN_DIR_PREFIX):
            suffix = entry.name[len(GEN_DIR_PREFIX):]
            if suffix.isdigit():
                numbers.append(int(suffix))
    return numbers


def current_generation(data_db_dir: Path) -> int | None:
    link = Path(data_db_dir) / CURRENT_LINK_NAME
    if not link.is_symlink() and not link.exists():
        return None
    target = os.readlink(link)
    name = Path(target).name
    if not name.startswith(GEN_DIR_PREFIX):
        return None
    suffix = name[len(GEN_DIR_PREFIX):]
    return int(suffix) if suffix.isdigit() else None


def build_next_generation(data_db_dir: Path) -> Path:
    data_db_dir = Path(data_db_dir)
    data_db_dir.mkdir(parents=True, exist_ok=True)
    current = current_generation(data_db_dir)
    next_n = 1 if current is None else current + 1
    path = generation_dir(data_db_dir, next_n)
    path.mkdir(parents=True, exist_ok=True)
    return intel_db_path(data_db_dir, next_n)


def swap_current(data_db_dir: Path, n: int) -> None:
    data_db_dir = Path(data_db_dir)
    if not generation_dir(data_db_dir, n).is_dir():
        raise FileNotFoundError(str(generation_dir(data_db_dir, n)))
    link = data_db_dir / CURRENT_LINK_NAME
    tmp = data_db_dir / f".{CURRENT_LINK_NAME}.tmp.{os.getpid()}"
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    os.symlink(f"{GEN_DIR_PREFIX}{n}", tmp)
    os.replace(tmp, link)


def gc_old_generations(data_db_dir: Path, keep: int = 2) -> list[int]:
    data_db_dir = Path(data_db_dir)
    gens = sorted(_all_generation_numbers(data_db_dir), reverse=True)
    to_keep = set(gens[:keep])
    removed: list[int] = []
    for g in gens:
        if g not in to_keep:
            shutil.rmtree(generation_dir(data_db_dir, g), ignore_errors=True)
            removed.append(g)
    return removed


def read_intel_generation(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT value FROM stats_meta WHERE key = 'intel_generation'"
    ).fetchone()
    return int(row[0]) if row else 0


def bump_intel_generation(conn: sqlite3.Connection, n: int) -> None:
    conn.execute(
        "INSERT INTO stats_meta (key, value) VALUES ('intel_generation', ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (str(n),),
    )
