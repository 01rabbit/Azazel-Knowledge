from __future__ import annotations

import json
import os
import sqlite3
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from fastapi.testclient import TestClient

from azazel_knowledge.api.app import Settings, create_app
from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.security.auth import mint_token
from azazel_knowledge.worker import WorkerPaths, ensure_local_db

REFERENCE_ONLY_NOTE = (
    "NOTE: reference-only on this platform; not a pass/fail gate (run on Pi 4 for S9)"
)
THERMAL_PATH = Path("/sys/class/thermal/thermal_zone0/temp")
THERMAL_LIMIT_MILLIC = 80_000
FIXED_QUERY_AS_OF = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)
DEFAULT_RESULTS_DIR = Path("bench-results")
DEFAULT_SCRATCH_ROOT = DEFAULT_RESULTS_DIR / "scratch"
DEFAULT_CONFIG_DIR = REPO_ROOT / "config"


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def fadvise_available() -> bool:
    return getattr(os, "posix_fadvise", None) is not None and getattr(
        os, "POSIX_FADV_DONTNEED", None
    ) is not None


def thermal_ok() -> bool | None:
    if not THERMAL_PATH.is_file():
        return None
    try:
        millidegrees = int(THERMAL_PATH.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return millidegrees < THERMAL_LIMIT_MILLIC


def authoritative() -> bool:
    return is_linux() and thermal_ok() is True


def platform_metadata() -> dict[str, Any]:
    thermal = thermal_ok()
    meta = {
        "platform": sys.platform,
        "linux": is_linux(),
        "fadvise_available": fadvise_available(),
        "thermal_ok": thermal,
        "authoritative": authoritative(),
    }
    if not meta["authoritative"]:
        meta["note"] = REFERENCE_ONLY_NOTE
    return meta


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(float(v) for v in values)
    rank = (len(ordered) - 1) * pct
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    if low == high:
        return ordered[low]
    fraction = rank - low
    return ordered[low] + (ordered[high] - ordered[low]) * fraction


def percentile_summary(values: Sequence[float]) -> dict[str, float]:
    return {
        "count": len(values),
        "p50_ms": round(percentile(values, 0.50), 6),
        "p95_ms": round(percentile(values, 0.95), 6),
        "p99_ms": round(percentile(values, 0.99), 6),
    }


def evaluate_gate(name: str, measured: float, threshold: float, cmp: str) -> dict[str, Any]:
    if cmp == "<":
        passed = measured < threshold
    elif cmp == "<=":
        passed = measured <= threshold
    elif cmp == ">=":
        passed = measured >= threshold
    elif cmp == ">":
        passed = measured > threshold
    else:
        raise ValueError(f"unsupported comparison: {cmp}")
    return {
        "metric": name,
        "measured": round(float(measured), 6),
        "threshold": float(threshold),
        "cmp": cmp,
        "pass": passed,
    }


def default_root() -> Path:
    return DEFAULT_SCRATCH_ROOT


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def deterministic_dump(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"unsupported type for JSON dump: {type(value)!r}")


def write_json(name: str, label: str, payload: dict[str, Any]) -> Path:
    path = DEFAULT_RESULTS_DIR / f"{name}-{label}.json"
    ensure_parent(path)
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, default=deterministic_dump) + "\n",
        encoding="utf-8",
    )
    return path


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_paths(root: Path, config_dir: Path | None = None) -> WorkerPaths:
    paths = WorkerPaths.from_root(root, config_dir=config_dir or DEFAULT_CONFIG_DIR)
    paths.ensure_dirs()
    ensure_local_db(paths.local_db_path)
    seed_local_meta(paths.local_db_path)
    return paths


def seed_local_meta(local_db_path: Path) -> None:
    conn = sqlite3.connect(local_db_path)
    try:
        conn.execute(
            "INSERT INTO local_meta (key, value) VALUES ('local_generation', '1') "
            "ON CONFLICT (key) DO NOTHING"
        )
        conn.execute(
            "INSERT INTO local_meta (key, value) VALUES ('stats_generation', '1') "
            "ON CONFLICT (key) DO NOTHING"
        )
        conn.commit()
    finally:
        conn.close()


def add_query_client(local_db_path: Path, key_id: str = "bench-query") -> str:
    token, token_hash = mint_token(key_id)
    conn = sqlite3.connect(local_db_path)
    try:
        conn.execute(
            "INSERT INTO api_client (key_id, token_sha256, scopes, quota_bytes, enabled, created_at) "
            "VALUES (?, ?, ?, NULL, 1, ?) "
            "ON CONFLICT (key_id) DO UPDATE SET "
            "token_sha256 = excluded.token_sha256, scopes = excluded.scopes, enabled = 1, "
            "created_at = excluded.created_at",
            (key_id, token_hash, json.dumps(["query"]), FIXED_QUERY_AS_OF.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def build_client(
    root: Path,
    *,
    config_dir: Path | None = None,
    context_deadline_ms: int | None = None,
    pool_size: int = 4,
):
    paths = resolve_paths(root, config_dir=config_dir)
    settings = Settings(
        config_dir=paths.config_dir,
        local_db_path=paths.local_db_path,
        data_db_dir=paths.data_db_dir,
        spool_root=paths.ingest_root,
        audit_dir=paths.audit_dir / "api",
        secrets_dir=paths.secrets_dir,
        proc_id="bench-api",
        boot_id="bench-boot",
        clock=FixedClock(FIXED_QUERY_AS_OF),
        pool_size=pool_size,
        context_deadline_ms=context_deadline_ms,
    )
    return create_app(settings), settings, paths

