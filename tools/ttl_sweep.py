#!/usr/bin/env python3
"""TTL sweep: recompute `ioc.agg_*` for rows past their next expiry (design S3).

`sweep(conn, now)` is the importable entry point the P2 worker batch
calls every 60s; running this file recomputes once against a given
intel.db path and exits, for manual/ops use.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

try:
    from azazel_knowledge.scoring.confidence import noisy_or as _noisy_or  # type: ignore
except ImportError:
    def _noisy_or(confidences: list[float]) -> float:
        product = 1.0
        for confidence in confidences:
            product *= 1.0 - (confidence / 100.0)
        return 100.0 * (1.0 - product)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sweep(conn: sqlite3.Connection, now: str) -> int:
    """Recompute `agg_raw_confidence`/`agg_next_expiry`/`agg_computed_at`
    for every `ioc` row whose `agg_next_expiry` has passed `now`.

    `agg_raw_confidence` is the noisy-OR over the row's non-expired
    `ioc_source` confidences; `agg_next_expiry` is the earliest future
    `expires_at` among those still-active sources (`NULL` once none
    remain -- a fully expired row is not re-swept until a new source
    gives it a future expiry again).
    """
    due = conn.execute(
        "SELECT ioc_id FROM ioc WHERE agg_next_expiry IS NOT NULL AND agg_next_expiry <= ?",
        (now,),
    ).fetchall()

    updated = 0
    for (ioc_id,) in due:
        sources = conn.execute(
            "SELECT source_confidence, expires_at FROM ioc_source WHERE ioc_id = ?",
            (ioc_id,),
        ).fetchall()
        active = [(conf, expires) for conf, expires in sources if expires is None or expires > now]
        raw_confidence = _noisy_or([conf for conf, _ in active]) if active else 0.0
        future_expiries = [expires for _, expires in active if expires is not None]
        next_expiry = min(future_expiries) if future_expiries else None

        conn.execute(
            "UPDATE ioc SET agg_raw_confidence = ?, agg_next_expiry = ?, agg_computed_at = ? "
            "WHERE ioc_id = ?",
            (raw_confidence, next_expiry, now, ioc_id),
        )
        updated += 1

    conn.commit()
    return updated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ttl_sweep", description=__doc__)
    parser.add_argument("--db", required=True, help="path to intel.db")
    parser.add_argument("--now", default=None, help="ISO8601 timestamp to sweep as of (default: now)")
    args = parser.parse_args(argv)

    now = args.now or _now_iso()
    conn = sqlite3.connect(args.db)
    try:
        count = sweep(conn, now)
    finally:
        conn.close()
    print(f"swept {count} ioc row(s) as of {now}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
