"""Export the reaction research dataset (design S8).

Exports every `reaction` row plus its resolved linkage state and
`metrics_eligible_strict` verdict as sorted, deterministic JSONL, with
`actor_key` pseudonymized as `HMAC-SHA256(site_key, actor_key)[:16]` hex so
raw IP/JA3/session-cluster values never leave the site. A manifest
alongside the export records the export file's SHA-256 and row count.

Usable both as a CLI (`python tools/export_research_dataset.py ...`) and
as an importable module for tests.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sqlite3
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
_SRC_DIR = _TOOLS_DIR.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from azazel_cti.core.clock import to_rfc3339  # noqa: E402
from azazel_cti.reactions import eligibility, linkage  # noqa: E402

PSEUDONYM_LENGTH = 16


def pseudonymize_actor_key(site_key: bytes, actor_key: str) -> str:
    digest = hmac.new(site_key, actor_key.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:PSEUDONYM_LENGTH]


def load_site_key(path: Path) -> bytes:
    return Path(path).read_bytes()


def _reaction_events(conn: sqlite3.Connection, reaction_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT event_type, edge_id, detail, created_at FROM reaction_trust_event "
        "WHERE reaction_id = ? ORDER BY event_id ASC",
        (reaction_id,),
    ).fetchall()
    return [
        {
            "event_type": r[0],
            "edge_id": r[1],
            "detail": json.loads(r[2]) if r[2] is not None else None,
            "created_at": r[3],
        }
        for r in rows
    ]


def export_reactions(
    conn: sqlite3.Connection, *, site_key: bytes
) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT reaction_id, edge_id, actor_key, action_applied, applied_at, reaction, "
        "reaction_window_s, events_in_window, classifier, classifier_version, "
        "evidence_refs, evidence_modality_count, trust_tier, advisory_id, "
        "advisory_linkage, created_at FROM reaction ORDER BY reaction_id ASC"
    ).fetchall()

    out: list[dict[str, Any]] = []
    for row in rows:
        record = dict(row)
        reaction_id = record["reaction_id"]
        events = _reaction_events(conn, reaction_id)

        record["actor_key"] = pseudonymize_actor_key(site_key, record["actor_key"])
        record["evidence_refs"] = json.loads(record["evidence_refs"])
        record["linkage_state"] = linkage.linkage_state(conn, reaction_id)
        record["metrics_eligible_strict"] = eligibility.metrics_eligible_strict(
            record, events
        )
        out.append(record)

    out.sort(key=lambda r: r["reaction_id"])
    return out


def write_jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def build_manifest(
    export_path: Path, *, conn: sqlite3.Connection, generated_at: str, row_count: int
) -> dict[str, Any]:
    sha256 = hashlib.sha256(Path(export_path).read_bytes()).hexdigest()
    return {
        "file": Path(export_path).name,
        "sha256": sha256,
        "generated_at": generated_at,
        "row_count": row_count,
        "ambiguous_linkage_rate": linkage.ambiguous_linkage_rate(conn),
    }


def run_export(
    *, local_db_path: Path, out_path: Path, site_key: bytes
) -> dict[str, Any]:
    conn = sqlite3.connect(local_db_path)
    try:
        rows = export_reactions(conn, site_key=site_key)
        write_jsonl(out_path, rows)
        manifest = build_manifest(
            out_path,
            conn=conn,
            generated_at=to_rfc3339(datetime.now(timezone.utc)),
            row_count=len(rows),
        )
        manifest_path = out_path.with_name(out_path.name + ".manifest.json")
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        return manifest
    finally:
        conn.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-db", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--site-key-file", required=True, type=Path)
    args = parser.parse_args(argv)

    site_key = load_site_key(args.site_key_file)
    manifest = run_export(
        local_db_path=args.local_db, out_path=args.out, site_key=site_key
    )
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
