from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from itertools import islice
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from _common import (
    REFERENCE_ONLY_NOTE,
    add_query_client,
    auth_header,
    build_client,
    default_root,
    evaluate_gate,
    fadvise_available,
    load_json,
    platform_metadata,
    write_json,
)

from azazel_cti.db import generations

MICROBENCH_READS = 5


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=default_root())
    parser.add_argument("--config-dir", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=Path("bench-results/dataset-manifest.json"))
    parser.add_argument("--label", default="run")
    parser.add_argument("--stamp", default=None)
    return parser


def _drop_cache(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        fadvise = getattr(os, "posix_fadvise", None)
        dontneed = getattr(os, "POSIX_FADV_DONTNEED", None)
        if fadvise is None or dontneed is None:
            raise RuntimeError("posix_fadvise unavailable")
        size = os.fstat(fd).st_size
        fadvise(fd, 0, size, dontneed)
    finally:
        os.close(fd)


def _leaf_read_ms(intel_path: Path, sample: dict[str, str]) -> float:
    _drop_cache(intel_path)
    started = time.perf_counter()
    conn = sqlite3.connect(intel_path)
    try:
        row = conn.execute(
            "SELECT agg_raw_confidence FROM ioc WHERE type = ? AND value = ?",
            (sample["type"], sample["value"]),
        ).fetchone()
        if row is None:
            raise RuntimeError("cold-read sample did not resolve")
    finally:
        conn.close()
    return (time.perf_counter() - started) * 1000.0


def run_cold_read(
    root: Path,
    manifest_path: Path,
    label: str,
    stamp: str | None,
    config_dir: Path | None = None,
):
    meta = platform_metadata()
    if not fadvise_available():
        payload = {
            "name": "cold-read",
            "label": label,
            "stamp": stamp,
            "authoritative": False,
            "skipped": True,
            "reason": "posix_fadvise unavailable (not Linux)",
            "pass": False,
            "note": REFERENCE_ONLY_NOTE,
            "platform": meta,
            "gates": [],
        }
        output_path = write_json("cold-read", label, payload)
        print(json.dumps({"output": str(output_path), "skipped": True}, sort_keys=True))
        return payload

    manifest = load_json(manifest_path)
    app, _, paths = build_client(
        root, config_dir=config_dir, context_deadline_ms=10**9, pool_size=1
    )
    token = add_query_client(paths.local_db_path)
    headers = auth_header(token)
    generation = generations.current_generation(paths.data_db_dir)
    if generation is None:
        raise RuntimeError("no current generation for cold-read benchmark")
    intel_path = generations.intel_db_path(paths.data_db_dir, generation)
    samples = list(islice(manifest["search_samples"], MICROBENCH_READS))
    microbench = [_leaf_read_ms(intel_path, sample) for sample in samples]

    from fastapi.testclient import TestClient

    _drop_cache(intel_path)
    with TestClient(app) as client:
        started = time.perf_counter()
        response = client.post(
            "/v1/context",
            json=manifest["context_body_templates"][0],
            headers=headers,
        )
        context_ms = (time.perf_counter() - started) * 1000.0
    if response.status_code != 200:
        raise RuntimeError(f"cold context failed with status {response.status_code}")

    headroom_pct = round(((250.0 - context_ms) / 250.0) * 100.0, 6)
    gates = [
        evaluate_gate("cold_context_ms", context_ms, 250.0, "<"),
        evaluate_gate("cold_context_headroom_pct", headroom_pct, 20.0, ">="),
    ]
    payload = {
        "name": "cold-read",
        "label": label,
        "stamp": stamp,
        "root": str(root),
        "manifest": str(manifest_path),
        "authoritative": meta["authoritative"],
        "skipped": False,
        "note": REFERENCE_ONLY_NOTE if not meta["authoritative"] else None,
        "platform": meta,
        "leaf_read_ms": {
            "count": len(microbench),
            "avg_ms": round(sum(microbench) / len(microbench), 6),
            "median_ms": round(sorted(microbench)[len(microbench) // 2], 6),
            "samples_ms": [round(value, 6) for value in microbench],
        },
        "worst_case_context_ms": round(context_ms, 6),
        "headroom_pct": headroom_pct,
        "gates": gates,
        "pass": all(gate["pass"] for gate in gates),
    }
    output_path = write_json("cold-read", label, payload)
    print(json.dumps({"output": str(output_path), "authoritative": payload["authoritative"]}, sort_keys=True))
    return payload


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    run_cold_read(args.root, args.manifest, args.label, args.stamp, args.config_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
