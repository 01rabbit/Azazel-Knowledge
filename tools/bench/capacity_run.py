from __future__ import annotations

import argparse
import json
import sys
import time
from itertools import cycle, islice
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from _common import (
    REFERENCE_ONLY_NOTE,
    add_query_client,
    auth_header,
    authoritative,
    build_client,
    default_root,
    load_json,
    percentile_summary,
    platform_metadata,
    write_json,
    evaluate_gate,
)

HUGE_DEADLINE_MS = 10**9


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=default_root())
    parser.add_argument("--config-dir", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=Path("bench-results/dataset-manifest.json"))
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument("--label", default="run")
    parser.add_argument("--stamp", default=None)
    return parser


def _measure(client, path: str, body: dict[str, object], headers: dict[str, str]) -> tuple[float, int]:
    started = time.perf_counter()
    response = client.post(path, json=body, headers=headers)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return elapsed_ms, response.status_code


def run_capacity(
    root: Path,
    manifest_path: Path,
    requests: int,
    warmup: int,
    label: str,
    stamp: str | None,
    config_dir: Path | None = None,
):
    manifest = load_json(manifest_path)
    app, settings, paths = build_client(
        root, config_dir=config_dir, context_deadline_ms=HUGE_DEADLINE_MS
    )
    token = add_query_client(paths.local_db_path)
    headers = auth_header(token)
    lookup_requests = list(islice(cycle(manifest["search_samples"]), requests))
    context_requests = list(islice(cycle(manifest["context_body_templates"]), requests))

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        for body in islice(cycle(manifest["search_samples"]), warmup):
            status = client.post("/v1/ioc/search", json=body, headers=headers).status_code
            if status != 200:
                raise RuntimeError(f"warmup lookup failed with status {status}")
        for body in islice(cycle(manifest["context_body_templates"]), warmup):
            status = client.post("/v1/context", json=body, headers=headers).status_code
            if status != 200:
                raise RuntimeError(f"warmup context failed with status {status}")

        lookup_latencies: list[float] = []
        lookup_statuses: dict[int, int] = {}
        for body in lookup_requests:
            elapsed_ms, status = _measure(client, "/v1/ioc/search", body, headers)
            lookup_latencies.append(elapsed_ms)
            lookup_statuses[status] = lookup_statuses.get(status, 0) + 1
            if status != 200:
                raise RuntimeError(f"lookup failed with status {status}")

        context_latencies: list[float] = []
        context_statuses: dict[int, int] = {}
        for body in context_requests:
            elapsed_ms, status = _measure(client, "/v1/context", body, headers)
            context_latencies.append(elapsed_ms)
            context_statuses[status] = context_statuses.get(status, 0) + 1
            if status != 200:
                raise RuntimeError(f"context failed with status {status}")

    lookup_stats = percentile_summary(lookup_latencies)
    context_stats = percentile_summary(context_latencies)
    gates = [
        evaluate_gate("lookup_p95_ms", lookup_stats["p95_ms"], 50.0, "<"),
        evaluate_gate("context_p95_ms", context_stats["p95_ms"], 250.0, "<"),
    ]
    meta = platform_metadata()
    payload = {
        "name": "capacity",
        "label": label,
        "stamp": stamp,
        "root": str(root),
        "manifest": str(manifest_path),
        "authoritative": meta["authoritative"],
        "gates": gates,
        "pass": all(gate["pass"] for gate in gates),
        "platform": meta,
        "breaker_disabled": True,
        "context_deadline_ms": settings.context_deadline_ms,
        "lookup": {
            **lookup_stats,
            "requests": requests,
            "statuses": lookup_statuses,
        },
        "context": {
            **context_stats,
            "requests": requests,
            "statuses": context_statuses,
        },
    }
    if not authoritative():
        payload["note"] = REFERENCE_ONLY_NOTE
    output_path = write_json("capacity", label, payload)
    print(json.dumps({"output": str(output_path), "authoritative": payload["authoritative"]}, sort_keys=True))
    return payload


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    run_capacity(
        args.root,
        args.manifest,
        args.requests,
        args.warmup,
        args.label,
        args.stamp,
        args.config_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
