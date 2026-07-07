from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    evaluate_gate,
    load_json,
    percentile_summary,
    platform_metadata,
    write_json,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=default_root())
    parser.add_argument("--config-dir", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=Path("bench-results/dataset-manifest.json"))
    parser.add_argument("--duration-s", type=float, default=None)
    parser.add_argument("--requests", type=int, default=400)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--label", default="run")
    parser.add_argument("--stamp", default=None)
    return parser


def _run_phase(app, headers: dict[str, str], requests: list[dict[str, object]], concurrency: int):
    from fastapi.testclient import TestClient

    thread_local = threading.local()

    def _client():
        client = getattr(thread_local, "client", None)
        if client is None:
            client = TestClient(app)
            thread_local.client = client
        return client

    def _task(body: dict[str, object]) -> tuple[int, float]:
        client = _client()
        started = time.perf_counter()
        response = client.post("/v1/context", json=body, headers=headers)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return response.status_code, elapsed_ms

    statuses: dict[int, int] = {}
    latencies: list[float] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_task, body) for body in requests]
        for future in as_completed(futures):
            status, elapsed_ms = future.result()
            statuses[status] = statuses.get(status, 0) + 1
            latencies.append(elapsed_ms)
    total = sum(statuses.values())
    breaker_total = statuses.get(503, 0)
    return {
        "requests": total,
        "breaker_total": breaker_total,
        "breaker_rate": round((breaker_total / total) if total else 0.0, 6),
        "statuses": statuses,
        **percentile_summary(latencies),
    }


def run_availability(
    root: Path,
    manifest_path: Path,
    duration_s: float | None,
    requests: int,
    concurrency: int,
    label: str,
    stamp: str | None,
    config_dir: Path | None = None,
):
    manifest = load_json(manifest_path)
    app, settings, paths = build_client(
        root,
        config_dir=config_dir,
        context_deadline_ms=None,
        pool_size=max(concurrency, 4),
    )
    token = add_query_client(paths.local_db_path)
    headers = auth_header(token)

    if duration_s is not None:
        base_count = max(concurrency, int(duration_s * concurrency * 10))
    else:
        base_count = requests
    base_requests = list(islice(cycle(manifest["context_body_templates"]), base_count))
    double_requests = list(islice(cycle(manifest["context_body_templates"]), base_count * 2))

    base = _run_phase(app, headers, base_requests, concurrency)
    doubled = _run_phase(app, headers, double_requests, concurrency)

    gates = [
        evaluate_gate("baseline_breaker_rate", base["breaker_rate"], 0.005, "<"),
        evaluate_gate("double_breaker_rate", doubled["breaker_rate"], 0.02, "<"),
    ]
    meta = platform_metadata()
    payload = {
        "name": "availability",
        "label": label,
        "stamp": stamp,
        "root": str(root),
        "manifest": str(manifest_path),
        "authoritative": meta["authoritative"],
        "note": (
            REFERENCE_ONLY_NOTE
            if not meta["authoritative"]
            else "Authoritative only on Pi 4 container runs; TestClient concurrency is an in-process approximation."
        ),
        "gates": gates,
        "pass": all(gate["pass"] for gate in gates),
        "platform": meta,
        "breaker_disabled": False,
        "context_deadline_ms": settings.context_deadline_ms,
        "concurrency": concurrency,
        "baseline": base,
        "double_load": doubled,
        "app_metrics": dict(app.state.metrics),
    }
    output_path = write_json("availability", label, payload)
    print(json.dumps({"output": str(output_path), "authoritative": payload["authoritative"]}, sort_keys=True))
    return payload


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    run_availability(
        args.root,
        args.manifest,
        args.duration_s,
        args.requests,
        args.concurrency,
        args.label,
        args.stamp,
        args.config_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
