from __future__ import annotations

import argparse
import json
import random
import sqlite3
import sys
from dataclasses import dataclass
from ipaddress import IPv4Network
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from _common import DEFAULT_RESULTS_DIR, default_root, resolve_paths

from azazel_grimoire.db import generations
from azazel_grimoire.db.repository import apply_migrations
from azazel_grimoire.normalize.ioc import normalize

DEFAULT_SEED = 20260706
BASE_IOC_COUNT = 10_000_000
DEFAULT_BATCH_SIZE = 50_000
SAMPLE_CAP_PER_TYPE = 256
FEED_IDS = ("urlhaus", "malwarebazaar", "threatfox", "edge_reported")
IOC_TYPES = ("ip", "domain", "sha256", "ja3", "ja4")


@dataclass(frozen=True)
class Sample:
    type: str
    value: str


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=default_root())
    parser.add_argument("--config-dir", type=Path, default=None)
    parser.add_argument("--scale", type=float, default=0.01)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_RESULTS_DIR / "dataset-manifest.json"
    )
    return parser


def _iso_for_index(index: int) -> str:
    day = (index % 28) + 1
    return f"2026-07-{day:02d}T00:00:00Z"


def _feed_for(ioc_type: str, index: int) -> str:
    if ioc_type == "sha256":
        return FEED_IDS[index % 2 + 1]
    if ioc_type in {"ja3", "ja4"}:
        return "edge_reported"
    return FEED_IDS[index % len(FEED_IDS)]


def _ip_value(index: int, rng: random.Random) -> str:
    octet2 = 16 + (index // 65_536) % 200
    octet3 = (index // 256) % 256
    octet4 = index % 256
    value = f"10.{octet2}.{octet3}.{octet4}"
    return normalize("ip", value)


def _domain_value(index: int, rng: random.Random) -> str:
    label = f"ioc-{index:012x}"
    return normalize("domain", f"{label}.bench.example")


def _sha256_value(index: int, rng: random.Random) -> str:
    return normalize("sha256", f"{index:064x}")


def _ja3_value(index: int, rng: random.Random) -> str:
    return normalize("ja3", f"{index:032x}")


def _ja4_value(index: int, rng: random.Random) -> str:
    return normalize("ja4", f"t13d{index:08x}h2_{index:05x}")


def _value_for(ioc_type: str, index: int, rng: random.Random) -> str:
    if ioc_type == "ip":
        return _ip_value(index, rng)
    if ioc_type == "domain":
        return _domain_value(index, rng)
    if ioc_type == "sha256":
        return _sha256_value(index, rng)
    if ioc_type == "ja3":
        return _ja3_value(index, rng)
    if ioc_type == "ja4":
        return _ja4_value(index, rng)
    raise ValueError(ioc_type)


def _ioc_row(ioc_id: int, ioc_type: str, value: str, ts: str, confidence: float) -> tuple[object, ...]:
    return (
        ioc_id,
        ioc_type,
        value,
        ts,
        ts,
        "[]",
        confidence,
        None,
        ts,
    )


def _ioc_source_row(
    ioc_id: int, feed_id: str, ts: str, intel_generation: int, source_confidence: int
) -> tuple[object, ...]:
    return (
        ioc_id,
        feed_id,
        source_confidence,
        ts,
        ts,
        None,
        intel_generation,
        0,
    )


def _cidr_rows(ioc_id: int, value: str, feed_id: str) -> list[tuple[object, ...]]:
    network_host = IPv4Network(f"{value}/32", strict=False)
    network_24 = IPv4Network(f"{value}/24", strict=False)
    network_16 = IPv4Network(f"{value}/16", strict=False)
    asn_bucket = 64_512 + (int(network_host.network_address) % 4096)
    return [
        ("host", int(network_host.network_address), int(network_host.broadcast_address), ioc_id, feed_id, None),
        ("/24", int(network_24.network_address), int(network_24.broadcast_address), ioc_id, feed_id, None),
        ("/16", int(network_16.network_address), int(network_16.broadcast_address), ioc_id, feed_id, None),
        ("asn", asn_bucket, asn_bucket, ioc_id, feed_id, None),
    ]


def _flush_batch(
    conn: sqlite3.Connection,
    ioc_rows: list[tuple[object, ...]],
    source_rows: list[tuple[object, ...]],
    cidr_rows: list[tuple[object, ...]],
) -> None:
    if ioc_rows:
        conn.executemany(
            "INSERT INTO ioc (ioc_id, type, value, first_seen, last_seen, tags, "
            "agg_raw_confidence, agg_next_expiry, agg_computed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ioc_rows,
        )
    if source_rows:
        conn.executemany(
            "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
            "expires_at, intel_generation, flagged_critical_infra) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            source_rows,
        )
    if cidr_rows:
        conn.executemany(
            "INSERT INTO ioc_cidr (tier, range_start, range_end, ioc_id, feed_id, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            cidr_rows,
        )
    conn.commit()


def generate_dataset(root: Path, scale: float, seed: int, manifest_path: Path) -> dict[str, object]:
    paths = resolve_paths(root)
    intel_path = generations.build_next_generation(paths.data_db_dir)
    generation = generations.current_generation(paths.data_db_dir)
    next_generation = 1 if generation is None else generation + 1

    count = max(1, round(scale * BASE_IOC_COUNT))
    rng = random.Random(seed)
    samples: dict[str, list[Sample]] = {ioc_type: [] for ioc_type in IOC_TYPES}

    conn = sqlite3.connect(intel_path)
    try:
        apply_migrations(conn, "intel")
        ioc_rows: list[tuple[object, ...]] = []
        source_rows: list[tuple[object, ...]] = []
        cidr_rows: list[tuple[object, ...]] = []

        for offset in range(count):
            ioc_id = offset + 1
            ioc_type = IOC_TYPES[offset % len(IOC_TYPES)]
            value = _value_for(ioc_type, offset, rng)
            ts = _iso_for_index(offset)
            feed_id = _feed_for(ioc_type, offset)
            confidence = 40.0 + float(offset % 60)
            source_confidence = 35 if feed_id == "edge_reported" else 80 + (offset % 11)
            ioc_rows.append(_ioc_row(ioc_id, ioc_type, value, ts, confidence))
            source_rows.append(
                _ioc_source_row(ioc_id, feed_id, ts, next_generation, source_confidence)
            )
            if ioc_type == "ip":
                cidr_rows.extend(_cidr_rows(ioc_id, value, feed_id))
            if len(samples[ioc_type]) < SAMPLE_CAP_PER_TYPE:
                samples[ioc_type].append(Sample(ioc_type, value))
            if len(ioc_rows) >= DEFAULT_BATCH_SIZE:
                _flush_batch(conn, ioc_rows, source_rows, cidr_rows)
                ioc_rows.clear()
                source_rows.clear()
                cidr_rows.clear()

        _flush_batch(conn, ioc_rows, source_rows, cidr_rows)
        conn.execute(
            "INSERT INTO stats_meta (key, value) VALUES ('intel_generation', ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (str(next_generation),),
        )
        conn.commit()
    finally:
        conn.close()

    generations.swap_current(paths.data_db_dir, next_generation)

    search_samples = [
        {"type": sample.type, "value": sample.value}
        for ioc_type in ("ip", "domain", "sha256")
        for sample in samples[ioc_type]
    ]
    context_body_templates = [
        {
            "entities": [{"type": samples["ip"][0].type, "value": samples["ip"][0].value}],
            "event": {"kind": "bench_context", "event_types": ["bench_context"]},
            "edge_id": "bench-edge",
            "actor_key": "bench-actor",
            "event_id": "bench-context-1",
        },
        {
            "entities": [
                {"type": samples["ip"][0].type, "value": samples["ip"][0].value},
                {"type": samples["domain"][0].type, "value": samples["domain"][0].value},
                {"type": samples["sha256"][0].type, "value": samples["sha256"][0].value},
                {"type": samples["ja3"][0].type, "value": samples["ja3"][0].value},
            ],
            "event": {"kind": "bench_context_multi", "event_types": ["bench_context_multi"]},
            "edge_id": "bench-edge",
            "actor_key": "bench-actor",
            "event_id": "bench-context-2",
        },
    ]
    manifest = {
        "root": str(root),
        "intel_db_path": str(generations.intel_db_path(paths.data_db_dir, next_generation)),
        "local_db_path": str(paths.local_db_path),
        "generation": next_generation,
        "scale": scale,
        "seed": seed,
        "count": count,
        "search_samples": search_samples,
        "samples_by_type": {
            ioc_type: [{"type": sample.type, "value": sample.value} for sample in values]
            for ioc_type, values in samples.items()
        },
        "context_body_templates": context_body_templates,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    manifest = generate_dataset(args.root, args.scale, args.seed, args.manifest)
    print(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "count": manifest["count"],
                "generation": manifest["generation"],
                "root": str(args.root),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
