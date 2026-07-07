#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import lzma
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from _common import DEFAULT_RESULTS_DIR, deterministic_dump, ensure_parent, platform_metadata
from synth_dataset import DEFAULT_SEED, generate_dataset

DEFAULT_ROOT = DEFAULT_RESULTS_DIR / "scratch-comp"
FULL_SCALE = 1.0
FULL_SCALE_IOC_COUNT = 10_000_000
REFERENCE_ONLY_NOTE = "reference-only; Pi 4 CPU/Adiantum differ. Run on Pi for import-time speed."
XZ_NOTE = "reference-only; Pi 4 CPU/Adiantum differ. Run on Pi for import-time speed. xz decompression can be CPU/memory heavy on Pi 4."


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--scale", type=float, default=0.01)
    parser.add_argument("--db", type=Path, default=None)
    parser.add_argument("--gzip-level", type=int, default=6)
    parser.add_argument("--xz-preset", type=int, default=6)
    parser.add_argument("--zstd-level", type=int, default=19)
    parser.add_argument("--label", default=None)
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    return parser


def _read_db_bytes(db_path: Path) -> bytes:
    return db_path.read_bytes()


def _count_rows(db_path: Path) -> int:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        if "ioc" in tables:
            return int(conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0])
        total = 0
        for table in tables:
            total += int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        return total
    finally:
        conn.close()


def _round_seconds(seconds: float) -> float:
    return round(float(seconds), 6)


def _metric_record(
    *,
    codec: str,
    level: int,
    original_bytes: int,
    compressed_bytes: int,
    compress_s: float,
    decompress_s: float,
    note: str,
) -> dict[str, Any]:
    ratio = compressed_bytes / original_bytes
    space_saving = 1.0 - ratio
    return {
        "available": True,
        "codec": codec,
        "level": level,
        "original_bytes": original_bytes,
        "compressed_bytes": compressed_bytes,
        "ratio": round(ratio, 6),
        "space_saving": round(space_saving, 6),
        "compress_s": _round_seconds(compress_s),
        "decompress_s": _round_seconds(decompress_s),
        "size_metrics": {
            "hardware_independent": True,
            "original_bytes": original_bytes,
            "compressed_bytes": compressed_bytes,
            "ratio": round(ratio, 6),
            "space_saving": round(space_saving, 6),
        },
        "speed_metrics": {
            "authoritative": False,
            "note": note,
            "compress_s": _round_seconds(compress_s),
            "decompress_s": _round_seconds(decompress_s),
        },
    }


def _gzip_metrics(payload: bytes, level: int) -> dict[str, Any]:
    started = time.perf_counter()
    compressed = gzip.compress(payload, compresslevel=level, mtime=0)
    compress_s = time.perf_counter() - started
    started = time.perf_counter()
    restored = gzip.decompress(compressed)
    decompress_s = time.perf_counter() - started
    if restored != payload:
        raise ValueError("gzip decompression round-trip mismatch")
    return _metric_record(
        codec="gzip",
        level=level,
        original_bytes=len(payload),
        compressed_bytes=len(compressed),
        compress_s=compress_s,
        decompress_s=decompress_s,
        note=REFERENCE_ONLY_NOTE,
    )


def _lzma_metrics(payload: bytes, preset: int) -> dict[str, Any]:
    started = time.perf_counter()
    compressed = lzma.compress(payload, format=lzma.FORMAT_XZ, preset=preset)
    compress_s = time.perf_counter() - started
    started = time.perf_counter()
    restored = lzma.decompress(compressed, format=lzma.FORMAT_XZ)
    decompress_s = time.perf_counter() - started
    if restored != payload:
        raise ValueError("lzma decompression round-trip mismatch")
    return _metric_record(
        codec="lzma",
        level=preset,
        original_bytes=len(payload),
        compressed_bytes=len(compressed),
        compress_s=compress_s,
        decompress_s=decompress_s,
        note=XZ_NOTE,
    )


def _zstd_metrics(payload: bytes, level: int) -> dict[str, Any]:
    zstd_path = shutil.which("zstd")
    if zstd_path is None:
        return {"available": False, "level": level}
    with TemporaryDirectory(prefix="compression-bench-zstd-") as temp_dir:
        temp_root = Path(temp_dir)
        source_path = temp_root / "intel.db"
        compressed_path = temp_root / "intel.db.zst"
        restored_path = temp_root / "intel.db.restored"
        source_path.write_bytes(payload)
        started = time.perf_counter()
        subprocess.run(
            [zstd_path, f"-{level}", "-q", "-f", str(source_path), "-o", str(compressed_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        compress_s = time.perf_counter() - started
        started = time.perf_counter()
        subprocess.run(
            [zstd_path, "-d", "-q", "-f", str(compressed_path), "-o", str(restored_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        decompress_s = time.perf_counter() - started
        restored = restored_path.read_bytes()
        if restored != payload:
            raise ValueError("zstd decompression round-trip mismatch")
        return _metric_record(
            codec="zstd",
            level=level,
            original_bytes=len(payload),
            compressed_bytes=compressed_path.stat().st_size,
            compress_s=compress_s,
            decompress_s=decompress_s,
            note=REFERENCE_ONLY_NOTE,
        )


def _extrapolated_record(metric: dict[str, Any], scale: float) -> dict[str, Any]:
    if scale <= 0.0 or scale >= FULL_SCALE:
        return {}
    factor = FULL_SCALE / scale
    return {
        "approximation": True,
        "note": "Linear extrapolation from the measured scale to scale=1.0; approximate only.",
        "scale_measured": scale,
        "scale_target": FULL_SCALE,
        "estimated_original_bytes": int(round(metric["original_bytes"] * factor)),
        "estimated_compressed_bytes": int(round(metric["compressed_bytes"] * factor)),
        "estimated_ioc_rows": int(round(FULL_SCALE_IOC_COUNT)),
    }


def _compare_smaller_text(name: str, baseline_name: str, current_bytes: int, baseline_bytes: int) -> str:
    delta = 1.0 - (current_bytes / baseline_bytes)
    if delta >= 0:
        return f"{name} compressed output is {delta * 100:.2f}% smaller than {baseline_name}."
    return f"{name} compressed output is {abs(delta) * 100:.2f}% larger than {baseline_name}."


def _format_mib(byte_count: int) -> str:
    return f"{byte_count / (1024 * 1024):.2f} MiB"


def _build_interpretation(payload: dict[str, Any]) -> list[str]:
    codecs = payload["codecs"]
    lines = [
        f"Measured intel.db payload is {_format_mib(payload['original_bytes'])} ({payload['original_bytes']} bytes)."
    ]
    gzip_metrics = codecs["gzip"]
    lines.append(
        f"gzip compressed size is {_format_mib(gzip_metrics['compressed_bytes'])} with ratio {gzip_metrics['ratio']:.6f}."
    )
    for name in ("lzma", "zstd"):
        metric = codecs.get(name)
        if not metric or not metric.get("available"):
            continue
        lines.append(
            _compare_smaller_text(
                name,
                "gzip",
                int(metric["compressed_bytes"]),
                int(gzip_metrics["compressed_bytes"]),
            )
        )
    if payload["scale"] < FULL_SCALE:
        for name in ("gzip", "lzma", "zstd"):
            metric = codecs.get(name)
            if not metric or not metric.get("available"):
                continue
            extrapolated = metric.get("extrapolated_full_scale")
            if extrapolated:
                lines.append(
                    f"Approximate full-scale {name} compressed size at scale=1.0 is {_format_mib(extrapolated['estimated_compressed_bytes'])}."
                )
    return lines


def run_compression_bench(
    *,
    root: Path,
    scale: float,
    db: Path | None = None,
    gzip_level: int = 6,
    xz_preset: int = 6,
    zstd_level: int = 19,
    label: str | None = None,
    stamp: str | None = None,
) -> dict[str, Any]:
    if scale <= 0.0:
        raise ValueError("scale must be > 0")
    manifest: dict[str, Any] | None = None
    db_path = db
    generated_from_scale = db_path is None
    if generated_from_scale:
        manifest_path = root / "dataset-manifest.json"
        manifest = generate_dataset(root=root, scale=scale, seed=DEFAULT_SEED, manifest_path=manifest_path)
        db_path = Path(str(manifest["intel_db_path"]))
    payload = _read_db_bytes(db_path)
    original_bytes = len(payload)
    db_rows = int(manifest["count"]) if manifest is not None else _count_rows(db_path)
    codecs = {
        "gzip": _gzip_metrics(payload, gzip_level),
        "lzma": _lzma_metrics(payload, xz_preset),
        "zstd": _zstd_metrics(payload, zstd_level),
    }
    if generated_from_scale and scale < FULL_SCALE:
        for metric in codecs.values():
            if metric.get("available"):
                metric["extrapolated_full_scale"] = _extrapolated_record(metric, scale)
    result = {
        "codecs": codecs,
        "db": str(db_path),
        "db_rows": db_rows,
        "extrapolated_full_scale": {
            name: metric["extrapolated_full_scale"]
            for name, metric in codecs.items()
            if metric.get("available") and metric.get("extrapolated_full_scale")
        },
        "interpretation": [],
        "label": label,
        "original_bytes": original_bytes,
        "platform": platform_metadata(),
        "scale": scale,
        "stamp": stamp,
    }
    result["interpretation"] = _build_interpretation(result)
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    payload = run_compression_bench(
        root=args.root,
        scale=args.scale,
        db=args.db,
        gzip_level=args.gzip_level,
        xz_preset=args.xz_preset,
        zstd_level=args.zstd_level,
        label=args.label,
        stamp=args.stamp,
    )
    rendered = json.dumps(payload, sort_keys=True, indent=2, default=deterministic_dump)
    print(rendered)
    if args.json_out is not None:
        ensure_parent(args.json_out)
        args.json_out.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
