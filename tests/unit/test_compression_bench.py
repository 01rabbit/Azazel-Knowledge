from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_ROOT = REPO_ROOT / "tools" / "bench"
if str(BENCH_ROOT) not in sys.path:
    sys.path.insert(0, str(BENCH_ROOT))

from compression_bench import main, run_compression_bench


def test_run_compression_bench_reports_required_codec_metrics(tmp_path: Path) -> None:
    payload = run_compression_bench(root=tmp_path, scale=0.0001, label="unit", stamp="fixture")

    for codec_name in ("gzip", "lzma"):
        codec = payload["codecs"][codec_name]
        assert codec["available"] is True
        assert codec["compressed_bytes"] < codec["original_bytes"]
        assert 0 < codec["ratio"] < 1
        assert codec["size_metrics"]["hardware_independent"] is True
        assert codec["speed_metrics"]["authoritative"] is False

    assert "available" in payload["codecs"]["zstd"]
    if payload["codecs"]["zstd"]["available"] is True:
        assert payload["codecs"]["zstd"]["compressed_bytes"] < payload["codecs"]["zstd"]["original_bytes"]
        assert 0 < payload["codecs"]["zstd"]["ratio"] < 1
        assert payload["codecs"]["zstd"]["size_metrics"]["hardware_independent"] is True
        assert payload["codecs"]["zstd"]["speed_metrics"]["authoritative"] is False

    assert payload["interpretation"]
    assert payload["platform"]["authoritative"] is False
    assert payload["extrapolated_full_scale"]["gzip"]["estimated_ioc_rows"] == 10_000_000


def test_main_writes_json_output(tmp_path: Path) -> None:
    json_out = tmp_path / "compression-bench.json"

    exit_code = main(
        [
            "--root",
            str(tmp_path / "scratch"),
            "--scale",
            "0.0001",
            "--label",
            "unit",
            "--stamp",
            "fixture",
            "--json-out",
            str(json_out),
        ]
    )

    assert exit_code == 0
    assert json_out.is_file()
    written = json.loads(json_out.read_text(encoding="utf-8"))
    assert written["label"] == "unit"
    assert written["stamp"] == "fixture"
    assert written["codecs"]["gzip"]["available"] is True
    assert written["codecs"]["lzma"]["available"] is True
    assert "available" in written["codecs"]["zstd"]


def test_run_compression_bench_with_db_skips_scale_extrapolation(tmp_path: Path) -> None:
    root = tmp_path / "scratch"
    db_payload = run_compression_bench(root=root, scale=0.0001, label="seed", stamp="s0")

    payload = run_compression_bench(
        root=tmp_path / "unused",
        scale=0.0001,
        db=Path(db_payload["db"]),
        label="direct",
        stamp="s1",
    )

    assert payload["db"] == db_payload["db"]
    assert payload["extrapolated_full_scale"] == {}
    assert "extrapolated_full_scale" not in payload["codecs"]["gzip"]
