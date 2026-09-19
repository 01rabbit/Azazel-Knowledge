"""Consumer fixture and interrupted-extraction behaviour (ADR-0015 Consequences 7/8).

The fixture is what Azazel-Nexus and Azazel-Boot run their embedded Lite reader
against in their own CI. These tests check that it is worth relying on: it
rebuilds byte-for-byte, it verifies under its own published anchor, and what it
claims in `expected.json` is what a reader actually finds.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from azazel_knowledge.bundle.verify import BundleVerifyError, peek_manifest, verify_bundle

_TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _emit(out_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(_TOOLS_DIR / "lite_fixture.py"), "emit", "--out", str(out_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture
def fixture_dir(tmp_path):
    out = tmp_path / "fixture"
    _emit(out)
    return out


def test_fixture_rebuilds_byte_for_byte(tmp_path):
    """A rebuilt fixture is the proof of D2, which is why it is emitted not committed.

    A checked-in blob would only show that a file was once added; rebuilding it
    on every use re-proves reproducibility each time.
    """
    first, second = tmp_path / "a", tmp_path / "b"
    _emit(first)
    _emit(second)
    assert (first / "lite.tar.gz").read_bytes() == (second / "lite.tar.gz").read_bytes()
    assert (first / "expected.json").read_text() == (second / "expected.json").read_text()


def test_fixture_verifies_under_its_published_anchor(fixture_dir, tmp_path):
    verify_bundle(
        fixture_dir / "lite.tar.gz",
        fixture_dir / "anchors.toml",
        tmp_path / "state.toml",
        tmp_path / "staging",
    )


def test_expected_json_matches_the_artifact_it_describes(fixture_dir):
    expected = json.loads((fixture_dir / "expected.json").read_text())
    bundle = fixture_dir / "lite.tar.gz"
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == expected["bundle_sha256"]
    manifest = peek_manifest(bundle)
    assert manifest["files"] == expected["files"]
    assert manifest["profile"] == expected["profile"]


def test_fixture_excludes_the_stale_row_and_aliases_indicators(fixture_dir):
    """What a consumer's reader must observe, stated as a test here too.

    `expected.json` says a stale indicator is absent and that values are
    aliased. A consumer trusting those notes deserves them to be true of the
    artifact rather than merely written beside it.
    """
    with tarfile.open(fixture_dir / "lite.tar.gz", "r:gz") as tar:
        payload = tar.extractfile("tables/ioc.jsonl").read().decode()
    assert "203.0.113.99" not in payload  # outside the freshness window
    assert "203.0.113.10" not in payload  # aliased, never verbatim
    rows = [json.loads(line) for line in payload.splitlines()]
    assert len(rows) == 3
    assert all(row["value"].startswith("az-") for row in rows)


def test_fixture_anchor_names_only_the_fixture_key(fixture_dir):
    anchors = (fixture_dir / "anchors.toml").read_text()
    assert "must never appear in a production anchor" in anchors
    assert anchors.count("=") >= 2


# --- interrupted extraction (ADR-0015 Consequences 7) ----------------------


def test_failed_extraction_leaves_no_verified_result(fixture_dir, tmp_path):
    """A bundle that fails mid-extraction yields an exception, never a partial result.

    The caller receives nothing it could mistake for a verified tree, which is
    what keeps an interrupted import from touching the current generation: the
    verifier stages, and only a *successful* return lets a caller promote.
    """
    bundle = fixture_dir / "lite.tar.gz"
    corrupted = tmp_path / "corrupted.tar.gz"

    with tarfile.open(bundle, "r:gz") as tar:
        members = [(i, tar.extractfile(i).read()) for i in tar.getmembers() if i.isreg()]

    import gzip as _gzip
    import io as _io

    with corrupted.open("wb") as raw:
        with _gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                for info, data in members:
                    if info.name.startswith("tables/"):
                        data = data + b'{"tampered": true}\n'
                    new = tarfile.TarInfo(name=info.name)
                    new.size = len(data)
                    tar.addfile(new, _io.BytesIO(data))

    staging = tmp_path / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(corrupted, fixture_dir / "anchors.toml", tmp_path / "state.toml", staging)
    assert exc.value.code == "BUNDLE_FILE_HASH_MISMATCH"


def test_staging_is_separate_from_any_live_tree(fixture_dir, tmp_path):
    """Extraction writes only under the caller-supplied staging directory.

    Promotion is the caller's step, so an interrupted verification cannot have
    modified a live generation -- it never had a path to one.
    """
    staging = tmp_path / "staging"
    sentinel = tmp_path / "live"
    sentinel.mkdir()
    (sentinel / "generation.txt").write_text("untouched", encoding="utf-8")

    verify_bundle(
        fixture_dir / "lite.tar.gz",
        fixture_dir / "anchors.toml",
        tmp_path / "state.toml",
        staging,
    )

    assert (sentinel / "generation.txt").read_text() == "untouched"
    assert list(sentinel.iterdir()) == [sentinel / "generation.txt"]
    assert staging.exists()
