"""Consumer fixture and interrupted-extraction behaviour (ADR-0015 Consequences 7/8).

The fixture is what Azazel-Nexus and Azazel-Boot run their embedded Lite reader
against in their own CI. These tests check that it is worth relying on: it
rebuilds byte-for-byte, it verifies under its own published anchor, and what it
claims in `expected.json` is what a reader actually finds.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import sqlite3
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from azazel_knowledge.bundle.importer import import_full
from azazel_knowledge.bundle.verify import BundleVerifyError, peek_manifest, verify_bundle
from azazel_knowledge.db import generations
from azazel_knowledge.db.repository import apply_migrations

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


def _corrupted_copy(bundle: Path, out: Path) -> Path:
    """A copy of `bundle` whose content members no longer match their declared digests.

    The manifest and its signature are carried over untouched, so the artifact
    is still correctly signed and still passes every gate up to the per-member
    hash check -- which is the point: the failure has to happen *during*
    extraction, after bytes have already been written to staging, or it says
    nothing about an interrupted one.
    """
    with tarfile.open(bundle, "r:gz") as tar:
        members = [(i, tar.extractfile(i).read()) for i in tar.getmembers() if i.isreg()]
    with out.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                for info, data in members:
                    if info.name.startswith("tables/"):
                        data = data + b'{"tampered": true}\n'
                    new = tarfile.TarInfo(name=info.name)
                    new.size = len(data)
                    tar.addfile(new, io.BytesIO(data))
    return out


def test_failed_extraction_leaves_no_verified_result(fixture_dir, tmp_path):
    """A bundle that fails mid-extraction yields an exception, never a partial result.

    The caller receives nothing it could mistake for a verified tree, which is
    what keeps an interrupted import from touching the current generation: the
    verifier stages, and only a *successful* return lets a caller promote.
    """
    corrupted = _corrupted_copy(fixture_dir / "lite.tar.gz", tmp_path / "corrupted.tar.gz")

    staging = tmp_path / "staging"
    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(corrupted, fixture_dir / "anchors.toml", tmp_path / "state.toml", staging)
    assert exc.value.code == "BUNDLE_FILE_HASH_MISMATCH"


def test_interrupted_staging_leaves_the_live_generation_in_service(fixture_dir, tmp_path):
    """Interrupted staging leaves the current generation unchanged (ADR-0015 Consequences 7).

    The test this replaces created a `sentinel` directory, called
    `verify_bundle` **without ever passing it**, and asserted the sentinel was
    untouched. That holds for any function that has never heard of the
    directory, and would have held just as well if verification had deleted
    every generation on the host -- its own docstring conceded the reader "never
    had a path to one".

    So this hands the code under test a live tree it genuinely does receive.
    `import_full` takes `data_db_dir`: it builds the next generation inside it,
    repoints `current`, and garbage-collects old generations. The assertions
    below are about that directory after a bundle fails *mid-extraction*, with
    bytes already written to staging. They go red if verification were ever
    reordered after the swap, if a half-built generation were left behind, or if
    a failed import recorded itself in the rollback anchor.
    """
    data_db_dir = tmp_path / "data" / "db"
    live_db = generations.build_next_generation(data_db_dir)
    conn = sqlite3.connect(live_db)
    apply_migrations(conn, "intel")
    conn.execute(
        "INSERT INTO ioc (type, value, first_seen, last_seen) VALUES "
        "('ip', '198.51.100.7', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')"
    )
    conn.commit()
    conn.close()
    generations.swap_current(data_db_dir, 1)
    before = hashlib.sha256(live_db.read_bytes()).hexdigest()

    corrupted = _corrupted_copy(fixture_dir / "lite.tar.gz", tmp_path / "corrupted.tar.gz")
    state_path = tmp_path / "state.toml"

    with pytest.raises(BundleVerifyError) as exc:
        import_full(corrupted, fixture_dir / "anchors.toml", state_path, data_db_dir)
    assert exc.value.code == "BUNDLE_FILE_HASH_MISMATCH"

    assert generations.current_generation(data_db_dir) == 1
    assert hashlib.sha256(live_db.read_bytes()).hexdigest() == before
    assert sorted(p.name for p in data_db_dir.iterdir() if p.name.startswith("gen-")) == ["gen-1"]
    assert not state_path.exists(), "a failed import must not record itself in the rollback anchor"

    conn = sqlite3.connect(live_db)
    try:
        assert [r[0] for r in conn.execute("SELECT value FROM ioc")] == ["198.51.100.7"]
    finally:
        conn.close()
