"""End-to-end Knowledge Lite bundle build (ADR-0015, Azazel-Knowledge#73).

The unit-level guarantees are covered in test_lite_policy.py and
test_lite_select.py. What is verified here is that a real artifact comes out of
the real CLI: it verifies under the *existing* verifier unchanged, it is
byte-identical when rebuilt from the same tuple, it carries no local-tier row,
and the build leaves the source database untouched.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_knowledge.bundle.verify import LOCAL_TIER_TABLES, peek_manifest, verify_bundle
from azazel_knowledge.db.repository import apply_migrations

_TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"

POLICY_YAML = """\
version: lite-export-v1
datasets:
  ioc:
    fields:
      - name: value
        mode: alias
      - name: type
      - name: last_seen
  ioc_source:
    fields:
      - name: feed_id
      - name: source_confidence
      - name: last_seen
"""


def _run_cli(*args: str, expect_success: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [sys.executable, str(_TOOLS_DIR / "bundle_build.py"), *args],
        capture_output=True,
        text=True,
    )
    if expect_success:
        assert result.returncode == 0, result.stderr
    return result


def _make_source_db(path: Path, *, ioc_rows: int = 3, last_seen: str = "2026-09-18T00:00:00Z") -> None:
    conn = sqlite3.connect(path)
    apply_migrations(conn, "intel")
    for i in range(ioc_rows):
        conn.execute(
            "INSERT INTO ioc (type, value, first_seen, last_seen) VALUES "
            "('ip', ?, '2026-01-01T00:00:00Z', ?)",
            (f"10.0.0.{i}", last_seen),
        )
        conn.execute(
            "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, last_seen, "
            "expires_at, intel_generation) VALUES (?, 'urlhaus', 85, '2026-01-01T00:00:00Z', ?, "
            "'2030-01-01T00:00:00Z', 1)",
            (i + 1, last_seen),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def lite_env(tmp_path):
    source_db = tmp_path / "intel.db"
    _make_source_db(source_db)
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY_YAML, encoding="utf-8")
    alias_key = tmp_path / "alias.hex"
    alias_key.write_text("00112233445566778899aabbccddeeff", encoding="utf-8")
    key_path = tmp_path / "sign.hex"
    _run_cli("keygen", "--out", str(key_path))
    return {
        "tmp_path": tmp_path,
        "source_db": source_db,
        "policy": policy,
        "alias_key": alias_key,
        "sign_key": key_path,
    }


def _build_lite(env, out: Path, **overrides) -> subprocess.CompletedProcess:
    expect_success = overrides.pop("_expect_success", True)
    args = {
        "--source-db": str(env["source_db"]),
        "--out": str(out),
        "--version": "1",
        "--profile": "knowledge-lite-16g",
        "--export-policy": str(env["policy"]),
        "--alias-key-file": str(env["alias_key"]),
        "--alias-scope": "mission-1",
        "--as-of": "2026-09-19T00:00:00Z",
        "--intel-generation": "7",
        "--stats-generation": "3",
        "--attack-version": "v15.1",
        "--config-hash": "cfg-abc",
        "--sign-key": str(env["sign_key"]),
    }
    args.update(overrides)
    flat = [item for pair in args.items() for item in pair]
    return _run_cli("build-lite", *flat, expect_success=expect_success)


def test_lite_bundle_verifies_under_the_existing_verifier(lite_env, tmp_path):
    """Lite is a profile, not a second format (ADR-0015 D1).

    Nothing about the container, member order, signature scheme, or trust
    sourcing changes, so the verifier that handles a full bundle handles this
    one with no Lite-specific code at all.
    """
    out = tmp_path / "lite.tar.gz"
    _build_lite(lite_env, out)

    signing_hex = Path(lite_env["sign_key"]).read_text().strip()
    verify_key = SigningKey(bytes.fromhex(signing_hex)).verify_key.encode().hex()
    key_id = verify_key[:8]
    anchors = tmp_path / "anchors.toml"
    anchors.write_text(f'threshold = 1\n[keys]\n"{key_id}" = "{verify_key}"\n', encoding="utf-8")
    state = tmp_path / "state.toml"

    result = verify_bundle(out, anchors, state, tmp_path / "staging")
    assert result is not None


def test_same_tuple_rebuilds_byte_identically(lite_env, tmp_path):
    """ADR-0015 D2: the pinned tuple determines the unsigned artifact.

    The manifest carries no wall-clock stamp precisely so this can hold; a
    `created_at` would make every rebuild differ for no informational gain,
    since the instant that matters is the pinned `as_of` inside the profile.
    """
    first = tmp_path / "a.tar.gz"
    second = tmp_path / "b.tar.gz"
    _build_lite(lite_env, first)
    _build_lite(lite_env, second)

    def members(path: Path) -> dict[str, bytes]:
        with tarfile.open(path, "r:gz") as tar:
            return {i.name: tar.extractfile(i).read() for i in tar.getmembers() if i.isreg()}

    assert members(first) == members(second)


def test_changing_the_tuple_changes_the_manifest(lite_env, tmp_path):
    base = tmp_path / "base.tar.gz"
    changed = tmp_path / "changed.tar.gz"
    _build_lite(lite_env, base)
    _build_lite(lite_env, changed, **{"--intel-generation": "8"})
    assert peek_manifest(base)["profile"] != peek_manifest(changed)["profile"]


def test_manifest_records_the_profile_block(lite_env, tmp_path):
    out = tmp_path / "lite.tar.gz"
    _build_lite(lite_env, out)
    profile = peek_manifest(out)["profile"]
    assert profile["profile_id"] == "knowledge-lite-16g"
    assert profile["selection_inputs"]["intel_generation"] == 7
    assert profile["selection_inputs"]["as_of"] == "2026-09-19T00:00:00Z"
    assert profile["counts"]["rows"] > 0
    assert profile["ceilings"]["freshness_window_days"] == 30


def test_manifest_carries_no_wall_clock_stamp(lite_env, tmp_path):
    out = tmp_path / "lite.tar.gz"
    _build_lite(lite_env, out)
    assert "created_at" not in peek_manifest(out)


def test_no_local_tier_table_is_ever_emitted(lite_env, tmp_path):
    out = tmp_path / "lite.tar.gz"
    _build_lite(lite_env, out)
    manifest = peek_manifest(out)
    emitted = set(manifest["tables"])
    assert not (emitted & LOCAL_TIER_TABLES)
    for name in manifest["files"]:
        assert not any(f"/{table}.jsonl" in name for table in LOCAL_TIER_TABLES)


def test_build_does_not_mutate_the_source_database(lite_env, tmp_path):
    """Absolute Constraint 5 / ADR-0015 D6, checked on the bytes.

    The connection is opened read-only, but the point of the test is the
    observable outcome rather than the mechanism: whatever the builder does
    internally, the research database must come out identical.
    """
    source = Path(lite_env["source_db"])
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    before_size = source.stat().st_size

    _build_lite(lite_env, tmp_path / "lite.tar.gz")

    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert source.stat().st_size == before_size


def test_stale_rows_are_excluded_by_the_freshness_window(lite_env, tmp_path):
    """A source whose rows all predate the window yields an empty selection."""
    stale_db = tmp_path / "stale.db"
    _make_source_db(stale_db, last_seen="2020-01-01T00:00:00Z")
    out = tmp_path / "stale.tar.gz"
    _build_lite(lite_env, out, **{"--source-db": str(stale_db)})
    assert peek_manifest(out)["profile"]["counts"]["rows"] == 0


def test_unknown_profile_is_rejected_by_the_cli(lite_env, tmp_path):
    result = _run_cli(
        "build-lite",
        "--source-db",
        str(lite_env["source_db"]),
        "--out",
        str(tmp_path / "x.tar.gz"),
        "--version",
        "1",
        "--profile",
        "knowledge-lite-99g",
        "--export-policy",
        str(lite_env["policy"]),
        "--alias-key-file",
        str(lite_env["alias_key"]),
        "--alias-scope",
        "m",
        "--as-of",
        "2026-09-19T00:00:00Z",
        "--intel-generation",
        "1",
        "--stats-generation",
        "1",
        "--attack-version",
        "v1",
        "--config-hash",
        "c",
        "--sign-key",
        str(lite_env["sign_key"]),
        expect_success=False,
    )
    assert result.returncode != 0


def test_aliased_field_is_not_emitted_verbatim(lite_env, tmp_path):
    out = tmp_path / "lite.tar.gz"
    _build_lite(lite_env, out)
    with tarfile.open(out, "r:gz") as tar:
        payload = tar.extractfile("tables/ioc.jsonl").read().decode()
    assert "10.0.0.0" not in payload
    assert "az-" in payload
    first = json.loads(payload.splitlines()[0])
    assert first["value"].startswith("az-")


def test_policy_naming_a_nonexistent_dataset_is_refused(lite_env, tmp_path):
    """A policy that has drifted from the schema fails the build, loudly.

    Silently skipping the unknown dataset would produce a thinner bundle that
    still claimed to satisfy the policy, which is the failure mode the whole
    deny-by-default design exists to avoid.
    """
    policy = tmp_path / "drifted.yaml"
    policy.write_text(
        POLICY_YAML + "  no_such_table:\n    fields:\n      - name: whatever\n", encoding="utf-8"
    )
    result = _build_lite(
        lite_env, tmp_path / "x.tar.gz", **{"--export-policy": str(policy), "_expect_success": False}
    )
    assert result.returncode != 0
    assert "no_such_table" in result.stderr
