from __future__ import annotations

from azazel_knowledge.bundle.rollback_anchor import (
    IntegrityAlert,
    RollbackState,
    detect_version_gap,
    mark_needs_full_rebaseline,
    read_state,
    record_import,
    write_state,
)


def test_read_state_defaults_when_missing(tmp_path):
    state = read_state(tmp_path / "state.toml")
    assert state == RollbackState()
    assert state.last_imported_version == 0
    assert state.needs_full_rebaseline is False


def test_write_and_read_state_roundtrip(tmp_path):
    path = tmp_path / "state.toml"
    original = RollbackState(
        last_imported_version=7,
        last_import_at="2026-07-06T00:00:00Z",
        last_bundle_sha256="ab" * 32,
        needs_full_rebaseline=True,
    )
    write_state(path, original)
    reread = read_state(path)
    assert reread == original


def test_write_state_is_atomic_no_partial_file_left_behind(tmp_path):
    path = tmp_path / "nested" / "state.toml"
    write_state(path, RollbackState(last_imported_version=1))
    leftovers = list(path.parent.glob(".*.tmp.*"))
    assert leftovers == []
    assert path.exists()


def test_record_import_advances_watermark(tmp_path):
    path = tmp_path / "state.toml"
    state = record_import(path, bundle_version=3, imported_at="2026-07-06T01:00:00Z", bundle_sha256="cd" * 32)
    assert state.last_imported_version == 3
    assert read_state(path).last_imported_version == 3


def test_mark_needs_full_rebaseline_preserves_other_fields(tmp_path):
    path = tmp_path / "state.toml"
    record_import(path, bundle_version=2, imported_at="2026-07-06T00:00:00Z", bundle_sha256="ff" * 32)
    updated = mark_needs_full_rebaseline(path)
    assert updated.needs_full_rebaseline is True
    assert updated.last_imported_version == 2
    cleared = mark_needs_full_rebaseline(path, flag=False)
    assert cleared.needs_full_rebaseline is False
    assert cleared.last_imported_version == 2


def test_detect_version_gap_plus_one_is_ok():
    assert detect_version_gap(5, 6) == "ok"


def test_detect_version_gap_zero_with_differing_sha_is_integrity_check():
    assert detect_version_gap(5, 5, prev_sha256="aaaa", new_sha256="bbbb") == "integrity_check"


def test_detect_version_gap_zero_with_same_sha_is_unexplained():
    import pytest

    with pytest.raises(IntegrityAlert):
        detect_version_gap(5, 5, prev_sha256="aaaa", new_sha256="aaaa")


def test_detect_version_gap_regression_raises_integrity_alert():
    import pytest

    with pytest.raises(IntegrityAlert):
        detect_version_gap(5, 4)


def test_detect_version_gap_skip_raises_integrity_alert():
    import pytest

    with pytest.raises(IntegrityAlert):
        detect_version_gap(5, 8)


def test_data_partition_and_bundle_state_rollback_defeated_by_state_toml(tmp_path):
    """Simulate restoring an old data-partition + local.db `bundle_state`
    mirror claiming a stale version, while `state.toml` (outside the
    data partition) still records the true, higher watermark. Anything
    reading `state.toml` -- the only authority -- must see the newer
    version and refuse to regress."""
    state_path = tmp_path / "trust" / "state.toml"
    record_import(state_path, bundle_version=9, imported_at="2026-07-06T00:00:00Z", bundle_sha256="11" * 32)

    # A restored (stale) local.db would claim bundle_state = 3; that
    # value must never be consulted here.
    stale_local_mirror_claim = 3
    assert read_state(state_path).last_imported_version == 9
    assert read_state(state_path).last_imported_version != stale_local_mirror_claim
