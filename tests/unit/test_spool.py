from __future__ import annotations

from azazel_cti.ingest.spool import BatchStatus, QuotaExceeded, SpoolWriter, new_batch_id


def test_new_batch_id_is_sortable_and_unique():
    ids = [new_batch_id(now=1000.0 + i) for i in range(5)]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)
    assert all(len(bid) == 30 for bid in ids)


def test_write_batch_is_durable_and_atomic(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    batch_id = spool.write_batch("events", "client-1", ["{}", '{"a": 1}'])

    endpoint_dir = tmp_path / "ingest" / "events"
    final_path = endpoint_dir / f"{batch_id}.jsonl"
    tmp_path_file = endpoint_dir / f"{batch_id}.jsonl.tmp"

    assert final_path.is_file()
    assert not tmp_path_file.exists()
    assert final_path.read_text() == '{}\n{"a": 1}\n'

    client_path = endpoint_dir / f"{batch_id}.client"
    assert client_path.read_text() == "client-1"


def test_write_batch_raises_quota_exceeded_over_client_cap(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest", quota_bytes=32)
    spool.write_batch("events", "client-1", ["x" * 20])

    try:
        spool.write_batch("events", "client-1", ["y" * 20])
    except QuotaExceeded as exc:
        assert exc.client_key_id == "client-1"
        assert exc.endpoint == "events"
        assert exc.quota_bytes == 32
    else:
        raise AssertionError("expected QuotaExceeded")


def test_quota_is_tracked_per_client_independently(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest", quota_bytes=32)
    spool.write_batch("events", "client-1", ["x" * 20])
    # A different client is unaffected by client-1's usage.
    spool.write_batch("events", "client-2", ["y" * 20])


def test_quota_drops_once_batch_is_marked_drained(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest", quota_bytes=25)
    batch_id = spool.write_batch("events", "client-1", ["x" * 20])

    try:
        spool.write_batch("events", "client-1", ["y" * 20])
        raise AssertionError("expected QuotaExceeded before drain")
    except QuotaExceeded:
        pass

    spool.write_status(
        "events",
        batch_id,
        BatchStatus(batch_id=batch_id, accepted="2026-07-06T00:00:00Z", line_count=1, valid=1, drained=True),
    )
    # Quota accounting excludes drained batches, so a fresh write now fits.
    spool.write_batch("events", "client-1", ["z" * 20])


def test_pending_batches_excludes_drained(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    b1 = spool.write_batch("events", "client-1", ["{}"])
    b2 = spool.write_batch("events", "client-1", ["{}"])

    pending = spool.pending_batches("events")
    assert sorted(p.batch_id for p in pending) == sorted([b1, b2])

    spool.write_status(
        "events",
        b1,
        BatchStatus(batch_id=b1, accepted="2026-07-06T00:00:00Z", line_count=1, valid=1, drained=True),
    )

    pending = spool.pending_batches("events")
    assert [p.batch_id for p in pending] == [b2]


def test_pending_batches_are_sorted_by_batch_id(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    ids = [spool.write_batch("events", "client-1", ["{}"]) for _ in range(3)]
    pending = spool.pending_batches("events")
    assert [p.batch_id for p in pending] == sorted(ids)


def test_read_status_locates_batch_without_endpoint_argument(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    batch_id = spool.write_batch("flows", "client-1", ["{}"])
    assert spool.read_status(batch_id) is None

    status = BatchStatus(
        batch_id=batch_id,
        accepted="2026-07-06T00:00:00Z",
        line_count=1,
        valid=1,
        invalid=[{"line_no": 2, "error": "bad"}],
        drained=True,
    )
    spool.write_status("flows", batch_id, status)

    loaded = spool.read_status(batch_id)
    assert loaded is not None
    assert loaded.drained is True
    assert loaded.valid == 1
    assert loaded.invalid == [{"line_no": 2, "error": "bad"}]


def test_write_batch_with_no_lines_produces_empty_file(tmp_path):
    spool = SpoolWriter(tmp_path / "ingest")
    batch_id = spool.write_batch("events", "client-1", [])
    path = tmp_path / "ingest" / "events" / f"{batch_id}.jsonl"
    assert path.read_text() == ""
