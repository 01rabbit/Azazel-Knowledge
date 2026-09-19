from __future__ import annotations

import json

import pytest

from azazel_knowledge.ingest.spool import BatchStatus, QuotaExceeded, SpoolWriter, new_batch_id


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


# --- drained batches leave the pending directory (ADR-0003 measurement) ------


def _accept(spool, client="edge-1", records=1):
    return spool.write_batch(
        "events", client, [json.dumps({"n": i}) for i in range(records)]
    )


def _drain(spool, batch_id, accepted="2026-09-19T00:00:00.000Z"):
    spool.write_status(
        "events",
        batch_id,
        BatchStatus(
            batch_id=batch_id,
            accepted=accepted,
            line_count=1,
            valid=1,
            drained=True,
        ),
    )


def test_accept_does_not_scan_batches_the_worker_already_drained(tmp_path):
    """The quota scan's cost must not grow with ingest history.

    Every accept walks the endpoint directory to total a client's pending
    bytes. Retention keeps drained batches for a week, so leaving them there
    made an accept O(batches accepted in the last 7 days) -- 2.07 ms against an
    empty directory, 232.92 ms against 5 000 drained ones (ADR-0003). This
    asserts the property that bounds it: what an accept scans is what the
    quota already bounds, not what the node has ever ingested.
    """
    spool = SpoolWriter(tmp_path / "ingest")
    endpoint_dir = tmp_path / "ingest" / "events"

    for _ in range(20):
        _drain(spool, _accept(spool))

    scanned = list(endpoint_dir.glob("*.jsonl"))
    assert scanned == [], f"accept would still scan {len(scanned)} drained batches"
    assert spool._pending_bytes_for_client(endpoint_dir, "edge-1") == 0


def test_drained_batch_is_never_handed_back_to_the_drainer(tmp_path):
    """Moving a batch must not weaken the replay guarantee.

    `drain.py` relies on a drained batch never reappearing as pending: that is
    what stops a crash-and-replay from committing its rows twice.
    """
    spool = SpoolWriter(tmp_path / "ingest")
    kept = _accept(spool)
    drained = _accept(spool)
    _drain(spool, drained)

    pending = spool.pending_batches("events")
    assert [b.batch_id for b in pending] == [kept]
    assert pending[0].path.is_file()


def test_status_of_a_drained_batch_is_still_readable(tmp_path):
    """A client polling its batch must not lose the answer to the move."""
    spool = SpoolWriter(tmp_path / "ingest")
    batch_id = _accept(spool)
    _drain(spool, batch_id)

    status = spool.read_status(batch_id)
    assert status is not None and status.drained is True
    assert status.batch_id == batch_id


def test_a_spool_written_before_the_move_is_still_read_correctly(tmp_path):
    """Upgrade safety: a node with a week of drained batches in the old flat
    layout must not have them re-drained, and must still report their status.

    Getting this wrong replays every already-committed batch on the first
    worker cycle after the upgrade, so it is asserted against a spool built the
    old way rather than through the current writer.
    """
    spool = SpoolWriter(tmp_path / "ingest")
    endpoint_dir = tmp_path / "ingest" / "events"
    batch_id = _accept(spool)
    # The pre-change layout: status written beside the payload, nothing moved.
    (endpoint_dir / f"{batch_id}.status.json").write_text(
        json.dumps(
            {
                "batch_id": batch_id,
                "accepted": "2026-09-19T00:00:00.000Z",
                "line_count": 1,
                "valid": 1,
                "invalid": [],
                "drained": True,
            }
        ),
        encoding="utf-8",
    )

    assert spool.pending_batches("events") == []
    assert spool._pending_bytes_for_client(endpoint_dir, "edge-1") == 0
    legacy = spool.read_status(batch_id)
    assert legacy is not None and legacy.drained is True


def test_a_pending_batch_still_counts_against_its_client_quota(tmp_path):
    """The move must not make the quota stop working."""
    spool = SpoolWriter(tmp_path / "ingest", quota_bytes=200)
    endpoint_dir = tmp_path / "ingest" / "events"

    big = _accept(spool, records=12)
    used = spool._pending_bytes_for_client(endpoint_dir, "edge-1")
    assert used > 0

    with pytest.raises(QuotaExceeded):
        _accept(spool, records=12)

    # Draining it releases the quota -- the bytes were pending, not spent.
    _drain(spool, big)
    assert spool._pending_bytes_for_client(endpoint_dir, "edge-1") == 0
    _accept(spool, records=12)


def test_retention_collects_drained_batches_in_both_layouts(tmp_path):
    """Moving drained batches must not make them immortal.

    Worker P3 deletes drained batches past the retention window. It swept one
    directory per endpoint; if it is not taught about the new one, drained
    batches accumulate on disk forever -- the disk-space version of the bug
    this change fixes.
    """
    from datetime import datetime, timezone

    from azazel_knowledge.worker import gc_ingest_spool

    root = tmp_path / "ingest"
    spool = SpoolWriter(root)
    endpoint_dir = root / "events"

    moved = _accept(spool)
    # Comfortably older than the cutoff below: the sweep keeps anything at or
    # after it, so a batch accepted *at* the cutoff would survive by design.
    _drain(spool, moved, accepted="2026-09-01T00:00:00.000Z")

    legacy = _accept(spool)
    (endpoint_dir / f"{legacy}.status.json").write_text(
        json.dumps(
            {
                "batch_id": legacy,
                "accepted": "2026-09-01T00:00:00.000Z",
                "line_count": 1,
                "valid": 1,
                "invalid": [],
                "drained": True,
            }
        ),
        encoding="utf-8",
    )

    removed = gc_ingest_spool(root, datetime(2026, 9, 19, tzinfo=timezone.utc))

    assert removed > 0
    assert list((endpoint_dir / "drained").glob(f"{moved}.*")) == []
    assert list(endpoint_dir.glob(f"{legacy}.*")) == []


def test_retention_keeps_a_drained_batch_inside_its_window(tmp_path):
    """The sweep must still be bounded by the cutoff, not delete on sight."""
    from datetime import datetime, timezone

    from azazel_knowledge.worker import gc_ingest_spool

    root = tmp_path / "ingest"
    spool = SpoolWriter(root)
    batch_id = _accept(spool)
    _drain(spool, batch_id)  # accepted 2026-09-19T00:00:00Z

    removed = gc_ingest_spool(root, datetime(2026, 9, 12, tzinfo=timezone.utc))

    assert removed == 0
    assert (root / "events" / "drained" / f"{batch_id}.jsonl").is_file()
