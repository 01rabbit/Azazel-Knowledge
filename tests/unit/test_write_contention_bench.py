"""Spec tests for the ADR-0003 write-path harness (`tools/bench/write_contention.py`).

The harness exists to produce evidence for ADR-0003's revisit triggers, so
what has to be right is its *accounting*: which records count as having
waited, how long they waited, whether the queue was draining, and when a
measurement is allowed to be called a verdict. These tests pin that
accounting, not the shape of the code that implements it.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = REPO_ROOT / "tools" / "bench"
if str(BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(BENCH_DIR))

import write_contention as wc  # noqa: E402

from azazel_knowledge.core.clock import parse_rfc3339  # noqa: E402
from azazel_knowledge.ingest.validators import validate_event_line  # noqa: E402
from _common import FIXED_QUERY_AS_OF  # noqa: E402


def _accept(batch_id: str, records: int, accepted_s: float) -> wc.BatchAccept:
    return wc.BatchAccept(
        batch_id=batch_id,
        client_key_id="bench-edge-0000",
        records=records,
        accepted_s=accepted_s,
        accept_ms=0.0,
    )


def _depth(series: list[tuple[float, int]]) -> list[wc.DepthSample]:
    return [
        wc.DepthSample(t_s=t, pending_batches=max(1, records // 10), pending_records=records)
        for t, records in series
    ]


# --- latency accounting ----------------------------------------------------


def test_latency_is_the_wait_from_api_accept_to_worker_commit():
    """ADR-0003's "write queue" is the wait, not the write. A batch accepted
    at t=1.0 and committed at t=1.25 waited 250 ms, and every record in it
    waited that long -- the threshold is stated per ingested record."""
    latencies = wc.spool_to_commit_latencies([_accept("b1", 3, 1.0)], {"b1": 1.25})

    assert latencies.per_batch_ms == pytest.approx([250.0])
    assert latencies.per_record_ms == pytest.approx([250.0, 250.0, 250.0])


def test_a_batch_the_worker_never_committed_is_counted_not_imputed():
    """The records that never made it are exactly the ones a queue-depth
    finding turns on. Giving them a latency -- any latency -- would flatter
    the result precisely where it must not."""
    accepts = [_accept("done", 2, 1.0), _accept("stuck", 7, 1.0)]

    latencies = wc.spool_to_commit_latencies(accepts, {"done": 1.1})

    assert latencies.per_batch_ms == pytest.approx([100.0])
    assert len(latencies.per_record_ms) == 2
    assert latencies.undrained_batches == 1
    assert latencies.undrained_records == 7


def test_a_commit_before_its_accept_is_refused_not_reported():
    """A negative wait means the instrumentation is wrong. Reporting it as a
    very fast commit would turn an instrumentation bug into evidence."""
    with pytest.raises(ValueError, match="committed before it was accepted"):
        wc.spool_to_commit_latencies([_accept("b1", 1, 2.0)], {"b1": 1.0})


# --- queue-depth accounting ------------------------------------------------


def test_a_queue_that_stays_the_same_depth_has_no_growth():
    samples = _depth([(0.0, 400), (1.0, 400), (2.0, 400), (3.0, 400)])

    assert wc.depth_slope_records_per_s(samples) == pytest.approx(0.0)


def test_growth_rate_is_reported_in_records_per_second():
    samples = _depth([(float(t), 100 * t) for t in range(10)])

    assert wc.depth_slope_records_per_s(samples) == pytest.approx(100.0)


def test_the_ramp_at_the_start_is_not_counted_as_growth():
    """Every queue grows while it fills. Fitting the whole series would
    report growth for a queue that reached its working depth and settled."""
    ramp = [(float(t), 100 * t) for t in range(10)]
    settled = [(float(t), 900) for t in range(10, 20)]

    slope = wc.depth_slope_records_per_s(_depth(ramp + settled))

    assert slope == pytest.approx(0.0, abs=1e-6)


# --- classification: the distinction ADR-0003 turns on ---------------------


def test_a_queue_that_never_empties_is_unbounded_whatever_its_percentiles():
    """An unbounded queue is the finding that matters, and it can hide behind
    good percentiles: while it fills, the batches that did commit committed
    fast."""
    assert wc.classify_queue(12.0, 0.0, drained_within_tail=False) == "unbounded"


def test_high_but_stable_latency_is_a_different_finding_from_unbounded():
    assert (
        wc.classify_queue(2500.0, 0.0, drained_within_tail=True) == "saturated_stable"
    )


def test_a_queue_growing_under_load_is_distinguished_from_a_settled_one():
    assert wc.classify_queue(12.0, 500.0, drained_within_tail=True) == "growing"
    assert wc.classify_queue(12.0, 0.0, drained_within_tail=True) == "stable"


# --- trigger evaluation ----------------------------------------------------


def test_write_queue_trigger_fires_only_when_a_config_crossed_one_second():
    """ADR-0003 says >1 s. A sweep whose worst p99 is 999 ms has not met the
    trigger, and the harness must not round its way into a migration."""
    under = [{"config": "8x2000", "p99_record_latency_ms": 999.0, "classification": "stable"}]
    over = [{"config": "8x2000", "p99_record_latency_ms": 1000.0, "classification": "growing"}]

    assert wc.evaluate_write_queue_trigger(under)["status"] == "not_met"
    result = wc.evaluate_write_queue_trigger(over)
    assert result["status"] == "met"
    assert result["breaching_configs"] == ["8x2000"]


def test_an_unrun_sweep_is_not_measured_rather_than_not_met():
    """"We did not look" and "we looked and it was fine" are different
    claims; a result file that cannot tell them apart is worse than none."""
    assert wc.evaluate_write_queue_trigger([])["status"] == "not_measured"
    assert wc.evaluate_write_queue_trigger([])["max_p99_record_latency_ms"] is None


def test_store_scale_short_of_ten_million_reports_the_shortfall():
    result = wc.evaluate_store_scale_trigger(1_000_000)

    assert result["status"] == "not_reached"
    assert result["shortfall_rows"] == 9_000_000
    assert result["max_rows_reached"] == 1_000_000


def test_store_scale_never_extrapolates_a_verdict_from_a_smaller_run():
    """The whole point of the second trigger is the size actually reached.
    A trend at 1 M is not a pass at 10 M, and the result file says so."""
    for reached in (1_000, 1_000_000, 10_000_000):
        assert wc.evaluate_store_scale_trigger(reached)["verdict_extrapolated"] is False
    assert wc.evaluate_store_scale_trigger(10_000_000)["status"] == "reached"


def test_growth_stops_on_disk_before_it_stops_on_time():
    """Exhausting the filesystem loses every step already measured; running
    out of time merely ends the run with its results intact. So disk wins."""
    both_breached = dict(
        rows=500, max_rows=10_000, free_bytes=1, floor_bytes=2, elapsed_s=99.0, budget_s=1.0
    )

    assert wc.stop_reason(**both_breached) == "disk_floor"
    assert wc.stop_reason(**{**both_breached, "free_bytes": 10**12}) == "time_budget"
    assert wc.stop_reason(**{**both_breached, "rows": 10_000}) == "target_reached"
    assert (
        wc.stop_reason(
            rows=500, max_rows=10_000, free_bytes=10**12, floor_bytes=2,
            elapsed_s=1.0, budget_s=99.0,
        )
        is None
    )


# --- deterministic synthetic load ------------------------------------------


def test_the_same_seed_regenerates_the_same_load_byte_for_byte():
    """A harness whose re-runs are not comparable measures nothing twice."""
    first = wc.synthetic_event_line(3, 17, seed=99)

    assert wc.synthetic_event_line(3, 17, seed=99) == first
    assert wc.synthetic_event_line(3, 17, seed=100) != first


def test_synthetic_records_take_the_accepted_path_through_the_real_validator():
    """If the drain quarantined these lines the harness would be timing the
    error path, and the measured throughput would be of nothing."""
    for record_index in range(20):
        line = wc.synthetic_event_line(2, record_index)
        ok, result = validate_event_line(line, now=FIXED_QUERY_AS_OF)
        assert ok, result
        assert result["entities"], "a record with no entity does no stats work at drain"


def test_offered_records_are_distinct_so_dedupe_cannot_silently_absorb_load():
    """`drain._insert_observations` suppresses duplicate `(event_id, edge_id)`.
    Colliding ids would let the worker 'keep up' by doing no work."""
    ids = {
        json.loads(wc.synthetic_event_line(client, record))["event_id"]
        for client in range(4)
        for record in range(50)
    }

    assert len(ids) == 4 * 50


def test_synthetic_indicators_are_unique_so_the_store_really_grows():
    """`ioc` upserts on `UNIQUE (type, value)`. Repeated values would turn
    Part B's inserts into updates and its growth curve into a fiction."""
    first, _ = wc.synthetic_ioc_rows(0, 3_000, seed=1, intel_generation=1)
    second, _ = wc.synthetic_ioc_rows(3_000, 3_000, seed=1, intel_generation=1)

    keys = {(row.type, row.value) for row in first + second}
    assert len(keys) == 6_000


def test_synthetic_observed_at_stays_inside_the_validators_skew_window():
    stamps = [
        parse_rfc3339(json.loads(wc.synthetic_event_line(0, i))["observed_at"])
        for i in range(200)
    ]

    assert all(abs((stamp - FIXED_QUERY_AS_OF).total_seconds()) < 48 * 3600 for stamp in stamps)


def test_sweep_spec_reads_as_clients_by_offered_rate():
    assert wc.parse_sweep("1x200, 16x4000") == [(1, 200.0), (16, 4000.0)]
    with pytest.raises(ValueError):
        wc.parse_sweep("16")
    with pytest.raises(ValueError):
        wc.parse_sweep("0x200")


def test_throughput_trend_is_labelled_derived():
    """Part B's trend is arithmetic over observations, not an observation.
    The result file has to say which is which."""
    trend = wc.throughput_trend([(100_000, 40_000.0), (1_000_000, 20_000.0)])

    assert trend["derived"] is True
    assert trend["retention_ratio"] == pytest.approx(0.5)


# --- the harness against the real ingest path ------------------------------


def test_a_sweep_config_measures_the_real_spool_to_worker_round_trip(tmp_path: Path):
    """End to end over the shipped path: SpoolWriter -> drain_endpoint ->
    PrioritySingleWriterQueue -> local.db. If the harness ever stopped
    exercising that path its numbers would be about something else."""
    result = wc.run_part_a_config(
        tmp_path / "cfg",
        clients=2,
        offered_rps=200.0,
        duration_s=0.5,
        batch_records=10,
        endpoint="events",
        seed=7,
        entity_pool=32,
        tail_budget_s=20.0,
        sample_interval_s=0.02,
        drain_interval_s=0.002,
    )
    observed = result["observed"]

    assert observed["accepted_records"] > 0
    assert observed["committed_records"] == observed["accepted_records"]
    assert observed["undrained_records"] == 0
    assert observed["drained_within_tail"] is True

    conn = sqlite3.connect(tmp_path / "cfg" / "data" / "db" / "local.db")
    try:
        stored = conn.execute("SELECT COUNT(*) FROM observation").fetchone()[0]
    finally:
        conn.close()
    assert stored == observed["accepted_records"]


def test_accept_cost_population_is_settled_backlog_not_a_pending_queue(tmp_path: Path):
    """`write_batch`'s quota scan reads every batch file in the endpoint
    directory. The cost that matters is the one a *healthy* node pays, so the
    population the harness builds must be fully drained -- a pending backlog
    would be a node already in trouble and a different measurement.

    Since the drained-directory change, a settled backlog no longer sits in the
    endpoint directory at all, which is the whole point: the harness must still
    build a real one, and the accept scan must no longer see it."""
    from azazel_knowledge.ingest.spool import DRAINED_DIRNAME, SpoolWriter

    spool = SpoolWriter(tmp_path / "ingest")
    wc.populate_drained_spool(
        spool, "events", "bench-edge-0000", 5, batch_records=2, seed=1, entity_pool=8
    )

    endpoint_dir = tmp_path / "ingest" / "events"
    drained_dir = endpoint_dir / DRAINED_DIRNAME
    assert spool.pending_batches("events") == []
    # The backlog is real: five drained batches exist...
    assert len(list(drained_dir.glob("*.jsonl"))) == 5
    # ...and none of them is in the directory an accept scans.
    assert list(endpoint_dir.glob("*.jsonl")) == []
    # The scan attributes a batch to a client through its `.client` sidecar,
    # which travels with the batch; without one a pending batch would be
    # skipped and the accept would look free.
    assert sorted(p.read_text() for p in drained_dir.glob("*.client")) == [
        "bench-edge-0000"
    ] * 5


def test_queue_growth_is_fitted_over_the_offered_load_not_the_drain_tail():
    """Once producers stop, every queue drains. Fitting the tail as well
    reports a shrinking queue for one that grew the whole time it was fed --
    which is precisely the configuration the finding is about."""
    load = [(float(t), 1000 * t) for t in range(10)]
    tail = [(10.0 + t, 9000 - 1000 * t) for t in range(1, 10)]
    samples = _depth(load + [(t, max(0, d)) for t, d in tail])

    during = wc.samples_during_load(samples, offer_window_s=9.0)

    assert [s.t_s for s in during] == [float(t) for t in range(10)]
    assert wc.depth_slope_records_per_s(during) == pytest.approx(1000.0)
    # A window that selects nothing must not be reported as a flat queue.
    assert wc.samples_during_load(samples, offer_window_s=-1.0) == list(samples)
