"""Every ingest lane must be registered in all three places, or it is a dead end.

An ingest lane is assembled from three registries that nothing connected:

* a `POST /v1/<endpoint>` route in `api/routers/`, which spools the batch;
* an entry in `drain._VALIDATORS`, which says how to read a spooled line;
* an entry in `worker.INGEST_ENDPOINTS`, which is the only thing that makes
  the P1 drain ever *visit* that spool directory.

Miss the third and the lane looks complete from every angle that gets tested:
the endpoint returns `202`, the batch lands durably on disk, the validator and
the insert both have their own passing tests. The rows simply never arrive, and
`GET /v1/ingest/{batch_id}` reports `drained=False` forever.

`engagement-events` shipped in exactly that state. It had a route, a
validator, a drain branch and 35 passing tests, and the worker never looked at
its spool directory. Nothing was wrong with any of the parts; nothing tied
them together.

This is that tie.
"""

from __future__ import annotations

from azazel_knowledge.api.models import IngestAcceptedResponse
from azazel_knowledge.ingest.drain import _VALIDATORS
from azazel_knowledge.worker import INGEST_ENDPOINTS

#: A literal, so deleting a lane from every registry at once is still visible
#: here. Derived from none of the three things under test.
EXPECTED_LANES = {
    "events",
    "flows",
    "reactions",
    "engagement-events",
    "outcome-evidence",
    "deception-observations",
    "deception-outcome-envelopes",
}


def _ingest_route_endpoints() -> set[str]:
    """The `<endpoint>` of every POST route that accepts an ingest batch.

    Identified by response model rather than by path: a lane is an ingest lane
    because it answers with an `IngestAcceptedResponse` batch id, and matching
    on a path prefix would quietly include or exclude routes as `/v1` grows.
    """

    from azazel_knowledge.api.app import app

    found: set[str] = set()
    for included in app.routes:
        router = getattr(included, "original_router", None)
        if router is None:
            continue
        for route in router.routes:
            methods = getattr(route, "methods", None) or ()
            if "POST" not in methods:
                continue
            if getattr(route, "response_model", None) is not IngestAcceptedResponse:
                continue
            found.add(route.path.removeprefix("/v1/"))
    return found


def test_the_route_surface_is_what_this_file_thinks_it_is():
    """Fails if the introspection above quietly stops finding routes.

    Every other assertion here compares sets, and two empty sets are equal.
    A change to FastAPI's router internals that made `_ingest_route_endpoints`
    return nothing would turn this whole file green and meaningless.
    """

    routes = _ingest_route_endpoints()
    assert routes, "no ingest routes were found at all -- the introspection broke"
    assert len(routes) == len(EXPECTED_LANES)


def test_every_endpoint_that_accepts_a_batch_is_drained_by_the_worker():
    accepted = _ingest_route_endpoints()
    never_drained = accepted - set(INGEST_ENDPOINTS)
    assert not never_drained, (
        f"{sorted(never_drained)} accept batches and spool them, but the worker's "
        "P1 drain never visits those spool directories -- the rows never arrive"
    )


def test_every_endpoint_the_worker_drains_can_be_reached():
    drained = set(INGEST_ENDPOINTS)
    unreachable = drained - _ingest_route_endpoints()
    assert not unreachable, (
        f"{sorted(unreachable)} are drained but have no ingest route"
    )


def test_every_drained_endpoint_has_a_validator():
    missing = set(INGEST_ENDPOINTS) - set(_VALIDATORS)
    assert not missing, (
        f"{sorted(missing)} are drained with no registered validator; "
        "`drain_endpoint` raises for these"
    )


def test_every_validator_belongs_to_a_drained_endpoint():
    orphaned = set(_VALIDATORS) - set(INGEST_ENDPOINTS)
    assert not orphaned, (
        f"{sorted(orphaned)} have a validator that nothing ever calls"
    )


def test_the_lane_set_is_pinned():
    assert set(INGEST_ENDPOINTS) == EXPECTED_LANES
    assert len(INGEST_ENDPOINTS) == len(EXPECTED_LANES), "a lane is listed twice"
