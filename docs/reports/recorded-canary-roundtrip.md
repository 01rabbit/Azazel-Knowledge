# Recorded nginx canary fact → actual Knowledge processes

Owners: Deception #31, Knowledge #66/#111. This regression reuses the existing
Knowledge API, spool, single writer, read-only database and deterministic
advisory function. It adds no production API, schema, dependency, replay engine,
activation path or runtime/training admission.

## Source evidence and claim boundary

`tests/fixtures/recorded_canary_v1.json` contains one canonical fact exported
from a **copy** of root-reviewed retained actual nginx lab evidence after the
original evidence chain was checked. The export preserves the captured
observation, opaque lure/session/boot IDs, evidence references, metadata,
limitations and runtime context. This test consumes that recorded fact; it
starts no new nginx, Docker, Deception producer, canary or external target.

The recorded source identifies Deception capture test commit
`83d88cbfd97e99b63ac3c6f905a54471da508e3b` and merge commit
`5bcebb2d75a497fc9c4788b7892ae76221afb04f`. Its original evidence SHA-256 is
`7446ff969aa2f2b70f0921f0235f7361ce9d38b9f83fe41c2041415a0cce58ff`.
The canonical payload SHA-256 remains exactly
`b08d19856629ac9f39fb630c444b7f1f7739009cade021df73f75df57e03db61`.
Root reviewed the synthetic public fixture for raw-token exclusion; opaque IDs
are retained as data, not interpreted as authenticated identities.

Additional provenance is outside the original payload:

- `runtime_context.architecture="amd64"` remains unchanged. It is reported
  fixture-host metadata, **not** an independently measured execution platform.
- Producer Fabric identity at original capture was not recorded. The Fabric
  version used to validate this replay does not establish that missing identity.
- Fixture controller/session/boot/HMAC context does not establish production
  approval, actor identity, runtime admission or a current live observation
  window. Production admission and hardware acceptance remain false.
- The raw limitation string preserves unverified presentation/interaction
  reporting, scanner/prefetch/replay/copied-link alternatives, and the explicit
  absence of AI identity, malice, belief or tactical verdict.

A literal reviewed whole-wrapper hash in the test peer binds payload, historical
clock and all provenance:
`6a66230355a24edd7b23ae6c616b845aae69aaee1427f0b3ebceb89e273ffeef`.
A changed self-declared payload hash cannot bypass that check. Hashes detect
changes against this checked-in reference; they do not authenticate an
independent producer, prove preregistration, attest the original host, or resist
coordinated source/fixture/root compromise. Original chain verification belongs
to the reviewed extract step, not a fabricated new verification of unavailable
private source material during this replay.

## Actual process path and assertions

The new tests reuse `Lab` and `_deception_process_peer.py` from the existing
process roundtrip. A closed `recorded-canary-v1` profile selects only this
bounded fixed fixture and validates it before bootstrap or socket activity.
The original `historical` profile retains its January 1 defaults. Recorded
profiles cannot invoke producer/tamper roles or generate fresh observations.

The captured observation time remains `2026-11-11T08:06:40.190492Z`.
API, drain and offline replay share the original case's
`query_as_of=2026-11-11T08:07:40.190492+00:00`, exactly 60 seconds later.
Neither source timestamps nor clocks are rewritten to the current time to
pass validation. This is historical recorded-lab replay, not a fresh live window.

The positive regression:

1. Starts the actual Knowledge uvicorn application on an inherited ephemeral
   `127.0.0.1` listener; its numeric AF_INET client uses no DNS or proxy.
2. Posts the existing canonical observation envelope. HTTP 202 alone is
   explicitly insufficient: read-only readback must still be empty before drain.
3. Runs the existing worker single-writer drain in a separate process, then
   requires the real ingest-status route to report one valid drained fact.
4. Reads the real database from a separate `mode=ro`, `query_only=ON` peer and
   compares the **complete raw fact** with the recorded payload. No metadata,
   opaque identifier, evidence reference, limitation or architecture value is
   rewritten or upgraded.
5. Compares the real HTTP advisory with two separate existing offline advisory
   replays, with sockets and child launch forbidden inside offline operations.
   The advisory stays `advisory_only`, `executable=false`, references the same
   observation, and retains unknown belief and absence of measured outcome.
6. Re-drains and submits an overlapping batch: the first is a no-op, the second
   is deduplicated, raw facts remain identical and the advisory is unchanged.

The existing advisory is a summary, not a verbatim metadata/limitation transport.
Raw source limitations remain in stored facts and fixture provenance; this
change does not claim the advisory independently resolved any of them.

Three negative variants alter payload, query clock or architecture provenance.
Each must fail the literal wrapper binding before any HTTP connection or process
launch. No Deception or Docker opt-in is needed for these new recorded tests.
The original fresh-producer cross-repository tests retain their explicit opt-in.

## Run, retain and remaining gates

With the existing API dependencies and stable Fabric v0.10.0 source prestaged:

```sh
PYTHONPATH=src:/absolute/clean-fabric-v0100/src \
  /absolute/known-knowledge-venv/bin/python -m pytest -q \
  tests/unit/test_recorded_canary_roundtrip.py
```

The reused lab keeps its private fresh database, API audit files, peer logs,
worker status and complete peer result artifacts under its test directory.
They are synthetic local evidence, not a durable independent witness. Existing
bounded peer/HTTP/cleanup behavior applies; there is no automatic retry, source
reset, production credential, feed/model/provider invocation or external target.
Preserve a fresh private test directory if retaining a review bundle. Default
pytest cleanup is not evidence retention.

This proves transport, validation, storage, deduplication and deterministic
advisory replay of a recorded nginx fact. It does not prove attacker identity,
AI usage, malice, belief, causal deception efficacy, independently verified
platform/source identity, hostile-load behavior, production activation,
hardware acceptance or Knowledge training promotion.

Validation: the first focused run collected the four new recorded cases plus
existing process helpers: five passed and four explicitly opt-in producer cases
skipped without their environment variables. The new recorded path ran with no
Deception/Docker opt-in. Full unit collection is **1811**, from the previous
**1807** plus four cases. The commander synchronizes the six existing baseline
sites before the required full-unit run; final results are appended afterward.

Final commander validation used a fresh Linux container with networking disabled,
read-only source, stable Fabric source/distribution metadata 0.10.0, temporary
benchmark storage and both clean Deception producer opt-ins enabled. Exactly
**1811 tests collected: 1810 passed, one existing skip, in 111.77 seconds**.
All nine new/previous process and cleanup cases executed. The six baseline
sites were synchronized to 1811 by the commander before this run.

The initial container-creation attempt failed before any test because the fresh
worktree lacked the ignored `bench-results` mountpoint. The commander retained
that initialization failure, created the empty ignored mountpoint without any
product source change, and used a fresh container for final validation. The
final retained log is
`work/knowledge-recorded-canary-verified-full.log` in the task workspace.
This agent ran no duplicate full suite and made no git operations.
