# Deception fact → Knowledge process roundtrip

Owners: Deception #31, Knowledge #66/#111. Scope: opt-in, synthetic historical
fact transport/storage and deterministic advisory replay. Product runtime
admission, live exposure, training promotion and defense authority remain closed.

## Reused contracts and actual processes

The two new test files compose existing implementations without adding a
production endpoint, schema, dependency or replay engine:

1. A separate Deception Python process uses `InteractionObserver.record` with
   explicit historical timestamps, checks `RuntimeStateStore.verify_evidence_chain`,
   then calls the existing canonical `export_observations`. No Compose,
   canary runtime, activation, provider or model is started.
2. A separate Knowledge process serves the existing `create_app(Settings(...))`
   using real uvicorn on a prebound, inherited `127.0.0.1` ephemeral listener.
   The test sends the existing `{environment_id, items}` envelope to
   `/v1/deception-observations` over actual HTTP. The client uses an AF_INET
   socket directly with a numeric address; there is no DNS, proxy or arbitrary
   remote target. No fake HTTP handler or acknowledgment substitutes for Knowledge.
3. An independent fixed worker peer invokes only existing
   `PrioritySingleWriterQueue` + `drain_endpoint('deception-observations', ...)`.
   It does not start the general worker/feed scheduler, maintenance or retention.
4. The existing `/v1/ingest/{batch_id}` must report actual completed validation.
   A separate readback process opens the fresh local database with SQLite
   `mode=ro` and `query_only=ON`; observation IDs **and full raw producer facts**
   must match. A 202 before drain is explicitly shown to leave the table empty.
5. Two actual `/v1/deception-effectiveness` reads must match, followed by
   byte-equivalent structured output from separate offline peers running the
   existing `summarize_effectiveness` and boundary model. Socket/process launch
   is forbidden inside those offline readback/replay operations. Authority
   remains `advisory_only`, `executable=false`, with attacker belief unknown and
   scanner-noise counter-evidence retained.

The API's test DB/token/intel bootstrap reuses `_api_support` provisioning; after
bootstrap, all fact writes pass through the existing worker queue. Original
repository data, tokens, local.db, services and registration are untouched.

This deliberately does not call `export_trajectory_bundle` or manufacture
Outcome records: that replay surface serves a different outcome-chain contract.
It also does not claim that these scripted observations came from actual
attacker traffic. A real producer process generates **explicit historical test
facts**, not new live engagement observations.

## Clock, source and environment pins

The fixture records `2026-01-01T00:00:00Z` observations and pins API/drain/replay
`query_as_of` to `2026-01-01T00:10:00Z`. Those timestamps are set at creation and
never rewritten to bypass the existing ±48-hour validator. Fresh API/storage
clock and historical provenance are kept distinct from wall-clock execution.

The reviewed setup uses isolated Knowledge source
`41cad719712bc76efc2b67f930fba958433e356a`, supplied clean Deception source
`5bcebb2d75a497fc9c4788b7892ae76221afb04f`, and the existing stable Fabric
v0.10.0 source at `397fcce7a87ca7ab1a5e84bc196c44d70c404907`.
Root/commander verifies those refs; the tests never invoke git. The operator
must provide the clean Deception source and known interpreter explicitly.
No package installation or silent dependency upgrade occurs.

Source paths may override older installed wheel metadata through `PYTHONPATH`.
The producer output therefore labels installed distribution metadata separately
from the loaded Fabric contract hash, and retains hashes of the actual imported
Deception producer/export/state source files plus its evidence-chain digest.
Do not describe an older installed version string as the loaded source version.

Example from an isolated Knowledge checkout with all dependencies prestaged:

```sh
export PYTHONPATH="$PWD/src:/absolute/clean-fabric-v0100/src"
export AZAZEL_DECEPTION_SOURCE=/absolute/clean-deception-checkout
export AZAZEL_DECEPTION_PYTHON=/absolute/known-deception-venv/bin/python
/absolute/known-knowledge-venv/bin/python -m pytest -q \
  tests/unit/test_deception_process_roundtrip.py
```

Without both explicit Deception variables, the four cross-repository process
cases are skipped; the cleanup unit regression still runs. A skipped lab is not roundtrip evidence. The repository's
required full unit run must use the prestaged Fabric/API candidate dependencies;
this test does not relax existing dependency checks or modify pins.

## Negative controls, bounds and retained evidence

Five tests cover the successful full process roundtrip and overlap/redrain
idempotency; wrong auth (401) and wrong ingest scope (403); corrupted producer
hash-chain refusal before any export/Knowledge process; and banned belief/verdict
fields rejected by the existing API contract (422); and injected termination/
channel/log failures that must not skip another group, reap or channel cleanup.
Neither redrain nor an
overlapping batch changes stored facts/counts or the deterministic advisory.

Every case uses a fresh private `0700` test directory. The complete producer
results, prepared test credentials, drain statistics, raw readback and offline
advisories are retained as exclusive `0600` result files alongside original
Deception evidence, SQLite data, spool/status records, API audit and peer logs.
These contain synthetic tokens and should remain private. They are test
artifacts, not an independently authenticated checkpoint, signing or durability
claim. The existing Deception chain is unkeyed; whole-chain owner rewrite is
outside its guarantee. Export is gated on verification but does not itself
supply an external retained head or authenticated producer identity.

Each fixed peer is launched in its own process group. Commands are an internal
role allowlist, not caller-supplied scripts. One-shot peers have 12-second
execution deadlines, server startup has a 10-second readiness budget, HTTP has
2-second waits and a 1-MiB response/body bound; cleanup attempts all children
with bounded terminate/kill/reap, including on assertion failures. There are no
retries, scope resets or historical repairs. Pytest may remove temporary files
later; choose and preserve a private `--basetemp` directory when retaining a
review bundle, and never reuse an earlier basetemp as automatic recovery.

This is functional transport/storage/replay evidence only. It does not validate
real attacker behavior, effectiveness calibration, hostile runtime, separate-UID
isolation, production deployment, model knowledge quality, training admission,
network exposure or service benefit.

## Validation at the implementation handoff

With the explicit clean-source/Python opt-ins above, the four process tests
passed (4.58 seconds). The required full `tests/unit` run collected **1806**
tests: **1805 passed, one baseline-documentation guard failed** (91.65 seconds).
The single failure was
`test_claude_md_baseline.py::test_baseline_is_not_below_the_real_test_count`:
the existing six documentation sites still stated 1802, exactly four below the
new collection. All functional tests, including these four actual-process tests,
passed. Test count is **1802 → 1806**. The commander must synchronize the
existing baseline sites and verify the guard; those files are outside this
three-file implementation's ownership. This handoff does not claim a green
full suite before that required update.


After review, per-process cleanup was strengthened to attempt every bounded
terminate/wait/force-kill/reap and channel-close step independently, then report
aggregated failure after all children and logs have been attempted. A fifth
focused regression injects a failed termination, timeout, channel-close error
and log-close error and verifies the remaining resources are still handled.
Final focused validation: **5 passed in 4.78 seconds**. Final collected test
count is expected to be **1807** (1802 existing + five new); the commander owns
the baseline-site synchronization and final collection/guard check. The full
unit run above is retained as history; it was not repeated after this focused
cleanup change.


## Root integration verification

The commander synchronized all six baseline sites to **1807** and kept the
cleanup unit case active without the producer opt-in. A network-disabled Linux
container with the declared stable Fabric v0.10.0 installed and both clean
source checkouts mounted read-only completed **1806 passed, 1 skipped** in
109.53 seconds, including all five new cases and the full-candidate collection
guard. Only the pre-existing benchmark output directory was a writable temporary
mount; no source, production database or original repository was changed.

The initial read-only Linux attempt retained three benchmark output-write errors
(`bench-results` was read-only), with 1803 passes and one skip. Giving that
existing output directory an ephemeral writable mount resolved all three in a
focused check before the final full run. Those failures and the earlier baseline
guard failure remain diagnostic history, not discarded successful runs.

The hosted default suite can skip the four cross-repository process cases; its
skips do not substitute for the explicit offline execution above. No product
permission, dependency, service, training or admission changes are introduced.
