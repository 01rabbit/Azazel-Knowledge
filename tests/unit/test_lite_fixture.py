"""Consumer fixtures and interrupted-extraction behaviour (ADR-0015 D7, Consequences 7/8).

The fixtures are what Azazel-Nexus and Azazel-Boot run their embedded Lite
reader against in their own CI (Azazel-Nexus#15, Azazel-Boot#16). These tests
check that they are worth relying on.

For the valid fixture that means: it rebuilds byte-for-byte, it verifies under
its own published anchor, and what it claims in `expected.json` is what a
reader actually finds inside it.

For the negative fixtures it means something stricter. A fixture labelled
"corrupt" that happens to fail for an unrelated reason is worse than no
fixture at all -- it would tell a consumer its fail-open path is exercised when
it is not. So every negative fixture is verified here and the *specific* gate
it hits is asserted, twice over: once against the literal error code, so the
emitter cannot quietly change what it ships, and once against the claim
`negative.json` makes about it, so the index a consumer reads cannot drift
away from the artifacts beside it.
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

#: Names the emitter promises `negative.json` will describe. Written out here
#: rather than read back from the index so that dropping a fixture from the
#: emitter fails this suite instead of silently shrinking what consumers get.
EXPECTED_NEGATIVE_FIXTURES = {
    "corrupt-signature",
    "corrupt-payload",
    "corrupt-truncated",
    "expired",
    "absent",
}


def _emit(out_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(_TOOLS_DIR / "lite_fixture.py"), "emit", "--out", str(out_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("fixture-set") / "fixture"
    _emit(out)
    return out


@pytest.fixture
def negative_index(fixture_dir):
    return json.loads((fixture_dir / "negative.json").read_text())


def _entry(index: dict, name: str) -> dict:
    matched = [e for e in index["fixtures"] if e["name"] == name]
    assert len(matched) == 1, f"{name!r} is not described exactly once in negative.json"
    return matched[0]


def _members(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, "r:gz") as tar:
        return {i.name: tar.extractfile(i).read() for i in tar.getmembers() if i.isreg()}


def _attempt(bundle: Path, fixture_dir: Path, work: Path):
    """Verify `bundle` and report what came back, without deciding what is acceptable.

    Returns `(outcome, staged)` where outcome is the `BUNDLE_*` code, the
    exception's qualified name, or `None` when verification succeeded. Each
    attempt gets a fresh `state.toml`: every fixture declares bundle_version 1
    because they are independent cases, and a shared watermark would trip
    anti-rollback and mask the gate under test.
    """
    work.mkdir(parents=True, exist_ok=True)
    staging = work / "staging"
    outcome: str | None
    try:
        verify_bundle(bundle, fixture_dir / "anchors.toml", work / "state.toml", staging)
        outcome = None
    except BundleVerifyError as exc:
        outcome = exc.code
    except Exception as exc:  # noqa: BLE001 -- the point is what a consumer would see
        outcome = f"{type(exc).__module__}.{type(exc).__name__}"
    staged = (
        sorted(str(p.relative_to(staging)) for p in staging.rglob("*") if p.is_file())
        if staging.exists()
        else []
    )
    return outcome, staged


# --- the valid fixture ------------------------------------------------------


def test_fixture_rebuilds_byte_for_byte(tmp_path):
    """A rebuilt fixture is the proof of D2, which is why it is emitted not committed.

    A checked-in blob would only show that a file was once added; rebuilding it
    on every use re-proves reproducibility each time. The negative fixtures are
    covered here too: a fixture a consumer cannot reproduce is a blob with
    extra steps, and two of the three corrupt shapes are re-gzipped by this
    emitter rather than by the builder, so their determinism is this file's
    responsibility rather than the builder's.
    """
    first, second = tmp_path / "a", tmp_path / "b"
    _emit(first)
    _emit(second)
    for relative in (
        "lite.tar.gz",
        "expected.json",
        "negative.json",
        "negative/corrupt-signature.tar.gz",
        "negative/corrupt-payload.tar.gz",
        "negative/corrupt-truncated.tar.gz",
        "negative/expired.tar.gz",
    ):
        assert (first / relative).read_bytes() == (second / relative).read_bytes(), relative


@pytest.mark.parametrize(
    "relative",
    [
        "lite.tar.gz",
        "negative/corrupt-signature.tar.gz",
        "negative/corrupt-payload.tar.gz",
        "negative/corrupt-truncated.tar.gz",
        "negative/expired.tar.gz",
    ],
)
def test_no_fixture_carries_a_wall_clock_gzip_stamp(fixture_dir, relative):
    """The gzip header's mtime field is zeroed on every emitted artifact.

    Pinned separately from `test_fixture_rebuilds_byte_for_byte`, and this is
    not belt-and-braces: two emits inside the same second produce the same
    wall-clock stamp, so the byte-identity test passes with a clock-stamped
    header and only starts failing on whichever unlucky run straddles a second
    boundary. `test_lite_bundle_build.py` makes the same separate assertion
    about the builder; the three corrupt fixtures are re-gzipped by
    `tools/lite_fixture.py` instead, so they need their own.
    """
    header = (fixture_dir / relative).read_bytes()[:10]
    assert header[:2] == b"\x1f\x8b", relative
    assert int.from_bytes(header[4:8], "little") == 0, relative


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


def test_fixture_is_built_with_the_shipped_default_export_policy(fixture_dir):
    """The fixture must represent what Knowledge exports, not a policy of its own.

    A private fixture policy would be a second source of truth, free to drift
    from `config/lite-export-policy.yaml` -- and a consumer testing against it
    would be testing a profile this node never ships.
    """
    from azazel_knowledge.bundle.lite_policy import load_export_policy

    repo_policy = load_export_policy(Path(__file__).resolve().parents[2] / "config" / "lite-export-policy.yaml")
    profile = peek_manifest(fixture_dir / "lite.tar.gz")["profile"]
    assert profile["selection_inputs"]["export_policy_digest"] == repo_policy.digest
    assert set(peek_manifest(fixture_dir / "lite.tar.gz")["tables"]) == set(repo_policy.datasets)


def test_fixture_excludes_the_stale_row_and_aliases_indicators(fixture_dir):
    """What a consumer's reader must observe, stated as a test here too.

    `expected.json` says a stale indicator is absent and that values are
    aliased. A consumer trusting those notes deserves them to be true of the
    artifact rather than merely written beside it.
    """
    payload = _members(fixture_dir / "lite.tar.gz")["tables/ioc.jsonl"].decode()
    assert "203.0.113.99" not in payload  # outside the freshness window
    assert "203.0.113.10" not in payload  # aliased, never verbatim
    rows = [json.loads(line) for line in payload.splitlines()]
    assert len(rows) == 3
    assert all(row["value"].startswith("az-") for row in rows)


def test_fixture_carries_a_second_dataset_that_the_freshness_window_does_not_touch(fixture_dir):
    """Static reference rows ride along, and none of them is dropped by freshness.

    A single-dataset fixture cannot show a consumer the difference between "an
    indicator aged out" and "this artifact is empty", and the expired fixture
    below depends on the distinction.
    """
    rows = [
        json.loads(line)
        for line in _members(fixture_dir / "lite.tar.gz")["tables/attack_technique.jsonl"]
        .decode()
        .splitlines()
    ]
    assert {row["technique_id"] for row in rows} == {"T1046", "T1110"}


def test_fixture_anchor_names_only_the_fixture_key(fixture_dir):
    anchors = (fixture_dir / "anchors.toml").read_text()
    assert "must never appear in a production anchor" in anchors
    assert anchors.count("=") >= 2


# --- the negative fixture set ----------------------------------------------


def test_negative_index_describes_exactly_the_fixtures_that_were_emitted(
    fixture_dir, negative_index
):
    """The index and the directory must agree, in both directions.

    A described fixture that is not there, or an emitted one nobody described,
    is how a consumer ends up testing something other than what it thinks.
    """
    described = {entry["name"] for entry in negative_index["fixtures"]}
    assert described == EXPECTED_NEGATIVE_FIXTURES

    for entry in negative_index["fixtures"]:
        path = fixture_dir / entry["path"]
        assert path.exists() is entry["exists"], entry["name"]
        if entry["exists"]:
            assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"], entry["name"]

    on_disk = {p.name for p in (fixture_dir / "negative").iterdir() if p.is_file()}
    declared = {
        Path(entry["path"]).name for entry in negative_index["fixtures"] if entry["exists"]
    }
    assert on_disk == declared


def test_every_negative_fixture_behaves_exactly_as_the_index_claims(
    fixture_dir, negative_index, tmp_path
):
    """The index is the contract a consumer reads; this is what makes it true.

    Checked as a loop over the shipped claims rather than as a hand-written
    table, so a fixture added to the emitter later cannot ship with an
    unverified description.
    """
    for entry in negative_index["fixtures"]:
        if not entry["exists"]:
            continue
        outcome, staged = _attempt(
            fixture_dir / entry["path"], fixture_dir, tmp_path / entry["name"]
        )
        expected = entry["expected_error_code"] or (
            entry["expected_exception"] if not entry["verifies"] else None
        )
        if entry["verifies"]:
            assert outcome is None, f"{entry['name']} claims it verifies, got {outcome}"
        else:
            assert outcome == expected, f"{entry['name']}: expected {expected}, got {outcome}"
        assert bool(staged) == entry["staging_written"], f"{entry['name']}: staged={staged}"


def test_corrupt_signature_fixture_fails_the_signature_gate(fixture_dir, tmp_path):
    """Refused on trust alone, before a content byte is read.

    The literal code is asserted here, not just "it failed": a broken-signature
    fixture that died on a malformed manifest would exercise a different gate
    and prove nothing about signature handling. The content members are
    asserted byte-identical to the valid artifact's so the *only* difference is
    the signature.
    """
    valid, corrupt = fixture_dir / "lite.tar.gz", fixture_dir / "negative/corrupt-signature.tar.gz"
    assert corrupt.read_bytes() != valid.read_bytes()
    assert peek_manifest(corrupt) == peek_manifest(valid)
    valid_members, corrupt_members = _members(valid), _members(corrupt)
    assert valid_members["manifest.sig"] != corrupt_members["manifest.sig"]
    assert len(valid_members["manifest.sig"]) == len(corrupt_members["manifest.sig"])
    for name in valid_members:
        if name != "manifest.sig":
            assert valid_members[name] == corrupt_members[name], name

    outcome, staged = _attempt(corrupt, fixture_dir, tmp_path / "sig")
    assert outcome == "BUNDLE_SIGNATURE_THRESHOLD_NOT_MET"
    assert staged == [], "the signature gate must refuse before anything is staged"


def test_corrupt_payload_fixture_fails_the_digest_gate_after_staging(fixture_dir, tmp_path):
    """Every trust gate passes; only the per-member digest catches it.

    This is the fixture that proves staging must never be promoted on failure:
    the tampered bytes are on disk when the refusal happens. The manifest is
    asserted identical to the valid artifact's, so the failure cannot be coming
    from the manifest having changed.
    """
    valid = fixture_dir / "lite.tar.gz"
    corrupt = fixture_dir / "negative/corrupt-payload.tar.gz"
    assert peek_manifest(corrupt) == peek_manifest(valid)
    assert _members(corrupt)["manifest.sig"] == _members(valid)["manifest.sig"]

    outcome, staged = _attempt(corrupt, fixture_dir, tmp_path / "payload")
    assert outcome == "BUNDLE_FILE_HASH_MISMATCH"
    assert "tables/ioc.jsonl" in staged, "the refusal must happen with bytes already in staging"


def test_corrupt_payload_fixture_raises_a_confidence(fixture_dir):
    """The tamper is the one ADR-0015 D4 names: bounding the data must not sharpen it.

    Asserted on the content, because "the digest does not match" is true of any
    edit at all, and a fixture that claimed a confidence tamper while flipping
    a random byte would be a lie a consumer could not see.
    """
    valid_rows = [
        json.loads(line)
        for line in _members(fixture_dir / "lite.tar.gz")["tables/ioc.jsonl"].decode().splitlines()
    ]
    tampered_payload = _members(fixture_dir / "negative/corrupt-payload.tar.gz")[
        "tables/ioc.jsonl"
    ].decode()
    tampered_rows = [json.loads(line) for line in tampered_payload.splitlines()]

    assert len(tampered_rows) == len(valid_rows)
    assert {r["agg_raw_confidence"] for r in valid_rows} == {72.5}
    assert sorted(r["agg_raw_confidence"] for r in tampered_rows) == [72.5, 72.5, 99.9]
    raised = [r for r in tampered_rows if r["agg_raw_confidence"] == 99.9]
    assert len(raised) == 1
    # Only the confidence moved: same indicator, same freshness, same expiry.
    twin = [r for r in valid_rows if r["value"] == raised[0]["value"]]
    assert len(twin) == 1
    assert {k: v for k, v in twin[0].items() if k != "agg_raw_confidence"} == {
        k: v for k, v in raised[0].items() if k != "agg_raw_confidence"
    }


def test_corrupt_truncated_fixture_fails_at_the_archive_gate(fixture_dir, tmp_path):
    """The container gate, which produces no BUNDLE_* code at all.

    This is the fact the fixture exists to hand a consumer: a reader that
    catches only `BundleVerifyError` lets a truncated artifact through as an
    unhandled error. Asserted as "not a BundleVerifyError, and a
    tarfile.ReadError" rather than as "it raised something", because "it
    raised" would stay true if the failure moved to an entirely different
    cause.
    """
    corrupt = fixture_dir / "negative/corrupt-truncated.tar.gz"
    assert len(gzip.decompress(corrupt.read_bytes())) < len(
        gzip.decompress((fixture_dir / "lite.tar.gz").read_bytes())
    )
    # The manifest and signature survive the cut, so the trust gates are
    # genuinely reached and passed before the decoder gives up.
    assert peek_manifest(corrupt) == peek_manifest(fixture_dir / "lite.tar.gz")

    with pytest.raises(BundleVerifyError) as exc:
        verify_bundle(
            corrupt,
            fixture_dir / "anchors.toml",
            tmp_path / "state.toml",
            tmp_path / "staging",
        )
    assert exc.value.code == "BUNDLE_ARCHIVE_UNREADABLE"
    # The underlying decoder error is preserved as the cause, so a consumer
    # that wants the detail still has it while dispatching on the code.
    assert isinstance(exc.value.__cause__, tarfile.TarError)
    outcome, _ = _attempt(corrupt, fixture_dir, tmp_path / "trunc")
    assert outcome == "BUNDLE_ARCHIVE_UNREADABLE"


def test_the_three_corrupt_fixtures_fail_at_three_distinct_gates(fixture_dir, tmp_path):
    """The reason there are three of them.

    If two shapes collapsed onto the same gate, one of them would be telling a
    consumer it had covered a path it had not.
    """
    outcomes = {
        name: _attempt(fixture_dir / f"negative/{name}.tar.gz", fixture_dir, tmp_path / name)[0]
        for name in ("corrupt-signature", "corrupt-payload", "corrupt-truncated")
    }
    assert len(set(outcomes.values())) == 3, outcomes
    assert None not in outcomes.values()


def test_expired_fixture_verifies_and_carries_only_expired_indicators(
    fixture_dir, negative_index, tmp_path
):
    """Expiry is a consumer-side judgement, not a verification failure (ADR-0015 D4).

    The artifact is valid and correctly signed, so it passes every gate; what
    makes it "expired" is the `agg_next_expiry` its rows carry, which the
    consumer evaluates against its own `query_as_of`. Both halves are asserted:
    verification succeeds, and every indicator in it has expired.
    """
    entry = _entry(negative_index, "expired")
    expired = fixture_dir / entry["path"]
    result = verify_bundle(
        expired, fixture_dir / "anchors.toml", tmp_path / "state.toml", tmp_path / "staging"
    )
    assert result is not None

    rows = [
        json.loads(line)
        for line in _members(expired)["tables/ioc.jsonl"].decode().splitlines()
    ]
    assert len(rows) == 3, "an empty dataset would make 'all expired' vacuously true"
    assert {row["agg_next_expiry"] for row in rows} == {entry["indicator_expiry"]}
    assert entry["indicator_expiry"] < peek_manifest(expired)["profile"]["selection_inputs"]["as_of"]

    # The valid fixture is the control: same rows, same policy, live expiry.
    valid_rows = [
        json.loads(line)
        for line in _members(fixture_dir / "lite.tar.gz")["tables/ioc.jsonl"].decode().splitlines()
    ]
    assert {row["agg_next_expiry"] for row in valid_rows} == {entry["valid_indicator_expiry"]}
    assert entry["valid_indicator_expiry"] > peek_manifest(expired)["profile"]["selection_inputs"]["as_of"]


def test_expired_fixture_still_carries_reference_rows_that_do_not_expire(fixture_dir):
    """So a consumer can withhold the expired claims without discarding the artifact.

    Refusing the whole artifact would also pass a naive "serves nothing
    expired" check, and would be the wrong behaviour: a Lite consumer must stay
    fully operational and keep using what is still good.
    """
    members = _members(fixture_dir / "negative/expired.tar.gz")
    rows = [json.loads(line) for line in members["tables/attack_technique.jsonl"].decode().splitlines()]
    assert {row["technique_id"] for row in rows} == {"T1046", "T1110"}
    assert all("agg_next_expiry" not in row for row in rows)


def test_absent_fixture_is_an_absence_the_set_guarantees(fixture_dir, negative_index):
    """"Absent" only means something if the emitter promises the path stays empty.

    A path that merely happens to be missing today is not a fixture. The
    anchors beside it exist, so a consumer knows it is testing a missing
    artifact rather than a missing trust anchor.
    """
    entry = _entry(negative_index, "absent")
    assert entry["exists"] is False
    assert entry["sha256"] is None
    absent = fixture_dir / entry["path"]
    assert not absent.exists()
    assert absent.parent.is_dir(), "the directory exists; only the artifact is missing"
    assert (fixture_dir / negative_index["anchors"]).is_file()


def test_absent_fixture_path_is_cleared_by_a_re_emit(tmp_path):
    """A stale file at the absent path would silently turn the case into its opposite."""
    out = tmp_path / "fixture"
    _emit(out)
    index = json.loads((out / "negative.json").read_text())
    absent = out / _entry(index, "absent")["path"]
    absent.write_bytes(b"not a bundle")
    assert absent.exists()

    _emit(out)
    assert not absent.exists()


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


def test_the_truncated_fixture_cuts_into_content_rather_than_a_block_boundary(fixture_dir):
    """The construction must not be disarmed by an empty dataset.

    `_corrupt_truncated` cuts the last content member in half. When the last
    content member is *empty*, half of zero is zero, the cut lands exactly on a
    tar block boundary, and the result is a shorter but perfectly well-formed
    archive: a "truncated" fixture that decodes without complaint and refuses
    nothing.

    This is not hypothetical. Adding `kev` to the default export policy put an
    empty `tables/kev.jsonl` last in the fixture and silently turned this
    fixture into a valid archive; the only reason it surfaced was that the
    tests asserting a refusal then failed. The emitter now excludes empty
    members and asserts the cut falls strictly inside a member's data, and this
    test pins the outcome rather than the mechanism.
    """
    full = gzip.decompress((fixture_dir / "lite.tar.gz").read_bytes())
    cut = gzip.decompress((fixture_dir / "negative/corrupt-truncated.tar.gz").read_bytes())
    assert len(cut) < len(full)

    # The cut must not be a whole number of tar blocks, which is exactly what a
    # boundary cut would produce and what a decoder would accept.
    assert len(cut) % 512 != 0, (
        "the truncated fixture ends on a tar block boundary, so it is a valid "
        "archive rather than a truncated one"
    )

    # And every content member the fixture declares must be non-empty, or a
    # later dataset could reintroduce the same trap.
    with tarfile.open(fileobj=io.BytesIO(full)) as tar:
        content = [m for m in tar.getmembers() if m.name.startswith("tables/")]
    assert content, "the fixture carries no content members"
    for member in content:
        assert member.size > 0, (
            f"{member.name} is empty; an empty last member disarms the truncated fixture"
        )
