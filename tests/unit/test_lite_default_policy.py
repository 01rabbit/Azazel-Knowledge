"""The shipped default export policy, and the D5 canaries checked on a real artifact.

`tests/unit/test_lite_policy.py` covers `apply_export_policy` as a function,
against policy dictionaries built inside the test. That is the right shape for
the unit-level guarantees and the wrong shape for ADR-0015 **D5**, which asks
for something else entirely:

    seeded canaries *in the source database* that must be absent from *every
    default-profile artifact*

Both halves matter. The canaries here are written into a SQLite source database
with real DDL; the artifact is built by running `tools/bundle_build.py
build-lite` against it with `config/lite-export-policy.yaml`, the policy this
repository actually ships; and the assertions are made against the bytes of the
built file, decompressed, which covers the manifest, the signature and every
content member -- including any member a future change might add that nobody
here thought to enumerate.

D5 names five categories, not one:

    canary secret, credential, raw sensitive evidence, internal hostname,
    operator identifier or site identifier

Each has a test below, each is seeded through a *different* carrier, and each
carrier is stopped by a *different* mechanism, so a regression in one does not
hide behind another:

===========================  ============================  ======================================
category                     carrier in the source db      mechanism that must stop it
===========================  ============================  ======================================
canary secret                ``ioc.tags``                  field allowlist, dataset *is* exported
credential                   ``feed_state.cursor``         dataset allowlist (eligible, unnamed)
raw sensitive evidence       ``sigma_rule_corpus.raw_yaml``  dataset allowlist (eligible, unnamed)
     "        "              ``observation.raw``           local-tier filter (never eligible)
internal hostname            ``ioc.value``                 ``mode: alias`` on an exported field
operator / site identifier   ``attack_technique.description``  field allowlist, second dataset
===========================  ============================  ======================================

**On vacuous passes.** ``assert CANARY not in blob`` is true of an empty file,
of a build that skipped the dataset, and of a canary that was never seeded. So
every canary test asserts the canary really is in the source database first,
and `test_default_artifact_carries_the_data_it_should` pins what the artifact
must *contain*: both datasets present, exact row counts, the exact set of
exported keys per row, and the aliased hostname row present under the
pseudonym computed independently here from the alias key. A build that emitted
nothing fails that test loudly rather than passing five canary tests quietly.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from azazel_knowledge.bundle.lite_policy import (
    PROVENANCE_ROLES,
    alias_value,
    load_export_policy,
)
from azazel_knowledge.bundle.verify import LOCAL_TIER_TABLES, peek_manifest
from azazel_knowledge.db.repository import apply_migrations

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOLS_DIR = _REPO_ROOT / "tools"

#: The policy under test: the one this repository ships, not a test fixture.
DEFAULT_POLICY_PATH = _REPO_ROOT / "config" / "lite-export-policy.yaml"

# --- the five D5 canaries ---------------------------------------------------
#
# Plain ASCII on purpose: `json.dumps` would escape a quote or a backslash, and
# a canary that cannot appear verbatim in JSON could not be found even if it
# leaked, which would make every assertion below vacuous for a second reason.

CANARY_SECRET = "canary-secret-8c1f27b4-must-never-leave-this-node"
CANARY_CREDENTIAL = "canary-credential-b71f3a02-feed-api-token"
CANARY_EVIDENCE = "canary-evidence-POST-/admin/login-password=hunter2-9b4e"
CANARY_HOSTNAME = "nas01.canary-internal-4d2c.invalid"
CANARY_OPERATOR = "canary-operator-analyst-7d3e@ops.invalid"
CANARY_SITE = "canary-site-HQ-TOKYO-4a8f"

ALL_CANARIES = (
    CANARY_SECRET,
    CANARY_CREDENTIAL,
    CANARY_EVIDENCE,
    CANARY_HOSTNAME,
    CANARY_OPERATOR,
    CANARY_SITE,
)

ALIAS_KEY_HEX = "00112233445566778899aabbccddeeff"
ALIAS_SCOPE = "canary-mission"
AS_OF = "2026-09-19T00:00:00Z"
SIGNING_SEED_HEX = "11" * 32

#: Inside the 30-day freshness window of `AS_OF`, so these rows are genuinely
#: selected. A stale `last_seen` would drop them and every canary test would
#: pass on an empty dataset.
FRESH = "2026-09-18T00:00:00Z"

#: What the default policy must export, per dataset. Written out rather than
#: read back from the policy so that a field silently added to the policy shows
#: up here as a failure instead of being mirrored into the expectation.
EXPECTED_IOC_KEYS = {"value", "type", "last_seen", "agg_next_expiry", "agg_raw_confidence"}
EXPECTED_TECHNIQUE_KEYS = {"technique_id", "name", "tactics", "attack_version"}


def _local_tier_ddl(table: str, scratch: Path) -> str:
    """The real DDL for a local-tier table, taken from a migrated local.db.

    Copied rather than hand-written so this test cannot drift away from the
    schema whose exclusion it is checking.
    """
    donor = sqlite3.connect(scratch)
    try:
        apply_migrations(donor, "local")
        row = donor.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
    finally:
        donor.close()
    scratch.unlink()
    assert row is not None, f"{table!r} is not a table in a migrated local.db"
    return row[0]


def _write_source_db(path: Path, scratch: Path) -> None:
    """A source database carrying every D5 canary, in a realistic place for each."""
    conn = sqlite3.connect(path)
    try:
        apply_migrations(conn, "intel")

        # Exported rows. Aggregated columns are populated because an indicator
        # that has not been through aggregation carries no expiry and no
        # confidence and so cannot satisfy D4 -- the build would refuse it
        # rather than export it thinner (ADR-0015 D4).
        for kind, value, tags in (
            ("ip", "203.0.113.10", json.dumps([f"canary:{CANARY_SECRET}"])),
            ("ip", "203.0.113.11", json.dumps([f"operator:{CANARY_OPERATOR}", f"site:{CANARY_SITE}"])),
            # An internal hostname that reached the indicator table. The
            # allowlist keeps it, because `value` is what a Lite artifact is
            # for; `mode: alias` is what stops it appearing verbatim.
            ("domain", CANARY_HOSTNAME, json.dumps([f"evidence:{CANARY_EVIDENCE}"])),
        ):
            conn.execute(
                "INSERT INTO ioc (type, value, first_seen, last_seen, tags, agg_raw_confidence, "
                "agg_next_expiry, agg_computed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (kind, value, "2026-01-01T00:00:00Z", FRESH, tags, 72.5,
                 "2027-01-01T00:00:00Z", "2026-09-18T12:00:00Z"),
            )

        for technique_id, name, tactics in (
            ("T1046", "Network Service Discovery", json.dumps(["discovery"])),
            ("T1110", "Brute Force", json.dumps(["credential-access"])),
        ):
            conn.execute(
                "INSERT INTO attack_technique (technique_id, name, tactics, is_subtechnique, "
                "description, data_sources, platforms, attack_version) "
                "VALUES (?, ?, ?, 0, ?, '[]', '[]', 'v15.1')",
                (
                    technique_id,
                    name,
                    tactics,
                    # A locally annotated description: who looked at it and
                    # where. The second dataset's allowlist has to drop it.
                    f"Seen against {CANARY_HOSTNAME} by {CANARY_OPERATOR} at {CANARY_SITE}.",
                ),
            )

        # Eligible intel-tier tables the policy does not name. Nothing filters
        # them out; they are simply never included.
        conn.execute(
            "INSERT INTO feed_state (feed_id, cursor, last_run, checksum) VALUES (?, ?, ?, ?)",
            ("canary_feed", f"Authorization: Bearer {CANARY_CREDENTIAL}", FRESH, CANARY_SECRET),
        )
        conn.execute(
            "INSERT INTO kev (cve_id, catalog_version, date_added, short_description) "
            "VALUES ('CVE-2026-0001', '2026.09.18', ?, ?)",
            (FRESH, f"observed payload: {CANARY_EVIDENCE}"),
        )
        conn.execute(
            "INSERT INTO sigma_rule_corpus (rule_uid, title, raw_yaml, license, source_url, "
            "corpus_version) VALUES ('11111111-2222-3333-4444-555555555555', 'canary rule', ?, "
            "'DRL-1.1', 'https://example.invalid/rule', 'r2026-09')",
            # A locally written rule quoting the captured request that
            # motivated it: the most plausible way raw evidence reaches the
            # intel tier at all.
            (f"detection:\n  keywords:\n    - '{CANARY_EVIDENCE}'\n",),
        )

        # A local-tier table physically present in the source database. It is
        # never eligible for export, so the row below is not reached by any
        # policy -- but the artifact has to prove that, not assume it.
        conn.executescript(_local_tier_ddl("observation", scratch))
        conn.execute(
            "INSERT INTO observation (event_id, edge_id, kind, observed_at, entities, raw, "
            "created_at) VALUES ('evt-1', ?, 'http', ?, '[]', ?, ?)",
            (
                CANARY_SITE,
                FRESH,
                json.dumps({"request": CANARY_EVIDENCE, "host": CANARY_HOSTNAME}),
                FRESH,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _build(tmp_dir: Path, *, policy: Path, source_db: Path, out: Path) -> subprocess.CompletedProcess:
    sign_key = tmp_dir / "sign.hex"
    sign_key.write_text(SIGNING_SEED_HEX, encoding="utf-8")
    alias_key = tmp_dir / "alias.hex"
    alias_key.write_text(ALIAS_KEY_HEX, encoding="utf-8")
    return subprocess.run(
        [
            sys.executable, str(_TOOLS_DIR / "bundle_build.py"), "build-lite",
            "--source-db", str(source_db),
            "--out", str(out),
            "--version", "1",
            "--profile", "knowledge-lite-16g",
            "--export-policy", str(policy),
            "--alias-key-file", str(alias_key),
            "--alias-scope", ALIAS_SCOPE,
            "--as-of", AS_OF,
            "--intel-generation", "7",
            "--stats-generation", "3",
            "--attack-version", "v15.1",
            "--config-hash", "cfg-canary",
            "--security-epoch", "1",
            "--sign-key", str(sign_key),
        ],
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def canary_artifact(tmp_path_factory) -> dict:
    """A real artifact built from a canary-seeded database with the shipped policy."""
    tmp_dir = tmp_path_factory.mktemp("canary")
    source_db = tmp_dir / "intel.db"
    _write_source_db(source_db, tmp_dir / "_local_donor.db")
    out = tmp_dir / "lite.tar.gz"
    result = _build(tmp_dir, policy=DEFAULT_POLICY_PATH, source_db=source_db, out=out)
    assert result.returncode == 0, result.stderr
    raw = out.read_bytes()
    return {
        "path": out,
        "source_db": source_db,
        "raw": raw,
        # The tar stream, which is where readable text lives: the artifact is
        # gzip, so searching its compressed bytes for a canary would pass
        # whether or not the canary was in it.
        "plain": gzip.decompress(raw),
        "manifest": peek_manifest(out),
    }


def _source_rows_containing(source_db: Path, needle: str) -> list[tuple[str, str]]:
    """Every (table, column) in the source database whose text holds `needle`.

    Used to prove a canary was really seeded before asserting it is absent from
    the artifact. Without this an unseeded canary passes every test below.
    """
    conn = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True)
    try:
        tables = [
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        ]
        hits: list[tuple[str, str]] = []
        for table in sorted(tables):
            columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            for column in columns:
                found = conn.execute(
                    f"SELECT 1 FROM {table} WHERE CAST({column} AS TEXT) LIKE ? LIMIT 1",
                    (f"%{needle}%",),
                ).fetchone()
                if found:
                    hits.append((table, column))
        return hits
    finally:
        conn.close()


def _assert_absent(artifact: dict, needle: str) -> None:
    assert needle.encode("utf-8") not in artifact["plain"], (
        f"{needle!r} reached the artifact's content; this is a release blocker (ADR-0015 D5)"
    )
    assert needle.encode("utf-8") not in artifact["raw"]


def _member(artifact: dict, name: str) -> str:
    with tarfile.open(artifact["path"], "r:gz") as tar:
        return tar.extractfile(name).read().decode("utf-8")


# --- the shipped policy itself ---------------------------------------------


def test_the_repository_ships_a_default_export_policy():
    """There has to be a default at all, or D5's "every default-profile artifact" is empty."""
    assert DEFAULT_POLICY_PATH.is_file()
    policy = load_export_policy(DEFAULT_POLICY_PATH)
    assert policy.version == "lite-export-default-v1"
    assert set(policy.datasets) == {"ioc", "attack_technique"}


def test_default_policy_covers_every_provenance_role_exactly_once():
    """ADR-0015 D4, checked on the shipped file rather than on a test document."""
    policy = load_export_policy(DEFAULT_POLICY_PATH)
    for name, dataset in policy.datasets.items():
        row, per_dataset = set(dataset.provenance.row), set(dataset.provenance.dataset)
        assert not (row & per_dataset), f"{name}: role satisfied twice"
        assert row | per_dataset == set(PROVENANCE_ROLES), f"{name}: roles do not match D4"


def test_default_policy_names_no_local_tier_dataset():
    """Absolute Constraint 5, checked on the policy as written.

    `tools/bundle_build.py::_eligible_tables` refuses a local-tier table and a
    test pins that refusal, but a policy that named one would still be a policy
    shipped in the repository stating an intention to export research data. The
    file itself has to be clean.
    """
    policy = load_export_policy(DEFAULT_POLICY_PATH)
    assert not (set(policy.datasets) & LOCAL_TIER_TABLES)


def test_default_policy_aliases_the_indicator_value():
    """The one field in the default profile that may not travel verbatim."""
    policy = load_export_policy(DEFAULT_POLICY_PATH)
    assert policy.datasets["ioc"].rule("value").mode == "alias"
    # Everything else is exported as-is, and a mode nobody reviewed is not.
    for dataset in policy.datasets.values():
        for rule in dataset.fields:
            assert rule.mode in ("allow", "alias")


# --- what the artifact must contain (this is what rules out a vacuous pass) --


def test_default_artifact_carries_the_data_it_should(canary_artifact):
    """The positive half of D5, without which every canary assertion is free.

    An empty artifact, a build that dropped a dataset, or a selection that
    filtered every row would satisfy "the canary is absent" perfectly. So this
    pins the artifact's content: both datasets, exact row counts, and the exact
    key set of every exported row.
    """
    manifest = canary_artifact["manifest"]
    assert manifest["tables"] == ["attack_technique", "ioc"]
    assert manifest["profile"]["counts"]["rows"] == 5
    assert manifest["profile"]["counts"]["datasets"] == 2

    ioc_rows = [json.loads(line) for line in _member(canary_artifact, "tables/ioc.jsonl").splitlines()]
    assert len(ioc_rows) == 3
    for row in ioc_rows:
        assert set(row) == EXPECTED_IOC_KEYS

    technique_rows = [
        json.loads(line)
        for line in _member(canary_artifact, "tables/attack_technique.jsonl").splitlines()
    ]
    assert len(technique_rows) == 2
    for row in technique_rows:
        assert set(row) == EXPECTED_TECHNIQUE_KEYS
    assert {row["technique_id"] for row in technique_rows} == {"T1046", "T1110"}
    assert b"Brute Force" in canary_artifact["plain"], "the artifact must carry readable content"


def test_default_artifact_omits_every_eligible_dataset_the_policy_does_not_name(canary_artifact):
    """Deny by default at dataset level, proved on a database that holds those rows.

    `feed_state`, `kev` and `sigma_rule_corpus` are intel-tier, eligible, and
    populated in the source database. They are absent because they were never
    included, not because anything excluded them.
    """
    source_db = canary_artifact["source_db"]
    conn = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True)
    try:
        for table in ("feed_state", "kev", "sigma_rule_corpus"):
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            assert count > 0, f"{table} is empty, so its exclusion proves nothing"
    finally:
        conn.close()

    manifest = canary_artifact["manifest"]
    for table in ("feed_state", "kev", "sigma_rule_corpus", "ioc_source", "ioc_cidr"):
        assert table not in manifest["tables"]
        assert f"tables/{table}.jsonl" not in manifest["files"]


# --- D5's five categories, one test each ------------------------------------


def test_canary_secret_is_absent_from_the_default_artifact(canary_artifact):
    """Category 1. Carrier: `ioc.tags`, a column of a dataset that *is* exported.

    The strongest form of the deny-by-default claim: the row ships, and the
    unlisted column on it does not. A column added by a later migration behaves
    the same way, which is the property that makes schema growth safe.
    """
    assert ("ioc", "tags") in _source_rows_containing(canary_artifact["source_db"], CANARY_SECRET)
    _assert_absent(canary_artifact, CANARY_SECRET)


def test_credential_is_absent_from_the_default_artifact(canary_artifact):
    """Category 2. Carrier: `feed_state.cursor`.

    A cursor for an authenticated feed genuinely carries a bearer token, and
    `feed_state` is an eligible intel-tier table -- so this is stopped by the
    dataset allowlist, not by anything about the column.
    """
    assert ("feed_state", "cursor") in _source_rows_containing(
        canary_artifact["source_db"], CANARY_CREDENTIAL
    )
    _assert_absent(canary_artifact, CANARY_CREDENTIAL)


def test_raw_sensitive_evidence_is_absent_from_the_default_artifact(canary_artifact):
    """Category 3. Two carriers, two different mechanisms.

    `sigma_rule_corpus.raw_yaml` is eligible and unnamed -- a locally written
    rule quoting the captured request that motivated it. `observation.raw` is
    local-tier and never eligible at all. Both hold the same evidence string,
    so this goes red if either guard fails.
    """
    hits = _source_rows_containing(canary_artifact["source_db"], CANARY_EVIDENCE)
    assert ("sigma_rule_corpus", "raw_yaml") in hits
    assert ("observation", "raw") in hits
    assert "observation" in LOCAL_TIER_TABLES, "read the constant: this carrier must be local-tier"
    _assert_absent(canary_artifact, CANARY_EVIDENCE)


def test_internal_hostname_is_absent_from_the_default_artifact(canary_artifact):
    """Category 4. Carrier: `ioc.value`, which the policy *does* export.

    Dropping the row would also satisfy "the hostname is absent", and would be
    a different, worse artifact -- so this asserts the row is present under the
    pseudonym the alias key produces, computed here independently of the
    builder, and only then that the plaintext is gone.
    """
    assert ("ioc", "value") in _source_rows_containing(canary_artifact["source_db"], CANARY_HOSTNAME)

    expected_alias = alias_value(
        CANARY_HOSTNAME,
        alias_key=bytes.fromhex(ALIAS_KEY_HEX),
        scope=ALIAS_SCOPE,
        dataset="ioc",
        field="value",
    )
    ioc_rows = [json.loads(line) for line in _member(canary_artifact, "tables/ioc.jsonl").splitlines()]
    aliases = {row["value"] for row in ioc_rows}
    assert expected_alias in aliases, "the aliased row must be exported, not dropped"
    assert [row["type"] for row in ioc_rows if row["value"] == expected_alias] == ["domain"]

    _assert_absent(canary_artifact, CANARY_HOSTNAME)


def test_operator_and_site_identifiers_are_absent_from_the_default_artifact(canary_artifact):
    """Category 5. Carriers in both exported datasets.

    Seeded in `ioc.tags` and in `attack_technique.description` so the field
    allowlist is proved on each exported dataset separately: a policy that grew
    a field on the second dataset only would still be caught.
    """
    for canary in (CANARY_OPERATOR, CANARY_SITE):
        hits = _source_rows_containing(canary_artifact["source_db"], canary)
        assert ("ioc", "tags") in hits
        assert ("attack_technique", "description") in hits
        _assert_absent(canary_artifact, canary)


def test_no_seeded_canary_survives_into_the_default_artifact(canary_artifact):
    """The whole D5 list in one assertion, so a canary added later is covered.

    Deliberately redundant with the five tests above: those name the category
    and the mechanism, this one closes the loop over the constant so nobody can
    add a canary to `ALL_CANARIES` and forget to assert it.
    """
    leaked = [c for c in ALL_CANARIES if c.encode("utf-8") in canary_artifact["plain"]]
    assert leaked == [], f"canaries reached the artifact: {leaked}"
