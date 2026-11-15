"""Official ATT&CK corpus conformance for attack-technique/v1 (work unit 51).

Two kinds of test, kept apart on purpose:

* Fixture tests (always run). ``tests/fixtures/attack-enterprise-20.1-extract.json`` is
  the output of ``attack_stix.flatten`` over the official Enterprise ATT&CK 20.1
  bundle (all 706 non-revoked, non-deprecated techniques, names and tactics verbatim).
  Every name and tactic goes through the product grammar, and the whole corpus is
  served through signed bundle -> import_full -> the real route.
* Official-file tests (``AZAZEL_ATTACK_CORPUS=<enterprise-attack-20.1.json>``). The
  file is checked against a pinned sha256 first; a different file FAILS (it is not
  skipped). Without the variable these tests are skipped with an explicit reason.
  The raw bundle is converted by the real AttackAdapter and compared one to one.

Freshness is never forged: the clock sits just after the acquisition time of the
corpus and ``last_success`` is that acquisition time.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytest.importorskip("azazel_fabric.knowledge_context")

from azazel_knowledge.api import attack_technique_context as atc
from azazel_knowledge.attack.attack_stix import flatten
from azazel_knowledge.core.clock import FixedClock, parse_rfc3339
from azazel_knowledge.db.repository import apply_migrations
from azazel_knowledge.db.writer import PrioritySingleWriterQueue
from azazel_knowledge.feeds.adapters.attack import AttackAdapter
from test_knowledge_attack_technique import (
    T, _nexus_validator, _request, _semantic, _serve, _unavailable,
)

HERE = Path(__file__).resolve().parent
EXTRACT = json.loads((HERE.parent / "fixtures" / "attack-enterprise-20.1-extract.json").read_text("utf-8"))
SOURCE_SHA256 = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"
ACQUIRED = "2026-11-15T14:38:00Z"          # when the corpus file was fetched
AS_OF = datetime(2026, 11, 15, 15, 0, 0, tzinfo=timezone.utc)
TECHNIQUES = EXTRACT["techniques"]
IDS = [t["id"] for t in TECHNIQUES]


def _rows(techniques=TECHNIQUES):
    return [f"{t['id']}|{t['name']}|{','.join(t['tactics'])}" for t in techniques]


def _query_all(client, signer):
    """Ask for every technique (sorted, 8 per request); return {id: {predicate: value}}."""
    out = {}
    for i in range(0, len(IDS), 8):
        _, semantic = _semantic(client, signer, _request(*IDS[i:i + 8]))
        for fact in semantic["facts"]:
            out.setdefault(fact["subject"]["value"], {})[fact["predicate"]] = fact["value"]
    return out


def _tool_bundle(raw: bytes, key_path: Path, out: Path, last_success: str) -> Path:
    """The official path: AttackAdapter over the real STIX bytes, then tools/bundle_build.py."""
    tools = Path(__file__).resolve().parents[2] / "tools"
    with tempfile.TemporaryDirectory(prefix="azn-u51-") as scratch:
        db = Path(scratch) / "source_intel.db"
        conn = sqlite3.connect(db)
        apply_migrations(conn, "intel")
        conn.commit()
        conn.close()
        writer = PrioritySingleWriterQueue(db, db.with_suffix(".lock"))
        writer.open()
        try:
            outcome = AttackAdapter(
                "attack", {"kind": "attack_stix", "group": "mitre"}, writer,
                clock=FixedClock(parse_rfc3339(last_success)), fetch_bytes=lambda: raw).run()
            assert outcome.status == "applied", outcome
        finally:
            writer.close()
        result = subprocess.run(
            [sys.executable, str(tools / "bundle_build.py"), "build", "--source-db", str(db), "--out", str(out),
             "--version", "1", "--attack-version", "20.1", "--feeds", "attack", "--sign-key", str(key_path)],
            capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    return out


# ---- fixture tests (always run) -------------------------------------------------


def test_extract_is_what_it_says():
    assert EXTRACT["attack_version"] == "20.1" and EXTRACT["source_sha256"] == SOURCE_SHA256
    assert len(TECHNIQUES) == 706 == len(set(IDS)) and IDS == sorted(IDS)
    assert all(atc.TECHNIQUE_ID_RE.match(i) for i in IDS)
    assert sum(1 for t in TECHNIQUES if t["parent"]) == 479 and all(
        (t["parent"] is not None) == ("." in t["id"]) for t in TECHNIQUES)


def test_every_official_name_and_tactics_set_passes_the_grammar():
    refused = [(t["id"], t["name"]) for t in TECHNIQUES if not atc.valid_name(t["name"])]
    assert refused == []
    bad = [(t["id"], t["tactics"]) for t in TECHNIQUES if atc.parse_tactics(json.dumps(t["tactics"])) is None]
    assert bad == []
    assert {x for t in TECHNIQUES for x in t["tactics"]} <= atc.TACTICS


def test_official_names_agree_with_the_nexus_validator():
    nexus = _nexus_validator()
    if nexus is None:
        pytest.skip("AZAZEL_NEXUS_SRC not set")
    for t in TECHNIQUES:
        assert nexus.name_grammar_ok(t["name"]) and atc.valid_name(t["name"]), t
        assert all(x in nexus.TACTICS for x in t["tactics"]), t
    assert set(nexus.TACTICS) == atc.TACTICS


def test_whole_official_corpus_is_found_through_the_signed_bundle_route(tmp_path):
    client, signer, _ = _serve(tmp_path, rows=_rows(), attack_version="20.1", last_success=ACQUIRED, as_of=AS_OF)
    got = _query_all(client, signer)
    assert set(got) == set(IDS)
    for t in TECHNIQUES:
        g = got[t["id"]]
        assert g == {"coverage": "found", "technique_name": t["name"],
                     "tactics": ",".join(sorted(t["tactics"])), "attack_version": "20.1"}, t["id"]


def test_stealth_and_defense_impairment_are_served_not_fail_closed(tmp_path):
    # Regression: 208 techniques use these v19+ tactics; with the old 14 name list the
    # whole corpus (not just those rows) answered `unavailable`.
    client, signer, _ = _serve(
        tmp_path, rows=["T1027|Obfuscated Files or Information|stealth", "T1553|Subvert Trust Controls|defense-impairment",
                        "T1110|Brute Force|credential-access"],
        attack_version="20.1", last_success=ACQUIRED, as_of=AS_OF)
    _, semantic = _semantic(client, signer, _request("T1027", "T1110", "T1553"))
    assert [f["value"] for f in semantic["facts"] if f["predicate"] == "coverage"] == ["found"] * 3
    assert [f["value"] for f in semantic["facts"] if f["predicate"] == "tactics"] == [
        "stealth", "credential-access", "defense-impairment"]


def test_unknown_tactic_still_makes_the_whole_corpus_unavailable(tmp_path):
    _unavailable(tmp_path, rows=["T1110|Brute Force|credential-access", "T1111|Other|not-a-tactic"])


def test_stale_synthetic_corpus_is_stale_without_touching_official_freshness(tmp_path):
    # Synthetic controls only: a clock 15 days after last_success (limit 14 days).
    late = datetime(2026, 11, 30, 15, 0, 0, tzinfo=timezone.utc)
    client, signer, _ = _serve(tmp_path, rows=_rows(TECHNIQUES[:8]), attack_version="20.1",
                               last_success=ACQUIRED, as_of=late)
    _, semantic = _semantic(client, signer, _request(*IDS[:8]))
    assert {f["value"] for f in semantic["facts"]} == {"stale"}


# ---- official-file tests (AZAZEL_ATTACK_CORPUS) -----------------------------------


@pytest.fixture(scope="module")
def official():
    path = os.environ.get("AZAZEL_ATTACK_CORPUS")
    if not path:
        pytest.skip("AZAZEL_ATTACK_CORPUS not set: official-file conformance not run (fixture tests above still run)")
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == SOURCE_SHA256, f"AZAZEL_ATTACK_CORPUS is not the pinned Enterprise ATT&CK 20.1 file: {digest}"
    return raw, json.loads(raw)


def _ext(obj):
    refs = [r for r in obj.get("external_references", [])
            if r.get("source_name") == "mitre-attack" and r.get("external_id")]
    return refs[0]["external_id"] if len(refs) == 1 else None


def test_official_counts_and_exclusion_rules(official):
    _, bundle = official
    patterns = [o for o in bundle["objects"] if o.get("type") == "attack-pattern"]
    assert len(patterns) == 867
    assert sum(1 for o in patterns if o.get("revoked")) == 149
    assert sum(1 for o in patterns if o.get("x_mitre_deprecated")) == 12
    assert sum(1 for o in patterns if o.get("x_mitre_is_subtechnique")) == 497
    active = [o for o in patterns if not (o.get("revoked") or o.get("x_mitre_deprecated"))]
    assert len(active) == 706 and sum(1 for o in active if o.get("x_mitre_is_subtechnique")) == 479
    assert all(_ext(o) for o in active)
    assert len({_ext(o) for o in active}) == 706
    assert {p["kill_chain_name"] for o in active for p in o["kill_chain_phases"]} == {"mitre-attack"}


def test_official_flatten_is_one_to_one_and_matches_the_extract(official):
    raw, bundle = official
    flat = flatten(bundle)
    assert flat.attack_version == "20.1" and len(flat.techniques) == 706
    by_id = {t.technique_id: t for t in flat.techniques}
    active = [o for o in bundle["objects"] if o.get("type") == "attack-pattern"
              and not (o.get("revoked") or o.get("x_mitre_deprecated"))]
    assert set(by_id) == {_ext(o) for o in active}
    for o in active:
        t = by_id[_ext(o)]
        assert t.name == o["name"] and t.description == o.get("description")
        assert t.tactics == sorted({p["phase_name"] for p in o["kill_chain_phases"]})
        assert t.is_subtechnique is bool(o["x_mitre_is_subtechnique"]) is ("." in t.technique_id)
        assert t.parent_technique_id == (t.technique_id.split(".")[0] if t.is_subtechnique else None)
    assert [{"id": t.technique_id, "name": t.name, "tactics": t.tactics, "parent": t.parent_technique_id}
            for t in sorted(flat.techniques, key=lambda t: t.technique_id)] == TECHNIQUES


def test_official_corpus_through_the_adapter_bundle_and_route(official, tmp_path):
    raw, bundle = official

    def build(key_path):
        return _tool_bundle(raw, key_path, tmp_path / "official.tar.gz", ACQUIRED)

    client, signer, settings = _serve(tmp_path, as_of=AS_OF, bundle_path=build)
    got = _query_all(client, signer)
    assert set(got) == set(IDS)
    assert {g["coverage"] for g in got.values()} == {"found"}
    assert {(g["technique_name"], g["tactics"]) for g in got.values()} == {
        (t["name"], ",".join(sorted(t["tactics"]))) for t in TECHNIQUES}
    assert {g["attack_version"] for g in got.values()} == {"20.1"}
    # an ID absent from the official corpus (revoked since) is no_match, not unavailable
    revoked = next(_ext(o) for o in bundle["objects"] if o.get("type") == "attack-pattern" and o.get("revoked")
                   and _ext(o) not in set(IDS))
    _, semantic = _semantic(client, signer, _request(revoked))
    assert [f["value"] for f in semantic["facts"]] == ["no_match"], revoked
