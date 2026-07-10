from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from azazel_knowledge.attack.attack_stix import flatten
from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.feeds.adapters.attack import AttackAdapter

from _feeds_support import make_intel_writer

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "feeds"
NOW = datetime(2026, 7, 6, 0, 0, 0, tzinfo=timezone.utc)


def _bundle() -> dict:
    return json.loads((FIXTURES / "attack_bundle.json").read_text())


def test_flatten_techniques_and_subtechniques():
    flat = flatten(_bundle())
    assert flat.attack_version == "15.1"

    by_id = {t.technique_id: t for t in flat.techniques}
    assert set(by_id) == {"T1110", "T1110.001"}

    parent = by_id["T1110"]
    assert parent.name == "Brute Force"
    assert parent.tactics == ["credential-access"]
    assert not parent.is_subtechnique
    assert parent.parent_technique_id is None
    assert parent.platforms == ["Linux", "Windows"]

    sub = by_id["T1110.001"]
    assert sub.is_subtechnique
    assert sub.parent_technique_id == "T1110"
    assert sub.tactics == ["credential-access"]


def test_flatten_excludes_revoked_objects():
    flat = flatten(_bundle())
    assert all(t.technique_id != "T9999" for t in flat.techniques)


def test_flatten_mitigations_and_relations_use_external_ids():
    flat = flatten(_bundle())
    assert [m.mitigation_id for m in flat.mitigations] == ["M1036"]
    assert flat.mitigations[0].name == "Account Use Policies"

    relations = {(r.source_id, r.relation_type, r.target_id) for r in flat.relations}
    assert ("M1036", "mitigates", "T1110") in relations
    assert ("T1110.001", "subtechnique-of", "T1110") in relations
    types = {(r.source_type, r.target_type) for r in flat.relations}
    assert ("course-of-action", "attack-pattern") in types


def test_flatten_version_override_wins():
    flat = flatten(_bundle(), version_override="99.0")
    assert flat.attack_version == "99.0"


def test_flatten_rejects_non_bundle():
    with pytest.raises(ValueError):
        flatten({"type": "attack-pattern"})


def _make_adapter(tmp_path, config: dict | None = None) -> AttackAdapter:
    return AttackAdapter(
        "attack",
        config or {"kind": "attack_stix", "group": "mitre"},
        make_intel_writer(tmp_path),
        clock=FixedClock(NOW),
        fetch_bytes=(FIXTURES / "attack_bundle.json").read_bytes,
    )


def _read_tables(adapter: AttackAdapter) -> dict[str, list[tuple]]:
    def query(conn: Any):
        return {
            "technique": conn.execute(
                "SELECT technique_id, name, tactics, is_subtechnique, parent_technique_id, "
                "attack_version FROM attack_technique ORDER BY technique_id"
            ).fetchall(),
            "mitigation": conn.execute(
                "SELECT mitigation_id, name, attack_version FROM attack_mitigation"
            ).fetchall(),
            "relation": conn.execute(
                "SELECT source_id, relation_type, target_id, attack_version FROM attack_relation "
                "ORDER BY relation_type"
            ).fetchall(),
        }

    return adapter._exec_intel(query)


def test_attack_adapter_flattens_into_tables_with_version_pin(tmp_path):
    adapter = _make_adapter(tmp_path)
    outcome = adapter.run()
    assert outcome.status == "applied"

    tables = _read_tables(adapter)
    technique_ids = [row[0] for row in tables["technique"]]
    assert technique_ids == ["T1110", "T1110.001"]
    assert all(row[5] == "15.1" for row in tables["technique"])

    t1110 = tables["technique"][0]
    assert json.loads(t1110[2]) == ["credential-access"]
    assert t1110[3] == 0

    sub = tables["technique"][1]
    assert sub[3] == 1
    assert sub[4] == "T1110"

    assert [row[0] for row in tables["mitigation"]] == ["M1036"]
    relation_triples = {(r[0], r[1], r[2]) for r in tables["relation"]}
    assert ("M1036", "mitigates", "T1110") in relation_triples


def test_attack_adapter_full_replace_in_one_transaction(tmp_path):
    adapter = _make_adapter(tmp_path)
    adapter.run()

    adapter.config["attack_version"] = "16.0"
    outcome = adapter.run()
    assert outcome.status == "applied"

    tables = _read_tables(adapter)
    assert len(tables["technique"]) == 2
    assert all(row[5] == "16.0" for row in tables["technique"])
    assert all(row[2] == "16.0" for row in tables["mitigation"])
    assert all(row[3] == "16.0" for row in tables["relation"])


def test_attack_adapter_never_touches_ioc_tables(tmp_path):
    adapter = _make_adapter(tmp_path)
    adapter.run()

    def query(conn: Any):
        return (
            conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM ioc_source").fetchone()[0],
        )

    assert adapter._exec_intel(query) == (0, 0)
