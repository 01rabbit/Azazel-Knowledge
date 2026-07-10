from __future__ import annotations

import pytest

from azazel_knowledge.patterns.index import PatternIndex
from azazel_knowledge.patterns.matchspec import (
    MAX_DEPTH,
    Pattern,
    SkipSpec,
    evaluate_patterns,
    evaluate_spec,
)

EVENT = {
    "alert": {"category": "scan", "proto": "ssh", "severity": 3},
    "src_ip": "192.0.2.7",
    "dns": {"query": "evil.example.com", "query_entropy": 4.2},
    "file": {"name": "c:/dump/lsass.dmp"},
}


def _spec(body: dict) -> dict:
    return {"v": 1, **body}


def test_eq_in_prefix_suffix_ops():
    assert evaluate_spec(
        _spec({"op": "eq", "field": "alert.category", "value": "scan"}), EVENT
    )
    assert not evaluate_spec(
        _spec({"op": "eq", "field": "alert.category", "value": "c2"}), EVENT
    )
    assert evaluate_spec(
        _spec({"op": "in", "field": "alert.proto", "value": ["ssh", "telnet"]}),
        EVENT,
    )
    assert evaluate_spec(
        _spec({"op": "prefix", "field": "dns.query", "value": "evil."}), EVENT
    )
    assert evaluate_spec(
        _spec({"op": "suffix", "field": "file.name", "value": "lsass.dmp"}), EVENT
    )


def test_cidr_gte_lte_exists_ops():
    assert evaluate_spec(
        _spec({"op": "cidr", "field": "src_ip", "value": "192.0.2.0/24"}), EVENT
    )
    assert not evaluate_spec(
        _spec({"op": "cidr", "field": "src_ip", "value": "10.0.0.0/8"}), EVENT
    )
    assert evaluate_spec(
        _spec({"op": "gte", "field": "dns.query_entropy", "value": 3.5}), EVENT
    )
    assert evaluate_spec(
        _spec({"op": "lte", "field": "alert.severity", "value": 3}), EVENT
    )
    assert evaluate_spec(_spec({"op": "exists", "field": "dns.query"}), EVENT)
    assert not evaluate_spec(_spec({"op": "exists", "field": "flow.bytes"}), EVENT)


def test_missing_field_is_false_not_error():
    assert not evaluate_spec(
        _spec({"op": "eq", "field": "nope.nothing", "value": 1}), EVENT
    )
    assert not evaluate_spec(
        _spec({"op": "gte", "field": "nope.nothing", "value": 1}), EVENT
    )


def test_combinators_all_any_not():
    assert evaluate_spec(
        _spec(
            {
                "all": [
                    {"op": "eq", "field": "alert.category", "value": "scan"},
                    {"op": "eq", "field": "alert.proto", "value": "ssh"},
                ]
            }
        ),
        EVENT,
    )
    assert evaluate_spec(
        _spec(
            {
                "any": [
                    {"op": "eq", "field": "alert.category", "value": "nope"},
                    {"op": "eq", "field": "alert.proto", "value": "ssh"},
                ]
            }
        ),
        EVENT,
    )
    assert evaluate_spec(
        _spec({"not": [{"op": "eq", "field": "alert.category", "value": "c2"}]}),
        EVENT,
    )


def test_nesting_depth_4_allowed_5_rejected():
    leaf = {"op": "eq", "field": "alert.category", "value": "scan"}
    spec4 = leaf
    for _ in range(MAX_DEPTH):
        spec4 = {"all": [spec4]}
    assert evaluate_spec(_spec(spec4), EVENT) is True

    spec5 = {"all": [spec4]}
    with pytest.raises(SkipSpec, match="depth"):
        evaluate_spec(_spec(spec5), EVENT)


def test_unknown_op_raises_skip_spec():
    with pytest.raises(SkipSpec, match="unsupported op"):
        evaluate_spec(
            _spec({"op": "regex", "field": "dns.query", "value": ".*"}), EVENT
        )


def test_unknown_version_raises_skip_spec():
    with pytest.raises(SkipSpec, match="version"):
        evaluate_spec(
            {"v": 2, "op": "eq", "field": "alert.category", "value": "scan"}, EVENT
        )


def test_evaluate_patterns_skips_bad_specs_without_failing(caplog):
    patterns = [
        Pattern("good", 0, _spec({"op": "eq", "field": "alert.category", "value": "scan"})),
        Pattern("bad-op", 0, _spec({"op": "regex", "field": "x", "value": ".*"})),
        Pattern("bad-version", 0, {"v": 9, "op": "eq", "field": "x", "value": 1}),
    ]
    with caplog.at_level("WARNING"):
        result = evaluate_patterns(patterns, EVENT, max_eval_ms=1000.0)
    assert result.matched == ("good",)
    assert result.scanned == 3
    assert result.total == 3
    assert result.truncated is False
    assert any("bad-op" in r.message for r in caplog.records)
    assert any("bad-version" in r.message for r in caplog.records)


def test_unindexed_cap_50_with_truncation_ordering():
    spec = _spec({"op": "eq", "field": "alert.category", "value": "scan"})
    patterns = [Pattern(f"p{i:03d}", priority=i % 7, spec=spec) for i in range(60)]
    result = evaluate_patterns(patterns, EVENT, max_eval_ms=10_000.0)
    assert result.truncated is True
    assert result.scanned == 50
    assert result.total == 60
    expected_order = [
        p.pattern_id
        for p in sorted(patterns, key=lambda p: (-p.priority, p.pattern_id))
    ][:50]
    assert list(result.matched) == expected_order


def test_indexed_cap_200():
    spec = _spec({"op": "eq", "field": "alert.category", "value": "scan"})
    patterns = [Pattern(f"p{i:03d}", 0, spec) for i in range(220)]
    candidate_ids = {p.pattern_id for p in patterns}
    result = evaluate_patterns(
        patterns, EVENT, candidate_ids=candidate_ids, max_eval_ms=10_000.0
    )
    assert result.truncated is True
    assert result.scanned == 200


def test_time_ceiling_truncates(monkeypatch):
    import azazel_knowledge.patterns.matchspec as ms

    ticks = iter([0.0] + [i * 1.0 for i in range(1, 300)])
    monkeypatch.setattr(ms.time, "monotonic", lambda: next(ticks))
    spec = _spec({"op": "eq", "field": "alert.category", "value": "scan"})
    patterns = [Pattern(f"p{i}", 0, spec) for i in range(10)]
    result = ms.evaluate_patterns(patterns, EVENT, max_eval_ms=5.0)
    assert result.truncated is True
    assert result.scanned < 10


def test_priority_desc_then_pattern_id_asc_on_ties():
    spec = _spec({"op": "eq", "field": "alert.category", "value": "scan"})
    patterns = [
        Pattern("zzz", 5, spec),
        Pattern("aaa", 5, spec),
        Pattern("mmm", 9, spec),
    ]
    result = evaluate_patterns(patterns, EVENT, max_eval_ms=1000.0)
    assert list(result.matched) == ["mmm", "aaa", "zzz"]


def test_index_candidates_by_literal_eq():
    p_scan = Pattern(
        "scan", 0, _spec({"op": "eq", "field": "alert.category", "value": "scan"})
    )
    p_c2 = Pattern(
        "c2", 0, _spec({"op": "eq", "field": "alert.category", "value": "c2-beacon"})
    )
    p_noeq = Pattern("noeq", 0, _spec({"op": "exists", "field": "dns.query"}))
    index = PatternIndex.build([p_scan, p_c2, p_noeq])

    candidates = index.candidates(EVENT)
    assert "scan" in candidates
    assert "c2" not in candidates
    assert "noeq" in candidates  # unindexable patterns always scanned


def test_index_nested_eq_predicates_are_indexed():
    pattern = Pattern(
        "nested",
        0,
        _spec(
            {
                "all": [
                    {"op": "eq", "field": "alert.category", "value": "scan"},
                    {"op": "gte", "field": "alert.severity", "value": 1},
                ]
            }
        ),
    )
    index = PatternIndex.build([pattern])
    assert "nested" in index.candidates(EVENT)
    assert "nested" not in index.candidates({"alert": {"category": "c2"}})
