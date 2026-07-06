"""Candidate-selection index for match_spec patterns (design S5).

Built synchronously at load: literal `eq` predicates anywhere in a spec
become `field=value` keys. `candidates(event)` returns the pattern ids
whose indexed `eq` keys match the event, unioned with patterns that have
no indexable `eq` predicate (which must always be scanned).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from azazel_cti.patterns.matchspec import COMBINATORS, Pattern, _get_field


def _collect_eq(node: Any, out: list[tuple[str, Any]]) -> None:
    if not isinstance(node, Mapping):
        return
    combinator = next((c for c in COMBINATORS if c in node), None)
    if combinator is not None:
        children = node[combinator]
        if isinstance(children, (list, tuple)):
            for child in children:
                _collect_eq(child, out)
        elif isinstance(children, Mapping):
            _collect_eq(children, out)
        return
    if node.get("op") == "eq" and isinstance(node.get("field"), str):
        value = node.get("value")
        if isinstance(value, (str, int, float, bool)):
            out.append((node["field"], value))


def _spec_eq_keys(spec: Mapping[str, Any]) -> list[tuple[str, Any]]:
    body = {k: v for k, v in spec.items() if k != "v"}
    out: list[tuple[str, Any]] = []
    _collect_eq(body, out)
    return out


def _key(field: str, value: Any) -> str:
    return f"{field}={value!r}"


class PatternIndex:
    def __init__(self) -> None:
        self._by_key: dict[str, set[str]] = {}
        self._unindexable: set[str] = set()

    def add(self, pattern: Pattern) -> None:
        eq_keys = _spec_eq_keys(pattern.spec)
        if not eq_keys:
            self._unindexable.add(pattern.pattern_id)
            return
        for field, value in eq_keys:
            self._by_key.setdefault(_key(field, value), set()).add(pattern.pattern_id)

    @classmethod
    def build(cls, patterns: Iterable[Pattern]) -> "PatternIndex":
        index = cls()
        for pattern in patterns:
            index.add(pattern)
        return index

    def candidates(self, event: Mapping[str, Any]) -> set[str]:
        result = set(self._unindexable)
        for key, ids in self._by_key.items():
            field, _, literal = key.partition("=")
            actual = _get_field(event, field)
            if actual is not None and _key(field, actual) == key:
                result |= ids
        return result
