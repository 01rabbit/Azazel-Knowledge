"""match_spec evaluation (design S5).

JSON specs with `"v": 1`, combinators `all|any|not` (depth <= 4), and
leaf ops `eq,in,prefix,suffix,cidr,gte,lte,exists`. No regex. Unknown
op/version raises `SkipSpec` which the pattern-set evaluator turns into a
logged skip. Evaluation is bounded (`max_patterns_scanned`,
`max_patterns_scanned_unindexed`, `max_eval_ms`) with truncation ordered
`(priority DESC, pattern_id ASC)` and disclosed via `MatchResult`.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any, Mapping, Sequence

_LOG = logging.getLogger(__name__)

SUPPORTED_OPS = frozenset(
    {"eq", "in", "prefix", "suffix", "cidr", "gte", "lte", "exists"}
)
COMBINATORS = frozenset({"all", "any", "not"})
SPEC_VERSION = 1
MAX_DEPTH = 4

DEFAULT_MAX_PATTERNS_SCANNED = 200
DEFAULT_MAX_PATTERNS_SCANNED_UNINDEXED = 50
DEFAULT_MAX_EVAL_MS = 5.0

_MISSING = object()


class SkipSpec(Exception):
    pass


@dataclass(frozen=True)
class Pattern:
    pattern_id: str
    priority: int
    spec: Mapping[str, Any]
    payload: Any = None


@dataclass(frozen=True)
class MatchResult:
    matched: tuple[str, ...]
    payloads: tuple[Any, ...]
    scanned: int
    total: int
    truncated: bool


def _get_field(event: Mapping[str, Any], dotted: str) -> Any:
    current: Any = event
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _eval_leaf(node: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    op = node.get("op")
    if op not in SUPPORTED_OPS:
        raise SkipSpec(f"unsupported op: {op!r}")
    field_name = node.get("field")
    if not isinstance(field_name, str):
        raise SkipSpec("leaf missing field")
    actual = _get_field(event, field_name)
    if op == "exists":
        return actual is not _MISSING
    if actual is _MISSING:
        return False
    value = node.get("value")
    if op == "eq":
        return actual == value
    if op == "in":
        return isinstance(value, (list, tuple)) and actual in value
    if op == "prefix":
        return isinstance(actual, str) and isinstance(value, str) and actual.startswith(value)
    if op == "suffix":
        return isinstance(actual, str) and isinstance(value, str) and actual.endswith(value)
    if op == "cidr":
        try:
            return ip_address(str(actual)) in ip_network(str(value), strict=False)
        except ValueError:
            return False
    if op == "gte":
        try:
            return float(actual) >= float(value)
        except (TypeError, ValueError):
            return False
    if op == "lte":
        try:
            return float(actual) <= float(value)
        except (TypeError, ValueError):
            return False
    raise SkipSpec(f"unhandled op: {op!r}")


def _eval_node(node: Any, event: Mapping[str, Any], depth: int) -> bool:
    if not isinstance(node, Mapping):
        raise SkipSpec("node is not a mapping")
    combinator = next((c for c in COMBINATORS if c in node), None)
    if combinator is None:
        return _eval_leaf(node, event)
    if depth + 1 > MAX_DEPTH:
        raise SkipSpec("combinator depth exceeds MAX_DEPTH")
    children = node[combinator]
    if combinator == "not":
        child = children[0] if isinstance(children, (list, tuple)) else children
        return not _eval_node(child, event, depth + 1)
    if not isinstance(children, (list, tuple)):
        raise SkipSpec(f"{combinator} requires a list")
    results = [_eval_node(child, event, depth + 1) for child in children]
    return all(results) if combinator == "all" else any(results)


def evaluate_spec(spec: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    if not isinstance(spec, Mapping):
        raise SkipSpec("spec is not a mapping")
    if spec.get("v") != SPEC_VERSION:
        raise SkipSpec(f"unsupported spec version: {spec.get('v')!r}")
    body = {k: v for k, v in spec.items() if k != "v"}
    return _eval_node(body, event, 0)


def _ordered(patterns: Sequence[Pattern]) -> list[Pattern]:
    return sorted(patterns, key=lambda p: (-p.priority, p.pattern_id))


def evaluate_patterns(
    patterns: Sequence[Pattern],
    event: Mapping[str, Any],
    *,
    candidate_ids: set[str] | None = None,
    max_patterns_scanned: int = DEFAULT_MAX_PATTERNS_SCANNED,
    max_patterns_scanned_unindexed: int = DEFAULT_MAX_PATTERNS_SCANNED_UNINDEXED,
    max_eval_ms: float = DEFAULT_MAX_EVAL_MS,
) -> MatchResult:
    total = len(patterns)
    ordered = _ordered(patterns)
    if candidate_ids is not None:
        ordered = [p for p in ordered if p.pattern_id in candidate_ids]
        cap = max_patterns_scanned
    else:
        cap = max_patterns_scanned_unindexed

    matched: list[str] = []
    payloads: list[Any] = []
    scanned = 0
    truncated = False
    started = time.monotonic()
    for pattern in ordered:
        if scanned >= cap:
            truncated = True
            break
        if (time.monotonic() - started) * 1000.0 > max_eval_ms:
            truncated = True
            break
        scanned += 1
        try:
            if evaluate_spec(pattern.spec, event):
                matched.append(pattern.pattern_id)
                payloads.append(pattern.payload)
        except SkipSpec as exc:
            _LOG.warning("skipping pattern %s: %s", pattern.pattern_id, exc)
    return MatchResult(
        matched=tuple(matched),
        payloads=tuple(payloads),
        scanned=scanned,
        total=total,
        truncated=truncated,
    )
