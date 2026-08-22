"""Advisory-only `engage_refs` / `rule_refs` lookups (ADR-0012 / ADR-0013 usage seam, #60/#61).

Surfaces the already-ingested MITRE Engage catalog
(`engage_activity`/`engage_attack_map`) and the YARA/Sigma rule corpus
(`sigma_rule_corpus`/`yara_rule_corpus`) as **additive, advisory-only,
match-gated, best-effort** annotations keyed off the ATT&CK technique(s) the
correlation pipeline already attributed to the request. This module never
scores anything and is never imported by `scoring/`: it is a pure, read-only,
deterministic sibling to `correlate/campaign.py`, reading the same intel-tier
database attachment (`intel.*`) the pipeline already reads through
`Repository`.

Determinism (Absolute Constraint 3): no `datetime.now`/`random`/environment/
file-order input anywhere in this module. The only input is the caller-
supplied `techniques` sequence (already deterministically sorted by the
pipeline, see `correlate/pipeline.py::_evaluate_attack`) plus whatever rows
the intel-tier tables hold for the current, already-pinned generation. Every
return value is sorted by a stable key before being capped, so truncation
(best-effort, Constraint 6) is itself deterministic.

Fail-open enrichment (Constraint 6): every lookup here degrades to `[]` on a
missing table, a malformed JSON column, or any other `sqlite3.Error` --
never an exception that could turn the `/v1/context` `200` into a `500`.

Advisory-only rule identity (Constraint 8): `lookup_rule_refs` returns rule
IDENTITY + metadata only (`rule_id`/`title`/`source_url`/`technique`). It
never reads or returns `raw_yaml`/`raw_text`/`condition`/`condition_summary`
-- nothing executable ever leaves this module.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Sequence

# Best-effort caps (Join semantics, spec): deterministic truncation, not an
# error condition -- silently keeping the first N after a stable sort.
MAX_ENGAGE_REFS = 20
MAX_RULE_REFS = 20

_ATTACK_PREFIX = "ATTACK."


def canonicalize_technique(raw: object) -> str | None:
    """Canonicalize a technique/attack-ref string to bare uppercase `T####[.###]`.

    Uppercases the whole value, then drops one leading `ATTACK.` prefix
    (SigmaHQ convention: `attack.t1059.001`; YARA corpora use a mix of
    `T1105`/`t1105`/`attack.t1105`). This is the ONE canonical form used to
    match a rule's `attack_refs` entry against the advisory's own bare,
    uppercase technique id (e.g. `T1059.001`) -- see spec "Join semantics".
    Returns `None` for anything empty/non-stringlike so callers can filter
    it out without special-casing.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    value = text.upper()
    if value.startswith(_ATTACK_PREFIX):
        value = value[len(_ATTACK_PREFIX):]
    return value or None


def _canonical_technique_set(techniques: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    for t in techniques:
        canonical = canonicalize_technique(t)
        if canonical:
            seen.add(canonical)
    return sorted(seen)


def _load_json_list(raw: object) -> list[Any]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return data


def _like_patterns(techniques: Sequence[str]) -> list[str]:
    """Coarse `LIKE` prefilter patterns, one per technique.

    Bounds the row scan on `attack_refs` (a JSON array stored as TEXT); the
    authoritative match is always the canonicalized Python comparison below,
    so a prefilter false-positive is harmless -- it is filtered back out.
    """
    patterns = []
    for t in techniques:
        digits = t[1:] if t.upper().startswith("T") else t
        patterns.append(f"%{digits}%")
    return patterns


def lookup_engage_refs(
    conn: sqlite3.Connection, techniques: Sequence[str]
) -> list[dict[str, Any]]:
    """Read-only, best-effort lookup of Engage activities for `techniques`.

    Returns `[]` when `techniques` is empty, when `engage_activity`/
    `engage_attack_map` are absent or empty (feed never ingested -- Constraint
    6/ADR-0012 §Determinism handling), or on any lookup error. Otherwise
    returns a list of `{technique, activity_id, name, approach}` dicts sorted
    by `(technique, activity_id)`, capped at `MAX_ENGAGE_REFS`.
    """
    wanted = _canonical_technique_set(techniques)
    if not wanted:
        return []

    try:
        placeholders = ",".join("?" for _ in wanted)
        rows = conn.execute(
            "SELECT eam.technique_id, ea.activity_id, ea.name, ea.approach "
            "FROM intel.engage_attack_map eam "
            "JOIN intel.engage_activity ea ON ea.activity_id = eam.activity_id "
            f"WHERE eam.technique_id IN ({placeholders})",
            wanted,
        ).fetchall()
    except sqlite3.Error:
        return []

    wanted_set = set(wanted)
    refs: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        technique = canonicalize_technique(row[0])
        if technique is None or technique not in wanted_set:
            continue
        activity_id = str(row[1])
        refs[(technique, activity_id)] = {
            "technique": technique,
            "activity_id": activity_id,
            "name": str(row[2]) if row[2] is not None else "",
            "approach": str(row[3]) if row[3] is not None else "",
        }

    ordered = sorted(refs.values(), key=lambda r: (r["technique"], r["activity_id"]))
    return ordered[:MAX_ENGAGE_REFS]


def _lookup_sigma_refs(
    conn: sqlite3.Connection, wanted: Sequence[str]
) -> list[dict[str, Any]]:
    like_patterns = _like_patterns(wanted)
    where = " OR ".join(["attack_refs LIKE ?"] * len(like_patterns))
    try:
        rows = conn.execute(
            "SELECT rule_uid, title, attack_refs, source_url "
            f"FROM intel.sigma_rule_corpus WHERE {where}",
            like_patterns,
        ).fetchall()
    except sqlite3.Error:
        return []

    wanted_set = set(wanted)
    out: list[dict[str, Any]] = []
    for row in rows:
        rule_uid, title, attack_refs_json, source_url = row[0], row[1], row[2], row[3]
        matched_techniques = {
            canonicalize_technique(ref) for ref in _load_json_list(attack_refs_json)
        }
        matched_techniques.discard(None)
        for technique in matched_techniques & wanted_set:
            out.append(
                {
                    "technique": technique,
                    "rule_type": "sigma",
                    "rule_id": str(rule_uid),
                    "title": str(title) if title is not None else None,
                    "source_url": str(source_url) if source_url is not None else None,
                }
            )
    return out


def _lookup_yara_refs(
    conn: sqlite3.Connection, wanted: Sequence[str]
) -> list[dict[str, Any]]:
    like_patterns = _like_patterns(wanted)
    where = " OR ".join(["attack_refs LIKE ?"] * len(like_patterns))
    try:
        rows = conn.execute(
            "SELECT rule_name, attack_refs, source_url "
            f"FROM intel.yara_rule_corpus WHERE {where}",
            like_patterns,
        ).fetchall()
    except sqlite3.Error:
        return []

    wanted_set = set(wanted)
    out: list[dict[str, Any]] = []
    for row in rows:
        rule_name, attack_refs_json, source_url = row[0], row[1], row[2]
        matched_techniques = {
            canonicalize_technique(ref) for ref in _load_json_list(attack_refs_json)
        }
        matched_techniques.discard(None)
        for technique in matched_techniques & wanted_set:
            out.append(
                {
                    "technique": technique,
                    "rule_type": "yara",
                    "rule_id": str(rule_name),
                    # YARA corpus rows carry no separate rule title -- rule_name
                    # doubles as identity; title is left absent (None) rather
                    # than duplicating rule_id.
                    "title": None,
                    "source_url": str(source_url) if source_url is not None else None,
                }
            )
    return out


def lookup_rule_refs(
    conn: sqlite3.Connection, techniques: Sequence[str]
) -> list[dict[str, Any]]:
    """Read-only, best-effort lookup of Sigma/YARA rule identity for `techniques`.

    Returns `[]` when `techniques` is empty, when both corpus tables are
    absent/empty (feeds never ingested), or on any lookup error -- one
    table's error never suppresses the other's rows (each is looked up and
    caught independently). Otherwise returns a list of
    `{technique, rule_type, rule_id, title, source_url}` dicts -- identity
    and metadata only, NEVER `raw_yaml`/`raw_text`/condition logic (Constraint
    8) -- sorted by `(technique, rule_type, rule_id)`, capped at
    `MAX_RULE_REFS`.
    """
    wanted = _canonical_technique_set(techniques)
    if not wanted:
        return []

    refs: dict[tuple[str, str, str], dict[str, Any]] = {}
    for ref in (*_lookup_sigma_refs(conn, wanted), *_lookup_yara_refs(conn, wanted)):
        key = (ref["technique"], ref["rule_type"], ref["rule_id"])
        refs[key] = ref

    ordered = sorted(refs.values(), key=lambda r: (r["technique"], r["rule_type"], r["rule_id"]))
    return ordered[:MAX_RULE_REFS]
