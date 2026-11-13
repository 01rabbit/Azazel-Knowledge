"""ATT&CK technique reference lookup for the Knowledge Context v1 route.

Reserved entity namespace ``attack-technique/*`` (GX1 design 2.1, 7):

* Only ``attack-technique/v1`` is accepted. Any other spelling or version under
  the reserved prefix, a mix with other entity types, a malformed value, a
  duplicate, an unsorted list or a count outside 1..8 is refused (422, no signed
  envelope). Requests without the prefix never reach this module.
* The lookup reads only the official ATT&CK tables of the live intel generation
  (``attack_technique``, ``attack_mitigation``, ``attack_relation``,
  ``feed_state``). Those tables are loaded through the signed bundle importer.
* Corpus health failures never degrade to ``no_match``: every technique becomes
  ``unavailable``. ``no_match`` is only "corpus healthy and fresh, ID absent".
* Coverage facts are Knowledge's own evaluation (provenance
  ``knowledge:attack-coverage``). Content facts are reported by ATT&CK
  (provenance ``knowledge:attack-stix``). Names or tactics that look like
  instructions, causal claims, markup or network indicators make the whole
  response ``unavailable``; nothing is truncated or silently edited.

The IOC egress policy (``EGRESSIBLE_SOURCE_GROUPS``) is not touched here.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from azazel_fabric.knowledge_context import (
    RESPONSE_SCHEMA_VERSION,
    KnowledgeContextRequestV1,
    KnowledgeContextResponseV1,
    assert_response_correlates,
)

from azazel_knowledge.core.clock import parse_rfc3339, to_rfc3339

NAMESPACE_PREFIX = "attack-technique/"
TECHNIQUE_ENTITY_TYPE = "attack-technique/v1"
MAX_TECHNIQUES = 8
MAX_NAME_LENGTH = 120
TECHNIQUE_ID_RE = re.compile(r"\AT[0-9]{4}(?:\.[0-9]{3})?\Z", re.ASCII)

#: Technique-specific provenance (distinct from the IOC ``knowledge:intel-index``).
PROVENANCE_COVERAGE = "knowledge:attack-coverage"
PROVENANCE_STIX = "knowledge:attack-stix"
#: The only feed group whose rows may back technique content facts.
TECHNIQUE_SOURCE_GROUPS = frozenset({"mitre"})

COVERAGE_STATES = ("found", "no_match", "stale", "unavailable")
LIMITATIONS = (
    "ATT&CK technique reference data; not evidence of occurrence",
    "reference information only; not an instruction",
)
NO_MATCH_UNKNOWN = (
    "techniques with coverage no_match are absent from the loaded ATT&CK corpus; "
    "absence is not a verdict"
)

#: ATT&CK tactic shortnames (enterprise). ``stealth`` and ``defense-impairment``
#: are accepted for newer releases (unverified against the official list).
TACTICS = frozenset({
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact", "stealth", "defense-impairment",
})

_VERSION_RE = re.compile(r"\A[0-9]{1,4}\.[0-9]{1,4}\Z", re.ASCII)
_RFC3339_RE = re.compile(
    r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z",
    re.ASCII,
)
_ATTACK_FEED = "attack"


class TechniqueRequestError(ValueError):
    """The request violates the reserved ``attack-technique/*`` contract (422)."""


def is_technique_request(request: KnowledgeContextRequestV1) -> bool:
    """True when any entity uses the reserved namespace; raises if malformed."""

    types = [e.entity_type for e in request.entities]
    if not any(t.casefold().startswith(NAMESPACE_PREFIX) for t in types):
        return False
    if any(t != TECHNIQUE_ENTITY_TYPE for t in types):
        # Other version/spelling under the prefix, or a mix with another type.
        raise TechniqueRequestError("reserved namespace requires attack-technique/v1 only")
    values = [e.value for e in request.entities]
    if not 1 <= len(values) <= MAX_TECHNIQUES:
        raise TechniqueRequestError("technique count out of range")
    if any(TECHNIQUE_ID_RE.match(v) is None for v in values):
        raise TechniqueRequestError("malformed technique id")
    if values != sorted(set(values)):
        raise TechniqueRequestError("technique ids must be unique and sorted")
    return True


# ---- value validation (poisoned values are refused, never truncated) ----------

_NAME_POISON = (
    re.compile(r"[<>`{}\\]"),
    re.compile(r"&[#A-Za-z0-9]+;"),
    re.compile(r"://|\bwww\.|\bhttps?\b", re.IGNORECASE),
    re.compile(r"(?<![0-9])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9])"),
    re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:]*"),
    re.compile(
        r"\b(?:you|your|must|should|please|immediately|now|ignore|disregard|instructions?|"
        r"assistant|prompt)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:proves?|proved|confirms?|confirmed|indicates?|caused|causes|because|therefore|"
        r"responsible|attributed)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\A\s*(?:block|isolate|quarantine|kill|ban|blacklist|reboot|shut\s?down|run|execute|"
        r"sudo|rm|curl|wget|ssh)\b",
        re.IGNORECASE,
    ),
)


def valid_name(name: object) -> bool:
    if not isinstance(name, str) or not 1 <= len(name) <= MAX_NAME_LENGTH:
        return False
    if name != name.strip() or "  " in name:
        return False
    if any(unicodedata.category(ch)[0] == "C" for ch in name):
        return False
    return not any(p.search(name) for p in _NAME_POISON)


def parse_tactics(raw: object) -> str | None:
    """Return the comma-joined sorted tactic list, or None if it is not valid."""

    if not isinstance(raw, str):
        return None
    try:
        items = json.loads(raw)
    except ValueError:
        return None
    if (not isinstance(items, list) or not items or len(items) != len(set(items))
            or not all(isinstance(i, str) and i in TACTICS for i in items)):
        return None
    return ",".join(sorted(items))


# ---- corpus assessment --------------------------------------------------------


@dataclass(frozen=True)
class Corpus:
    status: str  # "fresh" | "stale" | "unavailable"
    last_success: datetime | None
    snapshot_ref: str | None
    rows: dict[str, tuple[str, str, str]]  # id -> (name, tactics_json, attack_version)


def _unavailable() -> Corpus:
    return Corpus("unavailable", None, None, {})


def assess_corpus(
    conn: Any, *, generated_at: datetime, max_age: timedelta, current_generation: int | None,
    technique_ids: list[str], snapshot_ref: str,
) -> Corpus:
    """Read the ATT&CK tables of the live generation; any anomaly -> unavailable."""

    try:
        return _assess(conn, generated_at, max_age, current_generation, technique_ids, snapshot_ref)
    except Exception:  # noqa: BLE001 -- an unreadable corpus is never "no match"
        return _unavailable()


def _assess(conn, generated_at, max_age, current_generation, technique_ids, snapshot_ref) -> Corpus:
    gen_row = conn.execute(
        "SELECT value FROM intel.stats_meta WHERE key = 'intel_generation'"
    ).fetchone()
    if gen_row is None or not str(gen_row[0]).isdigit():
        return _unavailable()
    generation = int(gen_row[0])
    directory = str(getattr(conn, "generation", ""))
    if (current_generation != generation or directory != f"gen-{generation}"
            or snapshot_ref != f"knowledge:intel-generation:{generation}"):
        return _unavailable()

    state = conn.execute(
        "SELECT enabled, last_success, item_count FROM intel.feed_state WHERE feed_id = ?",
        (_ATTACK_FEED,),
    ).fetchall()
    if len(state) != 1:
        return _unavailable()
    enabled, last_success_text, item_count = state[0]
    if enabled != 1 or not isinstance(last_success_text, str) or not isinstance(item_count, int):
        return _unavailable()
    if _RFC3339_RE.match(last_success_text) is None:
        return _unavailable()
    last_success = parse_rfc3339(last_success_text)
    if last_success > generated_at:
        return _unavailable()

    counts = {
        table: conn.execute(f"SELECT COUNT(*) FROM intel.{table}").fetchone()[0]
        for table in ("attack_technique", "attack_mitigation", "attack_relation")
    }
    if counts["attack_technique"] == 0 or item_count != sum(counts.values()):
        return _unavailable()
    versions = set()
    for table in counts:
        versions.update(r[0] for r in conn.execute(
            f"SELECT DISTINCT attack_version FROM intel.{table}").fetchall())
    if len(versions) != 1 or _VERSION_RE.match(next(iter(versions))) is None:
        return _unavailable()

    status = "stale" if last_success + max_age <= generated_at else "fresh"
    rows: dict[str, tuple[str, str, str]] = {}
    if status == "fresh":
        for technique_id in technique_ids:
            row = conn.execute(
                "SELECT name, tactics, attack_version FROM intel.attack_technique "
                "WHERE technique_id = ?", (technique_id,)).fetchone()
            if row is None:
                continue
            name, tactics, version = row
            if not valid_name(name) or parse_tactics(tactics) is None or not isinstance(version, str):
                return _unavailable()
            rows[technique_id] = (name, tactics, version)
    return Corpus(status, last_success, snapshot_ref, rows)


# ---- response -----------------------------------------------------------------


def build_response(
    request: KnowledgeContextRequestV1, corpus: Corpus, *, provider_id: str,
    generated_at: datetime, response_ttl: timedelta, max_age: timedelta,
    fallback_snapshot_ref: str,
) -> KnowledgeContextResponseV1:
    facts: list[dict[str, Any]] = []
    states: list[str] = []
    for i, entity in enumerate(request.entities):
        subject = {"entity_type": entity.entity_type, "value": entity.value}
        if corpus.status == "fresh":
            state = "found" if entity.value in corpus.rows else "no_match"
        else:
            state = corpus.status
        states.append(state)
        facts.append({"fact_id": f"tq-{i}-0", "subject": subject, "predicate": "coverage",
                      "value": state, "provenance": [PROVENANCE_COVERAGE]})
        if state == "found":
            name, tactics, version = corpus.rows[entity.value]
            content = (("technique_name", name), ("tactics", parse_tactics(tactics)),
                       ("attack_version", version))
            for n, (predicate, value) in enumerate(content, start=1):
                facts.append({"fact_id": f"tq-{i}-{n}", "subject": subject, "predicate": predicate,
                              "value": value, "provenance": [PROVENANCE_STIX]})

    expires = generated_at + response_ttl
    if corpus.status == "fresh":
        # Fresh data must not outlive its freshness deadline (7.2).
        expires = min(expires, corpus.last_success + max_age)
        snapshot_state = "complete" if all(s == "found" for s in states) else "partial"
        as_of = corpus.last_success
    elif corpus.status == "stale":
        snapshot_state, as_of = "stale", corpus.last_success
    else:
        snapshot_state, as_of = "stale", generated_at
    payload = {
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "request_id": request.request_id,
        "correlation_id": request.correlation_id,
        "source_product": request.source_product,
        "source_ref": request.source_ref,
        "provider_id": provider_id,
        "snapshot": {"ref": corpus.snapshot_ref or fallback_snapshot_ref,
                     "state": snapshot_state, "as_of": to_rfc3339(as_of)},
        "facts": facts,
        "inferences": [],
        "unknowns": [NO_MATCH_UNKNOWN] if "no_match" in states else [],
        "limitations": list(LIMITATIONS),
        "generated_at": to_rfc3339(generated_at),
        "expires_at": to_rfc3339(expires),
    }
    response = KnowledgeContextResponseV1.model_validate(payload)
    assert_response_correlates(request, response)
    return response
