"""Authoritative Defensive State as a fact lane (Knowledge#65).

    **Knowledge advises; it never sets Defensive State.**

Everything in this module is about a state some *other* product already
decided. There is no function here that selects, requests, or transitions one,
and there is no enum here that says what the values are.

Why no enum
-----------
The canonical vocabulary is Azazel-Fabric's (Fabric#14). Mirroring the five
values here would make Knowledge a second place that defines them, and the two
copies would drift -- the back-door canonicalization Fabric#14 exists to
prevent. So Knowledge stores what it was told, records the vocabulary it was
told in, and leaves the meaning where it belongs.

The API boundary classifies against Fabric's canonical enum in
`api/contracts.py` (Knowledge#65 AC-6). Fabric `v0.9.0rc5` supplies that enum.
This module remains framework-free: it stores the reported value unchanged
and does not choose or rewrite a state.

Absence is not a state
----------------------
`lookup_reported_defensive_state` returns `None` for missing, unreadable, or
stale input. It never substitutes a default, and specifically never returns
`OBSERVE` to mean "nothing known" -- that would be Knowledge inventing a claim
about another product's posture out of its own ignorance.

Writes
------
`record_defensive_state_observation` is INSERT-only and belongs to the single
writer (Absolute Constraint 1). Nothing in `api/` or `taxii/` may call it; the
static scan in `tests/unit/test_api_static.py` enforces that. Ingest wiring for
the evidence chain is Knowledge#67's, not this module's.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Mapping

__all__ = [
    "AUTHORITY_CLASS",
    "SCHEMA_VERSION",
    "DefensiveStateMemoryError",
    "ReportedDefensiveState",
    "canonical_observation_json",
    "lookup_reported_defensive_state",
    "record_defensive_state_observation",
]

#: Pinned. A row in this table is a producer's report about itself and can be
#: nothing else; the table's CHECK constraint holds the same value.
AUTHORITY_CLASS = "producer_reported_state"
SCHEMA_VERSION = "defensive-state-observation/v0.1"

_TABLE = "defensive_state_observation_v0"

#: Required provenance. A state value without these is an assertion with no
#: author, which is exactly what must not be storable here.
_REQUIRED_FIELDS = (
    "observation_ref",
    "reported_state",
    "state_vocabulary",
    "producer_product",
    "producer_node",
    "trace_id",
    "decision_ref",
    "observed_at",
)

#: Field names that would turn a report into an instruction. A payload carrying
#: one is refused rather than stripped: a producer sending it has misunderstood
#: what this lane is, and silently accepting a cleaned copy would hide that.
_DIRECTIVE_FIELDS = frozenset(
    {
        "set_state",
        "target_state",
        "requested_state",
        "next_state",
        "transition_to",
        "apply",
        "execute",
        "enforce",
        "command",
        "override",
        "attacker_belief",
        "adversary_belief",
    }
)

_MAX_STRING = 512


class DefensiveStateMemoryError(ValueError):
    """A payload that cannot be stored as a provenance-linked fact."""


@dataclass(frozen=True)
class ReportedDefensiveState:
    """One producer's report. Carries its provenance; asserts nothing else."""

    reported_state: str
    state_vocabulary: str
    producer_product: str
    producer_node: str
    trace_id: str
    decision_ref: str
    observed_at: str
    observation_ref: str
    #: Always this value. Present so a consumer reading one field sees what
    #: kind of claim it is holding.
    authority_class: str = AUTHORITY_CLASS

    def as_fact(self) -> dict[str, Any]:
        """The shape served to a consumer. Never merged with advisory output."""

        return {
            "reported_state": self.reported_state,
            "state_vocabulary": self.state_vocabulary,
            "producer_product": self.producer_product,
            "producer_node": self.producer_node,
            "trace_id": self.trace_id,
            "decision_ref": self.decision_ref,
            "observed_at": self.observed_at,
            "observation_ref": self.observation_ref,
            "authority_class": self.authority_class,
        }


def _clean_string(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise DefensiveStateMemoryError(f"{field} must be a non-empty string")
    if len(value) > _MAX_STRING:
        raise DefensiveStateMemoryError(f"{field} exceeds {_MAX_STRING} characters")
    return value


def _assert_not_a_directive(payload: Mapping[str, Any], path: str = "") -> None:
    if isinstance(payload, Mapping):
        for key, child in payload.items():
            if isinstance(key, str) and key.strip().lower() in _DIRECTIVE_FIELDS:
                location = f"{path}.{key}" if path else key
                raise DefensiveStateMemoryError(
                    f"a reported state cannot carry {location!r}; this lane records "
                    "what a producer did, never what anyone should do next"
                )
            _assert_not_a_directive(child, f"{path}.{key}" if path else str(key))
    elif isinstance(payload, (list, tuple)):
        for index, child in enumerate(payload):
            _assert_not_a_directive(child, f"{path}.{index}")


def canonical_observation_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _validate(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise DefensiveStateMemoryError("payload must be a mapping")
    _assert_not_a_directive(payload)

    validated = {field: _clean_string(payload, field) for field in _REQUIRED_FIELDS}

    declared_authority = payload.get("authority_class", AUTHORITY_CLASS)
    if declared_authority != AUTHORITY_CLASS:
        raise DefensiveStateMemoryError(
            f"authority_class must be {AUTHORITY_CLASS!r}; this lane holds one kind of claim"
        )
    declared_schema = payload.get("schema_version", SCHEMA_VERSION)
    if declared_schema != SCHEMA_VERSION:
        raise DefensiveStateMemoryError(f"schema_version must be {SCHEMA_VERSION!r}")

    evidence = payload.get("evidence_refs", [])
    if not isinstance(evidence, (list, tuple)) or not all(
        isinstance(item, str) for item in evidence
    ):
        raise DefensiveStateMemoryError("evidence_refs must be a list of strings")
    validated["evidence_refs"] = list(evidence)
    return validated


def record_defensive_state_observation(
    conn: sqlite3.Connection, payload: Mapping[str, Any], *, received_at: str
) -> bool:
    """Append one reported state. Returns False when the ref is already stored.

    Single-writer only (Absolute Constraint 1). Idempotent by
    `observation_ref`, so a redelivered report does not create a second fact.
    """

    validated = _validate(payload)
    raw = canonical_observation_json(payload)

    existing = conn.execute(
        f"SELECT raw FROM {_TABLE} WHERE observation_ref = ?",
        (validated["observation_ref"],),
    ).fetchone()
    if existing is not None:
        if existing[0] != raw:
            raise DefensiveStateMemoryError(
                f"observation_ref {validated['observation_ref']!r} was already stored with "
                "different content; a fact is not rewritten"
            )
        return False

    conn.execute(
        f"INSERT INTO {_TABLE} ("
        "observation_ref, reported_state, state_vocabulary, producer_product, "
        "producer_node, trace_id, decision_ref, observed_at, evidence_refs, "
        "authority_class, schema_version, raw, received_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            validated["observation_ref"],
            validated["reported_state"],
            validated["state_vocabulary"],
            validated["producer_product"],
            validated["producer_node"],
            validated["trace_id"],
            validated["decision_ref"],
            validated["observed_at"],
            json.dumps(validated["evidence_refs"], sort_keys=True, separators=(",", ":")),
            AUTHORITY_CLASS,
            SCHEMA_VERSION,
            raw,
            received_at,
        ),
    )
    return True


def lookup_reported_defensive_state(
    conn: sqlite3.Connection, trace_id: str, *, query_as_of: str
) -> ReportedDefensiveState | None:
    """The latest state reported for `trace_id` at or before `query_as_of`.

    Deterministic: ordered by `(observed_at, observation_ref)` so two reports
    sharing an instant resolve the same way on every machine and every replay.

    Returns `None` when the table is absent (the migration has not run), when
    nothing was reported, or when everything reported is later than the caller's
    `query_as_of`. All three mean the same thing to a consumer -- *unknown* --
    and none of them justifies inventing a state.
    """

    if not isinstance(trace_id, str) or not trace_id.strip():
        return None
    try:
        row = conn.execute(
            f"SELECT reported_state, state_vocabulary, producer_product, producer_node, "
            f"trace_id, decision_ref, observed_at, observation_ref FROM {_TABLE} "
            "WHERE trace_id = ? AND observed_at <= ? "
            "ORDER BY observed_at DESC, observation_ref DESC LIMIT 1",
            (trace_id, query_as_of),
        ).fetchone()
    except sqlite3.Error:
        # Table absent, or any other read failure. Advisory output degrades to
        # "unknown"; it never becomes an error and never becomes a state.
        return None
    if row is None:
        return None
    return ReportedDefensiveState(
        reported_state=row[0],
        state_vocabulary=row[1],
        producer_product=row[2],
        producer_node=row[3],
        trace_id=row[4],
        decision_ref=row[5],
        observed_at=row[6],
        observation_ref=row[7],
    )
