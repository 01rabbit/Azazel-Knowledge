"""Strict append-only Outcome-as-Evidence v0 storage helpers.

This module does not import `azazel_fabric`, and must not: the dependency
lives in the `api` optional extra and never leaks into `db/`, `core/`,
`scoring/`, or `correlate/` (Absolute Constraint 7). The worker drains this
lane, and the worker runs without the api extra installed.

So the wire shapes below are a **second statement** of what Azazel-Fabric's
`outcome_contracts` say. That is a drift hazard, not a design preference --
the same one Azazel-Edge#413 removed on the producer side, where the shapes
had been "byte-for-byte identical to Fabric's models by coincidence of
maintenance rather than by construction". The coincidence is no longer left
to maintenance here either: `tests/unit/test_outcome_contract_drift.py` pins
`_SPECS` field-for-field against `ExecutionRefV0`, `MechanismObservationV0`,
`OutcomeObservationV0` and `TacticalEffectAssessmentRefV0`, pins every closed
vocabulary against the corresponding `Literal`, and requires this module's
refusals to be a superset of Fabric's. A divergence is a red test, not a
slow drift.

Where the two differ deliberately, this module is **stricter, never looser**:
Fabric defaults `evidence_refs`, `limitations` and the fact maps, while a row
reaching storage must carry them explicitly. The drift guard enforces the
direction, not equality, so "Knowledge is stricter" cannot quietly become
"Knowledge is looser".

It stores facts and can export a deterministic trajectory bundle. It never
creates authority or turns observations into success/causal claims.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Mapping


class OutcomeMemoryError(ValueError):
    pass


_BANNED_KEYS = {
    "execute", "execution_command", "provider_command", "command", "commands",
    "approve", "approval", "override", "arbiter_override", "auto_execute",
    "select_action", "selected_action", "model_recommendation", "attacker_belief",
    "success", "successful",
}
# Kept a superset of Fabric's `_TACTICAL_CLAIM_KEYS`, pinned by the drift
# guard. `effectiveness` and `initiative_score` are here because Fabric added
# them: a producer that cannot say `tactical_effect` in a descriptive fact map
# must not be able to say `effectiveness: 0.9` instead and mean the same
# thing.
_TACTICAL_CLAIM_KEYS = {
    "effect_class", "tactical_effect", "effectiveness", "initiative_score",
}
_ALLOWED_MECHANISMS = {
    "traffic_shaping", "redirection", "isolation", "notification",
    "observation_only", "unknown",
}
_ALLOWED_TACTICAL_EFFECTS = {
    "delay", "divert", "containment", "isolation", "observe", "restore",
}
# Lifted out of `_validate_shape` so the drift guard can compare them against
# Fabric's `Literal`s directly. Inline as set literals they were checkable
# only by feeding values through, which catches a value Fabric has and this
# module lost -- but not a value this module *gained*, and a vocabulary that
# has quietly grown an extra member is the looser of the two failures.
_ALLOWED_EXECUTION_STATUSES = {
    "applied", "partial", "failed", "rejected", "unverified", "released",
}
_ALLOWED_MECHANISM_STATUSES = {
    "observed", "not_observed", "unverified", "released", "stale", "disputed",
}
_ALLOWED_PHASES = {"before", "during", "after"}
_ALLOWED_ASSESSMENTS = {"supported", "unsupported", "inconclusive"}
_MAX_DEPTH = 6
_MAX_MAP = 64
_MAX_LIST = 128
_MAX_STRING = 2048
_MAX_RAW_BYTES = 64 * 1024

_SPECS: dict[str, dict[str, Any]] = {
    "outcome-execution/v0.1": {
        "table": "outcome_execution_v0",
        "id_field": "execution_ref",
        "fields": {
            "schema_version", "producer_product", "producer_node", "trace_id",
            "decision_ref", "execution_ref", "action", "status", "observed_at",
            "release_ref", "evidence_refs", "authority_class",
        },
        "required": {
            "schema_version", "producer_product", "producer_node", "trace_id",
            "decision_ref", "execution_ref", "action", "status", "observed_at",
            "evidence_refs", "authority_class",
        },
    },
    "outcome-mechanism/v0.1": {
        "table": "outcome_mechanism_v0",
        "id_field": "observation_id",
        "fields": {
            "schema_version", "observation_id", "producer_product", "producer_node",
            "trace_id", "decision_ref", "execution_ref", "mechanism_kind", "status",
            "observed_parameters", "observed_at", "evidence_refs", "limitations",
            "authority_class",
        },
        "required": {
            "schema_version", "observation_id", "producer_product", "producer_node",
            "trace_id", "decision_ref", "execution_ref", "mechanism_kind", "status",
            "observed_parameters", "observed_at", "evidence_refs", "limitations",
            "authority_class",
        },
    },
    "outcome-observation/v0.1": {
        "table": "outcome_observation_v0",
        "id_field": "observation_id",
        "fields": {
            "schema_version", "observation_id", "producer_product", "producer_node",
            "trace_id", "decision_ref", "execution_ref", "mechanism_observation_ref",
            "subject_ref", "window_start", "window_end", "phase", "observation_class",
            "observation_values", "telemetry_coverage", "confounders", "resource_impact",
            "evidence_refs", "observed_at", "authority_class",
        },
        "required": {
            "schema_version", "observation_id", "producer_product", "producer_node",
            "trace_id", "decision_ref", "execution_ref", "window_start", "window_end",
            "phase", "observation_class", "observation_values", "telemetry_coverage",
            "confounders", "resource_impact", "evidence_refs", "observed_at",
            "authority_class",
        },
    },
    "tactical-effect-assessment/v0.1": {
        "table": "outcome_effect_assessment_v0",
        "id_field": "assessment_id",
        "fields": {
            "schema_version", "assessment_id", "producer_product", "producer_node",
            "trace_id", "decision_ref", "execution_ref", "mechanism_observation_ref",
            "outcome_observation_refs", "tactical_effect", "assessment", "evaluator",
            "policy_ref", "evidence_refs", "limitations", "observed_at", "executable",
            "authority_class",
        },
        "required": {
            "schema_version", "assessment_id", "producer_product", "producer_node",
            "trace_id", "decision_ref", "execution_ref", "mechanism_observation_ref",
            "outcome_observation_refs", "tactical_effect", "assessment", "evaluator",
            "policy_ref", "evidence_refs", "limitations", "observed_at", "executable",
            "authority_class",
        },
    },
}


def _normalized_key(raw: str) -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "_" for ch in raw.strip())
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized.strip("_")


def _is_forbidden_key(raw: str) -> bool:
    key = _normalized_key(raw)
    return (
        key in _BANNED_KEYS
        or "provider_command" in key
        or key.endswith("_command")
        or key.startswith("command_")
        or key.startswith("success_")
        or key.endswith("_success")
        or "attacker_belief" in key
        or "model_recommendation" in key
    )


def _walk(value: Any, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise OutcomeMemoryError("fact exceeds maximum nesting depth")
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            raise OutcomeMemoryError("fact contains oversized string")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, Mapping):
        if len(value) > _MAX_MAP:
            raise OutcomeMemoryError("fact map exceeds maximum item count")
        for key, child in value.items():
            if not isinstance(key, str):
                raise OutcomeMemoryError("fact map key must be string")
            if _is_forbidden_key(key):
                raise OutcomeMemoryError(f"forbidden authority/overclaim field: {key}")
            if len(key) > 128:
                raise OutcomeMemoryError("fact contains oversized key")
            _walk(child, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_LIST:
            raise OutcomeMemoryError("fact list exceeds maximum item count")
        for child in value:
            _walk(child, depth + 1)
        return
    raise OutcomeMemoryError(f"unsupported fact type: {type(value).__name__}")


def _is_tactical_claim_key(raw: str) -> bool:
    """Mirror of Fabric's `_is_tactical_claim_key` (pinned by the drift guard).

    Exact-match alone is not enough: `observed_tactical_effect` and
    `redirect_effectiveness` are the same claim wearing a prefix, and a guard
    that only compares whole keys reads them as ordinary descriptive fields.
    """

    key = _normalized_key(raw)
    return (
        key in _TACTICAL_CLAIM_KEYS
        or "effect_class" in key
        or "tactical_effect" in key
        or key.startswith("initiative_score")
        or key.endswith("_effectiveness")
    )


def _assert_no_tactical_claim_fields(value: Any) -> None:
    """Reject tactical conclusions inside mechanism/outcome free-form fact maps.

    Tactical effect is legal only in the dedicated assessment contract.  A
    producer must not smuggle ``effect_class`` / ``tactical_effect`` /
    ``effectiveness`` / ``initiative_score`` (including punctuation/case and
    affix variants) into descriptive mechanism or outcome payloads.
    """

    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            if isinstance(raw_key, str) and _is_tactical_claim_key(raw_key):
                raise OutcomeMemoryError(f"tactical claim field is forbidden in fact map: {raw_key}")
            _assert_no_tactical_claim_fields(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_no_tactical_claim_fields(child)


def _non_empty_str(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise OutcomeMemoryError(f"{field} must be a non-empty string")
    if len(value) > _MAX_STRING:
        raise OutcomeMemoryError(f"{field} is oversized")
    return value


def _optional_str(payload: Mapping[str, Any], field: str) -> str | None:
    value = payload.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise OutcomeMemoryError(f"{field} must be null or a non-empty string")
    if len(value) > _MAX_STRING:
        raise OutcomeMemoryError(f"{field} is oversized")
    return value


def _list_of_strings(payload: Mapping[str, Any], field: str, *, non_empty: bool = False) -> list[str]:
    value = payload.get(field)
    if not isinstance(value, list):
        raise OutcomeMemoryError(f"{field} must be a list")
    if non_empty and not value:
        raise OutcomeMemoryError(f"{field} must be non-empty")
    if len(value) > _MAX_LIST:
        raise OutcomeMemoryError(f"{field} exceeds maximum item count")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise OutcomeMemoryError(f"{field} entries must be non-empty strings")
        if len(item) > _MAX_STRING:
            raise OutcomeMemoryError(f"{field} contains oversized entry")
    return value


def _mapping(payload: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    value = payload.get(field)
    if not isinstance(value, Mapping):
        raise OutcomeMemoryError(f"{field} must be a map")
    _walk(value)
    return value


def canonical_fact_json(payload: Mapping[str, Any]) -> str:
    _walk(payload)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(raw.encode("utf-8")) > _MAX_RAW_BYTES:
        raise OutcomeMemoryError("fact exceeds maximum canonical size")
    return raw


def _validate_common_identity(payload: Mapping[str, Any], *, id_field: str) -> None:
    for field in ("producer_product", "producer_node", "trace_id", "decision_ref", id_field, "observed_at"):
        _non_empty_str(payload, field)
    _list_of_strings(payload, "evidence_refs")


def _validate_shape(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise OutcomeMemoryError("fact must be a mapping")
    schema = payload.get("schema_version")
    if not isinstance(schema, str):
        raise OutcomeMemoryError("schema_version must be a string")
    spec = _SPECS.get(schema)
    if spec is None:
        raise OutcomeMemoryError("unsupported outcome evidence schema")
    keys = set(payload)
    extra = keys - spec["fields"]
    missing = spec["required"] - keys
    if extra:
        raise OutcomeMemoryError(f"unknown fields: {sorted(extra)}")
    if missing:
        raise OutcomeMemoryError(f"missing fields: {sorted(missing)}")
    _walk(payload)
    _validate_common_identity(payload, id_field=spec["id_field"])

    if schema != "outcome-execution/v0.1":
        _non_empty_str(payload, "execution_ref")

    if schema == "outcome-execution/v0.1":
        _non_empty_str(payload, "action")
        _optional_str(payload, "release_ref")
        if payload["status"] not in _ALLOWED_EXECUTION_STATUSES:
            raise OutcomeMemoryError("invalid execution status")
        if payload["authority_class"] != "producer_execution_fact":
            raise OutcomeMemoryError("invalid execution authority class")
    elif schema == "outcome-mechanism/v0.1":
        observed_parameters = _mapping(payload, "observed_parameters")
        _assert_no_tactical_claim_fields(observed_parameters)
        _list_of_strings(payload, "limitations")
        if payload["mechanism_kind"] not in _ALLOWED_MECHANISMS:
            raise OutcomeMemoryError("invalid mechanism kind")
        if payload["status"] not in _ALLOWED_MECHANISM_STATUSES:
            raise OutcomeMemoryError("invalid mechanism status")
        if payload["authority_class"] != "producer_mechanism_fact":
            raise OutcomeMemoryError("invalid mechanism authority class")
    elif schema == "outcome-observation/v0.1":
        _non_empty_str(payload, "window_start")
        _non_empty_str(payload, "window_end")
        _non_empty_str(payload, "observation_class")
        _optional_str(payload, "mechanism_observation_ref")
        _optional_str(payload, "subject_ref")
        for field in ("observation_values", "telemetry_coverage", "resource_impact"):
            fact_map = _mapping(payload, field)
            _assert_no_tactical_claim_fields(fact_map)
        _list_of_strings(payload, "confounders")
        if payload["phase"] not in _ALLOWED_PHASES:
            raise OutcomeMemoryError("invalid outcome phase")
        if payload["authority_class"] != "producer_outcome_fact":
            raise OutcomeMemoryError("invalid outcome authority class")
    else:
        _non_empty_str(payload, "mechanism_observation_ref")
        _non_empty_str(payload, "evaluator")
        _non_empty_str(payload, "policy_ref")
        _list_of_strings(payload, "outcome_observation_refs", non_empty=True)
        _list_of_strings(payload, "limitations")
        if payload["tactical_effect"] not in _ALLOWED_TACTICAL_EFFECTS:
            raise OutcomeMemoryError("invalid tactical effect")
        if payload["assessment"] not in _ALLOWED_ASSESSMENTS:
            raise OutcomeMemoryError("invalid tactical assessment")
        if payload["executable"] is not False:
            raise OutcomeMemoryError("tactical assessment must be non-executable")
        if payload["authority_class"] != "producer_assessment_fact":
            raise OutcomeMemoryError("invalid assessment authority class")
    return spec


def validate_outcome_fact(payload: Mapping[str, Any]) -> str:
    """Validate one fact's shape and vocabulary without a database.

    This is the half of `ingest_outcome_fact` that needs no connection: field
    set, required fields, bounded payload, closed vocabularies and the
    authority-class pins. The evidence-chain checks (does the referenced
    execution exist, does it belong to the same trace) need stored rows and
    stay in `ingest_outcome_fact`.

    The split exists so the spool drain can quarantine a structurally bad
    *line* before opening a write transaction, without a second
    implementation of the shape rules living in `ingest/`. Returns the fact's
    `schema_version`; raises `OutcomeMemoryError` on any violation.
    """

    _validate_shape(payload)
    return str(payload["schema_version"])


def _chain_tuple(payload: Mapping[str, Any]) -> tuple[str, str, str]:
    return (str(payload["trace_id"]), str(payload["decision_ref"]), str(payload["execution_ref"]))


def _raw_by_id(conn: sqlite3.Connection, table: str, id_field: str, identity: str) -> str | None:
    row = conn.execute(f"SELECT raw FROM {table} WHERE {id_field} = ?", (identity,)).fetchone()
    return None if row is None else str(row[0])


def _require_execution(conn: sqlite3.Connection, payload: Mapping[str, Any]) -> None:
    row = conn.execute(
        "SELECT trace_id, decision_ref FROM outcome_execution_v0 WHERE execution_ref = ?",
        (payload["execution_ref"],),
    ).fetchone()
    if row is None:
        raise OutcomeMemoryError("referenced execution fact is not present")
    if (str(row[0]), str(row[1]), str(payload["execution_ref"])) != _chain_tuple(payload):
        raise OutcomeMemoryError("cross-trace/cross-decision execution join rejected")


def _require_mechanism(conn: sqlite3.Connection, payload: Mapping[str, Any], ref: str) -> None:
    row = conn.execute(
        "SELECT trace_id, decision_ref, execution_ref FROM outcome_mechanism_v0 WHERE observation_id = ?",
        (ref,),
    ).fetchone()
    if row is None:
        raise OutcomeMemoryError("referenced mechanism fact is not present")
    if tuple(str(item) for item in row) != _chain_tuple(payload):
        raise OutcomeMemoryError("cross-trace/cross-decision mechanism join rejected")


def _require_outcome(conn: sqlite3.Connection, payload: Mapping[str, Any], ref: str) -> None:
    row = conn.execute(
        "SELECT trace_id, decision_ref, execution_ref FROM outcome_observation_v0 WHERE observation_id = ?",
        (ref,),
    ).fetchone()
    if row is None:
        raise OutcomeMemoryError("referenced outcome fact is not present")
    if tuple(str(item) for item in row) != _chain_tuple(payload):
        raise OutcomeMemoryError("cross-trace/cross-decision outcome join rejected")


def ingest_outcome_fact(
    conn: sqlite3.Connection,
    payload: Mapping[str, Any],
    *,
    received_at: str,
) -> bool:
    """Insert one canonical fact.

    Returns True for a new row and False for an identical replay. Reusing an
    identity with different canonical bytes is rejected rather than hidden by
    INSERT OR IGNORE.
    """

    if not isinstance(received_at, str) or not received_at.strip():
        raise OutcomeMemoryError("received_at must be a non-empty string")
    spec = _validate_shape(payload)
    raw = canonical_fact_json(payload)
    identity = str(payload[spec["id_field"]])
    existing = _raw_by_id(conn, spec["table"], spec["id_field"], identity)
    if existing is not None:
        if existing == raw:
            return False
        raise OutcomeMemoryError("fact identity collision with different canonical content")

    schema = str(payload["schema_version"])
    if schema != "outcome-execution/v0.1":
        _require_execution(conn, payload)
    if schema == "outcome-observation/v0.1" and payload.get("mechanism_observation_ref"):
        _require_mechanism(conn, payload, str(payload["mechanism_observation_ref"]))
    if schema == "tactical-effect-assessment/v0.1":
        _require_mechanism(conn, payload, str(payload["mechanism_observation_ref"]))
        for ref in payload["outcome_observation_refs"]:
            _require_outcome(conn, payload, str(ref))

    if schema == "outcome-execution/v0.1":
        conn.execute(
            "INSERT INTO outcome_execution_v0 (execution_ref, producer_product, producer_node, trace_id, decision_ref, action, status, observed_at, release_ref, evidence_refs, authority_class, schema_version, raw, received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (payload["execution_ref"], payload["producer_product"], payload["producer_node"], payload["trace_id"], payload["decision_ref"], payload["action"], payload["status"], payload["observed_at"], payload.get("release_ref"), json.dumps(payload["evidence_refs"], sort_keys=True), payload["authority_class"], schema, raw, received_at),
        )
    elif schema == "outcome-mechanism/v0.1":
        conn.execute(
            "INSERT INTO outcome_mechanism_v0 (observation_id, producer_product, producer_node, trace_id, decision_ref, execution_ref, mechanism_kind, status, observed_parameters, observed_at, evidence_refs, limitations, authority_class, schema_version, raw, received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (payload["observation_id"], payload["producer_product"], payload["producer_node"], payload["trace_id"], payload["decision_ref"], payload["execution_ref"], payload["mechanism_kind"], payload["status"], json.dumps(payload["observed_parameters"], sort_keys=True), payload["observed_at"], json.dumps(payload["evidence_refs"], sort_keys=True), json.dumps(payload["limitations"], sort_keys=True), payload["authority_class"], schema, raw, received_at),
        )
    elif schema == "outcome-observation/v0.1":
        conn.execute(
            "INSERT INTO outcome_observation_v0 (observation_id, producer_product, producer_node, trace_id, decision_ref, execution_ref, mechanism_observation_ref, subject_ref, window_start, window_end, phase, observation_class, observation_values, telemetry_coverage, confounders, resource_impact, evidence_refs, observed_at, authority_class, schema_version, raw, received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (payload["observation_id"], payload["producer_product"], payload["producer_node"], payload["trace_id"], payload["decision_ref"], payload["execution_ref"], payload.get("mechanism_observation_ref"), payload.get("subject_ref"), payload["window_start"], payload["window_end"], payload["phase"], payload["observation_class"], json.dumps(payload["observation_values"], sort_keys=True), json.dumps(payload["telemetry_coverage"], sort_keys=True), json.dumps(payload["confounders"], sort_keys=True), json.dumps(payload["resource_impact"], sort_keys=True), json.dumps(payload["evidence_refs"], sort_keys=True), payload["observed_at"], payload["authority_class"], schema, raw, received_at),
        )
    else:
        conn.execute(
            "INSERT INTO outcome_effect_assessment_v0 (assessment_id, producer_product, producer_node, trace_id, decision_ref, execution_ref, mechanism_observation_ref, outcome_observation_refs, tactical_effect, assessment, evaluator, policy_ref, evidence_refs, limitations, observed_at, executable, authority_class, schema_version, raw, received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (payload["assessment_id"], payload["producer_product"], payload["producer_node"], payload["trace_id"], payload["decision_ref"], payload["execution_ref"], payload["mechanism_observation_ref"], json.dumps(payload["outcome_observation_refs"], sort_keys=True), payload["tactical_effect"], payload["assessment"], payload["evaluator"], payload["policy_ref"], json.dumps(payload["evidence_refs"], sort_keys=True), json.dumps(payload["limitations"], sort_keys=True), payload["observed_at"], 0, payload["authority_class"], schema, raw, received_at),
        )
    return True


def export_trajectory_bundle(conn: sqlite3.Connection, trace_id: str) -> str:
    """Export one deterministic research/replay bundle without executable authority."""

    if not isinstance(trace_id, str) or not trace_id.strip():
        raise OutcomeMemoryError("trace_id must be non-empty")
    facts: list[dict[str, Any]] = []
    for table, id_field in (
        ("outcome_execution_v0", "execution_ref"),
        ("outcome_mechanism_v0", "observation_id"),
        ("outcome_observation_v0", "observation_id"),
        ("outcome_effect_assessment_v0", "assessment_id"),
    ):
        rows = conn.execute(
            f"SELECT raw FROM {table} WHERE trace_id = ? ORDER BY observed_at ASC, {id_field} ASC",
            (trace_id,),
        ).fetchall()
        facts.extend(json.loads(str(row[0])) for row in rows)
    facts.sort(
        key=lambda item: (
            str(item.get("observed_at", "")),
            str(item.get("schema_version", "")),
            str(item.get("execution_ref", "")),
            str(item.get("observation_id", item.get("assessment_id", ""))),
        )
    )
    bundle = {
        "schema_version": "outcome-trajectory-bundle/v0.1",
        "trace_id": trace_id,
        "replay_context": True,
        "executable": False,
        "facts": facts,
    }
    return json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)