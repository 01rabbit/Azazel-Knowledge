"""Pure, framework-free per-line validation for the ingest endpoints.

Every validator takes one raw JSONL line and the request's pinned
``now`` and returns ``(True, normalized_dict)`` on success or
``(False, error_message)`` on failure. Failures never raise -- a bad
line is quarantined by the caller (see ``ingest/drain.py``), it never
fails the surrounding batch (design S4: "never reject a whole batch for
line errors").
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from azazel_cti.core.clock import parse_rfc3339, to_rfc3339
from azazel_cti.db.repository import entity_key
from azazel_cti.normalize.ioc import NormalizationError, normalize

MAX_LINE_BYTES = 64 * 1024
MAX_SKEW = timedelta(hours=48)

ALLOWED_EVENT_KINDS = frozenset(
    {"eve_alert", "dns", "http", "ja3", "ja4", "canary_hit"}
)
ACTION_APPLIED_ENUM = frozenset(
    {"throttle", "redirect", "isolate", "delay", "deception"}
)
REACTION_ENUM = frozenset(
    {
        "continued_scanning",
        "shifted_port",
        "shifted_protocol",
        "shifted_target",
        "followed_decoy",
        "auth_pattern_changed",
        "disengaged",
        "unknown",
    }
)

_ENTITY_FIELD_TYPES: dict[str, str] = {
    "src_ip": "ip",
    "dst_ip": "ip",
    "dest_ip": "ip",
    "ip": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "ja3": "ja3",
    "ja4": "ja4",
    "sha256": "hash_sha256",
    "hash_sha256": "hash_sha256",
    "sha1": "hash_sha1",
    "hash_sha1": "hash_sha1",
    "md5": "hash_md5",
    "hash_md5": "hash_md5",
}

Result = tuple[bool, dict[str, Any] | str]

_PHASE2_PROMOTED_FIELDS = frozenset(
    {
        "actor_cluster_key",
        "action_profile",
        "decoy_touched",
        "decoy_profile",
        "retry_interval_ms",
        "timeout_adaptation",
    }
)
_PHASE2_PAYLOAD_FIELDS = frozenset(
    {"pre_action_summary", "post_action_summary", "raw_refs"}
)


def _check_size(line: str) -> str | None:
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        return f"line exceeds {MAX_LINE_BYTES} bytes"
    return None


def _parse_object(line: str) -> Mapping[str, Any]:
    obj = json.loads(line)
    if not isinstance(obj, Mapping):
        raise ValueError("line is not a JSON object")
    return obj


def _require_fields(obj: Mapping[str, Any], fields: Sequence[str]) -> str | None:
    for name in fields:
        if name not in obj or obj[name] is None:
            return f"missing field: {name}"
    return None


def _require_nonempty_str(obj: Mapping[str, Any], name: str) -> str | None:
    value = obj.get(name)
    if not isinstance(value, str) or not value.strip():
        return f"invalid field: {name}"
    return None


def _optional_string(
    obj: Mapping[str, Any], name: str
) -> tuple[str | None, str | None]:
    value = obj.get(name)
    if value is None:
        return None, None
    if not isinstance(value, str):
        return None, f"{name} must be a string when present"
    return value, None


def _optional_nonnegative_int(
    obj: Mapping[str, Any], name: str
) -> tuple[int | None, str | None]:
    value = obj.get(name)
    if value is None:
        return None, None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None, f"{name} must be a non-negative integer when present"
    return value, None


def _optional_decoy_touched(
    obj: Mapping[str, Any],
) -> tuple[int | None, str | None]:
    value = obj.get("decoy_touched")
    if value is None:
        return None, None
    if isinstance(value, bool):
        return int(value), None
    if isinstance(value, int) and value in (0, 1):
        return value, None
    return None, "decoy_touched must be a boolean or 0/1 when present"


def _parse_and_check_skew(value: Any, *, now: datetime) -> tuple[datetime | None, str | None]:
    if not isinstance(value, str):
        return None, "timestamp must be a string"
    try:
        parsed = parse_rfc3339(value)
    except ValueError as exc:
        return None, f"invalid timestamp: {exc}"
    if abs(parsed - now) > MAX_SKEW:
        return None, "timestamp outside +/-48h skew window"
    return parsed, None


def _extract_entities(obj: Mapping[str, Any]) -> list[dict[str, str]]:
    candidates: list[tuple[str, str]] = []
    explicit = obj.get("entities")
    if isinstance(explicit, list):
        for item in explicit:
            if isinstance(item, Mapping) and "type" in item and "value" in item:
                candidates.append((str(item["type"]), str(item["value"])))
    for field_name, type_ in _ENTITY_FIELD_TYPES.items():
        value = obj.get(field_name)
        if isinstance(value, str) and value.strip():
            candidates.append((type_, value))

    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for type_, value in candidates:
        try:
            normalized = normalize(type_, value)
        except NormalizationError:
            continue
        key = (type_, normalized)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "type": type_,
                "value": normalized,
                "entity_key": entity_key(type_, normalized).hex(),
            }
        )
    return out


def validate_event_line(line: str, *, now: datetime) -> Result:
    size_error = _check_size(line)
    if size_error:
        return False, size_error
    try:
        obj = _parse_object(line)
    except (json.JSONDecodeError, ValueError) as exc:
        return False, f"invalid json: {exc}"

    for name in ("event_id", "edge_id", "kind", "observed_at"):
        error = _require_fields(obj, [name]) or _require_nonempty_str(obj, name)
        if error:
            return False, error

    if obj["kind"] not in ALLOWED_EVENT_KINDS:
        return False, f"unknown kind: {obj['kind']!r}"

    observed_at, error = _parse_and_check_skew(obj["observed_at"], now=now)
    if error:
        return False, error

    return True, {
        "event_id": obj["event_id"],
        "edge_id": obj["edge_id"],
        "kind": obj["kind"],
        "observed_at": to_rfc3339(observed_at),
        "entities": _extract_entities(obj),
        "raw": dict(obj),
    }


def validate_flow_line(line: str, *, now: datetime) -> Result:
    size_error = _check_size(line)
    if size_error:
        return False, size_error
    try:
        obj = _parse_object(line)
    except (json.JSONDecodeError, ValueError) as exc:
        return False, f"invalid json: {exc}"

    required = (
        "event_id",
        "edge_id",
        "observed_at",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "proto",
        "bytes",
        "packets",
    )
    error = _require_fields(obj, required)
    if error:
        return False, error

    for name in ("event_id", "edge_id", "observed_at", "src_ip", "dst_ip", "proto"):
        error = _require_nonempty_str(obj, name)
        if error:
            return False, error

    observed_at, error = _parse_and_check_skew(obj["observed_at"], now=now)
    if error:
        return False, error

    try:
        src_ip = normalize("ip", obj["src_ip"])
        dst_ip = normalize("ip", obj["dst_ip"])
    except NormalizationError as exc:
        return False, f"invalid ip: {exc}"

    for name in ("src_port", "dst_port"):
        value = obj[name]
        if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 65535):
            return False, f"invalid port: {name}"

    for name in ("bytes", "packets"):
        value = obj[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return False, f"invalid counter: {name}"

    entities = [
        {"type": "ip", "value": src_ip, "entity_key": entity_key("ip", src_ip).hex()},
        {"type": "ip", "value": dst_ip, "entity_key": entity_key("ip", dst_ip).hex()},
    ]
    return True, {
        "event_id": obj["event_id"],
        "edge_id": obj["edge_id"],
        "kind": "flow",
        "observed_at": to_rfc3339(observed_at),
        "entities": entities,
        "raw": dict(obj),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": obj["src_port"],
        "dst_port": obj["dst_port"],
        "proto": obj["proto"],
        "bytes": obj["bytes"],
        "packets": obj["packets"],
    }


def validate_reaction_line(line: str, *, now: datetime) -> Result:
    size_error = _check_size(line)
    if size_error:
        return False, size_error
    try:
        obj = _parse_object(line)
    except (json.JSONDecodeError, ValueError) as exc:
        return False, f"invalid json: {exc}"

    required = (
        "edge_id",
        "actor_key",
        "action_applied",
        "applied_at",
        "reaction",
        "reaction_window_s",
        "evidence_refs",
    )
    error = _require_fields(obj, required)
    if error:
        return False, error

    for name in ("edge_id", "actor_key"):
        error = _require_nonempty_str(obj, name)
        if error:
            return False, error

    if obj["action_applied"] not in ACTION_APPLIED_ENUM:
        return False, f"unknown action_applied: {obj['action_applied']!r}"
    if obj["reaction"] not in REACTION_ENUM:
        return False, f"unknown reaction: {obj['reaction']!r}"

    try:
        applied_at = parse_rfc3339(obj["applied_at"])
    except (ValueError, TypeError) as exc:
        return False, f"invalid applied_at: {exc}"

    window = obj["reaction_window_s"]
    if not isinstance(window, int) or isinstance(window, bool) or window <= 0:
        return False, "reaction_window_s must be a positive integer"

    evidence_refs = obj["evidence_refs"]
    if not isinstance(evidence_refs, list) or not evidence_refs:
        return False, "evidence_refs must be a non-empty list"
    if not all(isinstance(ref, (str, int)) for ref in evidence_refs):
        return False, "evidence_refs entries must be strings or integers"

    advisory_id = obj.get("advisory_id")
    if advisory_id is not None and not isinstance(advisory_id, str):
        return False, "advisory_id must be a string when present"

    actor_cluster_key, error = _optional_string(obj, "actor_cluster_key")
    if error:
        return False, error
    action_profile, error = _optional_string(obj, "action_profile")
    if error:
        return False, error
    decoy_profile, error = _optional_string(obj, "decoy_profile")
    if error:
        return False, error
    timeout_adaptation, error = _optional_string(obj, "timeout_adaptation")
    if error:
        return False, error
    retry_interval_ms, error = _optional_nonnegative_int(obj, "retry_interval_ms")
    if error:
        return False, error
    decoy_touched, error = _optional_decoy_touched(obj)
    if error:
        return False, error

    raw_refs = obj.get("raw_refs")
    if raw_refs is not None and not isinstance(raw_refs, list):
        return False, "raw_refs must be a list when present"

    known_fields = set(required) | {
        "advisory_id",
        *_PHASE2_PROMOTED_FIELDS,
        *_PHASE2_PAYLOAD_FIELDS,
    }
    payload_ext: dict[str, Any] = {}
    if "pre_action_summary" in obj:
        payload_ext["pre_action_summary"] = obj["pre_action_summary"]
    if "post_action_summary" in obj:
        payload_ext["post_action_summary"] = obj["post_action_summary"]
    if raw_refs is not None:
        payload_ext["raw_refs"] = raw_refs
    for key, value in obj.items():
        if key not in known_fields:
            payload_ext[key] = value

    return True, {
        "edge_id": obj["edge_id"],
        "actor_key": obj["actor_key"],
        "action_applied": obj["action_applied"],
        "applied_at": to_rfc3339(applied_at),
        "reaction": obj["reaction"],
        "reaction_window_s": window,
        "evidence_refs": [str(ref) for ref in evidence_refs],
        "advisory_id": advisory_id,
        "actor_cluster_key": actor_cluster_key,
        "action_profile": action_profile,
        "decoy_touched": decoy_touched,
        "decoy_profile": decoy_profile,
        "retry_interval_ms": retry_interval_ms,
        "timeout_adaptation": timeout_adaptation,
        "payload_ext": payload_ext,
    }
