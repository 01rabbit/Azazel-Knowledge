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

from azazel_knowledge.core.clock import parse_rfc3339, to_rfc3339
from azazel_knowledge.db.repository import entity_key
from azazel_knowledge.normalize.ioc import NormalizationError, normalize

MAX_LINE_BYTES = 64 * 1024
MAX_SKEW = timedelta(hours=48)

# Untrusted-string bound for AZ-06 deception observations. Every string field
# on an InteractionObservation is attacker-influenceable (lure ids, evidence
# refs, metadata values are authored inside a live decoy). They are treated as
# opaque data -- never evaluated/executed -- and length-bounded so a single
# oversized field cannot bloat a row (the whole line is also capped at
# MAX_LINE_BYTES). See docs/azazel-deception-effectiveness.md (claim boundary).
MAX_OBS_STR_BYTES = 4096
MAX_OBS_LIST_LEN = 256

# Mirror of azazel_fabric.deception_contracts honesty-ladder enums. Fabric is
# import-confined to api/contracts.py (ADR-0010/0011); this framework-free drain
# validator therefore mirrors the closed sets structurally, exactly as
# validate_event_line/validate_reaction_line mirror the Cti* shapes without
# importing Fabric.
OBSERVATION_CLASS_ENUM = frozenset({"interaction", "reaction", "outcome"})
INTERACTION_SURFACE_ENUM = frozenset(
    {
        "service",
        "port",
        "file",
        "document",
        "credential_lure",
        "config_breadcrumb",
        "service_history",
        "persona_artifact",
        "unknown",
    }
)
REACTION_KIND_ENUM = frozenset(
    {
        "read",
        "enumerate",
        "authenticate",
        "lateral_move",
        "exfiltrate",
        "modify",
        "execute",
        "escalate",
        "unknown",
    }
)
CONFOUNDER_TAG_ENUM = frozenset(
    {
        "scanner_noise",
        "internal_health_check",
        "heartbeat_traffic",
        "host_capacity",
        "architecture_context",
        "replayed_traffic",
        "unknown",
    }
)
OBS_ARCHITECTURE_ENUM = frozenset({"arm64", "amd64"})
OBS_RUNTIME_ADAPTER_ENUM = frozenset(
    {"docker_compose", "podman", "kvm_libvirt", "k3s"}
)

# Mirror of azazel_fabric.deception_contracts.validation.BANNED_EFFECTIVENESS_
# VERDICT_FIELDS. A fact-only observation must never carry a belief/verdict/
# effectiveness field -- that is a layer-4 inference (Knowledge's advisory
# output), not an observed fact (interaction does not prove attacker belief).
BANNED_OBS_VERDICT_FIELDS = frozenset(
    {
        "attacker_believed",
        "believed",
        "belief",
        "belief_score",
        "deceived",
        "fooled",
        "convinced",
        "is_effective",
        "effective",
        "effectiveness_score",
        "success_score",
        "confidence",
    }
)

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


def _bounded_str(
    obj: Mapping[str, Any], name: str, *, required: bool
) -> tuple[str | None, str | None]:
    value = obj.get(name)
    if value is None:
        if required:
            return None, f"missing field: {name}"
        return None, None
    if not isinstance(value, str) or (required and not value.strip()):
        return None, f"invalid field: {name}"
    if len(value.encode("utf-8")) > MAX_OBS_STR_BYTES:
        return None, f"{name} exceeds {MAX_OBS_STR_BYTES} bytes"
    return value, None


def _bounded_str_list(
    obj: Mapping[str, Any], name: str
) -> tuple[list[str], str | None]:
    value = obj.get(name)
    if value is None:
        return [], None
    if not isinstance(value, list):
        return [], f"{name} must be a list when present"
    if len(value) > MAX_OBS_LIST_LEN:
        return [], f"{name} exceeds {MAX_OBS_LIST_LEN} entries"
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return [], f"{name} entries must be strings"
        if len(item.encode("utf-8")) > MAX_OBS_STR_BYTES:
            return [], f"{name} entry exceeds {MAX_OBS_STR_BYTES} bytes"
        out.append(item)
    return out, None


def _enum_list(
    obj: Mapping[str, Any], name: str, allowed: frozenset[str]
) -> tuple[list[str], str | None]:
    values, error = _bounded_str_list(obj, name)
    if error:
        return [], error
    for item in values:
        if item not in allowed:
            return [], f"unknown {name} value: {item!r}"
    return values, None


def _validate_runtime_context(
    value: Any,
) -> tuple[dict[str, Any] | None, str | None]:
    """Structural mirror of Fabric RuntimeContext (descriptive, no directives)."""
    if value is None:
        return None, None
    if not isinstance(value, Mapping):
        return None, "runtime_context must be an object when present"
    tier = value.get("selected_tier")
    if not isinstance(tier, str) or not tier.strip():
        return None, "runtime_context.selected_tier is required"
    if len(tier.encode("utf-8")) > MAX_OBS_STR_BYTES:
        return None, "runtime_context.selected_tier too long"
    arch = value.get("architecture")
    if arch not in OBS_ARCHITECTURE_ENUM:
        return None, f"runtime_context.architecture invalid: {arch!r}"
    adapter = value.get("runtime_adapter")
    if adapter not in OBS_RUNTIME_ADAPTER_ENUM:
        return None, f"runtime_context.runtime_adapter invalid: {adapter!r}"

    out: dict[str, Any] = {
        "selected_tier": tier,
        "architecture": arch,
        "runtime_adapter": adapter,
    }
    for list_field in ("active_components", "omitted_components", "capability_drift"):
        items, error = _enum_list_free(value, list_field)
        if error:
            return None, f"runtime_context.{error}"
        out[list_field] = items

    saturation = value.get("resource_saturation")
    if saturation is not None:
        if not isinstance(saturation, Mapping):
            return None, "runtime_context.resource_saturation must be an object"
        parsed_sat: dict[str, float] = {}
        for key, frac in saturation.items():
            if not isinstance(key, str) or isinstance(frac, bool) or not isinstance(frac, (int, float)):
                return None, "runtime_context.resource_saturation must map str->number"
            parsed_sat[key] = float(frac)
        out["resource_saturation"] = parsed_sat
    else:
        out["resource_saturation"] = None
    return out, None


def _enum_list_free(obj: Mapping[str, Any], name: str) -> tuple[list[str], str | None]:
    values, error = _bounded_str_list(obj, name)
    if error:
        return [], f"{name}: {error}"
    return values, None


def _extract_linkage(obj: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Pull edge_id/actor_key linkage from metadata (Edge-stamped, optional).

    Returns (edge_id, actor_key, error). Never synthesised: absent -> None.
    """
    metadata = obj.get("metadata")
    if metadata is None:
        return None, None, None
    if not isinstance(metadata, Mapping):
        return None, None, "metadata must be an object when present"
    edge_id = metadata.get("edge_id")
    actor_key = metadata.get("actor_key")
    for label, candidate in (("edge_id", edge_id), ("actor_key", actor_key)):
        if candidate is not None and (
            not isinstance(candidate, str)
            or len(candidate.encode("utf-8")) > MAX_OBS_STR_BYTES
        ):
            return None, None, f"metadata.{label} must be a bounded string"
    return (
        edge_id if isinstance(edge_id, str) and edge_id.strip() else None,
        actor_key if isinstance(actor_key, str) and actor_key.strip() else None,
        None,
    )


def validate_deception_observation_line(line: str, *, now: datetime) -> Result:
    """Validate one AZ-06 InteractionObservation JSONL line (design F-1, ADR-0011).

    Framework-free structural mirror of Fabric InteractionObservation. Every
    string field is untrusted attacker-authored content: it is length-bounded
    and stored as opaque data, never evaluated or executed. Fact-only honesty
    is enforced -- a belief/verdict/effectiveness field anywhere in the line is
    rejected (interaction does not prove attacker belief; that is layer-4).
    A bad line is quarantined at drain, never failing the batch (design S4).
    """
    size_error = _check_size(line)
    if size_error:
        return False, size_error
    try:
        obj = _parse_object(line)
    except (json.JSONDecodeError, ValueError) as exc:
        return False, f"invalid json: {exc}"

    # Honesty invariant: no belief/verdict/effectiveness field, anywhere.
    if _contains_banned_verdict(obj):
        return False, (
            "belief/verdict/effectiveness field not permitted on a fact-only "
            "observation (interaction does not prove attacker belief)"
        )

    authority = obj.get("authority")
    if authority is not None and authority != "descriptive_only":
        return False, "authority must be 'descriptive_only' when present"

    observation_uid, error = _bounded_str(obj, "observation_id", required=True)
    if error:
        return False, error
    environment_id, error = _bounded_str(obj, "environment_id", required=True)
    if error:
        return False, error
    package_id, error = _bounded_str(obj, "package_id", required=True)
    if error:
        return False, error
    node_id, error = _bounded_str(obj, "node_id", required=True)
    if error:
        return False, error

    observed_at, error = _parse_and_check_skew(obj.get("observed_at"), now=now)
    if error:
        return False, error

    observation_class = obj.get("observation_class")
    if observation_class not in OBSERVATION_CLASS_ENUM:
        return False, f"unknown observation_class: {observation_class!r}"
    surface = obj.get("surface")
    if surface not in INTERACTION_SURFACE_ENUM:
        return False, f"unknown surface: {surface!r}"

    reaction_kind = obj.get("reaction_kind")
    if reaction_kind is not None:
        if reaction_kind not in REACTION_KIND_ENUM:
            return False, f"unknown reaction_kind: {reaction_kind!r}"
        # Fabric model invariant: pure interaction is contact-only.
        if observation_class == "interaction":
            return False, (
                "observation_class 'interaction' cannot carry a reaction_kind"
            )

    lure_id, error = _bounded_str(obj, "lure_id", required=False)
    if error:
        return False, error

    latencies: dict[str, int | None] = {}
    for name in ("first_contact_latency_ms", "dwell_ms", "attempt_count"):
        value, error = _optional_nonnegative_int(obj, name)
        if error:
            return False, error
        latencies[name] = value

    confounder_tags, error = _enum_list(obj, "confounder_tags", CONFOUNDER_TAG_ENUM)
    if error:
        return False, error

    runtime_context, error = _validate_runtime_context(obj.get("runtime_context"))
    if error:
        return False, error

    evidence_refs, error = _bounded_str_list(obj, "evidence_refs")
    if error:
        return False, error

    edge_id, actor_key, error = _extract_linkage(obj)
    if error:
        return False, error

    return True, {
        "observation_uid": observation_uid,
        "environment_id": environment_id,
        "package_id": package_id,
        "node_id": node_id,
        "edge_id": edge_id,
        "actor_key": actor_key,
        "observed_at": to_rfc3339(observed_at),
        "observation_class": observation_class,
        "surface": surface,
        "reaction_kind": reaction_kind,
        "lure_id": lure_id,
        "first_contact_latency_ms": latencies["first_contact_latency_ms"],
        "dwell_ms": latencies["dwell_ms"],
        "attempt_count": latencies["attempt_count"],
        "confounder_tags": confounder_tags,
        "runtime_context": runtime_context,
        "evidence_refs": evidence_refs,
        "raw": dict(obj),
    }


def _contains_banned_verdict(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key) in BANNED_OBS_VERDICT_FIELDS:
                return True
            if _contains_banned_verdict(nested):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_banned_verdict(item) for item in value)
    return False
