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
from azazel_knowledge.db.outcome_memory import OutcomeMemoryError, validate_outcome_fact
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


# Mirror of azazel_fabric.deception_contracts BANNED_RUNTIME_DIRECTIVE_FIELDS.
# Same reason as BANNED_OBS_VERDICT_FIELDS above: Fabric is import-confined to
# api/contracts.py (ADR-0010/0011), so this framework-free drain validator
# mirrors the closed set structurally. A record of a completed action must
# never carry an instruction to perform one.
BANNED_RECORD_DIRECTIVE_FIELDS = frozenset(
    {
        "command",
        "cmd",
        "shell",
        "shell_command",
        "exec",
        "execute",
        "execute_now",
        "run",
        "script",
        "nft_rule",
        "iptables_rule",
        "firewall_rule",
        "route",
        "handler",
        "callback",
        "bypass_arbiter",
        "override",
        "must_execute",
        "required_action",
        "directive",
    }
)


def _contains_banned_directive(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key) in BANNED_RECORD_DIRECTIVE_FIELDS:
                return True
            if _contains_banned_directive(nested):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_banned_directive(item) for item in value)
    return False


# Engage vocabulary, mirrored structurally rather than imported.
#
# Fabric is import-confined to `api/contracts.py` (ADR-0010/0011), so this
# framework-free drain validator mirrors the closed sets the same way
# `validate_reaction_line` mirrors the Cti* shapes. The envelope at the API
# boundary already type-enforced every item against the canonical model; this
# is the second line, for a line that reached the spool by another route.
#
# These are deliberately NOT mapped onto `ACTION_APPLIED_ENUM`. Three values
# coincide (`throttle`, `redirect`, `isolate`) and five do not; deciding that
# `redirect_to_decoy` "is" `deception` would invent a mapping between two
# product vocabularies, which `correlate/engagement_advisory.py` already
# refuses in the other direction.
ENGAGEMENT_OBJECTIVE_ENUM = frozenset(
    {"collect", "detect", "prevent", "direct", "disrupt", "reassure"}
)
ENGAGEMENT_APPROACH_ENUM = frozenset(
    {"channel", "collect", "detect", "prevent", "disrupt", "reassure"}
)
ENGAGEMENT_ACTIVITY_ENUM = frozenset(
    {
        "observe",
        "notify",
        "throttle",
        "redirect",
        "isolate",
        "redirect_to_decoy",
        "expose_decoy_surface",
        "collect_credentials",
    }
)
ENGAGEMENT_REACTION_ENUM = frozenset(
    {
        "decoy_engaged",
        "followed_decoy",
        "continued_scanning",
        "continued_slowed",
        "shifted_port",
        "shifted_protocol",
        "shifted_target",
        "auth_pattern_changed",
        "escalated",
        "disengaged",
        "unknown",
    }
)


def validate_engagement_event_line(line: str, *, now: datetime) -> Result:
    """Validate one Azazel-Edge `EngagementEvent` JSONL line (Fabric#23 R1c).

    An engagement event is a *record of something already done*: what the
    producer selected and the reaction it observed. Knowledge stores it as a
    fact and reaches its own conclusions elsewhere -- reading somebody else's
    selection is not selecting.

    Two fields the Fabric contract does not model, `_envelope_edge_id` and
    `_envelope_actor_key`, are required here because they are what makes a row
    attributable. The API boundary folds them on from the batch envelope; the
    underscore prefix keeps them distinguishable from anything the producer
    sent under those names.
    """

    size_error = _check_size(line)
    if size_error:
        return False, size_error
    try:
        obj = _parse_object(line)
    except (json.JSONDecodeError, ValueError) as exc:
        return False, f"invalid json: {exc}"

    # A record of a completed action has no business carrying an instruction.
    if _contains_banned_directive(obj):
        return False, "runtime-directive field not permitted on an engagement event"

    required = (
        "schema_version",
        "event_id",
        "product",
        "objective",
        "approach",
        "activity",
        "_envelope_edge_id",
        "_envelope_actor_key",
    )
    error = _require_fields(obj, required)
    if error:
        return False, error

    if obj["schema_version"] != "engagement-event/v0.1":
        return False, f"unknown schema_version: {obj['schema_version']!r}"

    for name in ("event_id", "product", "_envelope_edge_id", "_envelope_actor_key"):
        error = _require_nonempty_str(obj, name)
        if error:
            return False, error

    for name, allowed in (
        ("objective", ENGAGEMENT_OBJECTIVE_ENUM),
        ("approach", ENGAGEMENT_APPROACH_ENUM),
        ("activity", ENGAGEMENT_ACTIVITY_ENUM),
    ):
        if obj[name] not in allowed:
            return False, f"unknown {name}: {obj[name]!r}"

    outcome = obj.get("outcome")
    if outcome is not None:
        if not isinstance(outcome, Mapping):
            return False, "outcome must be an object when present"
        reaction = outcome.get("attacker_reaction")
        if reaction is not None and reaction not in ENGAGEMENT_REACTION_ENUM:
            return False, f"unknown attacker_reaction: {reaction!r}"
        window = outcome.get("reaction_window_s")
        if window is not None and (not isinstance(window, int) or isinstance(window, bool)):
            return False, "reaction_window_s must be an integer when present"
        for stamp in ("started_at", "ended_at"):
            value = outcome.get(stamp)
            if value is None:
                continue
            try:
                parse_rfc3339(value)
            except (ValueError, TypeError) as exc:
                return False, f"invalid {stamp}: {exc}"

    refs = obj.get("evidence_refs", [])
    if not isinstance(refs, list):
        return False, "evidence_refs must be a list"

    outcome = outcome if isinstance(outcome, Mapping) else {}
    return True, {
        "event_ref": obj["event_id"],
        "product": obj["product"],
        "edge_id": obj["_envelope_edge_id"],
        "actor_key": obj["_envelope_actor_key"],
        "objective": obj["objective"],
        "approach": obj["approach"],
        "activity": obj["activity"],
        # Absent stays absent. An engagement whose outcome is not yet known is
        # a real state, and a placeholder would be indistinguishable from an
        # observation that the attacker did nothing.
        "attacker_reaction": outcome.get("attacker_reaction"),
        "reaction_window_s": outcome.get("reaction_window_s"),
        "started_at": outcome.get("started_at"),
        "ended_at": outcome.get("ended_at"),
        "termination_reason": outcome.get("termination_reason"),
        "evidence_refs": refs,
        "schema_version": obj["schema_version"],
        "raw": dict(obj),
    }


def validate_outcome_evidence_line(line: str, *, now: datetime) -> Result:
    """Validate one Outcome-as-Evidence fact (Fabric `outcome_contracts`, R1c).

    The shape rules live in `db/outcome_memory.validate_outcome_fact`, not
    here. Writing a second copy of them in this file is precisely the drift
    this lane exists to avoid: `outcome_memory` already states the four
    records field-for-field because it has to build the INSERTs, and
    `tests/unit/test_outcome_contract_drift.py` pins *that* statement against
    Fabric's models. A mirror in this module would be a third statement, and
    the guard pins only two.

    `now` is accepted for signature parity with the other validators and is
    deliberately unused: an outcome fact's `observed_at` is a producer fact
    about a window that has already closed, and rejecting one for arriving
    outside a skew bound would silently drop late evidence -- the batches most
    worth keeping, since they are the ones a degraded or reconnecting node
    sent. The chain checks that *do* constrain a fact (does the referenced
    execution exist, does it share the trace) need stored rows and run in
    `ingest_outcome_fact` at write time.

    Returns the fact itself as the normalized row: `ingest_outcome_fact`
    consumes the canonical payload, so re-keying it here would mean unpacking
    and repacking the very bytes whose identity is being preserved.
    """

    del now  # see docstring: not a skew-bounded lane
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        return False, "line exceeds maximum size"
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        return False, f"invalid json: {exc}"
    if not isinstance(obj, dict):
        return False, "line must be a JSON object"
    try:
        validate_outcome_fact(obj)
    except OutcomeMemoryError as exc:
        return False, str(exc)
    return True, obj


# --------------------------------------------------------------------------
# AZ-06 outcome envelope (Deception#55 / Knowledge#111 G7)
# --------------------------------------------------------------------------

# Mirrors of Fabric `effect_contracts` bounds and vocabularies, kept structural
# for the same reason as the sets above: Fabric is import-confined to the api
# extra and this validator runs in the worker. `tests/unit/
# test_deception_outcome_envelopes.py` pins these against the Fabric models.
OUTCOME_ENVELOPE_SCHEMA = "outcome-observation-envelope/v0.1"
EFFECT_OBSERVATION_SCHEMA = "effect-observation/v0.1"
OUTCOME_ENVELOPE_AUTHORITY_ENUM = frozenset({"observed_fact", "active_materialized"})
EFFECT_OBSERVATION_AUTHORITY_ENUM = frozenset({"observed_fact", "active_materialized"})
OUTCOME_ENVELOPE_LIST_MAX = 128

# Limitation / gap / confounder tokens are rendered into the effectiveness
# advisory that a downstream planner reads. Free prose in that position is an
# injection channel, so a token is held to an identifier-like charset: the
# producer's vocabulary (`telemetry_gap:process_events`, `stale`, ...) fits,
# a sentence does not.
_OUTCOME_TOKEN_MAX = 200
_OUTCOME_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@=+/~-"
)
_OUTCOME_REF_MAX = 256

_OUTCOME_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version", "envelope_id", "producer_product", "producer_node",
        "producer_version", "trace_id", "decision_ref", "effect_ref",
        "environment_ref", "presentation_ref", "actor_session_ref",
        "outcome_observation_refs", "window_start", "window_end",
        "observation_class", "telemetry_coverage", "coverage_complete",
        "telemetry_gaps", "confounders", "impact_observations", "evidence_refs",
        "provenance", "observed_at", "authority_class", "directive",
    }
)
_EFFECT_OBSERVATION_FIELDS = frozenset(
    {
        "schema_version", "observation_id", "effect_ref", "trace_id", "status",
        "observed_at", "materialization_producer", "execution_ref",
        "termination_reason", "evidence_refs", "limitations", "authority_class",
        "directive",
    }
)


def _outcome_str(obj: Mapping[str, Any], name: str, *, optional: bool = False) -> tuple[str | None, str | None]:
    value = obj.get(name)
    if value is None and optional:
        return None, None
    if not isinstance(value, str) or not value.strip():
        return None, f"{name} must be a non-empty string"
    if len(value) > _OUTCOME_REF_MAX:
        return None, f"{name} exceeds {_OUTCOME_REF_MAX} characters"
    return value, None


def _outcome_tokens(obj: Mapping[str, Any], name: str, *, charset: bool) -> tuple[list[str], str | None]:
    value = obj.get(name, [])
    if not isinstance(value, list):
        return [], f"{name} must be a list"
    if len(value) > OUTCOME_ENVELOPE_LIST_MAX:
        return [], f"{name} exceeds {OUTCOME_ENVELOPE_LIST_MAX} entries"
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return [], f"{name} entries must be non-empty strings"
        limit = _OUTCOME_TOKEN_MAX if charset else _OUTCOME_REF_MAX
        if len(item) > limit:
            return [], f"{name} entry exceeds {limit} characters"
        if charset and not set(item) <= _OUTCOME_TOKEN_CHARS:
            return [], f"{name} entry is not an identifier-like token"
    return list(value), None


def validate_deception_outcome_envelope_line(line: str, *, now: datetime) -> Result:
    """Validate one `{outcome, effect_observation}` pair (Deception#59 bundle).

    `now` is unused on purpose: an envelope describes a window that has already
    closed, and refusing one for arriving late would drop exactly the evidence
    a reconnecting node sends. Freshness is stated by the reader against its
    own pinned `query_as_of`; it is not decided here.

    The rules a row's CHECKs backstop -- `coverage_complete` agrees with
    `telemetry_gaps` in both directions -- are enforced here first, so a pair
    that contradicts itself is quarantined with a reason rather than failing an
    INSERT.
    """

    del now
    size_error = _check_size(line)
    if size_error:
        return False, size_error
    try:
        obj = _parse_object(line)
    except (json.JSONDecodeError, ValueError) as exc:
        return False, f"invalid json: {exc}"

    # Both Fabric models carry the literal `directive: false` as a field; that
    # one key is the contract saying "not a directive", so it is checked below
    # for being exactly `false` and left out of the banned-key walk. A
    # `directive` key anywhere deeper (a fact map) is still banned.
    scan = {
        k: ({kk: vv for kk, vv in v.items() if kk != "directive"} if k in ("outcome", "effect_observation") and isinstance(v, Mapping) else v)
        for k, v in obj.items()
    }
    if _contains_banned_directive(scan):
        return False, "runtime-directive field not permitted on an outcome envelope"
    if _contains_banned_verdict(obj):
        return False, "belief/verdict/effectiveness field not permitted on an outcome envelope"

    if set(obj) - {"environment_id", "package_id", "outcome", "effect_observation"}:
        return False, "unknown top-level fields"
    environment_id, error = _outcome_str(obj, "environment_id")
    if error:
        return False, error
    package_id, error = _outcome_str(obj, "package_id", optional=True)
    if error:
        return False, error
    env = obj.get("outcome")
    eff = obj.get("effect_observation")
    if not isinstance(env, Mapping) or not isinstance(eff, Mapping):
        return False, "outcome and effect_observation must be objects"
    if set(env) - _OUTCOME_ENVELOPE_FIELDS:
        return False, f"unknown outcome fields: {sorted(set(env) - _OUTCOME_ENVELOPE_FIELDS)}"
    if set(eff) - _EFFECT_OBSERVATION_FIELDS:
        return False, f"unknown effect_observation fields: {sorted(set(eff) - _EFFECT_OBSERVATION_FIELDS)}"
    if env.get("schema_version") != OUTCOME_ENVELOPE_SCHEMA:
        return False, f"unknown outcome schema_version: {env.get('schema_version')!r}"
    if eff.get("schema_version") != EFFECT_OBSERVATION_SCHEMA:
        return False, f"unknown effect_observation schema_version: {eff.get('schema_version')!r}"
    if env.get("directive") is not False or eff.get("directive") is not False:
        return False, "directive must be false"

    strings: dict[str, str | None] = {}
    for source, name, optional in (
        (env, "envelope_id", False), (env, "producer_product", False),
        (env, "producer_node", False), (env, "producer_version", False),
        (env, "trace_id", False), (env, "effect_ref", False),
        (env, "environment_ref", False), (env, "observation_class", False),
        (env, "decision_ref", True), (env, "presentation_ref", True),
        (eff, "observation_id", False), (eff, "effect_ref", False),
        (eff, "trace_id", False), (eff, "status", False),
        (eff, "materialization_producer", False),
        (eff, "termination_reason", True),
    ):
        value, error = _outcome_str(source, name, optional=optional)
        if error:
            return False, f"{'outcome' if source is env else 'effect_observation'}.{error}"
        strings[("o." if source is env else "e.") + name] = value

    if strings["o.environment_ref"] != f"environment:{environment_id}":
        return False, "outcome environment_ref is not the batch environment"
    if strings["e.effect_ref"] != strings["o.effect_ref"]:
        return False, "effect_observation belongs to a different effect"
    if strings["e.trace_id"] != strings["o.trace_id"]:
        return False, "effect_observation belongs to a different trace"
    if strings["e.materialization_producer"] != strings["o.producer_product"]:
        return False, "effect_observation was produced by a different product"

    if env.get("authority_class") not in OUTCOME_ENVELOPE_AUTHORITY_ENUM:
        return False, f"outcome authority_class not permitted: {env.get('authority_class')!r}"
    if eff.get("authority_class") not in EFFECT_OBSERVATION_AUTHORITY_ENUM:
        return False, f"effect_observation authority_class not permitted: {eff.get('authority_class')!r}"

    coverage_complete = env.get("coverage_complete")
    if not isinstance(coverage_complete, bool):
        return False, "coverage_complete must be a boolean"
    gaps, error = _outcome_tokens(env, "telemetry_gaps", charset=True)
    if error:
        return False, error
    if coverage_complete and gaps:
        return False, "coverage_complete is true but telemetry_gaps names gaps"
    if not coverage_complete and not gaps:
        return False, "coverage is incomplete but no telemetry_gaps are named"
    confounders, error = _outcome_tokens(env, "confounders", charset=True)
    if error:
        return False, error
    limitations, error = _outcome_tokens(eff, "limitations", charset=True)
    if error:
        return False, error
    evidence_refs, error = _outcome_tokens(env, "evidence_refs", charset=False)
    if error:
        return False, error
    _, error = _outcome_tokens(env, "outcome_observation_refs", charset=False)
    if error:
        return False, error
    _, error = _outcome_tokens(eff, "evidence_refs", charset=False)
    if error:
        return False, error

    for name in ("telemetry_coverage", "impact_observations"):
        if not isinstance(env.get(name, {}), Mapping):
            return False, f"{name} must be an object"

    try:
        window_start = parse_rfc3339(env["window_start"])
        window_end = parse_rfc3339(env["window_end"])
        observed = parse_rfc3339(env["observed_at"])
        parse_rfc3339(eff["observed_at"])
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        return False, f"invalid timestamp: {exc}"
    if window_end < window_start:
        return False, "window_end precedes window_start"

    return True, {
        "envelope_ref": strings["o.envelope_id"],
        "environment_id": environment_id,
        "package_id": package_id,
        "producer_product": strings["o.producer_product"],
        "producer_node": strings["o.producer_node"],
        "trace_id": strings["o.trace_id"],
        "decision_ref": strings["o.decision_ref"],
        "effect_ref": strings["o.effect_ref"],
        "presentation_ref": strings["o.presentation_ref"],
        "window_start": observed_utc(window_start),
        "window_end": observed_utc(window_end),
        "observation_class": strings["o.observation_class"],
        "coverage_complete": coverage_complete,
        "telemetry_coverage": dict(env.get("telemetry_coverage", {})),
        "telemetry_gaps": gaps,
        "confounders": confounders,
        "impact_observations": dict(env.get("impact_observations", {})),
        "evidence_refs": evidence_refs,
        "effect_observation_ref": strings["e.observation_id"],
        "effect_status": strings["e.status"],
        "termination_reason": strings["e.termination_reason"],
        "limitations": limitations,
        "observed_at": observed_utc(observed),
        "authority_class": env["authority_class"],
        "schema_version": env["schema_version"],
        "raw": dict(obj),
    }


def observed_utc(value: datetime) -> str:
    """Fixed-width UTC (microseconds, `Z`) so string order is time order."""

    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
