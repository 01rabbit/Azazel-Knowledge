"""STIX 2.1 boundary mapping (docs/data-model.md's mapping table).

Pure, dict-in/dict-out. Internal storage is never STIX; these functions
run only at import/export boundaries (bundle build/import now, the TAXII
inbox later). STIX ids are deterministic (`uuid5` over the same
`entity_key` used elsewhere in the codebase) so re-mapping the same
native row twice yields the same STIX id.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from azazel_grimoire.db.repository import entity_key

STIX_SPEC_VERSION = "2.1"
_NAMESPACE = uuid.UUID("2f6a5a2e-8b8a-4c9a-9e2c-9b6a2f6a5a2e")

# (native ioc type) -> (STIX cyber-observable object type, field path).
# Types with no standard STIX observable (ja3/ja4, azazel-specific) use a
# custom `x-azazel-*` object type, kept round-trippable via the same
# generic pattern grammar as the standard ones.
_TYPE_TO_STIX: dict[str, tuple[str, str]] = {
    "ip": ("ipv4-addr", "value"),
    "ipv6": ("ipv6-addr", "value"),
    "domain": ("domain-name", "value"),
    "url": ("url", "value"),
    "email": ("email-addr", "value"),
    "asn": ("autonomous-system", "number"),
    "hash_md5": ("file", "hashes.MD5"),
    "hash_sha1": ("file", "hashes.'SHA-1'"),
    "hash_sha256": ("file", "hashes.'SHA-256'"),
    "certificate": ("x509-certificate", "hashes.'SHA-256'"),
    "ja3": ("x-azazel-ja3", "value"),
    "ja4": ("x-azazel-ja4", "value"),
}
_STIX_TO_TYPE: dict[tuple[str, str], str] = {v: k for k, v in _TYPE_TO_STIX.items()}

_PATTERN_RE = re.compile(r"^\[(?P<obj>[\w.\-]+):(?P<field>[\w.\'\-]+) = '(?P<value>[^']*)'\]$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _stix_id(stix_type: str, key: bytes) -> str:
    return f"{stix_type}--{uuid.uuid5(_NAMESPACE, key.hex())}"


def _ioc_pattern(type_: str, value: str) -> str:
    stix_type, field = _TYPE_TO_STIX.get(type_, (f"x-azazel-{type_}", "value"))
    return f"[{stix_type}:{field} = '{value}']"


def _pattern_to_ioc(pattern: str) -> tuple[str, str]:
    match = _PATTERN_RE.match(pattern.strip())
    if not match:
        raise ValueError(f"unrecognized STIX pattern: {pattern!r}")
    obj, field, value = match["obj"], match["field"], match["value"]
    if obj.startswith("x-azazel-"):
        return obj[len("x-azazel-"):], value
    native_type = _STIX_TO_TYPE.get((obj, field))
    if native_type is None:
        raise ValueError(f"unrecognized STIX object/field: {obj}:{field}")
    return native_type, value


def ioc_to_indicator(row: dict[str, Any]) -> dict[str, Any]:
    type_, value = row["type"], row["value"]
    key = entity_key(type_, value)
    first_seen = row.get("first_seen") or _now()
    last_seen = row.get("last_seen") or first_seen
    return {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": _stix_id("indicator", key),
        "created": first_seen,
        "modified": last_seen,
        "valid_from": first_seen,
        "pattern_type": "stix",
        "pattern": _ioc_pattern(type_, value),
        "labels": list(row.get("tags", []) or []),
        "confidence": row.get("agg_raw_confidence"),
    }


def indicator_to_ioc(stix_obj: dict[str, Any]) -> dict[str, Any]:
    if stix_obj.get("type") != "indicator":
        raise ValueError(f"not an indicator: {stix_obj.get('type')!r}")
    type_, value = _pattern_to_ioc(stix_obj["pattern"])
    return {
        "type": type_,
        "value": value,
        "first_seen": stix_obj.get("created") or stix_obj.get("valid_from"),
        "last_seen": stix_obj.get("modified") or stix_obj.get("created"),
        "tags": list(stix_obj.get("labels", []) or []),
        "agg_raw_confidence": stix_obj.get("confidence"),
    }


def reaction_to_observed_data(row: dict[str, Any]) -> dict[str, Any]:
    applied_at = row["applied_at"]
    key = entity_key("reaction-actor", row["actor_key"])
    extension = {
        "edge_id": row["edge_id"],
        "actor_key": row["actor_key"],
        "action_applied": row["action_applied"],
        "reaction": row["reaction"],
        "reaction_window_s": row["reaction_window_s"],
        "events_in_window": row.get("events_in_window", 0),
        "classifier": row["classifier"],
        "classifier_version": row["classifier_version"],
        "evidence_refs": list(row.get("evidence_refs", []) or []),
        "evidence_modality_count": row.get("evidence_modality_count", 0),
        "trust_tier": row.get("trust_tier", "provisional"),
        "advisory_id": row.get("advisory_id"),
        "advisory_linkage": row.get("advisory_linkage", "none"),
    }
    return {
        "type": "observed-data",
        "spec_version": STIX_SPEC_VERSION,
        "id": _stix_id("observed-data", key),
        "created": applied_at,
        "modified": applied_at,
        "first_observed": applied_at,
        "last_observed": applied_at,
        "number_observed": 1,
        "object_refs": [],
        "extensions": {"x-azazel-reaction": extension},
    }


def observed_data_to_reaction(stix_obj: dict[str, Any]) -> dict[str, Any]:
    if stix_obj.get("type") != "observed-data":
        raise ValueError(f"not observed-data: {stix_obj.get('type')!r}")
    extension = stix_obj.get("extensions", {}).get("x-azazel-reaction")
    if extension is None:
        raise ValueError("observed-data missing x-azazel-reaction extension")
    row = dict(extension)
    row["applied_at"] = stix_obj.get("first_observed") or stix_obj.get("created")
    return row


def rule_draft_to_course_of_action(row: dict[str, Any]) -> dict[str, Any]:
    key = entity_key("rule_draft", row["sid"])
    created_at = row.get("created_at") or _now()
    return {
        "type": "course-of-action",
        "spec_version": STIX_SPEC_VERSION,
        "id": _stix_id("course-of-action", key),
        "created": created_at,
        "modified": created_at,
        "name": row["sid"],
        "description": row.get("content", ""),
        "x_azazel_format": row.get("format"),
        "x_azazel_status": row.get("status", "draft"),
        "x_azazel_confidence": row.get("confidence"),
    }


_NATIVE_TO_STIX = {
    "ioc": ioc_to_indicator,
    "reaction": reaction_to_observed_data,
    "rule_draft": rule_draft_to_course_of_action,
}
_STIX_TYPE_TO_NATIVE = {
    "indicator": indicator_to_ioc,
    "observed-data": observed_data_to_reaction,
}


def native_to_stix(kind: str, row: dict[str, Any]) -> dict[str, Any]:
    try:
        mapper = _NATIVE_TO_STIX[kind]
    except KeyError as exc:
        raise ValueError(f"no native_to_stix mapping for kind {kind!r}") from exc
    return mapper(row)


def stix_to_native(stix_obj: dict[str, Any]) -> dict[str, Any]:
    stix_type = stix_obj.get("type")
    try:
        mapper = _STIX_TYPE_TO_NATIVE[stix_type]
    except KeyError as exc:
        raise ValueError(f"no stix_to_native mapping for STIX type {stix_type!r}") from exc
    return mapper(stix_obj)
