"""MITRE ATT&CK enterprise STIX 2.1 bundle flattening (design S6).

Pure functions over an already-JSON-decoded STIX bundle: no I/O, no DB
access, so the flatten step is independently unit-testable from the
`attack` feed adapter that drives it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

MITRE_ATTACK_SOURCE = "mitre-attack"


@dataclass(frozen=True)
class FlatTechnique:
    technique_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_technique_id: str | None
    description: str | None
    data_sources: list[str]
    platforms: list[str]


@dataclass(frozen=True)
class FlatMitigation:
    mitigation_id: str
    name: str
    description: str | None


@dataclass(frozen=True)
class FlatRelation:
    source_id: str
    source_type: str | None
    relation_type: str
    target_id: str
    target_type: str | None


@dataclass(frozen=True)
class FlattenedAttack:
    attack_version: str
    techniques: list[FlatTechnique] = field(default_factory=list)
    mitigations: list[FlatMitigation] = field(default_factory=list)
    relations: list[FlatRelation] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.techniques) + len(self.mitigations) + len(self.relations)


def _external_id(obj: Mapping[str, Any]) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == MITRE_ATTACK_SOURCE and ref.get("external_id"):
            return ref["external_id"]
    return None


def _resolve_version(objects: list[Mapping[str, Any]], version_override: str | None) -> str:
    if version_override:
        return str(version_override)
    for obj in objects:
        if obj.get("type") == "x-mitre-collection" and obj.get("x_mitre_version"):
            return str(obj["x_mitre_version"])
    return "unknown"


def _is_revoked_or_deprecated(obj: Mapping[str, Any]) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def flatten(bundle: Mapping[str, Any], version_override: str | None = None) -> FlattenedAttack:
    if bundle.get("type") != "bundle":
        raise ValueError("expected a STIX 2.1 'bundle' object")
    objects: list[Mapping[str, Any]] = list(bundle.get("objects", []) or [])
    version = _resolve_version(objects, version_override)

    stix_id_to_external: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") in ("attack-pattern", "course-of-action") and not _is_revoked_or_deprecated(obj):
            ext_id = _external_id(obj)
            if ext_id and obj.get("id"):
                stix_id_to_external[obj["id"]] = ext_id

    techniques: list[FlatTechnique] = []
    mitigations: list[FlatMitigation] = []
    relations: list[FlatRelation] = []

    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "attack-pattern":
            if _is_revoked_or_deprecated(obj):
                continue
            ext_id = _external_id(obj)
            if not ext_id:
                continue
            tactics = sorted(
                {
                    phase.get("phase_name")
                    for phase in obj.get("kill_chain_phases", []) or []
                    if phase.get("kill_chain_name") == MITRE_ATTACK_SOURCE and phase.get("phase_name")
                }
            )
            is_sub = bool(obj.get("x_mitre_is_subtechnique")) or "." in ext_id
            parent_id = ext_id.split(".")[0] if is_sub and "." in ext_id else None
            techniques.append(
                FlatTechnique(
                    technique_id=ext_id,
                    name=obj.get("name", ""),
                    tactics=tactics,
                    is_subtechnique=is_sub,
                    parent_technique_id=parent_id,
                    description=obj.get("description"),
                    data_sources=list(obj.get("x_mitre_data_sources", []) or []),
                    platforms=list(obj.get("x_mitre_platforms", []) or []),
                )
            )
        elif obj_type == "course-of-action":
            ext_id = _external_id(obj)
            if not ext_id:
                continue
            mitigations.append(
                FlatMitigation(
                    mitigation_id=ext_id,
                    name=obj.get("name", ""),
                    description=obj.get("description"),
                )
            )
        elif obj_type == "relationship":
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            relations.append(
                FlatRelation(
                    source_id=stix_id_to_external.get(src, src),
                    source_type=src.split("--", 1)[0] if "--" in src else None,
                    relation_type=obj.get("relationship_type", ""),
                    target_id=stix_id_to_external.get(tgt, tgt),
                    target_type=tgt.split("--", 1)[0] if "--" in tgt else None,
                )
            )

    return FlattenedAttack(attack_version=version, techniques=techniques, mitigations=mitigations, relations=relations)
