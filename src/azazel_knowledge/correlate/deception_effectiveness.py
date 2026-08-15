"""Deterministic AZ-06 deception-effectiveness summary (ADR-0011, design S5).

Reads the immutable `deception_observation` rows for one environment and folds
them into the field set of a Fabric ``EffectivenessAdvisory`` -- assessment,
confidence, counter-evidence, observation refs, unknowns -- as a plain dict.
The Fabric model itself is constructed at the API boundary
(`api/contracts.py`); this module stays framework-free and Fabric-free
(Absolute Constraint 7 / ADR-0010).

Determinism (Absolute Constraint 3): the result is a pure function of the
stored rows, the `deception_effectiveness` config block, `query_as_of`, and
`config_hash`. No wall-clock (`time.monotonic` is a budget guard only, exactly
as `correlate/pipeline.py` uses it), no randomness, no env, no file-order.
Same inputs -> byte-identical advisory (advisory_id and content_hash are hashes
of the inputs, produced_at is the pinned `query_as_of`).

Effectiveness boundary (docs/azazel-deception-effectiveness.md, binding):

* narrative effectiveness is separated from runtime/capacity effects -- omitted
  optional components and resource saturation are surfaced as counter-evidence,
  never read as narrative failure;
* attacker belief is never claimed from interaction alone -- it is always listed
  under `unknowns`;
* the vocabulary is the claim-boundary vocabulary (observed interaction /
  observed reaction / measured outcome / runtime-context confounder / suggested
  posture / unknown-insufficient-evidence).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from azazel_knowledge.core.clock import to_rfc3339

_LADDER_LAYERS = ("interaction", "reaction", "outcome")

# Conservative built-in defaults, used when the config block is absent. Kept in
# sync with config/scoring.yaml:deception_effectiveness.
_DEFAULT_CONFIDENCE = {
    "base": 0.0,
    "per_observation": 0.05,
    "max_observation_bonus": 0.4,
    "ladder_layer_bonus": 0.2,
    "confounder_penalty": 0.15,
    "floor": 0.0,
    "ceil": 1.0,
    "round_ndigits": 6,
}
_DEFAULT_MIN_OBSERVATIONS = 3
_DEFAULT_COUNTER_EVIDENCE_CONFOUNDERS = (
    "scanner_noise",
    "internal_health_check",
    "host_capacity",
)
_DEFAULT_SATURATION_THRESHOLD = 0.85


class DeceptionEffectivenessTimeout(Exception):
    """The summary exceeded its monotonic budget; fail closed (503)."""


@dataclass(frozen=True)
class EffectivenessSummary:
    advisory: dict[str, Any]
    content_hash: str


def _deadline_check(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() > deadline:
        raise DeceptionEffectivenessTimeout("effectiveness deadline exceeded")


def _loads_list(value: Any) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []


def _loads_obj(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _clamp_round(raw: float, cfg: Mapping[str, Any]) -> float:
    floor = float(cfg.get("floor", 0.0))
    ceil = float(cfg.get("ceil", 1.0))
    ndigits = int(cfg.get("round_ndigits", 6))
    return round(min(max(raw, floor), ceil), ndigits)


def summarize_effectiveness(
    conn: sqlite3.Connection,
    *,
    environment_id: str,
    package_id: str | None,
    config: Mapping[str, Any],
    query_as_of: datetime,
    config_hash: str,
    deadline: float | None = None,
) -> EffectivenessSummary:
    """Summarize stored deception observations into an EffectivenessAdvisory dict."""
    _deadline_check(deadline)

    conf_cfg = {**_DEFAULT_CONFIDENCE, **(config.get("confidence", {}) or {})}
    min_obs = int(config.get("insufficient_evidence_min_observations", _DEFAULT_MIN_OBSERVATIONS))
    counter_confounders = list(
        config.get("counter_evidence_confounders", _DEFAULT_COUNTER_EVIDENCE_CONFOUNDERS)
    )
    saturation_threshold = float(
        config.get("saturation_confounder_threshold", _DEFAULT_SATURATION_THRESHOLD)
    )

    params: list[Any] = [environment_id]
    where = "environment_id = ?"
    if package_id is not None:
        where += " AND package_id = ?"
        params.append(package_id)

    rows = conn.execute(
        "SELECT observation_uid, package_id, node_id, observed_at, observation_class, "
        "surface, reaction_kind, confounder_tags, runtime_context "
        f"FROM deception_observation WHERE {where} ORDER BY observation_uid ASC",
        params,
    ).fetchall()
    _deadline_check(deadline)

    n = len(rows)
    classes_present: set[str] = set()
    surfaces: set[str] = set()
    reaction_kinds: set[str] = set()
    distinct_confounders: set[str] = set()
    omitted_components: set[str] = set()
    saturated: set[str] = set()
    observation_refs: list[str] = []
    packages: set[str] = set()
    nodes: set[str] = set()

    for row in rows:
        (uid, pkg, node, _observed_at, klass, surface, reaction_kind,
         confounder_json, runtime_json) = row
        observation_refs.append(str(uid))
        packages.add(str(pkg))
        nodes.add(str(node))
        classes_present.add(str(klass))
        surfaces.add(str(surface))
        if reaction_kind:
            reaction_kinds.add(str(reaction_kind))
        for tag in _loads_list(confounder_json):
            distinct_confounders.add(tag)
        runtime = _loads_obj(runtime_json)
        for comp in runtime.get("omitted_components", []) or []:
            omitted_components.add(str(comp))
        saturation = runtime.get("resource_saturation") or {}
        if isinstance(saturation, dict):
            for resource, frac in saturation.items():
                try:
                    if float(frac) >= saturation_threshold:
                        saturated.add(str(resource))
                except (TypeError, ValueError):
                    continue

    layers_present = sum(1 for layer in _LADDER_LAYERS if layer in classes_present)

    raw_conf = (
        float(conf_cfg["base"])
        + min(float(conf_cfg["per_observation"]) * n, float(conf_cfg["max_observation_bonus"]))
        + float(conf_cfg["ladder_layer_bonus"]) * layers_present
        - float(conf_cfg["confounder_penalty"]) * len(distinct_confounders)
    )
    confidence = _clamp_round(raw_conf, conf_cfg)

    # --- counter-evidence: confounders (config order) then capacity notes ----
    counter_evidence: list[str] = []
    for tag in counter_confounders:
        if tag in distinct_confounders:
            counter_evidence.append(
                f"runtime/context confounder present: {tag} "
                "(subtract before claiming effectiveness)"
            )
    if omitted_components:
        counter_evidence.append(
            "omitted optional components ("
            + ", ".join(sorted(omitted_components))
            + ") -- early disengagement or missing interaction may be "
            "runtime/capacity-driven, not narrative failure"
        )
    if saturated:
        counter_evidence.append(
            "resource saturation at/above threshold ("
            + ", ".join(sorted(saturated))
            + ") -- capacity confounder, not a narrative-effectiveness signal"
        )

    # --- unknowns (insufficient evidence + belief boundary) ------------------
    unknowns: list[str] = []
    if n < min_obs:
        unknowns.append(
            f"insufficient evidence: only {n} observation(s) (< {min_obs} required)"
        )
    if "outcome" not in classes_present:
        unknowns.append(
            "no measured outcome recorded (dwell / attempts / resource-spend unknown)"
        )
    unknowns.append(
        "attacker belief unknown: interaction does not prove the attacker was deceived"
    )
    if omitted_components:
        unknowns.append(
            "narrative vs capacity effect not separable: components omitted ("
            + ", ".join(sorted(omitted_components))
            + ")"
        )

    # --- suggested posture (bounded, non-executable) -------------------------
    has_counter_confounder = any(t in distinct_confounders for t in counter_confounders)
    if n == 0:
        posture = "insufficient-evidence"
    elif has_counter_confounder:
        posture = "inconclusive-control-confounders"
    elif "outcome" in classes_present and confidence >= 0.5:
        posture = "sustained-engagement-observed"
    elif "reaction" in classes_present:
        posture = "engagement-observed"
    else:
        posture = "contact-only-observed"

    assessment = (
        f"Environment {environment_id}: {n} observation(s) across surfaces "
        f"[{', '.join(sorted(surfaces)) or 'none'}]. "
        f"Observed layers present: [{', '.join(sorted(classes_present)) or 'none'}]. "
        f"Observed reactions: [{', '.join(sorted(reaction_kinds)) or 'none'}]. "
        f"Suggested posture: {posture}. "
        "Attacker belief is not asserted (interaction does not prove belief); "
        "narrative effectiveness is separated from runtime/capacity confounders."
    )

    advisory_package = package_id or (sorted(packages)[0] if packages else "unknown")
    advisory_node = sorted(nodes)[0] if nodes else "unknown"

    metadata: dict[str, Any] = {
        "observation_count": n,
        "ladder_layers_present": layers_present,
        "distinct_confounders": len(distinct_confounders),
        "omitted_components": len(omitted_components),
        "saturated_resources": len(saturated),
        "config_hash": config_hash,
        "suggested_posture": posture,
    }

    core = {
        "environment_id": environment_id,
        "package_id": advisory_package,
        "node_id": advisory_node,
        "assessment": assessment,
        "confidence": confidence,
        "counter_evidence": counter_evidence,
        "observation_refs": observation_refs,
        "unknowns": unknowns,
    }
    content_hash = hashlib.sha256(
        json.dumps({**core, "config_hash": config_hash}, sort_keys=True).encode("utf-8")
    ).hexdigest()

    advisory_id = "eff-" + hashlib.sha256(
        f"{environment_id}|{package_id or ''}|{config_hash}|{content_hash}".encode("utf-8")
    ).hexdigest()[:24]

    advisory = {
        **core,
        "advisory_id": advisory_id,
        "produced_at": to_rfc3339(query_as_of),
        "metadata": {**metadata, "content_hash": content_hash},
    }
    _deadline_check(deadline)
    return EffectivenessSummary(advisory=advisory, content_hash=content_hash)
