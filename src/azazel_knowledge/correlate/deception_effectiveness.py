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
* a producer's coverage and limitations (``deception_outcome_envelope_v0``) are
  surfaced as ``unknowns`` / ``counter_evidence`` and never move ``confidence``
  or the suggested posture: an incomplete window, a ``stale`` flag or observed
  isolation drift makes the advisory *less* able to conclude, and silence is
  never read as safety;
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

# Limitation tokens the producer (Azazel-Deception) states in its own words.
# Every token is surfaced verbatim under `unknowns` -- a limitation is by
# definition a bound on what can be concluded. These two additionally count
# against the observation, so they are repeated under `counter_evidence`.
# Anything not listed is still shown; this is a promotion list, not a filter.
_COUNTER_EVIDENCE_LIMITATIONS = ("stale", "isolation_drift_observed")
_NO_INTERACTION_LIMITATION = "no_interaction_observed_is_not_evidence_of_safety"
_ISOLATION_NOT_ASSERTED = "isolation_not_asserted"
_ISOLATION_DRIFT = "isolation_drift_observed"
_ADVISORY_REF_PREFIXES = ("advisory:", "observation_objective:", "hypothesis:", "frame:")
_ADVISORY_REF_CAP = 8


def _outcome_envelope_notes(
    conn: sqlite3.Connection,
    *,
    environment_id: str,
    package_id: str | None,
    n_observations: int,
) -> tuple[list[str], list[str], dict[str, Any], tuple[str, str] | None]:
    """Fold stored outcome envelopes into (unknowns, counter_evidence, metadata, scope).

    Only the latest envelope (by `observed_at`, then `envelope_ref`) speaks for
    the environment's current coverage; the count of all envelopes and of the
    incomplete ones is reported so an earlier gap is not erased by a later
    clean window. Returns empty results when none is stored, which keeps an
    advisory built without this lane byte-identical to what it was before it.
    `scope` is `(package_id, node_id)` of the latest envelope, used only as a
    fallback identity when no interaction observation exists.
    """

    params: list[Any] = [environment_id]
    where = "environment_id = ?"
    if package_id is not None:
        where += " AND package_id = ?"
        params.append(package_id)
    try:
        total, incomplete, dropped = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(coverage_complete = 0), 0), "
            "COALESCE(SUM(entries_dropped), 0) "
            f"FROM deception_outcome_envelope_v0 WHERE {where}",
            params,
        ).fetchone()
    except sqlite3.OperationalError as exc:
        # A local.db the worker has not migrated to 0008 yet (API upgraded
        # first). Same as "nothing stored"; any other error still propagates.
        if "no such table: deception_outcome_envelope_v0" not in str(exc):
            raise
        return [], [], {}, None
    if not total:
        return [], [], {}, None
    row = conn.execute(
        "SELECT envelope_ref, package_id, producer_node, decision_ref, effect_ref, "
        "observed_at, coverage_complete, telemetry_gaps, confounders, "
        "evidence_refs, effect_status, limitations "
        f"FROM deception_outcome_envelope_v0 WHERE {where} "
        "ORDER BY observed_at DESC, envelope_ref DESC LIMIT 1",
        params,
    ).fetchone()
    (ref, pkg, node, decision_ref, effect_ref, observed_at, complete,
     gaps_json, confounders_json, evidence_json, effect_status, limitations_json) = row
    gaps = _loads_list(gaps_json)
    confounders = _loads_list(confounders_json)
    limitations = list(dict.fromkeys(_loads_list(limitations_json)))
    advisory_refs = [
        r for r in _loads_list(evidence_json) if r.startswith(_ADVISORY_REF_PREFIXES)
    ][:_ADVISORY_REF_CAP]

    unknowns: list[str] = []
    counter: list[str] = []

    if not complete:
        counter.append(
            "telemetry coverage incomplete in the latest outcome envelope (gaps: "
            + ", ".join(gaps)
            + ") -- absence of observation inside a gap is not evidence of absence"
        )
        unknowns.append(
            "coverage incomplete: " + ", ".join(gaps) + " not observed in the producer's window"
        )
    else:
        unknowns.append(
            "coverage_complete describes telemetry only -- it says the producer "
            "could see the window, not that the decoy worked"
        )
    if confounders:
        counter.append(
            "outcome envelope confounders: " + ", ".join(confounders)
            + " (subtract before claiming effectiveness)"
        )
    if _ISOLATION_DRIFT in limitations:
        isolation = "drift_observed"
    elif _ISOLATION_NOT_ASSERTED in limitations:
        isolation = "not_asserted"
        unknowns.append("isolation not asserted by the producer")
    else:
        isolation = "no_drift_reported"
    for token in _COUNTER_EVIDENCE_LIMITATIONS:
        if token in limitations:
            counter.append(f"producer limitation: {token}")
    for token in limitations:
        unknowns.append(f"producer limitation: {token}")
    if n_observations == 0 or _NO_INTERACTION_LIMITATION in limitations:
        unknowns.append(
            "no interaction observed is not evidence of safety, and not evidence "
            "that the deception was effective or ineffective"
        )
    if dropped:
        unknowns.append(
            f"outcome_envelope_entries_dropped: {int(dropped)} limitation / gap / "
            "confounder entr(ies) were not valid tokens and were discarded; "
            "the producer's statement is incomplete to that extent"
        )
    unknowns.append(f"coverage as of {observed_at} (latest outcome envelope)")

    metadata: dict[str, Any] = {
        "outcome_envelope_count": int(total),
        "outcome_envelopes_incomplete": int(incomplete),
        "outcome_envelope_entries_dropped": int(dropped),
        "latest_envelope_ref": str(ref),
        "latest_envelope_observed_at": str(observed_at),
        "latest_coverage_complete": bool(complete),
        "latest_isolation": isolation,
        "latest_effect_status": str(effect_status),
        "latest_effect_ref": str(effect_ref),
    }
    if decision_ref:
        metadata["latest_decision_ref"] = str(decision_ref)
    if advisory_refs:
        metadata["latest_advisory_refs"] = ",".join(advisory_refs)
    return unknowns, counter, metadata, (str(pkg) if pkg else "", str(node))


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

    # --- producer coverage / limitations (outcome envelopes) -----------------
    env_unknowns, env_counter, env_metadata, env_scope = _outcome_envelope_notes(
        conn,
        environment_id=environment_id,
        package_id=package_id,
        n_observations=n,
    )
    _deadline_check(deadline)
    counter_evidence.extend(env_counter)
    unknowns.extend(env_unknowns)
    if env_scope is not None:
        if not packages and env_scope[0]:
            packages.add(env_scope[0])
        if not nodes:
            nodes.add(env_scope[1])

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
        **env_metadata,
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
