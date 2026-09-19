"""Deterministic engagement-effectiveness advisory (Knowledge#52).

    **Knowledge advises; it never selects, commands, schedules, or executes.**

What this folds, and what it refuses to invent
----------------------------------------------
Every input already exists as an immutable local-tier fact:

* `reaction` -- which bounded action was applied and how the actor behaved
  after it (Phase 1);
* `behavior_pattern` -- the deterministic behavior class and its confidence
  (Phase 2, `config/behavior-classify.yaml`).

Every output vocabulary already exists too. `behavior_class` is Knowledge's own
(`simple_scanner` ... `adaptive_probe` ... `disengaged_after_friction`), and
the posture vocabulary is Azazel-Fabric's MITRE Engage-aligned
`EngagementObjective` / `EngagementApproach` / `EngagementActivity`, pinned at
`v0.8.0`.

Nothing here defines a new vocabulary. A second definition of a shared word
drifts from the first, and the drift is invisible until a consumer compares
values across products.

Determinism (Absolute Constraint 3)
-----------------------------------
A pure function of the stored rows, the `engagement_advisory` config block,
and `query_as_of`. No wall-clock, no randomness, no environment, no file
order. Ties are broken by name so two machines fold the same rows the same
way. This module is framework-free and Fabric-free (Constraint 7 / ADR-0010);
the Fabric model is constructed at the API boundary.

Honesty discipline
------------------
*No evidence yields no advisory.* The function returns `None` rather than an
advisory whose every field says "unknown" -- a consumer can distinguish
"Knowledge has nothing" from "Knowledge looked and is unsure" only if the two
look different.

*A tie is not a dominant reaction.* When no reaction outnumbers the others, the
outcome is `unknown` and the tie is named in `limitations`.

*A posture suggestion needs evidence for that posture.* `redirect_to_decoy` is
suggested only where prior decoy actions actually produced decoy engagement.
Below the configured confidence floor there is no suggestion at all.

*Two Knowledge actions produce no suggested activity, by design.* `delay` and
`deception` have no equivalent in Fabric's activity vocabulary. They still
inform `prior_outcomes`, whose keys are free-form, but they never become a
suggested activity: inventing a mapping from a product-local action to a
canonical one would make the product word canonical by the back door.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Mapping

__all__ = [
    "ACTIONS_WITHOUT_A_CANONICAL_ACTIVITY",
    "DECOY_ENGAGEMENT_REACTIONS",
    "DEFAULTS",
    "summarize_engagement",
]

#: Conservative built-ins, used when `scoring.yaml:engagement_advisory` is
#: absent. Mirrors how `deception_effectiveness` treats its own block.
DEFAULTS: Mapping[str, Any] = {
    "version": 1,
    #: Below this many stored reactions there is no advisory at all.
    "minimum_reactions": 3,
    #: Below this confidence a posture is not suggested. The advisory itself
    #: still reports what was observed.
    "posture_confidence_floor": 0.5,
    #: How many prior decoy engagements it takes before `redirect_to_decoy`
    #: is a supported activity rather than a guess.
    "decoy_support_minimum": 2,
    "round_ndigits": 6,
}

#: Knowledge `reaction` values that evidence actual decoy engagement.
#:
#: `followed_decoy` is Knowledge's stored value; `decoy_engaged` exists in
#: Fabric's wider `AttackerReaction` vocabulary and is accepted here so the
#: two stay comparable without a mapping table.
DECOY_ENGAGEMENT_REACTIONS = frozenset({"followed_decoy", "decoy_engaged"})

#: Knowledge actions with no equivalent in Fabric's `EngagementActivity`.
#:
#: Named rather than silently skipped, so the gap is visible in the advisory's
#: own limitations instead of looking like an absence of evidence.
ACTIONS_WITHOUT_A_CANONICAL_ACTIVITY = frozenset({"delay", "deception"})

#: Knowledge actions that ARE Fabric activities, spelled identically.
_ACTIONS_THAT_ARE_ACTIVITIES = frozenset({"throttle", "redirect", "isolate"})


def _setting(config: Mapping[str, Any], key: str) -> Any:
    value = config.get(key)
    return DEFAULTS[key] if value is None else value


def _dominant(counts: Mapping[str, int]) -> tuple[str, bool]:
    """Return `(reaction, is_dominant)`.

    A reaction is dominant only when it strictly outnumbers every other. A tie
    is reported as `unknown` and is not silently resolved by ordering.
    """

    if not counts:
        return "unknown", False
    # The name is a secondary key. It changes nothing today -- an equal count
    # returns `unknown` below regardless of order -- and is kept so that a
    # later rule which *does* pick between equals cannot accidentally depend
    # on dict insertion order. Stated plainly because a mutation test proves
    # it is not currently load-bearing.
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    if len(ordered) > 1 and ordered[0][1] == ordered[1][1]:
        return "unknown", False
    return ordered[0][0], True


def summarize_engagement(
    conn: sqlite3.Connection,
    actor_key: str,
    *,
    query_as_of: str,
    config: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Fold this actor's prior engagements into an advisory, or `None`.

    `None` means there is nothing to say: fewer stored reactions than the
    configured minimum, or no actor key. It is not an error and never becomes
    an empty advisory.
    """

    if not isinstance(actor_key, str) or not actor_key.strip():
        return None
    settings = dict(config or {})

    try:
        rows = conn.execute(
            "SELECT action_applied, reaction, trust_tier, evidence_modality_count "
            "FROM reaction WHERE actor_key = ? AND applied_at <= ? "
            "ORDER BY applied_at ASC, reaction_id ASC",
            (actor_key, query_as_of),
        ).fetchall()
    except sqlite3.Error:
        # Table absent or unreadable. No advisory, never an error: Knowledge
        # failure cannot block Edge or Gadget operation.
        return None

    minimum = int(_setting(settings, "minimum_reactions"))
    if len(rows) < minimum:
        return None

    by_action: dict[str, dict[str, int]] = {}
    corroborated = 0
    for action, reaction, trust_tier, modality_count in rows:
        by_action.setdefault(str(action), {})
        counts = by_action[str(action)]
        counts[str(reaction)] = counts.get(str(reaction), 0) + 1
        if str(trust_tier) in {"same_edge_corroborated", "human_confirmed", "corroborated"}:
            corroborated += 1

    limitations: list[str] = []
    reasons: list[str] = []
    prior_outcomes: dict[str, dict[str, Any]] = {}
    for action in sorted(by_action):
        counts = by_action[action]
        dominant, is_dominant = _dominant(counts)
        prior_outcomes[action] = {
            "dominant_reaction": dominant,
            "evidence_count": sum(counts.values()),
            "distinct_reactions": len(counts),
        }
        if not is_dominant:
            limitations.append(
                f"no reaction outnumbered the others after {action}; reported as unknown"
            )
        if action in ACTIONS_WITHOUT_A_CANONICAL_ACTIVITY:
            limitations.append(
                f"{action!r} has no equivalent in the canonical engagement activity "
                "vocabulary, so it informs prior outcomes but suggests no activity"
            )

    behavior_class, pattern_confidence, repeatability = _behavior(conn, actor_key, query_as_of)
    if behavior_class is None:
        limitations.append("no behavior pattern has been generated for this actor yet")

    ndigits = int(_setting(settings, "round_ndigits"))
    confidence = _confidence(
        pattern_confidence=pattern_confidence,
        corroborated=corroborated,
        total=len(rows),
        ndigits=ndigits,
    )

    posture = _posture(
        by_action=by_action,
        confidence=confidence,
        settings=settings,
        reasons=reasons,
        limitations=limitations,
    )

    # Never an inference about who the actor is or what they believe.
    limitations.append(
        "describes observed outcomes only; it is not a prediction, an attribution, "
        "or a claim about the actor's intent or belief"
    )

    return {
        "seen_before": True,
        "behavior_class": behavior_class,
        "confidence": confidence,
        "repeatability_score": repeatability,
        "prior_outcomes": prior_outcomes,
        "posture_suggestion": posture,
        "reasons": sorted(set(reasons)),
        "limitations": sorted(set(limitations)),
    }


def _behavior(
    conn: sqlite3.Connection, actor_key: str, query_as_of: str
) -> tuple[str | None, int | None, int | None]:
    """The most recent behavior pattern for this actor at `query_as_of`."""

    try:
        row = conn.execute(
            "SELECT behavior_class, confidence, repeatability_score FROM behavior_pattern "
            "WHERE actor_key = ? AND observation_end <= ? "
            "ORDER BY observation_end DESC, pattern_id DESC LIMIT 1",
            (actor_key, query_as_of),
        ).fetchone()
    except sqlite3.Error:
        return None, None, None
    if row is None:
        return None, None, None
    return str(row[0]), int(row[1]), int(row[2])


def _confidence(
    *, pattern_confidence: int | None, corroborated: int, total: int, ndigits: int
) -> float:
    """Bounded 0.0-1.0 confidence.

    Two inputs, both already stored as facts: the behavior pattern's own
    confidence (0-100, Knowledge's scale) and the share of reactions that more
    than one source corroborated. Scaled to 0.0-1.0 because that is Fabric's
    contract for this field -- a rescale of an existing number, not a new claim.
    """

    base = 0.0 if pattern_confidence is None else max(0, min(100, pattern_confidence)) / 100.0
    corroboration = (corroborated / total) if total else 0.0
    value = min(1.0, max(0.0, (base * 0.7) + (corroboration * 0.3)))
    return round(value, ndigits)


def _posture(
    *,
    by_action: Mapping[str, Mapping[str, int]],
    confidence: float,
    settings: Mapping[str, Any],
    reasons: list[str],
    limitations: list[str],
) -> dict[str, Any] | None:
    """A bounded posture, or `None` when the evidence does not support one."""

    floor = float(_setting(settings, "posture_confidence_floor"))
    if confidence < floor:
        limitations.append(
            f"confidence {confidence} is below the {floor} floor; no posture is suggested"
        )
        return None

    decoy_minimum = int(_setting(settings, "decoy_support_minimum"))
    decoy_engagements = sum(
        count
        for counts in by_action.values()
        for reaction, count in counts.items()
        if reaction in DECOY_ENGAGEMENT_REACTIONS
    )

    supported: list[str] = []
    if decoy_engagements >= decoy_minimum:
        supported.append("redirect_to_decoy")
        reasons.append("similar_patterns_previously_engaged_decoy")
    for action in sorted(by_action):
        if action in _ACTIONS_THAT_ARE_ACTIVITIES:
            supported.append(action)
            reasons.append(f"prior_{action}_outcomes_recorded")

    if not supported:
        limitations.append(
            "no prior action maps onto a canonical engagement activity; no posture suggested"
        )
        return None

    return {
        # `collect` and `channel` are the bounded pair this evidence supports:
        # observing what an actor does next, through a path already approved.
        # Nothing stronger is claimed, because nothing stronger was observed.
        "objective": "collect",
        "approach": "channel",
        "supported_activities": sorted(set(supported)),
        "reasons": sorted(set(reasons)),
    }
