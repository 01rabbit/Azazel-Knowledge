"""Context correlation pipeline (design S5).

Normalizes a bounded `ContextRequest`, resolves candidate IOCs from the
Repository (exact, CIDR-containment tiers, domain-suffix walk), selects a
primary IOC, snapshots stats exactly once, assembles the scoring context,
and calls scoring + recommendation. Enforces a monotonic deadline
*between* stages and fails closed (`ContextTimeout`) — a caller never
returns a partial `reason[]`.
"""

from __future__ import annotations

import logging
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import AddressValueError, IPv4Address
from typing import Any, Mapping, Sequence

from azazel_grimoire.core.clock import Clock, parse_rfc3339, to_rfc3339
from azazel_grimoire.core.config import TrackedConfigLoader
from azazel_grimoire.correlate import campaign as campaign_mod
from azazel_grimoire.db import generations
from azazel_grimoire.db.repository import Repository, entity_key
from azazel_grimoire.normalize.ioc import NormalizationError, normalize
from azazel_grimoire.patterns import matchspec
from azazel_grimoire.recommend.select import recommend
from azazel_grimoire.scoring import confidence as conf
from azazel_grimoire.scoring.compute import (
    AttackMapInput,
    GeoAsnInput,
    HistoryInput,
    IocMatchInput,
    ScoringContext,
    SourceRef,
    score_event,
)

_LOG = logging.getLogger(__name__)

MAX_ENTITIES = 64
_CIDR_TIERS = ("host", "/24", "/16", "asn")
_EXACT_CORROBORATION_TYPES = frozenset(
    {"ip", "domain", "url", "hash", "md5", "sha1", "sha256"}
)
_HISTORY_CORROBORATION_THRESHOLD = 50
ADVISORY_NOTICE = (
    "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
)
_BEHAVIORAL_CTI_SUB_BUDGET_S = 0.02
_BEHAVIORAL_CTI_LIMITATIONS = (
    "Behavioral similarity is not attribution.",
    "AI usage is not directly proven.",
    ADVISORY_NOTICE,
)
_BEHAVIOR_CLASS_TO_POSTURE = {
    "simple_scanner": "observe",
    "scripted_automation": "delay",
    "adaptive_probe": "delay",
    "decoy_engaged": "decoy",
    "disengaged_after_friction": "no_change",
    "unknown": "unknown",
}


class ContextTimeout(Exception):
    pass


class ContextRequestTooLarge(Exception):
    pass


class _BehavioralLookupTimeout(Exception):
    pass


@dataclass(frozen=True)
class Entity:
    type: str
    value: str


@dataclass
class ContextRequest:
    entities: list[Entity] = field(default_factory=list)
    event: dict[str, Any] = field(default_factory=dict)
    edge_id: str = ""
    actor_key: str = ""
    event_id: str | None = None


@dataclass(frozen=True)
class AdvisoryResult:
    advisory_id: str
    threat_score: float
    confidence: float
    reason: tuple[dict[str, Any], ...]
    confidence_reason: tuple[dict[str, Any], ...]
    recommendation: dict[str, Any]
    threat_context: dict[str, Any]
    source_freshness: dict[str, Any]
    multi_ioc_scope: dict[str, Any]
    content_hash: str
    determinism: dict[str, Any]
    advisory_notice: str = ADVISORY_NOTICE


def _deadline_check(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() > deadline:
        raise ContextTimeout("context deadline exceeded between stages")


def _behavioral_subdeadline(deadline: float | None) -> float:
    subdeadline = time.monotonic() + _BEHAVIORAL_CTI_SUB_BUDGET_S
    if deadline is None:
        return subdeadline
    return min(deadline, subdeadline)


def _behavioral_deadline_check(subdeadline: float) -> None:
    if time.monotonic() > subdeadline:
        raise _BehavioralLookupTimeout("behavioral lookup sub-deadline exceeded")


def _parse_ts(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return parse_rfc3339(str(value))
    except (ValueError, TypeError):
        try:
            dt = datetime.fromisoformat(str(value))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None


def _parent_domains(domain: str, cap: int = 8) -> list[str]:
    labels = domain.split(".")
    result: list[str] = []
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate.count(".") < 1:
            break
        result.append(candidate)
        if len(result) >= cap:
            break
    return result


def _get_ioc_by_id(conn: sqlite3.Connection, ioc_id: int) -> sqlite3.Row | None:
    conn.row_factory = sqlite3.Row
    return conn.execute(
        "SELECT ioc_id, type, value, first_seen, last_seen, agg_raw_confidence, "
        "agg_next_expiry, agg_computed_at FROM intel.ioc WHERE ioc_id = ?",
        (ioc_id,),
    ).fetchone()


def _ioc_sources(
    conn: sqlite3.Connection, ioc_id: int, feed_groups: Mapping[str, str]
) -> tuple[SourceRef, ...]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT feed_id, source_confidence, first_seen, last_seen, expires_at "
        "FROM intel.ioc_source WHERE ioc_id = ? ORDER BY feed_id",
        (ioc_id,),
    ).fetchall()
    sources: list[SourceRef] = []
    for row in rows:
        feed_id = row["feed_id"]
        sources.append(
            SourceRef(
                feed_id=feed_id,
                group=feed_groups.get(feed_id, feed_id),
                base_confidence=float(row["source_confidence"]),
                first_seen=_parse_ts(row["first_seen"]) or datetime.min.replace(tzinfo=timezone.utc),
                last_seen=_parse_ts(row["last_seen"]) or datetime.min.replace(tzinfo=timezone.utc),
            )
        )
    return tuple(sources)


def _feed_groups(loader: TrackedConfigLoader) -> dict[str, str]:
    feeds = loader.feeds().get("feeds", {})
    return {
        feed_id: (spec or {}).get("group", feed_id) for feed_id, spec in feeds.items()
    }


def _local_meta(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute(
            "SELECT value FROM local_meta WHERE key = ?", (key,)
        ).fetchone()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def _intel_meta(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute(
            "SELECT value FROM intel.stats_meta WHERE key = ?", (key,)
        ).fetchone()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def _read_attack_version(conn: sqlite3.Connection, loader: TrackedConfigLoader) -> str:
    try:
        row = conn.execute(
            "SELECT attack_version FROM intel.attack_technique LIMIT 1"
        ).fetchone()
        if row and row[0]:
            return str(row[0])
    except sqlite3.Error:
        pass
    return str(loader.raw("attack-map.yaml").get("version", "unknown"))


def _behavior_evidence_ref(
    resolved: Any,
) -> str | None:
    evidence_type = resolved.evidence.evidence_type
    payload = resolved.payload
    if evidence_type == "observation":
        return f"obs-{payload['observation_id']}"
    if evidence_type == "reaction":
        return f"rxn-{payload['reaction_id']}"
    return None


def _behavior_explanation_short(
    behavior_class: str,
    similarity: float | None,
    evidence_refs: Sequence[str],
) -> str:
    label = behavior_class.replace("_", " ")
    if similarity is not None and evidence_refs:
        return (
            f"Observed {label} behavior matched a stored pattern with "
            f"precomputed similarity {similarity:.2f} and linked evidence."
        )
    if similarity is not None:
        return (
            f"Observed {label} behavior matched a stored pattern with "
            f"precomputed similarity {similarity:.2f}."
        )
    if evidence_refs:
        return f"Observed {label} behavior matched a stored pattern with linked evidence."
    return f"Observed {label} behavior matched a stored pattern."


def _build_behavioral_cti(
    conn: sqlite3.Connection,
    repo: Repository,
    *,
    actor_key: str,
    deadline: float | None,
) -> dict[str, Any] | None:
    if not actor_key:
        return None
    subdeadline = _behavioral_subdeadline(deadline)
    _behavioral_deadline_check(subdeadline)

    patterns = repo.get_behavior_patterns(conn, actor_key=actor_key)
    _behavioral_deadline_check(subdeadline)
    if not patterns:
        return None

    pattern = patterns[0]
    similarities = repo.get_behavior_pattern_similarities(
        conn, pattern.pattern_id, pattern.behavior_generation
    )
    _behavioral_deadline_check(subdeadline)
    similarity = similarities[0] if similarities else None

    evidence_rows = repo.get_behavior_pattern_evidence(
        conn, pattern.pattern_id, pattern.behavior_generation
    )
    evidence_refs: list[str] = []
    for evidence_row in evidence_rows:
        resolved = repo.resolve_behavior_evidence(conn, evidence_row)
        if resolved is None:
            continue
        ref = _behavior_evidence_ref(resolved)
        if ref is not None:
            evidence_refs.append(ref)
        _behavioral_deadline_check(subdeadline)

    similarity_value = round(similarity.similarity, 2) if similarity is not None else None
    repeatability_score = (
        similarity.repeatability if similarity is not None else pattern.repeatability_score
    )
    block = {
        "behavior_seen_before": True,
        "behavior_class": pattern.behavior_class,
        "pattern_id": pattern.pattern_id,
        "repeatability_score": repeatability_score,
        "novelty_score": pattern.novelty_score,
        "suggested_posture": _BEHAVIOR_CLASS_TO_POSTURE[pattern.behavior_class],
        "confidence": pattern.confidence,
        "evidence_refs": evidence_refs,
        "explanation_short": _behavior_explanation_short(
            pattern.behavior_class, similarity_value, evidence_refs
        ),
        "limitations": list(_BEHAVIORAL_CTI_LIMITATIONS),
        "behavior_generation": pattern.behavior_generation,
        "generator_version": pattern.generator_version,
        "behavior_config_hash": pattern.behavior_config_hash,
    }
    if similarity_value is not None:
        block["similarity"] = similarity_value
    return block


def _normalize_entities(request: ContextRequest) -> list[tuple[str, str]]:
    if len(request.entities) > MAX_ENTITIES:
        raise ContextRequestTooLarge(
            f"{len(request.entities)} entities exceeds cap {MAX_ENTITIES}"
        )
    normalized: list[tuple[str, str]] = []
    for entity in request.entities:
        try:
            value = normalize(entity.type, entity.value)
        except NormalizationError as exc:
            _LOG.warning("dropping un-normalizable entity %r: %s", entity, exc)
            continue
        normalized.append((entity.type.strip().lower(), value))
    return normalized


@dataclass
class _Match:
    row: sqlite3.Row
    type: str
    value: str
    tier: str


def _resolve_matches(
    conn: sqlite3.Connection, entities: Sequence[tuple[str, str]], repo: Repository
) -> list[_Match]:
    seen: dict[int, _Match] = {}

    def _register(row: sqlite3.Row, type_: str, value: str, tier: str) -> None:
        if row is None:
            return
        existing = seen.get(row["ioc_id"])
        if existing is None:
            seen[row["ioc_id"]] = _Match(row, type_, value, tier)

    for type_, value in entities:
        if type_ == "domain":
            for candidate in _parent_domains(value):
                row = repo.get_ioc(conn, "domain", candidate)
                if row is not None:
                    tier = "exact" if candidate == value else "domain_suffix"
                    _register(row, "domain", candidate, tier)
            continue

        row = repo.get_ioc(conn, type_, value)
        _register(row, type_, value, "exact")

        if type_ == "ip":
            try:
                packed = int(IPv4Address(value))
            except AddressValueError:
                continue
            for tier in _CIDR_TIERS:
                cidr_row = repo.find_cidr_containing(conn, tier, packed)
                if cidr_row is not None:
                    ioc_row = _get_ioc_by_id(conn, cidr_row["ioc_id"])
                    if ioc_row is not None:
                        _register(ioc_row, ioc_row["type"], ioc_row["value"], f"cidr_{tier}")

    return list(seen.values())


def _build_ioc_matches(
    conn: sqlite3.Connection, matches: Sequence[_Match], feed_groups: Mapping[str, str]
) -> list[IocMatchInput]:
    result: list[IocMatchInput] = []
    for match in matches:
        row = match.row
        key = entity_key(row["type"], row["value"]).hex()
        result.append(
            IocMatchInput(
                entity_key=key,
                type=row["type"],
                value=row["value"],
                ioc_id=int(row["ioc_id"]),
                agg_raw_confidence=float(row["agg_raw_confidence"]),
                first_seen=_parse_ts(row["first_seen"])
                or datetime.min.replace(tzinfo=timezone.utc),
                last_seen=_parse_ts(row["last_seen"])
                or datetime.min.replace(tzinfo=timezone.utc),
                sources=_ioc_sources(conn, int(row["ioc_id"]), feed_groups),
                match_tier=match.tier,
            )
        )
    return result


def _select_primary(
    ioc_matches: Sequence[IocMatchInput],
    query_as_of: datetime,
    half_life: float,
    floor: float,
) -> int | None:
    if not ioc_matches:
        return None
    best_index = 0
    best_key: tuple[float, str] | None = None
    for index, match in enumerate(ioc_matches):
        freshness = conf.freshness_decay(
            conf.age_days(query_as_of, match.last_seen), half_life, floor
        )
        strength = match.agg_raw_confidence * freshness
        candidate = (-strength, match.entity_key)
        if best_key is None or candidate < best_key:
            best_key = candidate
            best_index = index
    return best_index


def _build_history(
    conn: sqlite3.Connection, key: bytes, repo: Repository, burst_cap: int
) -> tuple[HistoryInput, datetime | None]:
    rows = repo.get_observation_stats(conn, key)
    if not rows:
        return HistoryInput(), None
    total = 0
    effective = 0
    excluded = 0
    trends: list[float] = []
    window_ends: list[datetime] = []
    updated: list[datetime] = []
    for row in rows:
        count = int(row["event_count"])
        total += count
        effective += min(count, burst_cap)
        excluded += max(0, count - burst_cap)
        if row["trend"] is not None:
            trends.append(float(row["trend"]))
        end = _parse_ts(row["window_end"])
        if end is not None:
            window_ends.append(end)
        upd = _parse_ts(row["updated_at"])
        if upd is not None:
            updated.append(upd)
    updated_at = max(updated) if updated else None
    history = HistoryInput(
        total_events=total,
        burst_excluded=excluded,
        effective_events=effective,
        trend=(sum(trends) / len(trends)) if trends else 0.0,
        freshest_window_end=max(window_ends) if window_ends else None,
        updated_at=updated_at,
        windows=len(rows),
    )
    return history, updated_at


def _augment_event(
    event: Mapping[str, Any], ioc_matches: Sequence[IocMatchInput]
) -> dict[str, Any]:
    eval_event = dict(event)
    ioc_block = dict(eval_event.get("ioc", {})) if isinstance(eval_event.get("ioc"), Mapping) else {}
    for match in ioc_matches:
        if match.type == "ip":
            ioc_block.setdefault("matched_ip", match.value)
        elif match.type == "domain":
            ioc_block.setdefault("matched_domain", match.value)
        elif match.type == "url":
            ioc_block.setdefault("matched_url", match.value)
        elif match.type in ("md5", "sha1", "sha256", "hash"):
            ioc_block.setdefault("matched_hash", match.value)
    if ioc_block:
        eval_event["ioc"] = ioc_block
    return eval_event


def _evaluate_attack(
    loader: TrackedConfigLoader, eval_event: Mapping[str, Any]
) -> AttackMapInput:
    rules = loader.attack_map()
    patterns = [
        matchspec.Pattern(
            pattern_id=str(rule.get("id")),
            priority=int(rule.get("priority", 0)),
            spec=rule.get("match", {}),
            payload=rule.get("technique_id"),
        )
        for rule in rules
        if rule.get("match")
    ]
    result = matchspec.evaluate_patterns(patterns, eval_event)
    techniques = tuple(sorted({p for p in result.payloads if p}))
    return AttackMapInput(
        techniques=techniques,
        rules_scanned=result.scanned,
        rules_total=result.total,
        truncated=result.truncated,
    )


def _build_geo_asn(
    conn: sqlite3.Connection,
    repo: Repository,
    event: Mapping[str, Any],
) -> GeoAsnInput:
    raw_asn = event.get("asn")
    if not raw_asn:
        return GeoAsnInput()
    try:
        asn = normalize("asn", str(raw_asn))
    except NormalizationError:
        return GeoAsnInput()
    row = repo.get_ioc(conn, "asn", asn)
    if row is None:
        return GeoAsnInput(asn=asn, tagged=False)
    return GeoAsnInput(
        asn=asn,
        tagged=True,
        reputation_score=float(row["agg_raw_confidence"]),
        updated_at=_parse_ts(row["agg_computed_at"]) or _parse_ts(row["last_seen"]),
    )


def _build_cve(
    conn: sqlite3.Connection,
    repo: Repository,
    event: Mapping[str, Any],
    applies_when: Sequence[str],
) -> tuple[bool, tuple[str, ...], datetime | None]:
    event_types = set(event.get("event_types", []) or [])
    if event.get("kind"):
        event_types.add(str(event["kind"]))
    applicable = bool(event_types & set(applies_when))
    cves = event.get("cves", []) or []
    if not cves:
        return applicable, (), None
    rows = repo.get_kev(conn, [str(c) for c in cves])
    hits = tuple(sorted(row["cve_id"] for row in rows))
    added_dates = [d for d in (_parse_ts(row["date_added"]) for row in rows) if d]
    return applicable, hits, (min(added_dates) if added_dates else None)


def run_context(
    repo: Repository,
    loader: TrackedConfigLoader,
    request: ContextRequest,
    clock: Clock,
    *,
    deadline: float | None = None,
) -> AdvisoryResult:
    scoring_cfg = loader.scoring()
    fresh_cfg = scoring_cfg.get("freshness", {})
    half_life = float(fresh_cfg.get("half_life_days", 30.0))
    floor = float(fresh_cfg.get("floor", 0.2))
    burst_cap = int(
        scoring_cfg.get("components", {}).get("history", {}).get("burst_cap", 500)
    )
    max_staleness_s = loader.max_staleness_s()
    feed_groups = _feed_groups(loader)

    entities = _normalize_entities(request)
    query_as_of = clock.query_as_of()

    with repo.connection() as conn:
        conn.row_factory = sqlite3.Row
        _deadline_check(deadline)

        matches = _resolve_matches(conn, entities, repo)
        ioc_matches = _build_ioc_matches(conn, matches, feed_groups)
        primary_index = _select_primary(ioc_matches, query_as_of, half_life, floor)
        _deadline_check(deadline)

        intel_generation = int(
            _intel_meta(conn, "intel_generation")
            or generations.current_generation(repo.data_db_dir)
            or 0
        )
        local_generation = int(_local_meta(conn, "local_generation") or 0)
        attack_version = _read_attack_version(conn, loader)

        primary_key: bytes | None = None
        reputation_score: float | None = None
        history = HistoryInput()
        stats_updated_at: datetime | None = None
        stats_generation = int(_local_meta(conn, "stats_generation") or 0)
        if primary_index is not None:
            primary = ioc_matches[primary_index]
            primary_key = bytes.fromhex(primary.entity_key)
            rep_row = repo.get_reputation(conn, primary_key)
            if rep_row is not None:
                reputation_score = float(rep_row["score"])
            history, stats_updated_at = _build_history(
                conn, primary_key, repo, burst_cap
            )
            stat_rows = repo.get_observation_stats(conn, primary_key)
            if stat_rows and not _local_meta(conn, "stats_generation"):
                stats_generation = max(int(r["stats_generation"]) for r in stat_rows)

        stats_stale = conf.is_stats_stale(query_as_of, stats_updated_at, max_staleness_s)

        geo_asn = _build_geo_asn(conn, repo, request.event)
        applies_when = (
            scoring_cfg.get("components", {})
            .get("cve_exploited", {})
            .get("applies_when", ["eve_alert"])
        )
        cve_applicable, cve_hits, cve_added = _build_cve(
            conn, repo, request.event, applies_when
        )
        _deadline_check(deadline)

        eval_event = _augment_event(request.event, ioc_matches)
        attack = _evaluate_attack(loader, eval_event)

        entity_keys = [bytes.fromhex(m.entity_key) for m in ioc_matches]
        campaign = campaign_mod.match_campaign(
            conn, entity_keys, attack.techniques, query_as_of
        )
        _deadline_check(deadline)

        corroborated = any(
            m.match_tier == "exact" and m.type in _EXACT_CORROBORATION_TYPES
            for m in ioc_matches
        ) or (history.effective_events >= _HISTORY_CORROBORATION_THRESHOLD)

        ctx = ScoringContext(
            query_as_of=query_as_of,
            intel_generation=intel_generation,
            local_generation=local_generation,
            stats_generation=stats_generation,
            attack_version=attack_version,
            config_hash=loader.config_hash,
            config=scoring_cfg,
            event=dict(request.event),
            ioc_matches=tuple(ioc_matches),
            primary_index=primary_index,
            corroborated=corroborated,
            history=history,
            stats_stale=stats_stale,
            attack=attack,
            campaign=campaign,
            geo_asn=geo_asn,
            cve_applicable=cve_applicable,
            cve_kev_hits=cve_hits,
            cve_added=cve_added,
            reputation_score=reputation_score,
            max_staleness_s=max_staleness_s,
        )

        _deadline_check(deadline)
        score = score_event(ctx)
        _deadline_check(deadline)

        recommendation = recommend(
            score.threat_score, score.confidence, loader.action_bands()
        )

        primary_ioc_id = (
            ioc_matches[primary_index].ioc_id if primary_index is not None else None
        )
        multi_ioc_scope = {
            "matched_count": len(ioc_matches),
            "primary_ioc_id": primary_ioc_id,
        }

        all_last_seen = [m.last_seen for m in ioc_matches]
        oldest_feed_days = (
            round(conf.age_days(query_as_of, min(all_last_seen)), 6)
            if all_last_seen
            else None
        )
        source_freshness = {
            "oldest_feed_days": oldest_feed_days,
            "attack_version": attack_version,
        }

        threat_context = {
            "ioc_matches": [
                {
                    "type": m.type,
                    "value": m.value,
                    "match_tier": m.match_tier,
                    "agg_raw_confidence": m.agg_raw_confidence,
                    "sources": sorted({s.group for s in m.sources}),
                }
                for m in ioc_matches
            ],
            "campaign": (
                {
                    "name": campaign.name,
                    "actor": campaign.actor,
                    "ioc_overlap": campaign.ioc_overlap,
                    "technique_overlap": campaign.technique_overlap,
                }
                if campaign.matched
                else None
            ),
            "attack_mapping": [{"technique": t} for t in attack.techniques],
            "pattern_match": None,
            "history": {
                "prior_observations": history.total_events,
                "trend": history.trend,
            },
        }
        try:
            behavioral_cti = _build_behavioral_cti(
                conn,
                repo,
                actor_key=request.actor_key,
                deadline=deadline,
            )
        except (sqlite3.Error, ValueError, _BehavioralLookupTimeout):
            behavioral_cti = None
        if behavioral_cti is not None:
            threat_context["behavioral_cti"] = behavioral_cti

        determinism = {
            "intel_generation": intel_generation,
            "local_generation": local_generation,
            "stats_generation": stats_generation,
            "attack_version": attack_version,
            "config_hash": loader.config_hash,
            "query_as_of": to_rfc3339(query_as_of),
        }

        return AdvisoryResult(
            advisory_id=uuid.uuid4().hex,
            threat_score=score.threat_score,
            confidence=score.confidence,
            reason=score.reason,
            confidence_reason=score.confidence_reason,
            recommendation=recommendation,
            threat_context=threat_context,
            source_freshness=source_freshness,
            multi_ioc_scope=multi_ioc_scope,
            content_hash=score.content_hash,
            determinism=determinism,
        )
