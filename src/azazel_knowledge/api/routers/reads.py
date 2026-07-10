"""Read-only browsing/operator endpoints (design S4).

Every route here is a plain `SELECT` against the read-only pool; there
is no intel-tier `campaign` table shipped in Phase 1 (see
`correlate/campaign.py`), so `/v1/campaigns` degrades defensively to an
empty result rather than erroring.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from azazel_knowledge.api.app import open_local_readonly, require_scope_dep
from azazel_knowledge.core.clock import parse_rfc3339, to_rfc3339
from azazel_knowledge.db import generations
from azazel_knowledge.reactions import linkage
from azazel_knowledge.reports.friction_timeline import (
    build_friction_timeline_report,
    get_behavior_pattern_detail,
    get_behavior_patterns_summary,
)
from azazel_knowledge.scoring import confidence as conf
from azazel_knowledge.security.auth import Scope

router = APIRouter(prefix="/v1", tags=["reads"])

_READ_SCOPE = Depends(require_scope_dep(Scope.READ))


def _parse_ts(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        return parse_rfc3339(str(value))
    except (ValueError, TypeError):
        try:
            dt = datetime.fromisoformat(str(value))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None


def _local_meta(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute("SELECT value FROM local_meta WHERE key = ?", (key,)).fetchone()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def _intel_tables(conn: sqlite3.Connection) -> set[str]:
    try:
        rows = conn.execute(
            "SELECT name FROM intel.sqlite_master WHERE type = 'table'"
        ).fetchall()
    except sqlite3.Error:
        return set()
    return {row[0] for row in rows}


def _attack_version(conn: sqlite3.Connection) -> str:
    try:
        row = conn.execute("SELECT attack_version FROM intel.attack_technique LIMIT 1").fetchone()
        if row and row[0]:
            return str(row[0])
    except sqlite3.Error:
        pass
    return "unknown"


@router.get("/campaigns")
def list_campaigns(request: Request, auth=_READ_SCOPE) -> dict[str, Any]:
    repo = request.app.state.repo
    with repo.connection() as conn:
        conn.row_factory = sqlite3.Row
        if "campaign" not in _intel_tables(conn):
            return {"campaigns": []}
        rows = conn.execute(
            "SELECT campaign_id, name, actor, last_seen FROM intel.campaign"
        ).fetchall()
    return {
        "campaigns": [
            {"id": r["campaign_id"], "name": r["name"], "actor": r["actor"], "last_seen": r["last_seen"]}
            for r in rows
        ]
    }


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str, request: Request, auth=_READ_SCOPE) -> dict[str, Any]:
    repo = request.app.state.repo
    with repo.connection() as conn:
        conn.row_factory = sqlite3.Row
        if "campaign" not in _intel_tables(conn):
            raise HTTPException(status_code=404, detail={"error": "campaign_not_found"})
        row = conn.execute(
            "SELECT campaign_id, name, actor, last_seen FROM intel.campaign WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "campaign_not_found"})
    return {"id": row["campaign_id"], "name": row["name"], "actor": row["actor"], "last_seen": row["last_seen"]}


@router.get("/behavior-patterns/summary")
def behavior_patterns_summary(
    request: Request,
    behavior_class: str | None = None,
    edge_id: str | None = None,
    window_hours: int = 168,
    limit: int = 20,
    auth=_READ_SCOPE,
) -> dict[str, Any]:
    state = request.app.state
    return get_behavior_patterns_summary(
        state.repo,
        query_as_of=state.clock.query_as_of(),
        behavior_class=behavior_class,
        edge_id=edge_id,
        window_hours=window_hours,
        limit=limit,
    )


@router.get("/behavior-patterns/{pattern_id}")
def behavior_pattern_detail(
    pattern_id: str,
    request: Request,
    auth=_READ_SCOPE,
) -> dict[str, Any]:
    repo = request.app.state.repo
    try:
        return get_behavior_pattern_detail(repo, pattern_id=pattern_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"error": "behavior_pattern_not_found"}) from exc


@router.get("/reports/friction-timeline")
def friction_timeline_report(
    request: Request,
    pattern_id: str | None = None,
    actor_key: str | None = None,
    edge_id: str | None = None,
    auth=_READ_SCOPE,
) -> dict[str, Any]:
    state = request.app.state
    try:
        return build_friction_timeline_report(
            state.repo,
            query_as_of=state.clock.query_as_of(),
            pattern_id=pattern_id,
            actor_key=actor_key,
            edge_id=edge_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"error": "friction_timeline_not_found"}) from exc


@router.get("/recommendations/rules")
def list_rule_drafts(request: Request, auth=_READ_SCOPE) -> dict[str, Any]:
    repo = request.app.state.repo
    with repo.connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT rule_id, sid, format, status, provenance, confidence, content, "
            "content_hash, created_at FROM rule_draft WHERE status IN ('draft', 'reviewed') "
            "ORDER BY created_at DESC"
        ).fetchall()
    return {
        "rules": [
            {
                "rule_id": r["rule_id"],
                "sid": r["sid"],
                "format": r["format"],
                "status": r["status"],
                "provenance": r["provenance"],
                "confidence": r["confidence"],
                "content": r["content"],
                "content_hash": r["content_hash"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
    }


@router.get("/reactions/summary")
def reactions_summary(request: Request, auth=_READ_SCOPE) -> dict[str, Any]:
    state = request.app.state
    repo = state.repo
    now = state.clock.query_as_of()
    with repo.connection() as conn:
        conn.row_factory = sqlite3.Row
        breakdown_rows = conn.execute(
            "SELECT action_applied, reaction, COUNT(*) AS c FROM reaction "
            "GROUP BY action_applied, reaction"
        ).fetchall()
        breakdown = [
            {"action_applied": r["action_applied"], "reaction": r["reaction"], "count": r["c"]}
            for r in breakdown_rows
        ]
        total = sum(r["count"] for r in breakdown)
        windows: dict[str, int] = {}
        for label, delta in (("24h", timedelta(hours=24)), ("7d", timedelta(days=7)), ("30d", timedelta(days=30))):
            since = to_rfc3339(now - delta)
            row = conn.execute(
                "SELECT COUNT(*) FROM reaction WHERE applied_at >= ?", (since,)
            ).fetchone()
            windows[label] = row[0]
        ambiguous_rate = linkage.ambiguous_linkage_rate(conn)
    return {
        "total": total,
        "breakdown": breakdown,
        "windows": windows,
        "ambiguous_linkage_rate": ambiguous_rate,
    }


@router.get("/edge-intel")
def edge_intel(request: Request, auth=_READ_SCOPE) -> dict[str, Any]:
    repo = request.app.state.repo
    with repo.connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT entity_key, type, value, edge_id, first_reported, report_count, status "
            "FROM edge_reported_ioc ORDER BY first_reported DESC"
        ).fetchall()
    return {
        "entries": [
            {
                "entity_key": r["entity_key"].hex(),
                "type": r["type"],
                "value": r["value"],
                "edge_id": r["edge_id"],
                "first_reported": r["first_reported"],
                "report_count": r["report_count"],
                "status": r["status"],
            }
            for r in rows
        ]
    }


@router.get("/health")
def health(request: Request, auth=_READ_SCOPE) -> dict[str, Any]:
    state = request.app.state
    repo = state.repo
    now = state.clock.query_as_of()
    data_db_dir = state.settings.data_db_dir
    intel_generation = generations.current_generation(data_db_dir)
    cache_state = "warm" if intel_generation is not None else "cold"

    local_conn = open_local_readonly(state.settings.local_db_path)
    try:
        local_generation = int(_local_meta(local_conn, "local_generation") or 0)
        stats_generation = int(_local_meta(local_conn, "stats_generation") or 0)
        pending_confirmations = local_conn.execute(
            "SELECT COUNT(*) FROM edge_reported_ioc WHERE status = 'quarantined'"
        ).fetchone()[0]
    finally:
        local_conn.close()

    feeds: list[dict[str, Any]] = []
    attack_version = "unknown"
    if intel_generation is not None:
        with repo.connection() as conn:
            conn.row_factory = sqlite3.Row
            try:
                feed_rows = conn.execute(
                    "SELECT feed_id, last_success, enabled, consecutive_polls FROM intel.feed_state"
                ).fetchall()
            except sqlite3.Error:
                feed_rows = []
            for r in feed_rows:
                last_success = _parse_ts(r["last_success"])
                age_days = (
                    round(conf.age_days(now, last_success), 6)
                    if last_success is not None
                    else None
                )
                feeds.append(
                    {
                        "feed_id": r["feed_id"],
                        "age_days": age_days,
                        "enabled": bool(r["enabled"]),
                        "consecutive_polls": r["consecutive_polls"],
                    }
                )
            attack_version = _attack_version(conn)

    metrics = state.metrics
    context_total = metrics.get("context_total", 0)
    breaker_total = metrics.get("context_breaker_total", 0)
    breaker_rate = (breaker_total / context_total) if context_total else 0.0

    return {
        "status": "ok",
        "cache_state": cache_state,
        "intel_generation": intel_generation,
        "local_generation": local_generation,
        "stats_generation": stats_generation,
        "attack_version": attack_version,
        "feeds": feeds,
        "audit_writer_ok": state.audit.healthy,
        "context_total": context_total,
        "context_breaker_total": breaker_total,
        "context_breaker_rate": breaker_rate,
        "pending_confirmations": pending_confirmations,
    }
