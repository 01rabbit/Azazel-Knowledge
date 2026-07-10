"""`POST /v1/ioc|ja3|ja4/search` (design S4/S5).

One-row read path: an exact `ioc.agg_*` lookup (falling back to CIDR
containment tiers for a missed `ip`), plus a single indexed point-read
on `reputation`. Confidence is the same canonical four-driver formula
`context` uses (`scoring/confidence.py`) so the two paths stay in
formula parity; the only input divergence is that this path never reads
`observation_stats`, so `local_corroboration` here reflects only the
`reputation` materialization, exactly as the parity contract documents.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from ipaddress import AddressValueError, IPv4Address

from fastapi import APIRouter, Depends, HTTPException, Request

from azazel_grimoire.api.app import AuthContext, ensure_warm_cache, require_scope_dep
from azazel_grimoire.api.models import (
    IocSearchRequest,
    Ja3Ja4SearchRequest,
    SearchBasis,
    SearchResponse,
)
from azazel_grimoire.audit.logger import AuditUnavailable
from azazel_grimoire.core.clock import parse_rfc3339, to_rfc3339
from azazel_grimoire.db.repository import Repository, entity_key
from azazel_grimoire.normalize.ioc import NormalizationError, normalize
from azazel_grimoire.scoring import confidence as conf
from azazel_grimoire.scoring.compute import HistoryInput, IocMatchInput, ScoringContext, SourceRef
from azazel_grimoire.security.auth import Scope

router = APIRouter(prefix="/v1", tags=["lookup"])

_QUERY_SCOPE = Depends(require_scope_dep(Scope.QUERY))
_CIDR_TIERS = ("host", "/24", "/16", "asn")
_EXACT_CORROBORATION_TYPES = frozenset(
    {"ip", "domain", "url", "hash", "md5", "sha1", "sha256"}
)


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


def _feed_groups(loader) -> dict[str, str]:
    feeds = loader.feeds().get("feeds", {})
    return {
        feed_id: (spec or {}).get("group", feed_id) for feed_id, spec in feeds.items()
    }


def _get_ioc_by_id(conn: sqlite3.Connection, ioc_id: int) -> sqlite3.Row | None:
    conn.row_factory = sqlite3.Row
    return conn.execute(
        "SELECT ioc_id, type, value, first_seen, last_seen, agg_raw_confidence, "
        "agg_next_expiry, agg_computed_at FROM intel.ioc WHERE ioc_id = ?",
        (ioc_id,),
    ).fetchone()


def _sources(
    conn: sqlite3.Connection, ioc_id: int, feed_groups: dict[str, str]
) -> tuple[SourceRef, ...]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT feed_id, source_confidence, first_seen, last_seen, expires_at "
        "FROM intel.ioc_source WHERE ioc_id = ? ORDER BY feed_id",
        (ioc_id,),
    ).fetchall()
    out = []
    for row in rows:
        out.append(
            SourceRef(
                feed_id=row["feed_id"],
                group=feed_groups.get(row["feed_id"], row["feed_id"]),
                base_confidence=float(row["source_confidence"]),
                first_seen=_parse_ts(row["first_seen"])
                or datetime.min.replace(tzinfo=timezone.utc),
                last_seen=_parse_ts(row["last_seen"])
                or datetime.min.replace(tzinfo=timezone.utc),
            )
        )
    return tuple(out)


def _audit_search(request: Request, auth: AuthContext, type_: str, raw_value: str, response: SearchResponse) -> None:
    event = {
        "type": "search",
        "ioc_type": type_,
        "value": raw_value,
        "key_id": auth.key_id,
        "match": response.match,
        "confidence": response.confidence,
    }
    try:
        request.app.state.audit.append(event)
    except AuditUnavailable:
        pass


def _do_search(request: Request, auth: AuthContext, type_: str, raw_value: str) -> SearchResponse:
    ensure_warm_cache(request)
    state = request.app.state
    loader = state.loader
    repo: Repository = state.repo
    clock = state.clock

    try:
        value = normalize(type_, raw_value)
    except NormalizationError:
        raise HTTPException(status_code=422, detail={"error": "invalid_value"})

    query_as_of = clock.query_as_of()
    feed_groups = _feed_groups(loader)

    row: sqlite3.Row | None = None
    match_tier = "exact"
    sources: tuple[SourceRef, ...] = ()
    reputation_score: float | None = None

    with repo.connection() as conn:
        conn.row_factory = sqlite3.Row
        row = repo.get_ioc(conn, type_, value)

        if row is None and type_ == "ip":
            try:
                packed = int(IPv4Address(value))
            except AddressValueError:
                packed = None
            if packed is not None:
                for tier in _CIDR_TIERS:
                    cidr_row = repo.find_cidr_containing(conn, tier, packed)
                    if cidr_row is not None:
                        candidate = _get_ioc_by_id(conn, cidr_row["ioc_id"])
                        if candidate is not None:
                            row = candidate
                            match_tier = f"cidr_{tier}"
                            break

        if row is not None:
            sources = _sources(conn, int(row["ioc_id"]), feed_groups)

        rep_row = repo.get_reputation(conn, entity_key(type_, value))
        reputation_score = float(rep_row["score"]) if rep_row is not None else None

    corroborated = (
        row is not None
        and match_tier == "exact"
        and row["type"] in _EXACT_CORROBORATION_TYPES
    )

    ioc_matches: tuple[IocMatchInput, ...] = ()
    if row is not None:
        ioc_matches = (
            IocMatchInput(
                entity_key=entity_key(row["type"], row["value"]).hex(),
                type=row["type"],
                value=row["value"],
                ioc_id=int(row["ioc_id"]),
                agg_raw_confidence=float(row["agg_raw_confidence"]),
                first_seen=_parse_ts(row["first_seen"])
                or datetime.min.replace(tzinfo=timezone.utc),
                last_seen=_parse_ts(row["last_seen"])
                or datetime.min.replace(tzinfo=timezone.utc),
                sources=sources,
                match_tier=match_tier,
            ),
        )

    scoring_cfg = loader.scoring()
    ctx = ScoringContext(
        query_as_of=query_as_of,
        intel_generation=0,
        local_generation=0,
        stats_generation=0,
        attack_version="",
        config_hash=loader.config_hash,
        config=scoring_cfg,
        event={},
        ioc_matches=ioc_matches,
        primary_index=0 if ioc_matches else None,
        corroborated=corroborated,
        history=HistoryInput(),
        stats_stale=False,
        reputation_score=reputation_score,
    )
    confidence_result = conf.score_confidence(ctx)

    confidence_basis = None
    if row is not None and row["type"] in ("ja3", "ja4"):
        cap = conf.ja_type_cap(
            row["type"], corroborated, scoring_cfg["components"]["ioc_match"]
        )
        if cap is not None:
            confidence_basis = "corroborated_cap" if corroborated else "type_cap"

    freshest = min((s.last_seen for s in sources), default=None) if sources else None
    source_freshness_days = (
        round(conf.age_days(query_as_of, freshest), 6) if freshest is not None else None
    )

    response = SearchResponse(
        match=row is not None,
        confidence=confidence_result.confidence,
        confidence_reason=list(confidence_result.confidence_reason),
        sources=sorted({s.feed_id for s in sources}),
        first_seen=to_rfc3339(ioc_matches[0].first_seen) if ioc_matches else None,
        last_seen=to_rfc3339(ioc_matches[0].last_seen) if ioc_matches else None,
        source_freshness_days=source_freshness_days,
        basis=SearchBasis(
            groups=sorted({s.group for s in sources}),
            source_count=len(sources),
            freshest_last_seen=to_rfc3339(freshest) if freshest is not None else None,
        ),
        confidence_basis=confidence_basis,
    )
    _audit_search(request, auth, type_, raw_value, response)
    return response


@router.post("/ioc/search", response_model=SearchResponse)
def search_ioc(
    request: Request, body: IocSearchRequest, auth: AuthContext = _QUERY_SCOPE
) -> SearchResponse:
    return _do_search(request, auth, body.type.strip().lower(), body.value)


@router.post("/ja3/search", response_model=SearchResponse)
def search_ja3(
    request: Request, body: Ja3Ja4SearchRequest, auth: AuthContext = _QUERY_SCOPE
) -> SearchResponse:
    return _do_search(request, auth, "ja3", body.value)


@router.post("/ja4/search", response_model=SearchResponse)
def search_ja4(
    request: Request, body: Ja3Ja4SearchRequest, auth: AuthContext = _QUERY_SCOPE
) -> SearchResponse:
    return _do_search(request, auth, "ja4", body.value)
