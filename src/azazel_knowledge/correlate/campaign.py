"""Campaign matching (design S5 campaign component).

Queries the intel campaign tables if present. Phase 1 intel migrations
ship no campaign tables, so this degrades to a zero-contribution
`CampaignInput` — every query is defensive and any missing table or
schema mismatch yields "no data" rather than an error.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Sequence

from azazel_knowledge.core.clock import parse_rfc3339
from azazel_knowledge.scoring.compute import CampaignInput

_CAMPAIGN_TABLES = ("campaign", "campaign_ioc", "campaign_technique")


def _intel_tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM intel.sqlite_master WHERE type = 'table'"
    ).fetchall()
    return {row[0] for row in rows}


def _parse_ts(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        return parse_rfc3339(str(value))
    except (ValueError, TypeError):
        try:
            return datetime.fromisoformat(str(value))
        except (ValueError, TypeError):
            return None


def match_campaign(
    conn: sqlite3.Connection,
    entity_keys: Sequence[bytes],
    technique_ids: Sequence[str],
    query_as_of: datetime,
) -> CampaignInput:
    empty = CampaignInput()
    try:
        tables = _intel_tables(conn)
    except sqlite3.Error:
        return empty
    if not all(table in tables for table in _CAMPAIGN_TABLES):
        return empty
    if not entity_keys and not technique_ids:
        return empty

    conn.row_factory = sqlite3.Row
    try:
        campaigns = conn.execute(
            "SELECT campaign_id, name, actor, last_seen FROM intel.campaign"
        ).fetchall()
    except sqlite3.Error:
        return empty

    best: CampaignInput = empty
    best_strength = -1.0
    key_set = set(entity_keys)
    technique_set = set(technique_ids)

    for campaign in campaigns:
        try:
            camp_iocs = {
                row[0]
                for row in conn.execute(
                    "SELECT entity_key FROM intel.campaign_ioc WHERE campaign_id = ?",
                    (campaign["campaign_id"],),
                )
            }
            camp_tech = {
                row[0]
                for row in conn.execute(
                    "SELECT technique_id FROM intel.campaign_technique "
                    "WHERE campaign_id = ?",
                    (campaign["campaign_id"],),
                )
            }
        except sqlite3.Error:
            continue

        ioc_overlap = (
            len(key_set & camp_iocs) / len(key_set) if key_set else 0.0
        )
        technique_overlap = (
            len(technique_set & camp_tech) / len(technique_set)
            if technique_set
            else 0.0
        )
        if ioc_overlap == 0.0 and technique_overlap == 0.0:
            continue

        matched_keys = key_set & camp_iocs
        ref_count = len(matched_keys) + len(technique_set & camp_tech)
        distinct_ref_types = int(bool(matched_keys)) + int(
            bool(technique_set & camp_tech)
        )
        strength = 0.7 * ioc_overlap + 0.3 * technique_overlap
        if strength > best_strength:
            best_strength = strength
            best = CampaignInput(
                matched=True,
                name=campaign["name"],
                actor=campaign["actor"],
                ioc_overlap=round(ioc_overlap, 6),
                technique_overlap=round(technique_overlap, 6),
                ref_count=ref_count,
                distinct_ref_types=distinct_ref_types,
                last_seen=_parse_ts(campaign["last_seen"]),
            )

    return best
