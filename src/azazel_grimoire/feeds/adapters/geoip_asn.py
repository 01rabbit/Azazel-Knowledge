"""Local MaxMind-style GeoIP/ASN CSV feed adapter (design S6, F-13).

Reads a local `network,asn,org` (MaxMind `GeoLite2-ASN-Blocks` naming:
`network,autonomous_system_number,autonomous_system_organization` also
accepted) CSV/TSV file -- never fetched over the network. There is no
`asn_org` mapping table in the intel schema, so organization data is
stored as a tag on the `ioc` row for that ASN (query-defensive: no
migration edits).
"""

from __future__ import annotations

import csv
import io
from ipaddress import ip_network
from typing import Any

from azazel_grimoire.core.clock import to_rfc3339
from azazel_grimoire.feeds.base import FeedAdapter, IocCidrRow, IocRow, IocSourceRow, resolve_ttl
from azazel_grimoire.normalize.ioc import NormalizationError, normalize

DEFAULT_SOURCE_CONFIDENCE = 60
_ASN_COLUMNS = ("asn", "autonomous_system_number")
_ORG_COLUMNS = ("org", "autonomous_system_organization")


def _sniff_delimiter(sample: str) -> str:
    return "\t" if "\t" in sample.splitlines()[0] else ","


def _first_present(row: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        if row.get(key):
            return row[key]
    return None


class GeoipAsnAdapter(FeedAdapter):
    def parse(self, raw: bytes) -> list[dict[str, str]]:
        text = raw.decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            return []
        delimiter = _sniff_delimiter(lines[0])
        reader = csv.DictReader(io.StringIO("\n".join(lines)), delimiter=delimiter)
        rows: list[dict[str, str]] = []
        for row in reader:
            network = (row.get("network") or "").strip()
            asn_raw = _first_present(row, _ASN_COLUMNS)
            if not network or not asn_raw:
                continue
            rows.append({"network": network, "asn": str(asn_raw).strip(), "org": (_first_present(row, _ORG_COLUMNS) or "").strip()})
        return rows

    def validate(self, items: list[dict[str, str]]) -> list[dict[str, Any]]:
        now_s = to_rfc3339(self.clock.query_as_of())
        entries: list[dict[str, Any]] = []
        for row in items:
            try:
                network = ip_network(row["network"], strict=False)
                asn = normalize("asn", row["asn"])
            except (ValueError, NormalizationError):
                continue
            if network.version != 4:
                continue
            entries.append(
                {
                    "network": network,
                    "asn": asn,
                    "org": row.get("org") or None,
                    "first_seen": now_s,
                    "last_seen": now_s,
                }
            )
        return entries

    def apply_batch(self, batch: list[dict[str, Any]]) -> int:
        confidence = int(self.config.get("source_confidence", DEFAULT_SOURCE_CONFIDENCE))
        ttl_cfg = self.config.get("ttl")
        generation = self.current_intel_generation()
        now = self.clock.query_as_of()
        ttl = resolve_ttl(ttl_cfg, "asn")
        expires_at = to_rfc3339(now + ttl) if ttl else None

        by_asn: dict[str, dict[str, Any]] = {}
        cidr_rows: list[IocCidrRow] = []
        for entry in batch:
            asn = entry["asn"]
            existing = by_asn.setdefault(
                asn, {"asn": asn, "org": entry["org"], "first_seen": entry["first_seen"], "last_seen": entry["last_seen"]}
            )
            if entry["org"] and not existing["org"]:
                existing["org"] = entry["org"]
            network = entry["network"]
            cidr_rows.append(
                IocCidrRow(
                    tier="asn",
                    range_start=int(network.network_address),
                    range_end=int(network.broadcast_address),
                    type="asn",
                    value=asn,
                    feed_id=self.feed_id,
                    expires_at=expires_at,
                )
            )

        ioc_rows: list[IocRow] = []
        source_rows: list[IocSourceRow] = []
        for asn, info in by_asn.items():
            tags = [f"org:{info['org']}"] if info["org"] else []
            ioc_rows.append(IocRow("asn", asn, info["first_seen"], info["last_seen"], tags=tags))
            source_rows.append(
                IocSourceRow(
                    "asn",
                    asn,
                    self.feed_id,
                    confidence,
                    info["first_seen"],
                    info["last_seen"],
                    expires_at,
                    generation,
                    flagged_critical_infra=False,
                )
            )

        source_count, _ = self.stage_and_swap_ioc_with_cidr(ioc_rows, source_rows, cidr_rows)
        return source_count
