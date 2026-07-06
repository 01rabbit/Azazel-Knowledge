"""Spamhaus ASN-DROP feed adapter (design S6, F-13).

Source document: `{"entries": [{"asn": "AS12345", "org": "...", "ranges": [...]}]}`.
Each entry becomes an `ioc` row of type `asn` (a reputation entry backing
the `geo_asn` scoring component) plus, when the entry carries IP ranges,
`ioc_cidr` rows in the `asn` tier so an IP lookup resolves to that ASN.
"""

from __future__ import annotations

import json
from ipaddress import ip_network
from typing import Any

from azazel_cti.core.clock import to_rfc3339
from azazel_cti.feeds.base import FeedAdapter, IocCidrRow, IocRow, IocSourceRow, resolve_ttl
from azazel_cti.normalize.ioc import NormalizationError, normalize

DEFAULT_SOURCE_CONFIDENCE = 70


class SpamhausAsnDropAdapter(FeedAdapter):
    def parse(self, raw: bytes) -> list[dict[str, Any]]:
        document = json.loads(raw)
        return list(document.get("entries", []) or [])

    def validate(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now_s = to_rfc3339(self.clock.query_as_of())
        entries: list[dict[str, Any]] = []
        for row in items:
            raw_asn = row.get("asn")
            if not raw_asn:
                continue
            try:
                asn = normalize("asn", str(raw_asn))
            except NormalizationError:
                continue
            ranges: list[str] = []
            for cidr in row.get("ranges", []) or []:
                try:
                    network = ip_network(cidr, strict=False)
                except ValueError:
                    continue
                if network.version == 4:
                    ranges.append(str(network))
            entries.append(
                {
                    "asn": asn,
                    "org": row.get("org"),
                    "ranges": ranges,
                    "first_seen": row.get("first_seen") or now_s,
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

        ioc_rows: list[IocRow] = []
        source_rows: list[IocSourceRow] = []
        cidr_rows: list[IocCidrRow] = []

        for entry in batch:
            tags = [f"org:{entry['org']}"] if entry.get("org") else []
            ioc_rows.append(IocRow("asn", entry["asn"], entry["first_seen"], entry["last_seen"], tags=tags))
            source_rows.append(
                IocSourceRow(
                    "asn",
                    entry["asn"],
                    self.feed_id,
                    confidence,
                    entry["first_seen"],
                    entry["last_seen"],
                    expires_at,
                    generation,
                    flagged_critical_infra=False,
                )
            )
            for cidr in entry["ranges"]:
                network = ip_network(cidr, strict=False)
                cidr_rows.append(
                    IocCidrRow(
                        tier="asn",
                        range_start=int(network.network_address),
                        range_end=int(network.broadcast_address),
                        type="asn",
                        value=entry["asn"],
                        feed_id=self.feed_id,
                        expires_at=expires_at,
                    )
                )

        source_count, _ = self.stage_and_swap_ioc_with_cidr(ioc_rows, source_rows, cidr_rows)
        return source_count
