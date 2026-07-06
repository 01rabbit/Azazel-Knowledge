"""URLhaus (abuse.ch) recent-URLs feed adapter (design S6).

CSV export with columns `url,host,date`. Each row's URL is the primary
IOC; a host (domain or IP) is derived from it and staged at
`source_confidence * 0.6`, tagged `derived-host`, and never eligible for
critical-infra flag-and-quarantine promotion (F-13 lineage guard).
"""

from __future__ import annotations

import csv
import io
from typing import Any

from azazel_cti.core.clock import to_rfc3339
from azazel_cti.feeds.adapters._common import DERIVED_HOST_CONFIDENCE_FACTOR, classify, derive_host
from azazel_cti.feeds.base import FeedAdapter, IocRow, IocSourceRow, resolve_ttl
from azazel_cti.feeds.sanity import within_length
from azazel_cti.normalize.exclusions import Decision, ExclusionPolicy
from azazel_cti.normalize.ioc import NormalizationError, normalize


class UrlhausAdapter(FeedAdapter):
    def __init__(self, *args: Any, exclusion_policy: ExclusionPolicy, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.exclusion_policy = exclusion_policy

    def parse(self, raw: bytes) -> list[dict[str, str]]:
        text = raw.decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        rows: list[dict[str, str]] = []
        for row in reader:
            url = (row.get("url") or "").strip()
            if not url or not within_length(url):
                continue
            rows.append(
                {
                    "url": url,
                    "host": (row.get("host") or "").strip(),
                    "date": (row.get("date") or "").strip(),
                }
            )
        return rows

    def validate(self, items: list[dict[str, str]]) -> list[dict[str, Any]]:
        now_s = to_rfc3339(self.clock.query_as_of())
        entries: list[dict[str, Any]] = []
        for row in items:
            try:
                url = normalize("url", row["url"])
            except NormalizationError:
                continue
            timestamp = row["date"] or now_s
            decision = classify(self.exclusion_policy, "url", url)
            if decision is Decision.REJECT:
                continue
            entry: dict[str, Any] = {
                "type": "url",
                "value": url,
                "first_seen": timestamp,
                "last_seen": now_s,
                "flag_critical_infra": decision is Decision.QUARANTINE_FLAG,
                "derived": None,
            }
            try:
                derived_type, derived_value = derive_host(url)
            except NormalizationError:
                derived_type = derived_value = None
            if derived_type is not None:
                derived_decision = classify(self.exclusion_policy, derived_type, derived_value)
                if derived_decision is Decision.ACCEPT:
                    entry["derived"] = {"type": derived_type, "value": derived_value}
            entries.append(entry)
        return entries

    def apply_batch(self, batch: list[dict[str, Any]]) -> int:
        confidence = int(self.config.get("source_confidence", 0))
        ttl_cfg = self.config.get("ttl")
        generation = self.current_intel_generation()
        now = self.clock.query_as_of()

        ioc_rows: list[IocRow] = []
        source_rows: list[IocSourceRow] = []
        quarantined: list[dict[str, Any]] = []

        for entry in batch:
            ttl = resolve_ttl(ttl_cfg, entry["type"])
            expires_at = to_rfc3339(now + ttl) if ttl else None
            ioc_rows.append(IocRow(entry["type"], entry["value"], entry["first_seen"], entry["last_seen"]))
            source_rows.append(
                IocSourceRow(
                    entry["type"],
                    entry["value"],
                    self.feed_id,
                    confidence,
                    entry["first_seen"],
                    entry["last_seen"],
                    expires_at,
                    generation,
                    flagged_critical_infra=entry["flag_critical_infra"],
                )
            )
            if entry["flag_critical_infra"]:
                quarantined.append(entry)

            derived = entry.get("derived")
            if derived:
                d_ttl = resolve_ttl(ttl_cfg, derived["type"])
                d_expires_at = to_rfc3339(now + d_ttl) if d_ttl else None
                derived_confidence = int(round(confidence * DERIVED_HOST_CONFIDENCE_FACTOR))
                ioc_rows.append(
                    IocRow(
                        derived["type"], derived["value"], entry["first_seen"], entry["last_seen"],
                        tags=["derived-host"],
                    )
                )
                source_rows.append(
                    IocSourceRow(
                        derived["type"],
                        derived["value"],
                        self.feed_id,
                        derived_confidence,
                        entry["first_seen"],
                        entry["last_seen"],
                        d_expires_at,
                        generation,
                        flagged_critical_infra=False,
                    )
                )

        applied = self.stage_and_swap_ioc(ioc_rows, source_rows)
        if quarantined:
            now_s = to_rfc3339(now)
            for entry in quarantined:
                self.insert_quarantine(now_s, "critical_infra", f"{entry['type']}:{entry['value']}")
        return applied
