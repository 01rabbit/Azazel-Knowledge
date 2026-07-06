"""ThreatFox (abuse.ch) JSON export feed adapter (design S6).

`{"data": [{"ioc": ..., "ioc_type": ..., "confidence_level": ...}]}`.
Per-item `confidence_level` is capped at `min(confidence_level, 90)`
(`feeds.yaml: threatfox.source_confidence.cap`). URL entries also derive
a host IOC, discounted and never critical-infra-flag-eligible, same as
urlhaus.
"""

from __future__ import annotations

import json
from typing import Any

from azazel_cti.core.clock import to_rfc3339
from azazel_cti.feeds.adapters._common import DERIVED_HOST_CONFIDENCE_FACTOR, classify, derive_host
from azazel_cti.feeds.base import FeedAdapter, IocRow, IocSourceRow, resolve_ttl
from azazel_cti.normalize.exclusions import Decision, ExclusionPolicy
from azazel_cti.normalize.ioc import NormalizationError, normalize

_TYPE_MAP = {
    "ip:port": "ip",
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "sha256_hash": "sha256",
    "sha1_hash": "sha1",
    "md5_hash": "md5",
}


def _split_ioc_type(ioc_type: str) -> str | None:
    return _TYPE_MAP.get(ioc_type.strip().lower())


def _strip_port(type_: str, value: str) -> str:
    if type_ == "ip" and ":" in value and not value.startswith("["):
        return value.rsplit(":", 1)[0]
    return value


class ThreatfoxAdapter(FeedAdapter):
    def __init__(self, *args: Any, exclusion_policy: ExclusionPolicy, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.exclusion_policy = exclusion_policy

    def parse(self, raw: bytes) -> list[dict[str, Any]]:
        document = json.loads(raw)
        return list(document.get("data", []) or [])

    def validate(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now_s = to_rfc3339(self.clock.query_as_of())
        cap_cfg = self.config.get("source_confidence")
        if isinstance(cap_cfg, dict):
            cap = int(cap_cfg.get("cap", 100))
        elif cap_cfg is not None:
            cap = int(cap_cfg)
        else:
            cap = 100
        entries: list[dict[str, Any]] = []
        for raw_item in items:
            mapped_type = _split_ioc_type(str(raw_item.get("ioc_type", "")))
            raw_value = raw_item.get("ioc")
            if not mapped_type or not raw_value:
                continue
            value = _strip_port(mapped_type, str(raw_value))
            try:
                value = normalize(mapped_type, value)
            except NormalizationError:
                continue

            decision = classify(self.exclusion_policy, mapped_type, value)
            if decision is Decision.REJECT:
                continue

            confidence = min(int(raw_item.get("confidence_level", 0)), cap)
            first_seen = raw_item.get("first_seen") or now_s
            last_seen = raw_item.get("last_seen") or now_s

            entry: dict[str, Any] = {
                "type": mapped_type,
                "value": value,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "confidence": confidence,
                "flag_critical_infra": decision is Decision.QUARANTINE_FLAG,
                "derived": None,
            }
            if mapped_type == "url":
                try:
                    derived_type, derived_value = derive_host(value)
                except NormalizationError:
                    derived_type = derived_value = None
                if derived_type is not None:
                    derived_decision = classify(self.exclusion_policy, derived_type, derived_value)
                    if derived_decision is Decision.ACCEPT:
                        entry["derived"] = {"type": derived_type, "value": derived_value}
            entries.append(entry)
        return entries

    def apply_batch(self, batch: list[dict[str, Any]]) -> int:
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
                    entry["confidence"],
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
                derived_confidence = int(round(entry["confidence"] * DERIVED_HOST_CONFIDENCE_FACTOR))
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
