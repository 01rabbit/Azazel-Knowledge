"""Shared helpers for the abuse.ch IOC-bearing feed adapters.

Kept separate from `feeds/base.py` (the adapter lifecycle ABC) because
this module is normalize/exclusion glue specific to urlhaus,
malwarebazaar and threatfox, not part of the generic adapter contract.
"""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlsplit

from azazel_grimoire.normalize.exclusions import Decision, ExclusionPolicy
from azazel_grimoire.normalize.ioc import NormalizationError, normalize

DERIVED_HOST_CONFIDENCE_FACTOR = 0.6


def derive_host(normalized_url: str) -> tuple[str, str]:
    """Return (type, normalized_value) for the host embedded in a normalized URL."""
    host = urlsplit(normalized_url).hostname
    if not host:
        raise NormalizationError(f"cannot derive host from {normalized_url!r}")
    try:
        ip_address(host)
        return "ip", normalize("ip", host)
    except ValueError:
        return "domain", normalize("domain", host)


def classify(policy: ExclusionPolicy, type_: str, value: str) -> Decision:
    return policy.is_critical_infra(type_, value)


def parse_feed_timestamp(value: str) -> datetime:
    text = value.strip()
    if not text:
        raise NormalizationError("empty timestamp")
    for candidate in (text, text.replace(" ", "T") + ("Z" if "Z" not in text and "+" not in text else "")):
        try:
            dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise NormalizationError(f"unparseable timestamp {value!r}")
