"""Sigma advisory rule drafting (design S5) — pure text via yaml.safe_dump."""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Mapping

import yaml

from azazel_knowledge.rules.suricata import RuleDraft

_LOG = logging.getLogger(__name__)


def build_sigma(
    *,
    title: str,
    logsource: Mapping[str, Any],
    selection: Mapping[str, Any],
    condition: str = "selection",
    sid_base: int,
    counter: int,
    provenance: Mapping[str, Any] | None = None,
    confidence: float | None = None,
    generated_at: str,
) -> RuleDraft | None:
    if not title.strip():
        _LOG.warning("sigma grammar failure: empty title")
        return None
    if not selection:
        _LOG.warning("sigma grammar failure: empty selection")
        return None
    if not isinstance(logsource, Mapping) or not logsource:
        _LOG.warning("sigma grammar failure: invalid logsource")
        return None

    sid = str(int(sid_base) + int(counter))
    prov: dict[str, Any] = dict(provenance or {})
    prov.setdefault("generated_at", generated_at)
    if confidence is not None:
        prov.setdefault("confidence", confidence)

    document = {
        "title": title,
        "id": sid,
        "status": "experimental",
        "logsource": dict(logsource),
        "detection": {"selection": dict(selection), "condition": condition},
        "azazel_provenance": prov,
    }
    try:
        content = yaml.safe_dump(document, sort_keys=True)
    except yaml.YAMLError as exc:
        _LOG.warning("sigma grammar failure: %s", exc)
        return None

    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return RuleDraft(
        format="sigma",
        sid=sid,
        content=content,
        provenance=prov,
        confidence=confidence,
        generated_at=generated_at,
        content_hash=content_hash,
    )
