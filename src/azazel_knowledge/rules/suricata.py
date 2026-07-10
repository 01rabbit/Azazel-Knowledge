"""Suricata advisory rule drafting (design S5) — pure text generation.

Rules are built from typed slots with strict `content` escaping (`|HH|`
for non-printables, backslash-escape for `; " \\`), refusing to draft on
grammar failure. Each draft carries provenance (ioc/feed ids,
generated_at, confidence) and a unique sid allocated from a config base
plus a counter. Round-trip byte-identity is verified by `rules/lint.py`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

_LOG = logging.getLogger(__name__)

_ALLOWED_PROTO = frozenset(
    {"tcp", "udp", "icmp", "ip", "http", "tls", "dns", "ssh", "smtp", "ftp"}
)
_ALLOWED_DIRECTION = frozenset({"->", "<>"})
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:/\[\]!,$-]+$")


@dataclass(frozen=True)
class RuleDraft:
    format: str
    sid: str
    content: str
    provenance: dict[str, Any]
    confidence: float | None
    generated_at: str
    content_hash: str = ""


@dataclass(frozen=True)
class SuricataSlots:
    proto: str
    src: str = "any"
    sport: str = "any"
    direction: str = "->"
    dst: str = "any"
    dport: str = "any"
    msg: str = ""
    contents: Sequence[str] = field(default_factory=tuple)
    rev: int = 1


def allocate_sid(sid_base: int, counter: int) -> str:
    return str(int(sid_base) + int(counter))


def escape_content(raw: str) -> str:
    out: list[str] = []
    for ch in raw:
        o = ord(ch)
        if ch in ('"', "\\", ";"):
            out.append("\\" + ch)
        elif 32 <= o < 127 and ch != "|":
            out.append(ch)
        else:
            out.append(f"|{o:02X}|")
    return "".join(out)


def unescape_content(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
            continue
        if ch == "|":
            end = text.index("|", i + 1)
            hex_part = text[i + 1 : end].replace(" ", "")
            for k in range(0, len(hex_part), 2):
                out.append(chr(int(hex_part[k : k + 2], 16)))
            i = end + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _valid_token(token: str) -> bool:
    return bool(_TOKEN_RE.match(token))


def _provenance_metadata(provenance: Mapping[str, Any]) -> str:
    encoded = json.dumps(provenance, sort_keys=True, separators=(",", ":"))
    return "azazel_provenance " + encoded.encode("utf-8").hex()


def _render(header_tokens: Sequence[str], options: Sequence[tuple[str, str]]) -> str:
    body = " ".join(f"{kw}:{val};" for kw, val in options)
    return " ".join(header_tokens) + " (" + body + ")"


def build_suricata(
    slots: SuricataSlots,
    *,
    sid_base: int,
    counter: int,
    provenance: Mapping[str, Any] | None = None,
    confidence: float | None = None,
    generated_at: str,
) -> RuleDraft | None:
    if slots.proto not in _ALLOWED_PROTO:
        _LOG.warning("suricata grammar failure: proto %r", slots.proto)
        return None
    if slots.direction not in _ALLOWED_DIRECTION:
        _LOG.warning("suricata grammar failure: direction %r", slots.direction)
        return None
    for name, token in (
        ("src", slots.src),
        ("sport", slots.sport),
        ("dst", slots.dst),
        ("dport", slots.dport),
    ):
        if not _valid_token(token):
            _LOG.warning("suricata grammar failure: %s %r", name, token)
            return None
    if not slots.msg.strip():
        _LOG.warning("suricata grammar failure: empty msg")
        return None
    if int(slots.rev) < 0:
        _LOG.warning("suricata grammar failure: rev %r", slots.rev)
        return None

    sid = allocate_sid(sid_base, counter)
    prov: dict[str, Any] = dict(provenance or {})
    prov.setdefault("generated_at", generated_at)
    if confidence is not None:
        prov.setdefault("confidence", confidence)

    header_tokens = [
        "alert",
        slots.proto,
        slots.src,
        slots.sport,
        slots.direction,
        slots.dst,
        slots.dport,
    ]
    options: list[tuple[str, str]] = [("msg", f'"{escape_content(slots.msg)}"')]
    for content_value in slots.contents:
        options.append(("content", f'"{escape_content(content_value)}"'))
    options.append(("sid", sid))
    options.append(("rev", str(int(slots.rev))))
    options.append(("metadata", _provenance_metadata(prov)))

    content = _render(header_tokens, options)
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return RuleDraft(
        format="suricata",
        sid=sid,
        content=content,
        provenance=prov,
        confidence=confidence,
        generated_at=generated_at,
        content_hash=content_hash,
    )
