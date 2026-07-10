"""Rule-draft linting (design S5): round-trip byte-identity for Suricata,
`yaml.safe_load` equality for Sigma. Pure verification, no side effects.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import yaml

from azazel_knowledge.rules.suricata import unescape_content

_LOG = logging.getLogger(__name__)

_OPTION_KEYWORD_RE = re.compile(r"^[a-z_]+$")


def _split_options(optbody: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    while i < len(optbody):
        ch = optbody[i]
        if ch == "\\" and i + 1 < len(optbody):
            buf.append(ch)
            buf.append(optbody[i + 1])
            i += 2
            continue
        if ch == ";":
            parts.append("".join(buf))
            buf = []
            i += 1
            if i < len(optbody) and optbody[i] == " ":
                i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf)
    if tail.strip():
        parts.append(tail)
    return [p for p in parts if p != ""]


def parse_suricata(content: str) -> dict[str, Any]:
    open_idx = content.index("(")
    close_idx = content.rindex(")")
    header = content[:open_idx]
    optbody = content[open_idx + 1 : close_idx]
    tokens = header.split()
    options: list[tuple[str, str]] = []
    for option in _split_options(optbody):
        kw, sep, val = option.partition(":")
        if not sep:
            raise ValueError(f"malformed option: {option!r}")
        options.append((kw, val))
    return {"header": tokens, "options": options}


def render_suricata(parsed: dict[str, Any]) -> str:
    body = " ".join(f"{kw}:{val};" for kw, val in parsed["options"])
    return " ".join(parsed["header"]) + " (" + body + ")"


def lint_suricata(content: str) -> bool:
    try:
        parsed = parse_suricata(content)
        if render_suricata(parsed) != content:
            return False
        for kw, val in parsed["options"]:
            if not _OPTION_KEYWORD_RE.match(kw):
                return False
            if kw in ("msg", "content"):
                if not (val.startswith('"') and val.endswith('"')):
                    return False
                unescape_content(val[1:-1])
        return True
    except (ValueError, IndexError) as exc:
        _LOG.warning("suricata lint failure: %s", exc)
        return False


def lint_sigma(content: str) -> bool:
    try:
        loaded = yaml.safe_load(content)
        if not isinstance(loaded, dict):
            return False
        reloaded = yaml.safe_load(yaml.safe_dump(loaded, sort_keys=True))
        return reloaded == loaded
    except yaml.YAMLError as exc:
        _LOG.warning("sigma lint failure: %s", exc)
        return False
