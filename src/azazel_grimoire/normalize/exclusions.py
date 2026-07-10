from __future__ import annotations

from enum import Enum
from ipaddress import ip_address, ip_network
from pathlib import Path


class Decision(Enum):
    REJECT = "reject"
    QUARANTINE_FLAG = "quarantine_flag"
    ACCEPT = "accept"


def _parse_scalar(text: str):
    text = text.strip()
    if text == "[]":
        return []
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [item.strip().strip("\"'") for item in inner.split(",")]
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _parse_yaml_subset(text: str) -> dict:
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if line.strip():
            indent = len(line) - len(line.lstrip(" "))
            lines.append((indent, line.strip()))

    pos = 0

    def parse_list(indent: int) -> list:
        nonlocal pos
        items: list = []
        while pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("- "):
            content = lines[pos][1][2:].strip()
            pos += 1
            if ":" in content:
                item: dict = {}
                key, _, rest = content.partition(":")
                item[key.strip()] = _parse_scalar(rest) if rest.strip() else None
                child_indent = indent + 2
                while pos < len(lines) and lines[pos][0] == child_indent:
                    k2, sep2, r2 = lines[pos][1].partition(":")
                    if not sep2:
                        break
                    item[k2.strip()] = _parse_scalar(r2) if r2.strip() else None
                    pos += 1
                items.append(item)
            else:
                items.append(_parse_scalar(content))
        return items

    def parse_block(indent: int) -> dict:
        nonlocal pos
        result: dict = {}
        while pos < len(lines) and lines[pos][0] == indent:
            key, sep, rest = lines[pos][1].partition(":")
            if not sep:
                raise ValueError(f"cannot parse line: {lines[pos][1]!r}")
            key = key.strip()
            rest = rest.strip()
            pos += 1
            if rest:
                result[key] = _parse_scalar(rest)
            elif pos < len(lines) and lines[pos][0] > indent and lines[pos][1].startswith("- "):
                result[key] = parse_list(lines[pos][0])
            elif pos < len(lines) and lines[pos][0] > indent:
                result[key] = parse_block(lines[pos][0])
            else:
                result[key] = {}
        return result

    return parse_block(0) if lines else {}


def _matches_network(networks: list[str], type_: str, value: str) -> bool:
    if type_ == "ip":
        try:
            candidate = ip_address(value)
        except ValueError:
            return False
        for net in networks:
            try:
                if candidate in ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
        return False
    if type_ == "cidr":
        try:
            candidate_net = ip_network(value, strict=False)
        except ValueError:
            return False
        for net in networks:
            try:
                if candidate_net.overlaps(ip_network(net, strict=False)):
                    return True
            except ValueError:
                continue
        return False
    return False


class ExclusionPolicy:
    def __init__(self, own_networks: list[str], critical_infrastructure: list[dict]) -> None:
        self._own_networks = list(own_networks)
        self._critical_entries = list(critical_infrastructure)
        self._critical_networks = [
            entry["cidr"] for entry in self._critical_entries if isinstance(entry, dict) and entry.get("cidr")
        ]

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> "ExclusionPolicy":
        text = Path(path).read_text()
        data = _parse_yaml_subset(text)
        own = data.get("own_networks") or []
        critical = data.get("critical_infrastructure") or []
        return cls(own, critical)

    @classmethod
    def empty(cls) -> "ExclusionPolicy":
        return cls([], [])

    @staticmethod
    def is_bogon(ip: str) -> bool:
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        return addr.is_private or addr.is_multicast or addr.is_reserved or addr.is_unspecified

    def is_own_infra(self, type_: str, value: str) -> bool:
        return _matches_network(self._own_networks, type_, value)

    def is_critical_infra(self, type_: str, value: str) -> Decision:
        if type_ == "ip" and self.is_bogon(value):
            return Decision.REJECT
        if self.is_own_infra(type_, value):
            return Decision.REJECT
        if _matches_network(self._critical_networks, type_, value):
            return Decision.QUARANTINE_FLAG
        return Decision.ACCEPT
