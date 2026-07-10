from __future__ import annotations

import re
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from urllib.parse import urlsplit

import idna


class NormalizationError(ValueError):
    pass


_HXXP_RE = re.compile(r"hxxp", re.IGNORECASE)
_AT_RE = re.compile(r"\[at\]", re.IGNORECASE)
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_JA4_RE = re.compile(r"^[A-Za-z0-9_]+$")
_ASN_RE = re.compile(r"^(AS)?(\d+)$", re.IGNORECASE)

_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}


def _rearm(value: str) -> str:
    v = value.strip()
    v = _HXXP_RE.sub("http", v)
    v = v.replace("[.]", ".").replace("(.)", ".")
    v = _AT_RE.sub("@", v)
    v = v.replace("[:]//", "://")
    return v


def _is_ip_literal(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def _to_alabel(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if not host:
        raise NormalizationError("empty host")
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise NormalizationError(f"invalid domain {host!r}: {exc}") from exc


def _normalize_domain(value: str) -> str:
    return _to_alabel(_rearm(value))


def _split_netloc(netloc: str) -> tuple[str | None, str, str | None]:
    userinfo = None
    hostport = netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            raise NormalizationError(f"malformed IPv6 host in URL: {netloc!r}")
        host = hostport[: end + 1]
        rest = hostport[end + 1 :]
        port = rest[1:] if rest.startswith(":") else None
    elif ":" in hostport:
        host, _, port = hostport.rpartition(":")
        if not port.isdigit():
            host, port = hostport, None
    else:
        host, port = hostport, None
    return userinfo, host, port


def _normalize_url(value: str) -> str:
    raw = _rearm(value)
    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        raise NormalizationError(f"invalid URL {value!r}")
    scheme = parts.scheme.lower()
    userinfo, host, port = _split_netloc(parts.netloc)
    if not host:
        raise NormalizationError(f"invalid URL {value!r}")
    if host.startswith("[") and host.endswith("]"):
        inner = host[1:-1]
        if not _is_ip_literal(inner):
            raise NormalizationError(f"invalid IPv6 literal in URL: {host!r}")
        host_norm = f"[{ip_address(inner).compressed}]"
    elif _is_ip_literal(host):
        host_norm = ip_address(host).compressed
    else:
        host_norm = _to_alabel(host)
    if port is not None and port.isdigit() and int(port) == _DEFAULT_PORTS.get(scheme):
        port = None
    netloc = host_norm
    if userinfo:
        netloc = f"{userinfo}@{netloc}"
    if port:
        netloc = f"{netloc}:{port}"
    result = f"{scheme}://{netloc}{parts.path}"
    if parts.query:
        result += f"?{parts.query}"
    if parts.fragment:
        result += f"#{parts.fragment}"
    return _PERCENT_RE.sub(lambda m: m.group(0).upper(), result)


def _normalize_ip(value: str) -> str:
    v = _rearm(value).strip()
    try:
        return ip_address(v).compressed
    except ValueError as exc:
        raise NormalizationError(f"invalid ip {value!r}: {exc}") from exc


def _normalize_hash(kind: str, value: str) -> str:
    v = value.strip().lower()
    length = _HASH_LENGTHS[kind]
    if len(v) != length or not _HEX_RE.match(v):
        raise NormalizationError(f"invalid {kind} hash {value!r}")
    return v


def _normalize_email(value: str) -> str:
    v = _rearm(value).strip()
    if v.count("@") != 1:
        raise NormalizationError(f"invalid email {value!r}")
    local, domain = v.split("@")
    if not local or not domain:
        raise NormalizationError(f"invalid email {value!r}")
    return f"{local}@{_to_alabel(domain)}"


def _normalize_ja3(value: str) -> str:
    v = value.strip().lower()
    if len(v) != 32 or not _HEX_RE.match(v):
        raise NormalizationError(f"invalid ja3 {value!r}")
    return v


def _normalize_ja4(value: str) -> str:
    v = value.strip()
    if not v or not _JA4_RE.match(v):
        raise NormalizationError(f"invalid ja4 {value!r}")
    return v


def _normalize_asn(value: str) -> str:
    v = value.strip()
    match = _ASN_RE.match(v)
    if not match:
        raise NormalizationError(f"invalid asn {value!r}")
    return f"AS{int(match.group(2))}"


def _normalize_cidr(value: str) -> str:
    v = _rearm(value).strip()
    try:
        network = ip_network(v, strict=False)
    except ValueError as exc:
        raise NormalizationError(f"invalid cidr {value!r}: {exc}") from exc
    return str(network)


def normalize(type_: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NormalizationError("empty value")
    key = type_.strip().lower()
    if key == "domain":
        return _normalize_domain(value)
    if key == "url":
        return _normalize_url(value)
    if key == "ip":
        return _normalize_ip(value)
    if key in _HASH_LENGTHS:
        return _normalize_hash(key, value)
    if key == "email":
        return _normalize_email(value)
    if key == "ja3":
        return _normalize_ja3(value)
    if key == "ja4":
        return _normalize_ja4(value)
    if key == "asn":
        return _normalize_asn(value)
    if key == "cidr":
        return _normalize_cidr(value)
    raise NormalizationError(f"unknown IOC type: {type_!r}")


def pack_ipv4_range(network: IPv4Network) -> tuple[bytes, bytes]:
    if not isinstance(network, IPv4Network):
        raise NormalizationError("expected IPv4Network")
    return (
        int(network.network_address).to_bytes(4, "big"),
        int(network.broadcast_address).to_bytes(4, "big"),
    )


def pack_ipv6_range(network: IPv6Network) -> tuple[bytes, bytes]:
    if not isinstance(network, IPv6Network):
        raise NormalizationError("expected IPv6Network")
    return (
        int(network.network_address).to_bytes(16, "big"),
        int(network.broadcast_address).to_bytes(16, "big"),
    )
