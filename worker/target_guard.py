"""Reject Deep Scan targets that are private, loopback, link-local, or metadata.

The web app applies the same policy before enqueue. The worker checks again so a
signed or dev-unsigned job cannot aim nmap/nuclei at the cloud metadata service.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeTargetError(ValueError):
    pass


_METADATA = {
    "metadata.google.internal",
    "metadata.goog",
}
_SUFFIXES = (".localhost", ".local", ".localdomain", ".internal")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_BENCH = ipaddress.ip_network("198.18.0.0/15")


def _token_values(token: str) -> list[int]:
    if token.lower().startswith("0x"):
        try:
            return [int(token, 16)]
        except ValueError:
            return []
    if not token.isdigit():
        return []
    decimal = int(token, 10)
    if len(token) > 1 and token.startswith("0") and all(c in "01234567" for c in token):
        octal = int(token, 8)
        return [decimal] if octal == decimal else [octal, decimal]
    return [decimal]


def _ipv4_values(host: str) -> list[int]:
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return []
    choices = [_token_values(part) for part in parts]
    if any(not choice for choice in choices):
        return []
    widths = {1: [32], 2: [8, 24], 3: [8, 8, 16], 4: [8, 8, 8, 8]}[len(parts)]
    out: list[int] = []

    def walk(index: int, acc: list[int]) -> None:
        if index == len(choices):
            value = 0
            for part, bits in zip(acc, widths):
                limit = 1 << bits
                if part < 0 or part >= limit:
                    return
                value = (value << bits) | part
            out.append(value & 0xFFFFFFFF)
            return
        for number in choices[index]:
            walk(index + 1, [*acc, number])

    walk(0, [])
    return out


def _bad_ip(addr: str) -> bool:
    text = addr.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        values = _ipv4_values(text)
        if not values:
            return False
        return any(_bad_ip(str(ipaddress.IPv4Address(value))) for value in values)
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if isinstance(ip, ipaddress.IPv4Address) and (ip in _CGNAT or ip in _BENCH):
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_blocked_host(hostname: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or host in _METADATA or host == "localhost":
        return True
    if any(host.endswith(suffix) for suffix in _SUFFIXES):
        return True
    if ":" in host:
        return _bad_ip(host)
    values = _ipv4_values(host)
    if values:
        return any(_bad_ip(str(ipaddress.IPv4Address(value))) for value in values)
    if "." not in host:
        return True
    return False


def guard_target(target: str) -> str:
    """Return a normalized http(s) URL or raise UnsafeTargetError."""
    raw = (target or "").strip()
    if not raw:
        raise UnsafeTargetError("Missing target URL")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTargetError("Only http and https targets are allowed")
    if is_blocked_host(parsed.hostname):
        raise UnsafeTargetError("Refusing to scan private or internal hosts")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise UnsafeTargetError("Could not resolve target to a public address") from exc
    for info in infos:
        address = info[4][0]
        if _bad_ip(address):
            raise UnsafeTargetError("Refusing to scan hosts that resolve to private addresses")
    return parsed.geturl()
