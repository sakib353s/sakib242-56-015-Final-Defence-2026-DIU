"""Egress guard for operator-supplied URLs (osint url_report, docfp crawl).

Loopback and RFC1918 stay ALLOWED on purpose: this is a lab platform whose own
services (127.0.0.1:8471, 10.x lab nets) are legitimate crawl/report targets —
refusing them would break the product. What must never be reachable is
link-local (169.254.0.0/16 — cloud metadata), unspecified, multicast and
reserved ranges, on the seed URL AND below every redirect hop (a public URL
that 302s to the metadata endpoint is the classic SSRF chain).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from app.core.errors import RefusedOutOfWork


def _blocked(ip: ipaddress._BaseAddress) -> bool:
    # loopback first: CPython lists ::1/128 in the IPv6 *reserved* set, so
    # checking is_reserved without this would refuse "localhost" — a core lab
    # target — while still allowing 127.0.0.1. Anything else odd is refused.
    if ip.is_loopback:
        return False
    return ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved


def guard_public_url(url: str) -> None:
    """Raise RefusedOutOfWork if the URL's host resolves (even partly) to a
    blocked range. Blocking DNS call — call via asyncio.to_thread in async paths."""
    host = urlsplit(url).hostname
    if not host:
        raise RefusedOutOfWork("URL has no host to resolve")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise RefusedOutOfWork(f"target host does not resolve: {host}") from None
    for *_rest, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if _blocked(ip):
            raise RefusedOutOfWork(f"egress to {ip} is blocked (link-local/metadata/reserved)")
