"""Warrant scope semantics: exact IP, CIDR, domain (subdomain-inclusive)."""
from __future__ import annotations

import ipaddress
import re

DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def is_target_like(t: str) -> bool:
    return is_ip(t) or is_cidr(t) or DOMAIN_RE.match(t or "") is not None


def is_ip(t: str) -> bool:
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def is_cidr(t: str) -> bool:
    try:
        ipaddress.ip_network(t, strict=True)
        return "/" in t
    except ValueError:
        return False


def matches(scope: list[str], target: str) -> bool:
    target = target.strip().lower().rstrip(".")
    for entry in scope:
        e = entry.strip().lower()
        if "/" in e:
            try:
                if is_ip(target) and ipaddress.ip_address(target) in ipaddress.ip_network(e):
                    return True
                continue
            except ValueError:
                continue
        if e == target:
            return True
        if DOMAIN_RE.match(e) and target.endswith("." + e):
            return True
    return False


def first_out_of_scope(scope: list[str], targets: list[str]) -> str | None:
    for t in targets:
        if not matches(scope, t):
            return t
    return None
