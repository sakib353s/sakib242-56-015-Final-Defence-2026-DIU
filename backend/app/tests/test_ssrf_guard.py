"""Egress guard contract for operator-supplied URLs (osint/docfp).

Regressions guarded:
  * loopback must stay allowed (crawler targets the platform's own lab services);
  * link-local/metadata/unspecified must stay refused (::1 must not be
    refused merely because CPython counts it in the IPv6 reserved set).
"""
import pytest

from app.core.errors import RefusedOutOfWork
from app.core.ssrf import guard_public_url


def test_loopback_allowed_both_families():
    guard_public_url("http://127.0.0.1:8471/api/v1/health")
    guard_public_url("http://localhost:3000/")


def test_metadata_and_unspecified_refused():
    with pytest.raises(RefusedOutOfWork):
        guard_public_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(RefusedOutOfWork):
        guard_public_url("http://0.0.0.0/")


def test_garbage_refused_not_crash():
    for bad in ("http:///nohost", "not a url"):
        with pytest.raises(RefusedOutOfWork):
            guard_public_url(bad)
