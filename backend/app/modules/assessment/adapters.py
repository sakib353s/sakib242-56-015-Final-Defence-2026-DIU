"""Real scanner adapters for the Security Assessment Studio.

Each adapter performs genuine network analysis using installed libraries and
returns structured observations + evidence. Adapters NEVER fabricate results:
when a capability is unavailable they return an honest degraded marker that the
pipeline records as stage status 'degraded'/'skipped'. No payloads, no exploits,
no brute force — passive + single benign request observation only.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import ssl
from urllib.parse import urlparse

import dns.asyncresolver
import dns.rdatatype
import httpx

ENGINE_VERSION = "1.0.0"


def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def canonicalize(raw: str) -> tuple[str, str]:
    """Return (canonical_value, target_type). Strips scheme/path from URLs,
    lowercases domains, validates IPs."""
    raw = raw.strip()
    low = raw.lower()
    if low.startswith(("http://", "https://")):
        p = urlparse(low)
        host = p.hostname or ""
        if not host:
            raise ValueError("URL has no hostname")
        try:
            ipaddress.ip_address(host)
            return host, "ip"
        except ValueError:
            return host.rstrip("."), "url" if p.path not in ("", "/") else "domain"
    try:
        ipaddress.ip_address(raw)
        return raw, "ip"
    except ValueError:
        pass
    return raw.lower().rstrip("."), "domain"


async def dns_analyze(target: str, target_type: str) -> dict:
    """Resolve A/AAAA/MX/NS/TXT/CNAME/SOA via dnspython. Real queries."""
    obs: list[dict] = []
    ev: list[dict] = []
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.lifetime = 8.0
    resolver.timeout = 4.0
    queried_host = target if target_type != "url" else target
    try:
        answers = {}
        for rdtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            try:
                resp = await asyncio.wait_for(resolver.resolve(queried_host, rdtype), timeout=10)
                rrset = resp.rrset
                vals = [r.to_text() for r in rrset] if rrset is not None else []
            except (dns.exception.DNSException, OSError, asyncio.TimeoutError):
                vals = []
            answers[rdtype] = vals
            if vals:
                obs.append({
                    "kind": f"dns.{rdtype.lower()}",
                    "entity_type": "record",
                    "entity_value": ",".join(vals[:10]),
                    "confidence": 0.95,
                    "payload": {"host": queried_host, "type": rdtype, "values": vals},
                })
        raw = json.dumps(answers, sort_keys=True)
        ev.append({
            "kind": "dns_answers",
            "ref": queried_host,
            "sha256": _sha256(raw),
            "size": len(raw),
            "mime": "application/json",
            "description": f"DNS answer set for {queried_host}",
            "raw": raw,
        })
        resolved_ips = answers.get("A", []) + answers.get("AAAA", [])
        return {"observations": obs, "evidence": ev,
                "resolved_ips": resolved_ips, "engine_version": ENGINE_VERSION}
    except Exception as e:
        return {"observations": [], "evidence": [], "resolved_ips": [],
                "error": str(e)[:200], "engine_version": ENGINE_VERSION}


async def tls_analyze(host: str, port: int = 443) -> dict:
    """TLS handshake + certificate inspection via stdlib ssl. Passive observation."""
    obs: list[dict] = []
    ev: list[dict] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=8)
        writer.close()
        await writer.wait_closed()
        with ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) as c2:
            c2.check_hostname = False
            c2.verify_mode = ssl.CERT_NONE
            transport_reader, transport_writer = await asyncio.open_connection(host, port)
            ssl_transport = await asyncio.wait_for(
                asyncio.get_event_loop().start_tls(
                    transport_reader, transport_writer, c2, server_hostname=host),
                timeout=8)
            cert_bin = ssl_transport.get_extra_info("peercert", True)
            cipher = ssl_transport.get_extra_info("cipher")
            proto = ssl_transport.get_extra_info("version")
            transport_writer.close()
        obs.append({
            "kind": "tls.version", "entity_type": "protocol",
            "entity_value": proto or "unknown", "confidence": 0.9,
            "payload": {"protocol": proto, "cipher": cipher},
        })
        if proto and proto in ("SSLv3", "TLSv1", "TLSv1.1"):
            obs.append({
                "kind": "tls.weak_protocol", "entity_type": "configuration",
                "entity_value": proto, "confidence": 0.85,
                "payload": {"protocol": proto, "issue": "deprecated_weak_tls"},
            })
        cert_detail = {}
        if isinstance(cert_bin, dict):
            subject = dict(x[0] for x in cert_bin.get("subject", ()))
            issuer = dict(x[0] for x in cert_bin.get("issuer", ()))
            cert_detail = {
                "cn": subject.get("commonName", ""),
                "issuer_cn": issuer.get("organizationName", "") or issuer.get("commonName", ""),
                "not_after": cert_bin.get("notAfter", ""),
                "san": list(cert_bin.get("subjectAltName", ())),
            }
            raw_cert = json.dumps(cert_detail, sort_keys=True, default=str)
            ev.append({
                "kind": "certificate", "ref": f"{host}:{port}",
                "sha256": _sha256(raw_cert), "size": len(raw_cert),
                "mime": "application/json",
                "description": f"Peer certificate metadata for {host}:{port}",
                "raw": raw_cert,
            })
        obs.append({
            "kind": "tls.cert", "entity_type": "certificate",
            "entity_value": cert_detail.get("cn", "?"), "confidence": 0.9,
            "payload": cert_detail,
        })
        return {"observations": obs, "evidence": ev, "engine_version": ENGINE_VERSION}
    except Exception as e:
        return {"observations": [], "evidence": [],
                "error": str(e)[:200], "engine_version": ENGINE_VERSION}


_SECURITY_HEADERS = {
    "strict-transport-security": ("missing_hsts", "medium",
        "HTTP Strict Transport Security header absent on HTTPS endpoint."),
    "content-security-policy": ("missing_csp", "low",
        "Content-Security-Policy header absent; XSS mitigation relies on app code."),
    "x-frame-options": ("missing_xfo", "low",
        "X-Frame-Options / frame-ancestors absent; clickjacking surface."),
    "x-content-type-options": ("missing_xcto", "informational",
        "X-Content-Type-Options: nosniff absent."),
    "referrer-policy": ("missing_referrer_policy", "informational",
        "Referrer-Policy header absent."),
}


async def http_analyze(url: str) -> dict:
    """Single benign GET via httpx. Inspects response headers/status/server.
    Never follows more than 5 redirects, never sends cookies or auth."""
    obs: list[dict] = []
    ev: list[dict] = []
    parsed = urlparse(url if "://" in url else f"https://{url}")
    final_url = parsed._replace(scheme=parsed.scheme or "https").geturl()
    hdrs_to_redact = {"authorization", "cookie", "set-cookie"}
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                     max_redirects=5, timeout=12.0) as h:
            r = await h.get(final_url, headers={"user-agent": "cwb-assessment/1.0"})
        status = r.status_code
        red_headers = {k: (v if k.lower() not in hdrs_to_redact else "[REDACTED]")
                       for k, v in r.headers.items()}
        raw_meta = json.dumps({"status": status, "headers": red_headers,
                               "final_url": str(r.url)}, sort_keys=True)
        ev.append({
            "kind": "http_response_meta", "ref": final_url,
            "sha256": _sha256(raw_meta), "size": len(raw_meta),
            "mime": "application/json", "redacted": 1,
            "description": f"HTTP response metadata for {final_url}",
            "raw": raw_meta,
        })
        obs.append({
            "kind": "http.status", "entity_type": "endpoint",
            "entity_value": str(status), "confidence": 0.95,
            "payload": {"url": str(r.url), "status": status},
        })
        server = r.headers.get("server", "")
        if server:
            obs.append({
                "kind": "http.server_banner", "entity_type": "technology",
                "entity_value": server[:120], "confidence": 0.7,
                "payload": {"server": server},
            })
        lowered = {k.lower(): v for k, v in r.headers.items()}
        if parsed.scheme == "https" or str(r.url).startswith("https"):
            for hdr, (key, sev, desc) in _SECURITY_HEADERS.items():
                if hdr not in lowered:
                    obs.append({
                        "kind": f"http.{key}", "entity_type": "configuration",
                        "entity_value": key, "confidence": 0.8,
                        "payload": {"header": hdr, "severity": sev, "description": desc},
                    })
        if any(t in lowered.get("server", "").lower() for t in ("apache/2.", "nginx/1.", "iis/")):
            pass
        return {"observations": obs, "evidence": ev, "status": status,
                "final_url": str(r.url), "engine_version": ENGINE_VERSION}
    except httpx.HTTPError as e:
        return {"observations": [], "evidence": [],
                "error": f"http_unreachable: {str(e)[:160]}",
                "engine_version": ENGINE_VERSION}


_TECH_SIGS = [
    (re.compile(r"<meta[^>]+generator=[\"']([^\"']+)", re.I), "html_generator"),
    (re.compile(r"wp-content|wp-includes", re.I), "wordpress"),
    (re.compile(r"drupal", re.I), "drupal"),
    (re.compile(r"__NEXT_DATA__|/_next/", re.I), "nextjs"),
    (re.compile(r"data-reactroot|react-dom", re.I), "react"),
    (re.compile(r"ng-version|angular", re.I), "angular"),
    (re.compile(r"vue\.?js|data-v-", re.I), "vue"),
    (re.compile(r"laravel|XSRF-TOKEN", re.I), "laravel"),
    (re.compile(r"JSESSIONID|tomcat", re.I), "java_tomcat"),
    (re.compile(r"PHPSESSID|x-powered-by:\s*php", re.I), "php"),
    (re.compile(r"Django|csrftoken", re.I), "django"),
    (re.compile(r"rails|_session_id", re.I), "ruby_rails"),
]


async def tech_identify(url: str, body_limit: int = 200_000) -> dict:
    """Fetch page body once (already-fetched URL reused via cache-less second GET)
    and match technology signatures. Pure observation, no exploitation."""
    obs: list[dict] = []
    ev: list[dict] = []
    parsed = urlparse(url if "://" in url else f"https://{url}")
    fetch_url = parsed._replace(scheme=parsed.scheme or "https").geturl()
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                     max_redirects=5, timeout=12.0) as h:
            r = await h.get(fetch_url, headers={"user-agent": "cwb-assessment/1.0"})
        body = r.text[:body_limit]
        full = (body + "\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items())).lower()
        found: set[str] = set()
        for rx, name in _TECH_SIGS:
            if rx.search(full) and name not in found:
                found.add(name)
                obs.append({
                    "kind": "tech.fingerprint", "entity_type": "technology",
                    "entity_value": name, "confidence": 0.6,
                    "payload": {"signature": name, "source": "response_body+headers"},
                })
        raw = json.dumps({"found": sorted(found), "title": _extract_title(body)},
                         sort_keys=True)
        ev.append({
            "kind": "tech_fingerprint", "ref": fetch_url,
            "sha256": _sha256(raw), "size": len(raw),
            "mime": "application/json",
            "description": f"Technology fingerprint for {fetch_url}",
            "raw": raw,
        })
        return {"observations": obs, "evidence": ev, "technologies": sorted(found),
                "engine_version": ENGINE_VERSION}
    except httpx.HTTPError as e:
        return {"observations": [], "evidence": [],
                "error": str(e)[:160], "engine_version": ENGINE_VERSION}


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""


async def service_probe(ip: str, ports: list[int]) -> list[dict]:
    """Reuse existing recon banner-grabber for discovered IPs."""
    from app.modules.recon import fingerprint_many

    return await fingerprint_many(ip, ports)