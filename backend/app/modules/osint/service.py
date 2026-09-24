"""OSINT & Breach — public data only (FR-O01…O04). No auth-bypassing scrapers.
Audit rows carry subject HASHES only — never raw PII."""
from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import socket
from datetime import datetime, timezone

import dns.resolver
import httpx

from app.audit import chain
from app.core.config import get_settings
from app.core.errors import CWBError, RefusedOutOfWork
from app.core.ids import new_id
from app.core.security import now_iso
from app.db import sqlite as sql

S = get_settings()
HIBP = "https://haveibeenpwned.com/api/v3"
SHODAN = "https://api.shodan.io"


def subject_hash(subject_type: str, subject: str) -> str:
    return hashlib.sha256(f"{subject_type}:{subject.lower()}".encode()).hexdigest()[:32]


async def email_breaches(email: str, actor: str) -> dict:
    """Keyless-first (works with zero API keys configured):
    - default               → FREE breach-registry search on the email's domain
      via /breaches?Domain= (no key required) + global registry stats.
    - optional CWB_HIBP_API_KEY → exact per-account search (breachedaccount).
    Both paths return identical shapes plus `mode` so the UI can badge honestly."""
    domain = email.split("@", 1)[1].lower()
    registry_total = None
    if S.hibp_api_key:
        async with httpx.AsyncClient(timeout=20) as h:
            r = await h.get(f"{HIBP}/breachedaccount/{quote(email)}",
                            headers={"hibp-api-key": S.hibp_api_key, "user-agent": "cwb-core"},
                            params={"responseMode": "full"})
        if r.status_code == 404:
            breaches = []
        elif r.status_code == 429:
            raise CWBError("HIBP rate-limited — retry later", status=429)
        elif r.status_code in (400, 401):
            raise CWBError(f"HIBP rejected request ({r.status_code})", status=502)
        else:
            r.raise_for_status()
            breaches = r.json()
        mode = "exact-account"
    else:
        async with httpx.AsyncClient(timeout=20) as h:
            r = await h.get(f"{HIBP}/breaches",
                            headers={"user-agent": "cwb-core"}, params={"Domain": domain})
            rb = await h.get(f"{HIBP}/breaches", headers={"user-agent": "cwb-core"})
        r.raise_for_status()
        rb.raise_for_status()
        breaches = r.json()
        mode = "domain-level"
        if rb.status_code == 200:
            registry_total = len(rb.json())
    summary = [{"Name": b.get("Name"), "Title": b.get("Title"), "BreachDate": b.get("BreachDate"),
                "DataClasses": b.get("DataClasses"), "Domain": b.get("Domain"),
                "Verified": b.get("IsVerified")} for b in breaches]
    cid = _store_case("email", subject_hash("email", email), actor,
                      {"mode": mode, "domain": domain, "breach_count": len(breaches),
                       "breaches": summary})
    chain.append(actor, "osint.query.email", cid, {"subject_hash": subject_hash("email", email)})
    return {"case_id": cid, "mode": mode, "domain": domain, "registry_total": registry_total,
            "breach_count": len(breaches), "breaches": summary}


PP_RANGE = "https://api.pwnedpasswords.com/range"


async def password_exposure(password: str, actor: str) -> dict:
    """FREE k-anonymity breach check (Pwned Passwords — no key, no payment).
    Only the first 5 chars of the SHA-1 travel the wire; the secret never does."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    async with httpx.AsyncClient(timeout=20) as h:
        r = await h.get(f"{PP_RANGE}/{prefix}", headers={"user-agent": "cwb-core",
                                                         "hibp-api-key": "cwb-free-range-api"})
    if r.status_code != 200:
        raise CWBError(f"PwnedPasswords range unreachable ({r.status_code})", status=502)
    hits = [int(l.split(":")[1]) for l in r.text.splitlines()
            if l.startswith(suffix) and ":" in l]
    count = hits[0] if hits else 0
    cid = _store_case("url", subject_hash("password", password), actor,
                      {"k_anon_range_check": True, "pwned": count > 0})
    chain.append(actor, "osint.query.password", cid,
                 {"subject_hash": subject_hash("password", password), "count_band": _band(count)})
    return {"pwned": count > 0, "approximate_exposures": count, "case_id": cid}


def _band(count: int) -> str:
    return "none" if count == 0 else "1-99" if count < 100 else "100-9999" if count < 10000 else "10k+"


def quote(s: str) -> str:
    from urllib.parse import quote as _q
    return _q(s, safe="")


async def domain_recon(domain: str, actor: str) -> dict:
    """Shodan (keyed) + DNS + RDAP WHOIS + TLS cert + subdomains via crt.sh. All public."""
    out: dict = {"domain": domain}
    async with httpx.AsyncClient(timeout=20) as h:
        if S.shodan_api_key:
            try:
                r = await h.get(f"{SHODAN}/dns/domain/{domain}", params={"key": S.shodan_api_key})
                if r.status_code == 200:
                    j = r.json()
                    out["shodan"] = {"hosts": [hh.get("ip_str") for hh in j.get("hosts", [])][:25],
                                     "data": list(j.get("data", {}).keys())}
                elif r.status_code == 429:
                    out["shodan"] = {"error": "rate-limited"}
            except httpx.HTTPError:
                out["shodan"] = {"error": "unreachable"}
        # DNS
        dns_recs = {}
        for rtype in ("A", "AAAA", "MX", "TXT", "NS"):
            try:
                ans = await asyncio.to_thread(_resolve, domain, rtype)
                if ans:
                    dns_recs[rtype] = ans
            except Exception:
                pass
        out["dns"] = dns_recs
        # RDAP whois
        try:
            r = await h.get(f"https://rdap.org/domain/{domain}",
                            headers={"accept": "application/rdap+json"})
            if r.status_code == 200:
                j = r.json()
                out["rdap"] = {"handle": j.get("handle"),
                               "events": [{"eventAction": e.get("eventAction"),
                                           "date": e.get("eventDate")} for e in j.get("events", [])[:6]]}
        except httpx.HTTPError:
            out["rdap"] = {"error": "unreachable"}
        # TLS certificate
        out["tls"] = await asyncio.to_thread(_tls_probe, domain)
        # subdomain enumeration via Certificate Transparency
        try:
            r = await h.get("https://crt.sh", params={"q": f"%.{domain}", "output": "json"})
            if r.status_code == 200:
                names = sorted({row.get("name_value", "").split("\n")[0].lstrip("*.")
                                for row in r.json() if row.get("name_value")})
                out["subdomains"] = [n for n in names if n.endswith(domain)][:100]
        except httpx.HTTPError:
            pass
    cid = _store_case("domain", subject_hash("domain", domain), actor, out)
    chain.append(actor, "osint.query.domain", cid, {"subject_hash": subject_hash("domain", domain)})
    return {"case_id": cid, **out}


def _resolve(domain: str, rtype: str) -> list[str]:
    return [str(x) for x in dns.resolver.resolve(domain, rtype, lifetime=8)]


def _tls_probe(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {"subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "not_after": cert.get("notAfter"),
                        "expire_warning": _cert_expiring(cert.get("notAfter"))}
    except Exception as e:
        return {"error": type(e).__name__}


def _cert_expiring(not_after: str | None) -> bool:
    if not not_after:
        return False
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(not_after) < datetime.now(timezone.utc)
    except Exception:
        return False


# (rubric key, weight, the signal it reads, threshold) — one table so the weights
# published to the console cannot drift from what exposure_score() applies.
EXPOSURE_RULES = [
    ("email_exposed", 25, "email_breached", lambda s: bool(s.get("email_breached"))),
    ("breach_count_gt_3", 15, "breach_count", lambda s: s.get("breach_count", 0) > 3),
    ("open_ports_gt_2", 15, "open_ports", lambda s: s.get("open_ports", 0) > 2),
    ("cert_expired", 10, "cert_expired", lambda s: bool(s.get("cert_expired"))),
    ("subdomains_gt_20", 10, "subdomain_count", lambda s: s.get("subdomain_count", 0) > 20),
]
EXPOSURE_WEIGHTS = {k: w for k, w, _, _ in EXPOSURE_RULES}


def exposure_score(signals: dict) -> int:
    """0–100 rubric (P-05e): weighted public-exposure signals."""
    return min(100, sum(w for _, w, _, hit in EXPOSURE_RULES if hit(signals)))


def rubric_for(signals: dict) -> dict:
    """Only the weights this subject could actually move. Listing checks the
    scorer never ran reads as a promise the platform doesn't keep."""
    return {k: w for k, w, src, _ in EXPOSURE_RULES if src in signals}


async def url_report(url: str, actor: str) -> dict:
    """Redirect chain + headers + cert for a public URL — no scanning, just GET metadata."""
    if not url.startswith(("http://", "https://")):
        raise RefusedOutOfWork("Only http(s) public URLs are in scope")
    async with httpx.AsyncClient(follow_redirects=True, timeout=15,
                                 headers={"user-agent": "cwb-core/5.0"}) as h:
        try:
            r = await h.get(url)
            out = {"status": r.status_code, "final_url": str(r.url),
                   "headers": {k: v for k, v in r.headers.items()
                               if k.lower() in ("server", "x-powered-by", "content-security-policy",
                                                "strict-transport-security", "x-frame-options")},
                   "redirects": [str(x.url) for x in r.history]}
        except httpx.HTTPError as e:
            raise CWBError(f"URL unreachable: {type(e).__name__}", status=502)
    cid = _store_case("url", subject_hash("url", url), actor, out)
    chain.append(actor, "osint.query.url", cid, {"subject_hash": subject_hash("url", url)})
    return {"case_id": cid, **out}


async def leak_scan(actor: str) -> dict:
    """FR-O04: scheduled monitor over public sources. Queries registered leak_watch
    entries against GitHub public search API. (Raw credential harvesting is out of scope.)"""
    rows = sql.all_("SELECT * FROM leak_watch")
    hits = []
    async with httpx.AsyncClient(timeout=20, headers={"user-agent": "cwb-core/5.0"}) as h:
        for w in rows:
            q = json.loads(w["hit_json"] or "{}").get("query") or w["query_hash"][:8]
            try:
                r = await h.get("https://api.github.com/search/repositories",
                                params={"q": f"{q} password", "per_page": 5})
                total = r.json().get("total_count", 0) if r.status_code == 200 else -1
            except httpx.HTTPError:
                total = -1
            hits.append({"watch_id": w["id"], "query": q, "query_hash": w["query_hash"],
                         "public_repos_matched": total, "checked_at": now_iso()})
            with sql.get_db() as c:
                c.execute("UPDATE leak_watch SET hit_json=?, checked_at=? WHERE id=?",
                          (json.dumps({"query": q, "matched": total}), now_iso(), w["id"]))
    chain.append(actor, "osint.leak_scan", "leak_watch", {"count": len(hits)})
    return {"results": hits}


def create_watch(query: str, actor: str) -> dict:
    wid = new_id()
    with sql.get_db() as c:
        c.execute("INSERT INTO leak_watch (id, query_hash, source, hit_json, created_at) VALUES (?,?,?,?,?)",
                  (wid, subject_hash("watch", query), "github-public-search",
                   json.dumps({"query": query}), now_iso()))
    chain.append(actor, "osint.watch.create", wid, {"subject_hash": subject_hash("watch", query)})
    return {"watch_id": wid}


def _store_case(subject_type: str, shash: str, actor: str, result: dict) -> str:
    cid = new_id()
    with sql.get_db() as c:
        c.execute("INSERT INTO osint_cases (id, subject_type, subject_hash, result_json, source,"
                  " created_by, created_at) VALUES (?,?,?,?,?,?,?)",
                  (cid, subject_type, shash, json.dumps(result, default=str), "multi", actor, now_iso()))
    return cid
