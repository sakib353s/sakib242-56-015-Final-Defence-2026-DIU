"""Vuln Scanner — port discovery (vendored naabu) + service/version fingerprinting,
NVD CVE lookup per detected product version, CVSS risk scoring.
risk_score = Σ(cvss)/count normalized 0–100 (per P-05b). Report PDF auto-generates
on completion and lands in the unified report library."""
from __future__ import annotations

import asyncio

import httpx

from app.audit import chain
from app.core.config import get_settings
from app.core.errors import CWBError
from app.core.ids import new_id
from app.core.jobs import job_finish, job_progress, job_start
from app.core.security import now_iso
from app.db import sqlite as sql
from app.gateway.wsmanager import manager
from app.modules.recon import fingerprint_many, naabu_ports

S = get_settings()
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_nvd_cache: dict[str, list[dict]] = {}


def _parse_nvd(payload: dict) -> list[dict]:
    out = []
    for v in payload.get("vulnerabilities", []):
        cve = v["cve"]
        metrics = cve.get("metrics", {})
        cvss = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
                or metrics.get("cvssMetricV2") or [{}])[0]
        score = (cvss.get("cvssData") or {}).get("baseScore")
        if score is None:
            continue
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        cwe = ""
        for w in cve.get("weaknesses", []):
            if w.get("source") == "nvd@nist.gov":
                cwe = next((d["value"] for d in w.get("description", [])
                            if d.get("value", "").startswith("CWE")), "")
                if cwe:
                    break
        out.append({"id": cve["id"], "cvss": float(score),
                    "severity": _sev(float(score)), "description": desc[:400],
                    "mitre": cwe or None})
    return out


async def _nvd_lookup(query: str, cpe: str | None = None) -> list[dict]:
    """CPE-accurate lookup when we have product+version (fewer, correct CVEs);
    falls back to keyword search when CPE is rejected or version is unknown."""
    key = cpe or query
    if key in _nvd_cache:
        return _nvd_cache[key]
    headers = {"user-agent": "cwb-core/5.0"}
    if S.nvd_api_key:
        headers["apiKey"] = S.nvd_api_key
    async with httpx.AsyncClient(timeout=15) as h:
        if cpe:
            try:
                r = await h.get(NVD, params={"cpeName": cpe, "resultsPerPage": 20}, headers=headers)
                if r.status_code == 200:
                    out = _parse_nvd(r.json())
                    _nvd_cache[key] = out
                    return out
            except httpx.HTTPError:
                pass
        params = {"keywordSearch": query, "resultsPerPage": 15}
        for attempt in range(3):
            try:
                r = await h.get(NVD, params=params, headers=headers)
                if r.status_code == 429:  # rate-limited: back off, then WARN
                    await asyncio.sleep(6 * (attempt + 1))
                    continue
                if r.status_code != 200:
                    return []
                out = _parse_nvd(r.json())
                _nvd_cache[key] = out
                return out
            except httpx.HTTPError:
                await asyncio.sleep(2)
    return []


def cpe_for(product: str, version: str) -> str | None:
    from app.modules.recon import CPE_PARTS

    base = product.lower().strip()
    parts = CPE_PARTS.get(base)
    if not parts or not version:
        return None
    return f"cpe:2.3:a:{parts}:{version}:*:*:*:*:*:*:*"



def _sev(score: float) -> str:
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def risk_score(cves: list[dict]) -> float:
    if not cves:
        return 0.0
    return round(min(100.0, sum(c["cvss"] for c in cves) / len(cves) * 10), 1)


async def run_scan(scan_id: str, user_id: str) -> None:
    try:
        await _run(scan_id, user_id)
    except Exception as e:  # never leave a scan in PENDING/RUNNING on a worker crash
        with sql.get_db() as c:
            c.execute("UPDATE vuln_scans SET status='FAILED', finished_at=? WHERE id=?",
                      (now_iso(), scan_id))
        chain.safe_append(user_id, "vuln.worker_crash", scan_id, {"error": str(e)[:300]})


async def _run(scan_id: str, user_id: str) -> None:
    row = sql.one("SELECT * FROM vuln_scans WHERE id=?", scan_id)
    jid = await job_start("vuln.scan", scan_id, {"target": row["target"]})
    await job_progress(jid, 0.1, "service detection")

    from app.modules.recon import resolve
    ip = await asyncio.to_thread(resolve, row["target"])
    if not ip:
        with sql.get_db() as c:
            c.execute("UPDATE vuln_scans SET status='FAILED', finished_at=? WHERE id=?",
                      (now_iso(), scan_id))
        await job_finish(jid, "error", f"cannot resolve {row['target']}")
        return

    ports = await naabu_ports(ip, timeout=150)
    if ports is None:
        with sql.get_db() as c:
            c.execute("UPDATE vuln_scans SET status='FAILED', finished_at=? WHERE id=?",
                      (now_iso(), scan_id))
        await job_finish(jid, "error", "naabu engine unavailable")
        return
    await job_progress(jid, 0.35, f"fingerprinting {len(ports)} open services")
    services = await fingerprint_many(ip, ports)

    all_cves: list[dict] = []
    seen: set[str] = set()
    for i, svc in enumerate(services):
        product, _, ver = (svc.get("product") or "").partition(" ")
        if not product:
            continue
        await job_progress(jid, 0.35 + 0.5 * (i + 1) / max(1, len(services)),
                           f"NVD lookup: {product} {ver}"[:40])
        for cve in await _nvd_lookup(f"{product} {ver}".strip(), cpe_for(product, ver)):
            if cve["id"] in seen:
                continue
            seen.add(cve["id"])
            cve["host"], cve["port"] = ip, svc["portid"]
            cve["service"] = svc.get("service") or ""
            all_cves.append(cve)
    score = risk_score(all_cves)
    with sql.get_db() as c:
        for cve in all_cves:
            c.execute(
                "INSERT INTO findings (id, source, source_id, host, port, service, cve, severity,"
                " cvss, mitre, description, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (new_id(), "vuln", scan_id, cve["host"], cve["port"], cve["service"], cve["id"],
                 cve["severity"], cve["cvss"], cve.get("mitre"), cve["description"], now_iso()),
            )
        c.execute("UPDATE vuln_scans SET status='DONE', risk_score=?, findings_count=?, finished_at=?"
                  " WHERE id=?", (score, len(all_cves), now_iso(), scan_id))
    chain.append(user_id, "vuln.scan.complete", scan_id, {"cves": len(all_cves), "risk": score})

    await job_progress(jid, 0.93, "generating report")
    from app.reports import vuln_pdf
    from app.reports.signing import register_report
    try:
        path = await asyncio.to_thread(vuln_pdf.build, scan_id)
        register_report(path, f"vuln-{scan_id}.pdf", "vuln_scan", scan_id, user_id)
        with sql.get_db() as c:
            c.execute("UPDATE vuln_scans SET report_path=? WHERE id=?", (path, scan_id))
    except Exception as e:
        await job_finish(jid, "done", f"report failed: {e}")
    else:
        await job_finish(jid, "done", f"risk {score}/100 · {len(all_cves)} CVEs")

    if any(c["severity"] == "CRITICAL" for c in all_cves):
        await manager.publish("alerts", "vuln.critical", {"scan": scan_id, "count":
                          sum(1 for c in all_cves if c["severity"] == "CRITICAL")})
