"""MITRE technique profile — REAL official technique metadata (attack.mitre.org
technique page parsed with BeautifulSoup, 30-day disk cache) joined with this
system's own observed alerts for the same technique. Nothing is fabricated:
when both sources are unavailable the response says so explicitly.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

from app.core.config import DATA
from app.db import sqlite as sql

CACHE = DATA / "mitre_cache"
UA = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
TTL_DAYS = 30
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
PLATFORM_WORDS = ("Windows", "Linux", "macOS", "IaaS", "SaaS", "Office Suite", "Identity Provider",
                  "Browser", "Network Devices", "Embedded Devices", "Cloud Environment",
                  "Mobile Device", "OT Intensive Systems", "Virtualization Solution", "PRE")


def _cache_path(tid: str) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    return CACHE / f"{tid}.json"


def _read_cache(tid: str) -> dict | None:
    p = _cache_path(tid)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def _parse(html: str, tid: str, url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.string or "").strip() if soup.title else ""
    m = re.search(r"Technique (T\d{4}(?:\.\d{3})?) - (\w+)", title)
    name = soup.select_one("h1").get_text(" ", strip=True) if soup.select_one("h1") else tid
    desc_ps = [p.get_text(" ", strip=True) for p in soup.find_all("p")]
    desc = max((p for p in desc_ps if len(p) > 120), key=len, default="")
    tactics, seen = [], set()
    for a in soup.select("a[href*='/tactics/TA']"):
        t = a.get_text(" ", strip=True)
        href = a.get("href") or ""
        mm = re.search(r"TA\d{4}", href)
        if t and mm and mm.group(0) not in seen:
            seen.add(mm.group(0))
            tactics.append({"id": mm.group(0), "name": t})
    subtechniques, mitigations = [], []
    for tbl in soup.find_all("table"):
        for row in tbl.find_all("tr"):
            cells = [c.get_text(" ", strip=True) for c in row.find_all(["td", "th"])]
            if len(cells) >= 2 and TECH_RE.match(cells[0] or "") and "." in cells[0]:
                subtechniques.append({"id": cells[0], "name": cells[1]})
            if len(cells) >= 3 and re.match(r"^M\d{4}$", cells[0] or ""):
                mitigations.append({"id": cells[0], "name": cells[1], "description": cells[2]})
    platforms = []
    el = soup.find(string=re.compile(r"^Platforms"))
    if el:
        node = el.find_parent() or el.parent
        for _ in range(3):
            if node is None:
                break
            txt = node.get_text(" ", strip=True)
            if any(w in txt for w in PLATFORM_WORDS):
                platforms = sorted({w for w in PLATFORM_WORDS if re.search(rf"\b{re.escape(w)}", txt)},
                                   key=txt.find)
                break
            node = node.find_parent()
    return {
        "id": tid,
        "name": name,
        "matrix": (m.group(2) if m else "Enterprise"),
        "url": url,
        "description": desc,
        "tactics": tactics,
        "platforms": platforms,
        "subtechniques": sorted({s["id"]: s for s in subtechniques}.values(), key=lambda s: s["id"]),
        "mitigations": sorted({mm["id"]: mm for mm in mitigations}.values(), key=lambda mm: mm["id"]),
        "source": "attack.mitre.org",
        "fetched": datetime.now(timezone.utc).isoformat(),
    }


async def official_technique(tid: str) -> dict:
    """Live parse with 30-day disk cache; stale cache beats nothing when offline."""
    cached = _read_cache(tid)
    if cached:
        age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(cached.get("fetched", "1970-01-01"))).days
        if cached.get("source") == "attack.mitre.org" and age_days <= TTL_DAYS:
            return {**cached, "source": "cache"}
    url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get(url, headers=UA)
            r.raise_for_status()
        meta = _parse(r.text, tid, url)
        if meta["description"] or meta["name"] != tid:
            _cache_path(tid).write_text(json.dumps(meta))
            return meta
        raise ValueError("unrecognized page shape")
    except Exception:
        if cached:
            return {**cached, "source": "cache (stale — mitre unreachable)"}
        return {"id": tid, "name": tid, "matrix": "Enterprise", "url": url, "description": "",
                "tactics": [], "platforms": [], "subtechniques": [], "mitigations": [],
                "source": "unavailable — attack.mitre.org unreachable and no cached copy",
                "fetched": None}


_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "INFORMATIONAL": 1}


def _observed(tid: str) -> dict:
    base = ("SELECT id, ts, severity, signature, category, src_ip, dest_ip, mitre, status "
            "FROM alerts WHERE mitre IS NOT NULL AND ")
    if "." in tid:  # exact sub-technique only — siblings are not this technique's events
        rows = sql.all_(base + "mitre = ? ORDER BY ts ASC", tid)
    else:           # parent technique = its own tags + every sub-technique under it
        rows = sql.all_(base + "(mitre = ? OR mitre LIKE ?) ORDER BY ts ASC", tid, tid + ".%")
    hosts: dict[str, dict] = {}
    sigs: dict[str, dict] = {}
    subs: dict[str, int] = {}
    timeline: dict[str, int] = {}
    pairs: dict[tuple[str, str], int] = {}
    for a in rows:
        t = (a["ts"] or "")[:13] + ":00"
        timeline[t] = timeline.get(t, 0) + 1
        subs[a["mitre"]] = subs.get(a["mitre"], 0) + 1
        sig = a["signature"] or "unknown signature"
        s = sigs.setdefault(sig, {"signature": sig, "events": 0, "max_severity": "INFO"})
        s["events"] += 1
        if _SEV_RANK.get((a["severity"] or "").upper(), 0) > _SEV_RANK.get(s["max_severity"], 0):
            s["max_severity"] = (a["severity"] or "INFO").upper()
        for ip, role in ((a["src_ip"], "source"), (a["dest_ip"], "destination")):
            if not ip:
                continue
            h = hosts.setdefault(ip, {"ip": ip, "events": 0, "sources": 0, "destinations": 0,
                                      "first": a["ts"], "last": a["ts"], "by_mitre": {}})
            h["events"] += 1
            h["sources" if role == "source" else "destinations"] += 1
            h["by_mitre"][a["mitre"]] = h["by_mitre"].get(a["mitre"], 0) + 1
            if a["ts"]:
                h["first"] = min(h["first"] or a["ts"], a["ts"])
                h["last"] = max(h["last"] or a["ts"], a["ts"])
        if a["src_ip"] and a["dest_ip"]:
            pairs[(a["src_ip"], a["dest_ip"])] = pairs.get((a["src_ip"], a["dest_ip"]), 0) + 1
    return {
        "events": len(rows),
        "first": rows[0]["ts"] if rows else None,
        "last": rows[-1]["ts"] if rows else None,
        "subtechniques_seen": subs,
        "hosts": sorted(hosts.values(), key=lambda h: -h["events"]),
        "signatures": sorted(sigs.values(), key=lambda s: -s["events"]),
        "timeline": [{"hour": k, "count": v} for k, v in sorted(timeline.items())],
        "pairs": [{"src": k[0], "dst": k[1], "count": v} for k, v in
                  sorted(pairs.items(), key=lambda kv: -kv[1])[:20]],
        "recent": list(reversed(rows))[:30],
    }


def _graph(obs: dict, tid: str) -> dict:
    """Tree-shaped graph: technique → (sub-techniques + signatures) → hosts.
    A host hangs under the sub-technique its events actually matched.
    Host↔host traffic is kept as secondary (cross) links."""
    nodes, links = [], []
    nodes.append({"id": tid, "label": tid, "kind": "technique",
                  "weight": max(1, obs["events"]),
                  "detail": f"{obs['events']} observed event(s)"})
    for sub, n in obs["subtechniques_seen"].items():
        if sub == tid:  # profile IS this sub-technique — no self-node, no self-loop
            continue
        nodes.append({"id": sub, "label": sub, "kind": "sub", "weight": n,
                      "detail": f"{n} event(s) matched this sub-technique"})
        links.append({"source": tid, "target": sub, "value": n})
    sig_sev = {s["signature"]: s["max_severity"] for s in obs["signatures"]}
    for s in obs["signatures"][:10]:
        nid = f"sig:{s['signature']}"
        nodes.append({"id": nid, "label": s["signature"], "kind": "sig", "weight": s["events"],
                      "detail": f"peak severity {sig_sev.get(s['signature'], 'INFO')}"})
        links.append({"source": tid, "target": nid, "value": s["events"]})
    hosts = obs["hosts"][:16]
    for h in hosts:
        parent = tid
        real_subs = {k: v for k, v in (h.get("by_mitre") or {}).items()
                     if "." in k and k in obs["subtechniques_seen"]}
        if real_subs:
            parent = max(real_subs, key=real_subs.get)
        nodes.append({"id": f"host:{h['ip']}", "label": h["ip"],
                      "kind": "host-src" if h["sources"] and not h["destinations"] else
                      "host-dst" if h["destinations"] and not h["sources"] else "host-both",
                      "weight": h["events"],
                      "detail": f"source {h['sources']} · destination {h['destinations']} · last {h['last'] or '—'}"})
        links.append({"source": parent, "target": f"host:{h['ip']}", "value": h["events"]})
    host_ids = {f"host:{h['ip']}" for h in hosts}
    for p in obs["pairs"]:
        a, b = f"host:{p['src']}", f"host:{p['dst']}"
        if a in host_ids and b in host_ids and a != b:
            links.append({"source": a, "target": b, "value": p["count"], "cross": True})
    return {"nodes": nodes, "links": links}


async def profile(tid: str) -> dict:
    tid = tid.upper()
    meta = await official_technique(tid)
    obs = _observed(tid)
    parent_activity = None
    parent = tid.split(".")[0]
    if parent != tid:
        prow = sql.one("SELECT COUNT(*) AS c FROM alerts WHERE mitre = ? OR mitre LIKE ?",
                       parent, parent + ".%")
        parent_activity = {"id": parent, "events": (prow or {}).get("c", 0)}
        if (meta["source"].startswith("attack.mitre") or meta["source"] == "cache") \
                and not meta.get("subtechniques"):
            p_meta = await official_technique(parent)
            if p_meta["id"] != meta["id"]:
                meta["parent"] = {"id": p_meta["id"], "name": p_meta["name"], "url": p_meta["url"]}
    return {"technique": meta, "observed": obs, "graph": _graph(obs, tid),
            "parent_activity": parent_activity,
            "as_of": datetime.now(timezone.utc).isoformat()}
