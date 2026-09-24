"""Real-data services for the system console.

Everything here reports genuine state: psutil counters for this machine,
the audit chain head, and CISA's public RSS advisories (no key, no simulation).
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import socket
import time
from collections import deque

import httpx
import psutil

from app.audit import chain

log = logging.getLogger("cwb.system")

# psutil percent calls need a first, blocking sample to prime their deltas.
psutil.cpu_percent(interval=None)
_last_net = [psutil.net_io_counters(), time.monotonic()]
_NET_KEYS = ("bytes_sent", "bytes_recv", "packets_sent", "packets_recv")

SAMPLE_SECONDS = 2.0
HISTORY_POINTS = 180  # six minutes of real readings

# The sampler is the only caller of cpu_percent in the process: an interval-less
# psutil call reports the delta since the previous call, so a second caller would
# silently change the window each series covers.
_latest: dict | None = None
_history: deque[dict] = deque(maxlen=HISTORY_POINTS)


def sample() -> dict:
    point = {
        "ts_ms": int(time.time() * 1000),
        "cpu": round(psutil.cpu_percent(interval=None), 1),
        "per_core": [round(x, 1) for x in psutil.cpu_percent(interval=None, percpu=True)],
        "mem": psutil.virtual_memory().percent,
    }
    globals()["_latest"] = point
    _history.append(point)
    return point


async def sampler_loop() -> None:
    while True:
        try:
            sample()
        except Exception:
            log.exception("telemetry sample failed")
        await asyncio.sleep(SAMPLE_SECONDS)


def _current() -> dict:
    return _latest if _latest is not None else sample()


def telemetry() -> dict:
    global _last_net
    now = time.monotonic()
    net = psutil.net_io_counters()
    dt = max(now - _last_net[1], 0.001)
    rates = {k: (getattr(net, k) - getattr(_last_net[0], k)) / dt for k in _NET_KEYS}
    _last_net = [net, now]

    vm = psutil.virtual_memory()
    try:
        load = os.getloadavg()
    except OSError:
        load = (0.0, 0.0, 0.0)
    disk = psutil.disk_usage("/")
    cur = _current()
    procs = []
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            rss = getattr(p.info["memory_info"], "rss", 0)
            if rss:
                procs.append({"pid": p.info["pid"], "name": p.info["name"], "rss": rss})
        except (psutil.Error, OSError):
            continue
    procs = sorted(procs, key=lambda p: p["rss"], reverse=True)[:8]

    addrs = psutil.net_if_addrs()
    ips = {
        nic: [a.address for a in ads if a.family == socket.AF_INET]
        for nic, ads in addrs.items()
    }

    return {
        "ts_ms": int(time.time() * 1000),
        "host": {"hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()}",
                 "machine": platform.machine(), "boot_ts": int(psutil.boot_time() * 1000)},
        "cpu": {"percent": cur["cpu"], "cores": psutil.cpu_count(logical=True),
                "per_core": cur["per_core"], "load": [round(x, 2) for x in load]},
        "mem": {"percent": vm.percent, "used": vm.used, "total": vm.total},
        "disk": {"percent": disk.percent, "used": disk.used, "total": disk.total},
        "history": [{"ts_ms": h["ts_ms"], "cpu": h["cpu"], "mem": h["mem"]} for h in _history],
        "net": {"rates": {k: round(v) for k, v in rates.items()}, "totals": {k: getattr(net, k) for k in _NET_KEYS}},
        "procs": {"count": len(psutil.pids()), "top_rss": procs},
        "interfaces": {k: v for k, v in ips.items() if v},
    }


def pulse(limit: int = 30) -> list[dict]:
    """Head of the real HMAC audit chain — minimal fields, no secrets."""
    return [
        {"ts_ms": r["ts_ms"], "actor": r["actor"], "action": r["action"], "object_ref": r["object_ref"]}
        for r in chain.query(limit=limit)
    ]


_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=8"
_UA = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
_cache = {"items": [], "fetched_ts": 0.0, "error": None}
_TTL = 900.0


async def threat_feed() -> dict:
    now = time.time()
    if _cache["items"] and now - _cache["fetched_ts"] < _TTL:
        return {"source": "cache", "items": _cache["items"], "error": _cache["error"],
                "fetched_ts": int(_cache["fetched_ts"] * 1000)}
    items, errors = [], []
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, headers=_UA) as cx:
        try:
            r = await cx.get(_KEV)
            r.raise_for_status()
            cat = r.json().get("vulnerabilities", [])
            newest = sorted(cat, key=lambda v: v.get("dateAdded", ""), reverse=True)[:8]
            for v in newest:
                rw = " [RANSOMWARE]" if str(v.get("knownRansomwareCampaignUse", "")).upper().startswith("KNOW") else ""
                cve_id = v.get("cveID") or ""
                prod = f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
                name = (v.get("vulnerabilityName") or "").strip()
                # KEV names usually repeat the product ("Linux Kernel — race condition …")
                if prod and name.lower().startswith(prod.lower()):
                    name = name[len(prod):].lstrip(" –—-:").strip()
                items.append({
                    "source": "CISA-KEV",
                    "title": f"{cve_id} · {prod} · {name}{rw} · due {v.get('dueDate', '?')}",
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else _KEV,
                    "published": v.get("dateAdded", ""),
                })
        except Exception as e:
            errors.append(f"CISA-KEV: {type(e).__name__}")
        try:
            r = await cx.get(_NVD)
            r.raise_for_status()
            for v in r.json().get("vulnerabilities", [])[:8]:
                cve = v.get("cve", {})
                desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                items.append({"source": "NVD", "title": f"{cve.get('id')} · {desc[:120]}",
                              "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
                              "published": (cve.get("published") or "")[:10]})
        except Exception as e:
            errors.append(f"NVD: {type(e).__name__}")
    if items:
        _cache.update(items=items, fetched_ts=now, error="; ".join(errors) or None)
    return {"source": "live", "items": items or _cache["items"],
            "error": "; ".join(errors) or _cache["error"], "fetched_ts": int(now * 1000)}
