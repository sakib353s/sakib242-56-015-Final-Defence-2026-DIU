"""Threat Map aggregation — projects EXISTING security truth onto geography.

Sources of truth (this module invents nothing):
  attack-observed    : alerts with a public source IP (Suricata / detection engine)
  asset-exposure     : monitored hw_assets with a public address
  ti-infrastructure  : TI indicators/infrastructure whose observables are IPs
  incident           : open incidents whose payload carries a public IP

Geolocation: ip-api.com (keyless free tier, matching the project's free-by-design
rule), cached, public IPs only, every result labelled approximate intelligence.
When the resolver is unreachable the event still plots as location-unknown —
never dropped, never faked.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json

import httpx

from app.audit import chain
from app.core.ids import new_id
from app.core.security import now_iso
from app.db import sqlite as sql

GEO_URL = "https://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon"
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4,
             "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global
    except ValueError:
        return False


def _cached_geo(ip: str) -> dict | None:
    return sql.one("SELECT * FROM geo_cache WHERE ip=?", ip)


async def resolve_geo(ip: str) -> dict:
    """Public-IP geolocation with cache + honest failure. Always 'approx'."""
    if not is_public(ip):
        return {"lat": None, "lon": None, "country": None, "city": None,
                "accuracy": "unknown", "source": "private-or-invalid"}
    hit = _cached_geo(ip)
    if hit:
        return {"lat": hit["lat"], "lon": hit["lon"], "country": hit["country"],
                "city": hit["city"],
                "accuracy": "ip-approx" if hit["lat"] is not None else "unknown",
                "source": hit["source"]}
    try:
        async with httpx.AsyncClient(timeout=4.0) as h:
            r = await h.get(GEO_URL.format(ip=ip))
            d = r.json()
        if d.get("status") == "success" and d.get("lat") is not None:
            row = {"lat": float(d["lat"]), "lon": float(d["lon"]),
                   "country": str(d.get("country") or "")[:60] or None,
                   "city": str(d.get("city") or "")[:80] or None,
                   "accuracy": "ip-approx", "source": "ip-api.com"}
        else:
            row = {"lat": None, "lon": None, "country": None, "city": None,
                   "accuracy": "unknown", "source": "ip-api.com:refused"}
    except Exception:
        row = {"lat": None, "lon": None, "country": None, "city": None,
               "accuracy": "unknown", "source": "resolver-unreachable"}
    with sql.get_db() as c:
        c.execute(
            "INSERT OR REPLACE INTO geo_cache (ip, lat, lon, country, city, source, resolved_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (ip, row["lat"], row["lon"], row["country"], row["city"], row["source"],
             now_iso()),
        )
    return row


def _upsert(ev: dict) -> None:
    now = now_iso()
    existing = sql.one("SELECT id, first_seen FROM map_events WHERE source_table=? AND source_id=?",
                       ev["source_table"], ev["source_id"])
    with sql.get_db() as c:
        if existing:
            c.execute(
                "UPDATE map_events SET lat=?, lon=?, location_accuracy=?, location_source=?,"
                " country=?, city=?, severity=?, confidence=?, state=?, last_seen=?, title=?,"
                " description=? WHERE id=?",
                (ev["lat"], ev["lon"], ev["location_accuracy"], ev["location_source"],
                 ev["country"], ev["city"], ev.get("severity"), ev.get("confidence"),
                 ev["state"], now, ev["title"], ev.get("description"), existing["id"]))
        else:
            c.execute(
                "INSERT INTO map_events (id, layer, source_table, source_id, ip, entity,"
                " entity_kind, title, description, lat, lon, location_accuracy,"
                " location_source, country, city, severity, confidence, state, first_seen,"
                " last_seen, evidence_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (new_id(), ev["layer"], ev["source_table"], ev["source_id"], ev.get("ip"),
                 ev["entity"], ev.get("entity_kind"), ev["title"], ev.get("description"),
                 ev["lat"], ev["lon"], ev["location_accuracy"], ev["location_source"],
                 ev["country"], ev["city"], ev.get("severity"), ev.get("confidence"),
                 ev["state"], now, now, ev.get("evidence_ref")),
            )


async def rebuild(actor: str = "system:map") -> dict:
    """Aggregate all layers from existing tables. Idempotent upsert."""
    counts = {"attack-observed": 0, "asset-exposure": 0, "ti-infrastructure": 0,
              "incident": 0, "geo_unresolved": 0}

    alerts = sql.all_(
        "SELECT * FROM alerts WHERE src_ip IS NOT NULL AND src_ip <> 'unknown'"
        " AND ts > datetime('now','-30 days') ORDER BY ts DESC LIMIT 500")
    for a in alerts:
        ip = a["src_ip"]
        geo = await resolve_geo(ip)
        if geo["accuracy"] != "ip-approx":
            counts["geo_unresolved"] += 1
        _upsert({
            "layer": "attack-observed", "source_table": "alerts", "source_id": a["id"],
            "ip": ip, "entity": ip, "entity_kind": "source-ip",
            "title": (a["signature"] or "alert")[:200],
            "description": f"{a['severity']} alert from {ip}"
                           + (f" · {a['mitre']}" if a.get("mitre") else ""),
            "lat": geo["lat"], "lon": geo["lon"],
            "location_accuracy": geo["accuracy"], "location_source": geo["source"],
            "country": geo["country"], "city": geo["city"],
            "severity": (a["severity"] or "").lower(), "confidence": 0.9,
            "state": "observed", "evidence_ref": a["id"],
        })
        counts["attack-observed"] += 1

    for asst in sql.all_("SELECT * FROM hw_assets WHERE disabled=0"):
        host = asst["host"]
        if not is_public(host):
            continue
        geo = await resolve_geo(host)
        if geo["accuracy"] != "ip-approx":
            counts["geo_unresolved"] += 1
        _upsert({
            "layer": "asset-exposure", "source_table": "hw_assets", "source_id": asst["id"],
            "ip": host, "entity": asst["name"], "entity_kind": "managed-asset",
            "title": f"Managed asset {asst['name']} ({asst['kind']})",
            "description": "Owned infrastructure with public address — location approximate",
            "lat": geo["lat"], "lon": geo["lon"],
            "location_accuracy": geo["accuracy"], "location_source": geo["source"],
            "country": geo["country"], "city": geo["city"],
            "severity": "informational", "confidence": 1.0, "state": "observed",
            "evidence_ref": asst["id"],
        })
        counts["asset-exposure"] += 1

    ti_ips = sql.all_(
        "SELECT o.value AS ip, t.id AS tid, t.name, t.confidence, t.tlp, t.source"
        " FROM ti_observables o JOIN ti_objects t ON o.ti_object_id=t.id"
        " WHERE o.observable_type='ipv4' AND t.revoked=0 LIMIT 200")
    for row in ti_ips:
        ip = row["ip"]
        if not is_public(ip):
            continue
        geo = _cached_geo(ip)
        g = await resolve_geo(ip) if not geo else {
            "lat": geo["lat"], "lon": geo["lon"], "country": geo["country"],
            "city": geo["city"], "accuracy": "ip-approx" if geo["lat"] is not None else "unknown",
            "source": geo["source"]}
        if g["accuracy"] != "ip-approx":
            counts["geo_unresolved"] += 1
        _upsert({
            "layer": "ti-infrastructure", "source_table": "ti_objects", "source_id": row["tid"],
            "ip": ip, "entity": ip, "entity_kind": "ti-indicator",
            "title": f"TI indicator: {row['name']}"[:200],
            "description": f"Indicator from source {row['source']} "
                           f"(TLP:{row['tlp'] or '?'}) — untrusted intelligence",
            "lat": g["lat"], "lon": g["lon"],
            "location_accuracy": g["accuracy"], "location_source": g["source"],
            "country": g["country"], "city": g["city"],
            "severity": "medium" if (row["confidence"] or 0) >= 70 else "low",
            "confidence": (row["confidence"] or 50) / 100.0, "state": "ti-derived",
            "evidence_ref": row["tid"],
        })
        counts["ti-infrastructure"] += 1

    for inc in sql.all_("SELECT * FROM incidents WHERE status='open' LIMIT 100"):
        ip = None
        try:
            payload = json.loads(inc["payload_json"] or "{}")
            ip = (payload.get("event") or {}).get("src_ip")
        except json.JSONDecodeError:
            pass
        if not ip:
            continue
        geo = _cached_geo(ip)
        g = await resolve_geo(ip) if not geo else {
            "lat": geo["lat"], "lon": geo["lon"], "country": geo["country"],
            "city": geo["city"], "accuracy": "ip-approx" if geo["lat"] is not None else "unknown",
            "source": geo["source"]}
        _upsert({
            "layer": "incident", "source_table": "incidents", "source_id": inc["id"],
            "ip": ip, "entity": inc["playbook"], "entity_kind": "incident",
            "title": f"Open incident · {inc['playbook']}"[:200],
            "description": "Incident opened by detection correlation",
            "lat": g["lat"], "lon": g["lon"],
            "location_accuracy": g["accuracy"], "location_source": g["source"],
            "country": g["country"], "city": g["city"],
            "severity": "high", "confidence": 0.8, "state": "correlated",
            "evidence_ref": inc["id"],
        })
        counts["incident"] += 1

    chain.safe_append(actor, "map.rebuild", "threat-map", counts)
    return counts


async def record_alert(alert: dict) -> None:
    """Real-time hook from the SOC pipeline."""
    ip = alert.get("src_ip")
    if not is_public(ip or ""):
        return
    _upsert({
        "layer": "attack-observed", "source_table": "alerts", "source_id": alert["id"],
        "ip": ip, "entity": ip, "entity_kind": "source-ip",
        "title": (alert.get("signature") or "alert")[:200],
        "description": f"{alert.get('severity')} alert from {ip}",
        "lat": None, "lon": None, "location_accuracy": "unknown",
        "location_source": "pending-rebuild", "country": None, "city": None,
        "severity": (alert.get("severity") or "").lower(), "confidence": 0.9,
        "state": "observed", "evidence_ref": alert["id"],
    })


def events(since: str | None = None, until: str | None = None,
           layers: list[str] | None = None, min_severity: str | None = None,
           located_only: bool = False, limit: int = 500) -> dict:
    where, args = ["1=1"], []
    if since:
        where.append("last_seen >= ?"); args.append(since)
    if until:
        where.append("first_seen <= ?"); args.append(until)
    if layers:
        where.append(f"layer IN ({','.join('?' * len(layers))})"); args += layers
    if min_severity:
        rank = _SEV_RANK.get(min_severity.lower(), 4)
        allowed = [s for s, r in _SEV_RANK.items() if r <= rank and s.islower()]
        where.append(f"severity IN ({','.join('?' * len(allowed))})")
        args += allowed
    if located_only:
        where.append("lat IS NOT NULL")
    rows = sql.all_(
        "SELECT * FROM map_events WHERE " + " AND ".join(where) +
        " ORDER BY last_seen DESC LIMIT ?", *args, min(limit, 1000))
    located = sum(1 for r in rows if r["lat"] is not None)
    return {"events": rows, "located": located, "unlocated": len(rows) - located,
            "note": "Geolocation is approximate intelligence from public IP "
                    "registration data — not proof of a person's location."}


def stats() -> dict:
    by_layer = sql.all_("SELECT layer, COUNT(*) n FROM map_events GROUP BY layer")
    located = sql.scalar("SELECT COUNT(*) FROM map_events WHERE lat IS NOT NULL")
    total = sql.scalar("SELECT COUNT(*) FROM map_events")
    geo_sources = sql.all_("SELECT source, COUNT(*) n FROM geo_cache GROUP BY source")
    return {"by_layer": by_layer, "total": total, "located": located,
            "geo_sources": geo_sources}


def set_manual_geo(event_id: str, lat: float, lon: float, actor: str, note: str) -> dict:
    ev = sql.one("SELECT * FROM map_events WHERE id=?", event_id)
    if not ev:
        from app.core.errors import CWBError
        raise CWBError("map event not found", status=404)
    with sql.get_db() as c:
        c.execute("UPDATE map_events SET lat=?, lon=?, location_accuracy='manual',"
                  " location_source=?, country=COALESCE(country,? ) WHERE id=?",
                  (lat, lon, f"manual by {actor}" + (f": {note[:100]}" if note else ""),
                   None, event_id))
    chain.append(actor, "map.geo.manual", event_id, {"lat": lat, "lon": lon})
    return {"ok": True}


async def map_refresh_loop():
    await asyncio.sleep(25)
    while True:
        try:
            await rebuild()
        except Exception:
            pass
        await asyncio.sleep(300)
