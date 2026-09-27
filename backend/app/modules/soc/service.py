"""SOC Center — Suricata EVE tail → alert pipeline (severity, MITRE, WS+FCM fan-out).

Defensive module: role-based, no warrant needed. IP blocking deploys real rules via
the configured host-agent (iptables on Linux); failures roll back and CRITICAL-audit.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.audit import chain
from app.core.config import get_settings
from app.core.errors import CWBError
from app.core.ids import new_id
from app.core.security import now_iso
from app.db import mongo, sqlite as sql
from app.gateway.wsmanager import manager

S = get_settings()
MITRE = json.loads((Path(__file__).parent / "mitre_map.json").read_text())
SEV_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


def classify_mitre(alert: dict) -> str | None:
    hay = " ".join(str(alert.get(k, "")) for k in ("signature", "category", "msg")).lower()
    for tech, kws in MITRE.items():
        if any(k in hay for k in kws):
            return tech
    return None


def ingest_eve_line(line: str) -> dict | None:
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if ev.get("event_type") != "alert":
        return None
    a = ev["alert"]
    aid = new_id()
    mitre = classify_mitre(a)
    row = {
        "id": aid, "source": "suricata", "signature": a.get("signature", "?")[:400],
        "category": a.get("category"), "severity": SEV_MAP.get(a.get("severity"), "MEDIUM"),
        "src_ip": ev.get("src_ip"), "dest_ip": ev.get("dest_ip"),
        "mitre": mitre, "status": "new", "ts": now_iso(), "raw_json": json.dumps(ev),
    }
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(timespec="milliseconds")
    with sql.get_db() as c:
        dup = c.execute("SELECT id FROM alerts WHERE src_ip=? AND signature=? AND ts > ?"
                        " LIMIT 1", (row["src_ip"], row["signature"], cutoff)).fetchone()
        if dup:
            return None  # dedupe replayed alerts (T-S04)
        c.execute(
            "INSERT INTO alerts (id, source, signature, category, severity, src_ip, dest_ip, mitre,"
            " status, ts, raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            tuple(row[k] for k in ("id", "source", "signature", "category", "severity",
                                   "src_ip", "dest_ip", "mitre", "status", "ts", "raw_json")),
        )
    mongo.store("alerts", {**row, "raw": None})
    try:
        from app.modules.soc import detection
        detection.evaluate({**row, "source": "suricata"}, already_alerted=True)
    except Exception:
        pass  # rule engine must never stall the EVE pipeline
    return row


async def eve_tail():
    """Background worker: tail EVE JSON, fan out new alerts."""
    path = Path(S.suricata_eve_path)
    if not path.exists():
        chain.safe_append("system:soc", "soc.eve_absent", str(path), {"note": "tail worker idle"})
        return
    path.parent  # noqa
    with open(path) as f:
        f.seek(0, 2)  # start at end of history
        while True:
            line = await asyncio.to_thread(f.readline)
            if not line:
                await asyncio.sleep(0.5)
                continue
            row = ingest_eve_line(line)
            if row:
                await manager.publish("alerts", "alert.new", row)


async def block_ip(ip: str, actor: str, expires_min: int = 60) -> dict:
    """Deploy a real iptables DROP via host agent. Non-Linux/unavailable = honest failure."""
    import ipaddress

    ipaddress.ip_address(ip)  # raises ValueError on garbage -> 422 via handler
    rule = f"iptables -I INPUT -s {ip} -j DROP"
    bid = new_id()
    if S.block_agent_script:
        try:
            p = await asyncio.to_thread(subprocess.run,
                                        [S.block_agent_script, "block", ip],
                                        capture_output=True, text=True, timeout=20)
            ok, via, err = p.returncode == 0, "host-agent", p.stderr[:200]
        except Exception as e:
            ok, via, err = False, "host-agent", str(e)
    else:
        import platform
        if platform.system() != "Linux":
            ok, via, err = False, "none", "no block agent configured; iptables requires Linux host"
        else:
            try:
                p = await asyncio.to_thread(subprocess.run,
                                            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                                            capture_output=True, text=True, timeout=20)
                ok, via, err = p.returncode == 0, "iptables", p.stderr[:200]
            except Exception as e:
                ok, via, err = False, "iptables", str(e)
    if not ok:
        chain.append(actor, "soc.ip_block_failed", ip, {"error": err})
        raise CWBError(f"Block deployment failed: {err}", status=502)
    expires = datetime.now(timezone.utc) + timedelta(minutes=expires_min)
    expires_iso = f"{expires:%Y-%m-%dT%H:%M:%S}.{expires.microsecond // 1000:03d}+00:00"
    with sql.get_db() as c:
        c.execute("INSERT INTO ip_blocks (id, ip, rule, status, deployed_via, expires_at, created_by, created_at)"
                  " VALUES (?,?,?,?,?,?,?,?)",
                  (bid, ip, rule, "active", via, expires_iso, actor, now_iso()))
    chain.append(actor, "soc.ip_block", bid, {"ip": ip, "rule": rule})
    await manager.publish("alerts", "ip.blocked", {"id": bid, "ip": ip})
    return {"block_id": bid, "ip": ip, "status": "active"}


async def unblock_ip(block_id: str, actor: str, reason: str = "manual/rollback-timer") -> bool:
    """Reverses the rule via the SAME channel that deployed it (deployed_via). A rule
    placed with direct iptables must be removed with iptables -D — not just marked."""
    row = sql.one("SELECT * FROM ip_blocks WHERE id=?", block_id)
    if not row or row["status"] != "active":
        return False
    via = row["deployed_via"]
    ok, err = True, ""
    if via == "host-agent" and S.block_agent_script:
        try:
            p = await asyncio.to_thread(subprocess.run, [S.block_agent_script, "unblock", row["ip"]],
                                        capture_output=True, text=True, timeout=20)
            ok, err = p.returncode == 0, p.stderr[:200]
        except Exception as e:  # TimeoutExpired/FileNotFoundError must not kill the watchdog
            ok, err = False, f"{type(e).__name__}: {e}"
    elif via == "iptables":
        try:
            p = await asyncio.to_thread(subprocess.run,
                                        ["iptables", "-D", "INPUT", "-s", row["ip"], "-j", "DROP"],
                                        capture_output=True, text=True, timeout=20)
            ok, err = p.returncode == 0, p.stderr[:200]
        except Exception as e:
            ok, err = False, str(e)
    # via "none" → nothing was deployed on the firewall, so DB-only inactivation is correct
    if not ok:
        chain.append(actor, "soc.ip_unblock_failed", block_id, {"reason": reason, "error": err})
        return False
    with sql.get_db() as c:
        c.execute("UPDATE ip_blocks SET status='inactive', unblocked_at=? WHERE id=?", (now_iso(), block_id))
    chain.append(actor, "soc.ip_unblock", block_id, {"reason": reason, "via": via})
    return True


async def block_expiry_watchdog():
    while True:
        for r in sql.all_("SELECT id FROM ip_blocks WHERE status='active' AND expires_at < ?",
                          now_iso()):
            try:
                await unblock_ip(r["id"], "system:watchdog", "rollback-timer")
            except Exception as e:
                # an unsupervised create_task: any escape here would silently
                # retire the watchdog and leave expired DROPs in place forever
                chain.safe_append("system:watchdog", "soc.watchdog_error", r["id"],
                                  {"error": str(e)[:200]})
        await asyncio.sleep(60)
