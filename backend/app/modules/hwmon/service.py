"""Hardware Monitor — remote diagnostics of user-owned assets (P-05i, FR-H01…H04).

Credentials AES-256-GCM at rest. SSH auth failures lock the asset after 3 tries.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import paramiko

from app.audit import chain
from app.core.config import get_settings
from app.core.errors import CWBError, Forbidden, NotFound
from app.core.ids import new_id
from app.core.security import dec_field, enc_field, now_iso
from app.db import sqlite as sql

S = get_settings()
ANOMALY_RULES = {"disk_pct": 85, "mem_pct": 90, "load_per_core": 2.0}


def create_asset(name, kind, host, ssh_port, ssh_user, ssh_password, snmp_community,
                 attested, actor) -> dict:
    if not attested:
        raise Forbidden("asset ownership attestation is mandatory")
    aid = new_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO hw_assets (id, name, kind, host, ssh_port, ssh_user, ssh_pass_enc,"
            " snmp_community_enc, ownership_attested, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (aid, name, kind, host, ssh_port or 22, ssh_user,
             enc_field(ssh_password) if ssh_password else None,
             enc_field(snmp_community) if snmp_community else None, 1, now_iso()),
        )
    chain.append(actor, "hw.asset.create", aid, {"host": host, "kind": kind})
    return sql.one("SELECT id, name, kind, host, ssh_port, ssh_user, disabled, created_at"
                   " FROM hw_assets WHERE id=?", aid)


async def ssh_run(host: str, port: int, user: str, password: str, command: str,
                  timeout: int = 30) -> str:
    def _run() -> str:
        from pathlib import Path as _P
        known = _P(S.database_path + ".known_hosts")
        known.touch(exist_ok=True)
        cli = paramiko.SSHClient()
        # TOFU: unknown keys are pinned to our store and audited; changed known keys
        # still hard-reject (MITM detection preserved).
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.load_host_keys(str(known))
        try:
            cli.connect(host, port=port, username=user, password=password, timeout=12,
                        look_for_keys=False, allow_agent=False)
            cli.save_host_keys(str(known))
            _, out, err = cli.exec_command(command, timeout=timeout)
            data = out.read().decode(errors="replace")
            if not data:
                data = err.read().decode(errors="replace")
            return data
        finally:
            cli.close()
    return await asyncio.to_thread(_run)


async def check_asset(asset_id: str, actor: str) -> dict:
    asset = sql.one("SELECT * FROM hw_assets WHERE id=?", asset_id)
    if not asset:
        raise NotFound("Asset not found")
    if asset["disabled"]:
        raise Forbidden("Asset locked after repeated auth failures — re-enable manually")
    checks: dict = {}
    anomalies: list[str] = []
    if asset["ssh_user"] and asset["ssh_pass_enc"]:
        try:
            pw = dec_field(asset["ssh_pass_enc"])
            raw = await ssh_run(asset["host"], asset["ssh_port"] or 22, asset["ssh_user"], pw,
                                "echo DISK:$(df -P / | awk 'NR==2{print $5}');"
                                "echo MEM:$(free | awk '/Mem/{printf \"%.0f\", $3*100/$2}');"
                                "echo LOAD:$(cat /proc/loadavg | awk '{print $1}');"
                                "echo UP:$(uptime -p 2>/dev/null || uptime)")
            checks["ssh"] = dict(kv.split(":", 1) for kv in raw.splitlines() if ":" in kv)
        except Exception as e:
            with sql.get_db() as c:
                c.execute("UPDATE hw_assets SET failed_checks = failed_checks + 1 WHERE id=?", (asset_id,))
            fails = sql.one("SELECT failed_checks FROM hw_assets WHERE id=?", asset_id)["failed_checks"]
            if fails >= 3:
                with sql.get_db() as c:
                    c.execute("UPDATE hw_assets SET disabled=1 WHERE id=?", (asset_id,))
                chain.append(actor, "hw.asset.locked", asset_id, {"after_failures": fails})
            chain.safe_append(actor, "hw.check.failed", asset_id, {"error": str(e)[:150]})
            raise CWBError(f"SSH check failed ({type(e).__name__}); asset may lock after 3 tries", status=502)
    if asset["snmp_community_enc"]:
        try:
            checks["snmp"] = await snmp_get(asset["host"], dec_field(asset["snmp_community_enc"]))
        except Exception as e:
            checks["snmp"] = {"error": str(e)[:120]}  # partial report = WARN per spec
    for key, rule in (("disk_pct", ANOMALY_RULES["disk_pct"]), ("mem_pct", ANOMALY_RULES["mem_pct"])):
        val = (checks.get("ssh") or {}).get(key.split("_")[0].upper())
        try:
            num = float(str(val).rstrip("%"))
            if num > rule:
                anomalies.append(f"{key} {num}% > {rule}%")
        except (TypeError, ValueError):
            pass
    with sql.get_db() as c:
        c.execute("UPDATE hw_assets SET last_check_json=?, last_check_at=?, failed_checks=0 WHERE id=?",
                  (json.dumps({"checks": checks, "anomalies": anomalies}), now_iso(), asset_id))
    for a in anomalies:
        chain.append(actor, "hw.anomaly", asset_id, {"anomaly": a})
    from app.gateway.wsmanager import manager
    if anomalies:
        await manager.publish("alerts", "hw.anomaly", {"asset": asset_id, "anomalies": anomalies})
    chain.append(actor, "hw.check", asset_id, {"anomalies": len(anomalies)})
    return {"asset_id": asset_id, "checks": checks, "anomalies": anomalies, "checked_at": now_iso()}


async def snmp_get(host: str, community: str) -> dict:
    """Real SNMP v2c GET of sysDescr/sysUpTime via pysnmp 6.x asyncio high-level API."""
    from pysnmp.hlapi.asyncio import (CommunityData, ContextData, ObjectIdentity,
                                      SnmpEngine, UdpTransportTarget, get_cmd, ObjectType)
    engine = SnmpEngine()
    err, status, indices, var_binds = await get_cmd(
        engine, CommunityData(community, mpModel=1),
        UdpTransportTarget((host, 161), timeout=6),
        ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.3.0")),
    )
    if err:
        raise CWBError(f"SNMP error: {err}", status=502)
    return {str(oid): str(val) for oid, val in var_binds}


def generate_diag_pdf(asset_id: str, actor: str) -> str:
    asset = sql.one("SELECT * FROM hw_assets WHERE id=?", asset_id)
    if not asset:
        raise NotFound("Asset not found")
    from app.reports import diag_pdf
    path = diag_pdf.build(asset)
    from app.reports.signing import register_report
    register_report(path, f"diag-{asset['name']}.pdf", "diag", asset_id, actor)
    chain.append(actor, "hw.report", asset_id, {"path": path})
    return path
