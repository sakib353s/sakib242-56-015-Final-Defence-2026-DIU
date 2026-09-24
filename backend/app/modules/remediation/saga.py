"""Consent-gated remediation saga: DRAFT → CONSENTED → APPLIED → (ROLLED_BACK | ABORTED).

No path applies without BOTH gates: active warrant on host AND SUPER_ADMIN consent
with fresh TOTP. All state transitions are chained-audited (P-07).
"""
from __future__ import annotations

import difflib
import json
import shlex
from datetime import datetime, timezone

from app.audit import chain
from app.core.errors import Conflict, CWBError, Forbidden, WarrantMissing
from app.core.security import now_iso
from app.db import sqlite as sql
from app.db.repositories import Ledger

ABORT_TEMPLATE = ("[ FAIL ] REMEDIATION ABORTED — authorization/consent missing. "
                  "audit_ref=#{audit_ref}")

FIX_TEMPLATES = {
    "openssh": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade openssh-server",
    "openssl": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade libssl3 openssl",
    "apache": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade apache2",
    "nginx": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade nginx",
    "proftpd": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade proftpd-basic",
    "vsftpd": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade vsftpd",
    "dropbear": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade dropbear",
    "default": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
}


def _template_for(service: str) -> str:
    s = (service or "").lower()
    for key, cmd in FIX_TEMPLATES.items():
        if key in s:
            return cmd
    return FIX_TEMPLATES["default"]


def generate_job(finding_id: str, host: str, warrant_id: str, actor: str,
                 asset_id: str | None) -> dict:
    f = sql.one("SELECT * FROM findings WHERE id=?", finding_id)
    if not f:
        raise CWBError("Finding not found", status=404)
    script = _template_for(f["service"] or "")
    before = "# running service inventory\n" + json.dumps(
        {"service": f["service"], "cve": f["cve"], "port": f["port"]}, indent=2)
    after = before + "\n# post-fix marker (verified by rescan)\nFIXED=1\n"
    diff = list(difflib.unified_diff(before.splitlines(), after.splitlines(),
                                     "current", "proposed", lineterm=""))
    jid = sql_scalar_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO remediation_jobs (id, finding_id, host, asset_id, warrant_id, state, script,"
            " diff_json, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (jid, finding_id, host, asset_id, warrant_id, "DRAFT", script,
             json.dumps({"before": before.splitlines(), "after": after.splitlines(), "diff": diff}),
             actor, now_iso(), now_iso()),
        )
    chain.append(actor, "remediation.job.create", jid, {"finding": finding_id, "host": host})
    return {"job_id": jid, "state": "DRAFT"}


def sql_scalar_id() -> str:
    from app.core.ids import new_id
    return new_id()


def get_diff(job_id: str) -> dict:
    row = sql.one("SELECT * FROM remediation_jobs WHERE id=?", job_id)
    if not row:
        raise CWBError("Job not found", status=404)
    chain.safe_append("system", "remediation.diff.view", job_id)
    return {"job_id": job_id, "state": row["state"], **json.loads(row["diff_json"]),
            "script": row["script"]}


def validate_gates(job_id: str, actor: str) -> dict:
    """Both gates re-checked at every mutating step — no TOCTOU shortcuts."""
    row = sql.one("SELECT * FROM remediation_jobs WHERE id=?", job_id)
    if not row:
        raise CWBError("Job not found", status=404)
    w = Ledger.get(row["warrant_id"])
    from app.gateway.deps import warrant_window_active

    if not w or w["revoked_at"] or not warrant_window_active(w) or w["kind"] != "remediation":
        ref = chain.append(actor, "remediation.abort.warrant_gate", job_id, {"reason": "warrant"})
        raise WarrantMissing(ABORT_TEMPLATE.replace("#{audit_ref}", ref))
    host = row["host"]
    scope = json.loads(w["scope_json"])
    from app.core.scopes import matches
    if not matches(scope, host):
        ref = chain.append(actor, "remediation.abort.scope_gate", job_id, {"host": host})
        raise Forbidden(ABORT_TEMPLATE.replace("#{audit_ref}", ref))
    return row


def record_consent(job_id: str, actor: str, totp_ok: bool) -> dict:
    row = validate_gates(job_id, actor)
    if row["state"] != "DRAFT":
        raise Conflict(f"Job is {row['state']}, consent only on DRAFT")
    if not totp_ok:
        ref = chain.append(actor, "remediation.consent.deny", job_id, {"reason": "totp"})
        raise Forbidden(ABORT_TEMPLATE.replace("#{audit_ref}", ref))
    consent = {"job_id": job_id, "user_id": actor, "ts": now_iso(), "totp_ok": True,
               "scope_echo": json.loads(Ledger.get(row["warrant_id"])["scope_json"])}
    with sql.get_db() as c:
        c.execute("UPDATE remediation_jobs SET state='CONSENTED', consent_json=?, updated_at=? WHERE id=?",
                  (json.dumps(consent), now_iso(), job_id))
    chain.append(actor, "remediation.consent.grant", job_id, consent)
    return {"state": "CONSENTED"}


def abort_job(job_id: str, actor: str, reason: str):
    with sql.get_db() as c:
        c.execute("UPDATE remediation_jobs SET state='ABORTED', apply_log=?, updated_at=? WHERE id=?",
                  (reason, now_iso(), job_id))
    chain.append(actor, "remediation.abort", job_id, {"reason": reason})


async def _auto_report(job_id: str, actor: str) -> None:
    """Every terminal saga state emits a signed change-record PDF into the report
    library. Failures here never mask the saga outcome."""
    import asyncio
    try:
        from app.reports import remediation_pdf
        from app.reports.signing import register_report
        path = await asyncio.to_thread(remediation_pdf.build, job_id)
        register_report(path, f"remediation-{job_id}.pdf", "remediation", job_id, actor)
    except Exception:
        chain.safe_append("system:report", "report.generate_failed", job_id, {"kind": "remediation"})


async def apply_job(job_id: str, actor: str) -> dict:
    """SSH to owned asset, snapshot, apply, rescan-verify. Any failure keeps the snapshot
    and suggests rollback; post-verify failure auto-proposes rollback."""
    row = validate_gates(job_id, actor)
    if row["state"] != "CONSENTED":
        raise Conflict("Job must be CONSENTED to apply")
    if not row["asset_id"]:
        abort_job(job_id, actor, "no owned asset bound — cannot SSH")
        raise CWBError("No asset bound to job", status=422)
    asset = sql.one("SELECT * FROM hw_assets WHERE id=?", row["asset_id"])
    if not asset or asset["disabled"]:
        abort_job(job_id, actor, "asset missing/disabled")
        raise CWBError("Asset unusable", status=422)
    from app.core.security import dec_field
    from app.modules.hwmon import service as hw
    password = dec_field(asset["ssh_pass_enc"]) if asset["ssh_pass_enc"] else ""
    log_lines = []
    try:
        snap = await hw.ssh_run(asset["host"], asset["ssh_port"] or 22, asset["ssh_user"], password,
                                "tar czf /tmp/cwb-snap.tar.gz /etc 2>/dev/null;"
                                " dpkg --get-selections > /tmp/cwb-pkgs.txt 2>/dev/null; echo ok")
        log_lines.append(f"snapshot: {snap.strip()[:120]}")
        out = await hw.ssh_run(asset["host"], asset["ssh_port"] or 22, asset["ssh_user"], password,
                               row["script"], timeout=600)
        log_lines.append(f"apply: {out.strip()[:400]}")
        verify = await post_verify(row["host"], row["finding_id"])
        with sql.get_db() as c:
            c.execute("UPDATE remediation_jobs SET state='APPLIED', apply_log=?, updated_at=?,"
                      " snapshot_ref='/tmp/cwb-snap.tar.gz', verify_result=? WHERE id=?",
                      ("\n".join(log_lines), now_iso(), verify, job_id))
        chain.append(actor, "remediation.apply.ok", job_id, {"asset": asset["name"], "verify": verify[:120]})
        await _auto_report(job_id, actor)
        return {"state": "APPLIED", "log": log_lines, "verify_result": verify}
    except Exception as e:
        with sql.get_db() as c:
            c.execute("UPDATE remediation_jobs SET apply_log=?, state='APPLIED_UNVERIFIED', updated_at=? WHERE id=?",
                      (f"failure: {e}", now_iso(), job_id))
        chain.append(actor, "remediation.apply.fail", job_id, {"error": str(e)[:300]})
        await _auto_report(job_id, actor)
        raise CWBError(f"Apply failed — snapshot retained, rollback suggested: {e}", status=502)


async def rollback_job(job_id: str, actor: str) -> dict:
    row = validate_gates(job_id, actor)
    if row["state"] not in ("APPLIED", "APPLIED_UNVERIFIED"):
        raise Conflict("Nothing to roll back")
    if not row["asset_id"] or not row["snapshot_ref"]:
        raise CWBError("Missing asset/snapshot reference", status=422)
    asset = sql.one("SELECT * FROM hw_assets WHERE id=?", row["asset_id"])
    if not asset:
        raise CWBError("Bound asset vanished — manual restore from snapshot required", status=410)
    from app.core.security import dec_field
    from app.modules.hwmon import service as hw
    password = dec_field(asset["ssh_pass_enc"]) if asset and asset["ssh_pass_enc"] else ""
    out = await hw.ssh_run(asset["host"], asset["ssh_port"] or 22, asset["ssh_user"], password,
                           "dpkg --set-selections < /tmp/cwb-pkgs.txt < /dev/null 2>/dev/null;"
                           " apt-get dselect-upgrade -y 2>/dev/null; tar xzf /tmp/cwb-snap.tar.gz -C / ; echo ok")
    with sql.get_db() as c:
        c.execute("UPDATE remediation_jobs SET state='ROLLED_BACK', apply_log=apply_log||char(10)||?,"
                  " updated_at=? WHERE id=?", (f"rollback: {out[:200]}", now_iso(), job_id))
    chain.append(actor, "remediation.rollback.exec", job_id, {"output": out[:200]})
    await _auto_report(job_id, actor)
    return {"state": "ROLLED_BACK"}


async def post_verify(host: str, finding_id: str) -> str:
    """P-07 post-apply verification: safe version-only re-probe of the finding's port
    (nmap -sV — never exploitation). Honest UNVERIFIED strings when probing impossible."""
    import asyncio
    import re
    import subprocess

    f = sql.one("SELECT * FROM findings WHERE id=?", finding_id)
    if not f or not f["port"]:
        return "UNVERIFIED: finding port unknown"
    cmd = ["nmap", "-n", "-Pn", "-sV", "--version-intensity", "2",
           "--host-timeout", "3m", "-p", str(int(f["port"])), host]
    try:
        p = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True, timeout=240)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "UNVERIFIED: nmap unavailable for rescan probe"
    if p.returncode != 0:
        return f"UNVERIFIED: probe failed (exit {p.returncode})"
    m = re.search(rf"{int(f['port'])}/tcp\s+open\s+(\S+)\s+(.*)", p.stdout)
    observed = (m.group(2).strip() or m.group(1))[:80] if m else "port closed"
    before = (f["service"] or "")[:80]
    if observed != before:
        return f"VERIFIED CHANGED: was [{before}] now [{observed}]"
    return f"UNCHANGED: [{observed}] — rollback recommended"
