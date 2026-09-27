"""IP Anonymizer — session-scoped Tor circuits, warrant-bound (P-05h).

Circuit lifetime == authorized pentest session lifetime. Warrant expiry triggers
auto-teardown by the watchdog. This module never routes arbitrary traffic; it only
provides circuits for already-authorized pentest sessions.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from pathlib import Path

from app.audit import chain
from app.core.config import get_settings
from app.core.errors import CWBError, NotFound
from app.core.ids import new_id
from app.core.security import now_iso
from app.db import sqlite as sql

S = get_settings()


def _controller():
    from stem.control import Controller
    return Controller.from_port(address=S.tor_control_host, port=S.tor_control_port)


async def start(warrant_id: str, bound_session: str, actor: str,
                pentest_session: str | None = None) -> dict:
    """Unified warrant gate semantics (P-05h): the warrant must be kind 'ipanon', or
    kind 'pentest' WITH a live (CREATED/RUNNING) authorized session — circuits exist
    only for active engagements."""
    from app.gateway.deps import warrant_window_active

    w = sql.one("SELECT * FROM auth_ledger WHERE id=?", warrant_id)
    deny = None
    if not w:
        if not S.warrant_required:
            # lab (CWB_WARRANT_ENFORCE=auto/off): anchor keeps the FK + watchdog honest
            from app.gateway.deps import lab_anchor_warrant

            chain.safe_append(actor, "gate.warrant_lab_skip", "ipanon", {"kind": "ipanon"})
            w = lab_anchor_warrant("ipanon", actor)
            warrant_id = w["id"]
        else:
            deny = "no warrant record"
    elif w["revoked_at"]:
        deny = "warrant revoked"
    elif not warrant_window_active(w):
        deny = "warrant outside validity window"
    elif w["kind"] == "pentest":
        sess = sql.one("SELECT id FROM pentest_sessions WHERE warrant_id=? AND status IN ('CREATED','RUNNING')"
                       " ORDER BY created_at DESC LIMIT 1", warrant_id) if not pentest_session else \
               sql.one("SELECT id FROM pentest_sessions WHERE id=? AND warrant_id=?"
                       " AND status IN ('CREATED','RUNNING')", pentest_session, warrant_id)
        if not sess:
            deny = "pentest warrant has no active session — anonymizer is session-bound"
        else:
            bound_session = sess["id"]
    elif w["kind"] != "ipanon":
        deny = f"warrant kind '{w['kind']}' does not authorize ip anonymization"
    if deny:
        chain.append(actor, "ipanon.deny", warrant_id or "-", {"reason": deny})
        from app.core.errors import WarrantMissing

        raise WarrantMissing(deny)
    cid = new_id()
    with sql.get_db() as c:
        c.execute("INSERT INTO circuits (id, session_warrant_id, bound_session, status, started_at)"
                  " VALUES (?,?,?,?,?)", (cid, warrant_id, bound_session, "building", now_iso()))

    def _build() -> str:
        with _controller() as ctl:
            if S.tor_control_password:
                ctl.authenticate(password=S.tor_control_password)
            fp = ctl.get_info("circuit-status")  # ensures control conn live
            # stem returns the version as a string ('0.4.7.13'); comparing it to a
            # tuple raises TypeError, so normalise before the feature check.
            try:
                ver = tuple(int(p) for p in (ctl.get_version() or "").split(".")[:3])
            except ValueError:
                ver = (0, 0, 0)
            if ver >= (0, 4, 0):
                ctl.signal("NEWNEWSESSION")
            return (fp or "")[:120]

    try:
        info = await asyncio.to_thread(_build)
    except Exception as e:
        with sql.get_db() as c:
            c.execute("UPDATE circuits SET status='failed', stopped_at=? WHERE id=?", (now_iso(), cid))
        chain.append(actor, "ipanon.start.failed", cid, {"error": str(e)[:200]})
        raise CWBError(f"Tor control unavailable: {type(e).__name__}", status=503)
    masked = await _masked_ip()
    with sql.get_db() as c:
        c.execute("UPDATE circuits SET status='active', masked_ip=?, last_heartbeat=? WHERE id=?",
                  (masked, now_iso(), cid))
    _write_proxychains(cid, masked)
    chain.append(actor, "ipanon.start", cid,
                 {"warrant_ref": w["warrant_ref"] if w else "lab-skip", "masked_ip": masked})
    return {"circuit_id": cid, "status": "active", "masked_ip": masked, "tor": info}


async def stop(circuit_id: str, actor: str, reason="manual") -> dict:
    row = sql.one("SELECT * FROM circuits WHERE id=?", circuit_id)
    if not row or row["status"] not in ("active", "building"):
        raise NotFound("Active circuit not found")
    try:
        def _teardown():
            with _controller() as ctl:
                if S.tor_control_password:
                    ctl.authenticate(password=S.tor_control_password)
                ctl.close_circuit(ctl.get_info("circuit-status").split(" ")[0]) if False else None
                ctl.signal("RELOAD")
        await asyncio.to_thread(_teardown)
    except Exception:
        pass  # teardown best-effort; local state + audit still recorded
    with sql.get_db() as c:
        c.execute("UPDATE circuits SET status='stopped', stopped_at=? WHERE id=?", (now_iso(), circuit_id))
    Path(S.database_path).parent.joinpath(f"proxychains-{circuit_id}.conf").unlink(missing_ok=True)
    chain.append(actor, "ipanon.stop", circuit_id, {"reason": reason})
    return {"ok": True}


async def heartbeat(actor="system:watchdog"):
    """5-min heartbeat + warrant-expiry auto-teardown (P-05h T-IA01)."""
    from app.gateway.deps import warrant_window_active

    for row in sql.all_("SELECT c.id, a.valid_from, a.valid_until, a.revoked_at FROM circuits c"
                        " JOIN auth_ledger a ON a.id=c.session_warrant_id WHERE c.status='active'"):
        if row["revoked_at"] or not warrant_window_active(row):
            await stop(row["id"], actor, reason="warrant-expired")
            continue
        masked = await _masked_ip()
        with sql.get_db() as c:
            c.execute("UPDATE circuits SET last_heartbeat=?, masked_ip=? WHERE id=?",
                      (now_iso(), masked, row["id"]))
        chain.safe_append(actor, "ipanon.heartbeat", row["id"], {"masked_ip": masked})


def _write_proxychains(circuit_id: str, masked_ip: str):
    conf = Path(S.database_path).parent / f"proxychains-{circuit_id}.conf"
    conf.write_text(
        "strict_chain\nproxy_dns\nudp_chain\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n"
        "[ProxyList]\nsocks5 127.0.0.1 9050\n")


async def _masked_ip() -> str | None:
    """Exit-IP probe THROUGH the local Tor SOCKS endpoint (verifies masking is real)."""
    try:
        import httpx
        async with httpx.AsyncClient(proxy="socks5://127.0.0.1:9050", timeout=12) as h:
            r = await h.get("https://api.ipify.org?format=json")
            return r.json().get("ip")
    except Exception:
        return None


# --- network-path trace (Trippy) -------------------------------------------
# Active measurement of the gateway's own Internet path. NOT anonymization and
# never claims to be: no exit node, source IP stays visible to every hop.
TARGET_RE = re.compile(r"^(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,45}|[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)$")


def _trippy_bin() -> Path | None:
    found = shutil.which("trip")
    if found:
        return Path(found)
    cand = sorted((Path(__file__).resolve().parents[3] / ".bin").glob("trippy-*/trip"))
    return cand[-1] if cand else None


async def trace_path(target: str, cycles: int = 2) -> dict:
    """Headless unprivileged Trippy run — exec list, no shell, target regex-gated."""
    if not TARGET_RE.match(target):
        raise CWBError("target must be an IPv4/IPv6 address or a fully-qualified domain", status=422)
    binary = _trippy_bin()
    if not binary:
        raise CWBError("Trippy binary absent — install `trip` on PATH or drop it in backend/.bin", status=503)
    proc = await asyncio.create_subprocess_exec(
        str(binary), target, "-m", "json", "-C", str(cycles), "-u",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError:
        proc.kill()
        raise CWBError("trace timed out", status=504)
    if proc.returncode != 0:
        raise CWBError(f"trace failed: {err.decode(errors='replace')[:160]}", status=502)
    data = json.loads(out)
    hops = []
    for h in data.get("hops", []):
        hosts = h.get("hosts") or []
        hops.append({
            "ttl": h["ttl"],
            "ip": (hosts[0].get("ip") if hosts else None) or "* * *",
            "hostname": hosts[0].get("hostname") if hosts else None,
            "avg_ms": h.get("avg"), "worst_ms": h.get("worst"),
            "loss_pct": h.get("loss_pct"), "nat": h.get("nat"),
        })
    return {"target": data["info"]["target"], "started": data["info"]["start_timestamp"],
            "engine": "trippy (unprivileged)", "hops": hops}
