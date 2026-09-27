"""SOC Center API — defensive, role-gated (no warrant). FR-S01…S06."""


from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field

from app.audit import chain
from app.core import idempotency as idem
from app.core.errors import CWBError, NotFound
from app.core.ids import new_id
from app.core.security import now_iso
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_analyst, require_super, require_totp_stepup
from app.modules.soc import service
from app.modules.soc.playbooks import PLAYBOOKS, FORFEIT_HONEYPOT_NOTE

router = APIRouter(prefix="/api/v1/soc", tags=["soc"])


@router.get("/alerts")
async def alerts(sev: str | None = None, limit: int = 100, p: Principal = Depends(require_analyst)):
    if sev:
        rows = sql.all_("SELECT * FROM alerts WHERE severity=? ORDER BY ts DESC LIMIT ?", sev, limit)
    else:
        rows = sql.all_("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", limit)
    return {"alerts": rows}


class AckBody(BaseModel):
    note: str = Field(default="", max_length=500)


@router.post("/alerts/{alert_id}/ack")
async def ack(request: Request, alert_id: str, body: AckBody,
              p: Principal = Depends(require_analyst),
              idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
    if idempotency_key is not None:
        if not 8 <= len(idempotency_key) <= 128:
            raise CWBError("Idempotency-Key must be 8-128 chars (uuid recommended)", status=422)
        replay = idem.lookup(idempotency_key)
        if replay is not None:
            return replay  # exactly-once replay of the first execution's response
    if not sql.one("SELECT id FROM alerts WHERE id=?", alert_id):
        raise NotFound("Alert not found")
    ts = now_iso()
    with sql.get_db() as c:
        c.execute("UPDATE alerts SET status='acked', ack_by=?, ack_at=? WHERE id=?",
                  (p.user_id, ts, alert_id))
    ref = chain.append(p.user_id, "soc.alert.ack", alert_id, {"note": body.note})
    resp = {"ok": True, "alert_id": alert_id, "acked_at": ts, "audit_ref": ref}
    if idempotency_key is not None:
        idem.store(idempotency_key, resp)
    return resp


class BlockBody(BaseModel):
    ip: str
    expires_min: int = Field(default=60, ge=5, le=1440)


@router.post("/block-ip")
async def block_ip(request: Request, body: BlockBody, p: Principal = Depends(require_analyst)):
    require_totp_stepup(request, p)
    res = await service.block_ip(body.ip, p.user_id, body.expires_min)
    return res


@router.get("/blocks")
async def list_blocks(status: str | None = None, p: Principal = Depends(require_analyst)):
    """Active + recent firewall deployments, straight from the ledger of rules."""
    if status:
        rows = sql.all_("SELECT * FROM ip_blocks WHERE status=? ORDER BY created_at DESC LIMIT 200", status)
    else:
        rows = sql.all_("SELECT * FROM ip_blocks ORDER BY created_at DESC LIMIT 200")
    return {"blocks": rows}


class UnblockBody(BaseModel):
    block_id: str


@router.post("/unblock-ip")
async def unblock(request: Request, body: UnblockBody, p: Principal = Depends(require_analyst)):
    ok = await service.unblock_ip(body.block_id, p.user_id)
    if not ok:
        raise NotFound("Active block not found")
    return {"ok": True}


class PlaybookBody(BaseModel):
    playbook: str
    context: dict = Field(default_factory=dict)


@router.post("/incidents/{incident_id}/playbook")
async def run_playbook(request: Request, incident_id: str, body: PlaybookBody,
                       p: Principal = Depends(require_analyst)):
    pb = PLAYBOOKS.get(body.playbook)
    if pb is None:
        raise NotFound(f"Unknown playbook '{body.playbook}' — available: {sorted(PLAYBOOKS)}")
    result = pb.plan(body.context)
    with sql.get_db() as c:
        row = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            c.execute("INSERT INTO incidents (id, alert_ref, playbook, payload_json, opened_at)"
                      " VALUES (?,?,?,?,?)",
                      (incident_id, body.context.get("alert_id"), pb.name,
                       __import__("json").dumps(result.__dict__), now_iso()))
    chain.append(p.user_id, "soc.playbook.run", incident_id,
                 {"playbook": pb.name, "steps": [s["step"] for s in result.steps]})
    return {"incident_id": incident_id, **result.__dict__}


class NewIncident(BaseModel):
    alert_id: str | None = None
    playbook: str


@router.post("/incidents")
async def new_incident(body: NewIncident, p: Principal = Depends(require_analyst)):
    iid = new_id()
    with sql.get_db() as c:
        c.execute("INSERT INTO incidents (id, alert_ref, playbook, payload_json, opened_at) VALUES (?,?,?,?,?)",
                  (iid, body.alert_id, body.playbook, "{}", now_iso()))
    chain.append(p.user_id, "soc.incident.open", iid, {"playbook": body.playbook})
    return {"incident_id": iid}


@router.post("/honeypot/deploy")
async def honeypot(request: Request, p: Principal = Depends(require_super)):
    require_totp_stepup(request, p)
    chain.append(p.user_id, "soc.honeypot.deploy_request", "honeypot", {"note": FORFEIT_HONEYPOT_NOTE})
    return {"status": "AWAITING_SEGMENT_AUTHORIZATION", "policy_note": FORFEIT_HONEYPOT_NOTE}


@router.get("/mitre-profile/{tid}")
async def mitre_profile(tid: str, p: Principal = Depends(require_analyst)):
    """In-app MITRE technique view: official metadata (parsed live from
    attack.mitre.org, cached) + this system's own observed alerts as a graph."""
    from app.modules.soc import mitre_profile as mp
    if not mp.TECH_RE.match(tid.upper()):
        raise CWBError("technique id must look like T1070 or T1070.001", status=422)
    return await mp.profile(tid)


@router.get("/mitre/{alert_id}")
async def mitre(alert_id: str, p: Principal = Depends(require_analyst)):
    a = sql.one("SELECT signature, category, src_ip, dest_ip, mitre, severity FROM alerts WHERE id=?", alert_id)
    if not a:
        raise NotFound("Alert not found")
    return {"alert_id": alert_id, "technique": a["mitre"] or service.classify_mitre(a),
            "matrix_url": f"https://attack.mitre.org/techniques/{(a['mitre'] or 'T0000').replace('.', '/')}/"}
