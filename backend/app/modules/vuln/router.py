"""Vuln Scanner API — warrant-gated."""


from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pydantic import BaseModel, Field, field_validator

from app.audit import chain
from app.core.ids import new_id
from app.core.scopes import is_target_like
from app.core.security import now_iso
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_analyst, require_totp_stepup, warrant_gate
from app.modules.vuln import service

router = APIRouter(prefix="/api/v1/vuln", tags=["vuln"])


class ScanBody(BaseModel):
    target: str = Field(min_length=4, max_length=253)
    warrant_id: str
    authorization_confirmed: bool

    @field_validator("target")
    @classmethod
    def t_ok(cls, v):
        if not is_target_like(v):
            raise ValueError("target must be IP or domain")
        return v.lower()

    @field_validator("authorization_confirmed")
    @classmethod
    def attested(cls, v):
        if v is not True:
            raise ValueError("written authorization must be confirmed")
        return v


@router.post("/scan")
async def scan(request: Request, body: ScanBody, bg: BackgroundTasks,
               p: Principal = Depends(require_analyst)):
    w = warrant_gate(request, p, body.warrant_id, "vuln_scan", body.target)
    require_totp_stepup(request, p)
    sid = new_id()
    with sql.get_db() as c:
        c.execute("INSERT INTO vuln_scans (id, warrant_id, target, created_by, bound_session, created_at)"
                  " VALUES (?,?,?,?,?,?)", (sid, w["id"], body.target, p.user_id, p.sid, now_iso()))
    chain.append(p.user_id, "vuln.scan.create", sid, {"target": body.target})
    bg.add_task(service.run_scan, sid, p.user_id)
    return {"scan_id": sid, "status": "PENDING"}


@router.get("/scans")
async def list_scans(p: Principal = Depends(require_analyst)):
    return {"scans": sql.all_("SELECT * FROM vuln_scans ORDER BY created_at DESC LIMIT 100")}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, p: Principal = Depends(require_analyst)):
    row = sql.one("SELECT * FROM vuln_scans WHERE id=?", scan_id)
    findings = sql.all_("SELECT * FROM findings WHERE source='vuln' AND source_id=?"
                        " ORDER BY cvss DESC", scan_id)
    return {"scan": row, "findings": findings}


@router.get("/scans/{scan_id}/report")
async def report_link(scan_id: str, p: Principal = Depends(require_analyst)):
    from app.core.errors import CWBError
    from app.reports.signing import signed_url
    row = sql.one("SELECT report_path FROM vuln_scans WHERE id=?", scan_id)
    if not row or not row["report_path"]:
        raise CWBError("Report not generated yet", status=409)
    return {"download": signed_url(row["report_path"], ttl_s=300)}
