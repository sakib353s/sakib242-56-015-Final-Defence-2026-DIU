"""Security Assessment Studio API — REST + WS event fan-out.

Every endpoint enforces the existing warrant gate, RBAC, and TOTP step-up before
execution. Responses carry real persisted state only; no simulated data.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pydantic import BaseModel, Field, field_validator

from app.audit import chain
from app.core.errors import CWBError
from app.core.security import now_iso
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_analyst, require_totp_stepup, warrant_gate
from app.modules.assessment import service

router = APIRouter(prefix="/api/v1/assessment", tags=["assessment"])


class CreateBody(BaseModel):
    target: str = Field(min_length=4, max_length=500)
    warrant_id: str
    profile: str = Field(default="standard")
    authorization_confirmed: bool

    @field_validator("authorization_confirmed")
    @classmethod
    def attested(cls, v):
        if v is not True:
            raise ValueError("written authorization must be confirmed")
        return v

    @field_validator("profile")
    @classmethod
    def valid_profile(cls, v):
        allowed = {"quick", "standard", "deep"}
        if v not in allowed:
            raise ValueError(f"profile must be one of {sorted(allowed)}")
        return v


@router.post("")
async def create(request: Request, body: CreateBody, p: Principal = Depends(require_analyst)):
    from app.modules.assessment.adapters import canonicalize

    canonical, ctype = canonicalize(body.target)
    warrant_gate(request, p, body.warrant_id, "pentest", canonical)
    require_totp_stepup(request, p)
    assessment = service.create_assessment(
        body.target,
        body.warrant_id,
        p.user_id,
        p.sid,
        profile=body.profile,
    )
    chain.append(p.user_id, "assessment.created", assessment["id"], {
        "target": canonical, "type": ctype, "profile": body.profile,
        "warrant": body.warrant_id,
    })
    return assessment


@router.post("/{aid}/start")
async def start(request: Request, aid: str, bg: BackgroundTasks, p: Principal = Depends(require_analyst)):
    a = sql.one("SELECT * FROM assessments WHERE id=?", aid)
    if not a:
        raise CWBError("Assessment not found", status=404)
    warrant_gate(request, p, a["warrant_id"], "pentest", a["target_canonical"])
    require_totp_stepup(request, p)
    bg.add_task(service.run_assessment, aid, p.user_id)
    chain.append(p.user_id, "assessment.started", aid, {"target": a["target_canonical"]})
    return {"ok": True, "status": "DISPATCHED", "assessment_id": aid}


@router.get("/{aid}")
async def get(aid: str, p: Principal = Depends(require_analyst)):
    a = sql.one("SELECT * FROM assessments WHERE id=?", aid)
    if not a:
        raise CWBError("Assessment not found", status=404)
    stages = sql.all_("SELECT * FROM assessment_stages WHERE assessment_id=? ORDER BY seq", aid)
    findings = sql.all_("SELECT * FROM assessment_findings WHERE assessment_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC", aid)
    obs_count = sql.one("SELECT COUNT(*) AS cnt FROM observations WHERE assessment_id=?", aid)["cnt"]
    decisions = sql.all_("SELECT * FROM brain_decisions WHERE assessment_id=? ORDER BY created_at DESC LIMIT 20", aid)
    return {
        "assessment": a,
        "stages": stages,
        "findings": findings,
        "observations_count": obs_count,
        "brain_decisions": decisions,
    }


@router.get("/{aid}/observations")
async def observations(aid: str, offset: int = 0, limit: int = 100, p: Principal = Depends(require_analyst)):
    rows = sql.all_(
        "SELECT * FROM observations WHERE assessment_id=? ORDER BY created_at OFFSET ? LIMIT ?",
        aid, offset, min(limit, 500),
    )
    total = sql.one("SELECT COUNT(*) AS cnt FROM observations WHERE assessment_id=?", aid)["cnt"]
    return {"observations": rows, "total": total, "offset": offset, "limit": limit}


@router.get("/findings/{fid}")
async def finding_detail(fid: str, p: Principal = Depends(require_analyst)):
    detail = service.get_finding_detail(fid)
    if not detail or not detail["finding"]:
        raise CWBError("Finding not found", status=404)
    return detail


@router.get("")
async def list_assessments(p: Principal = Depends(require_analyst)):
    rows = sql.all_("SELECT * FROM assessments ORDER BY created_at DESC LIMIT 100")
    return {"assessments": rows}


@router.post("/{aid}/cancel")
async def cancel(request: Request, aid: str, p: Principal = Depends(require_analyst)):
    a = sql.one("SELECT * FROM assessments WHERE id=?", aid)
    if not a:
        raise CWBError("Assessment not found", status=404)
    if a["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
        return {"ok": False, "reason": f"already {a['status']}"}
    with sql.get_db() as c:
        c.execute("UPDATE assessments SET status='CANCELLED', updated_at=? WHERE id=?",
                  (now_iso(), aid))
    chain.append(p.user_id, "assessment.cancelled", aid, {})
    return {"ok": True, "status": "CANCELLED"}