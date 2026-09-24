"""Finding Engine API — lifecycle transitions + real retest.

Mutating transitions enforce RBAC per-state; remediated requires SUPER_ADMIN.
Retest dispatches through the registered adapters and produces an honest outcome
without trusting exit codes alone."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pydantic import BaseModel, Field

from app.audit import chain
from app.core.errors import CWBError
from app.db import sqlite as sql
from app.gateway.deps import Principal, ROLE_ORDER, require_analyst, require_totp_stepup
from app.modules.findings import engine

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


class TransitionBody(BaseModel):
    to_state: str = Field(min_length=3, max_length=40)
    reason: str | None = Field(default=None, max_length=500)
    evidence_ref: str | None = Field(default=None, max_length=200)


@router.get("/queue")
async def queue_view(min_severity: str = "low", limit: int = 200,
                     p: Principal = Depends(require_analyst)):
    return {"queue": engine.queue(min_severity=min_severity, limit=limit)}


@router.get("/{fid}")
async def get_one(fid: str, p: Principal = Depends(require_analyst)):
    f = engine.get_finding(fid)
    if not f:
        raise CWBError("Finding not found", status=404)
    hist = engine.history(fid)
    a = sql.one("SELECT warrant_id FROM assessments WHERE id=?", f["assessment_id"])
    return {"finding": f, "history": hist, "warrant_id": (a or {}).get("warrant_id")}


@router.post("/{fid}/transition")
async def do_transition(request: Request, fid: str, body: TransitionBody,
                        p: Principal = Depends(require_analyst)):
    rank = ROLE_ORDER[p.role]
    a = sql.one(
        "SELECT ass.warrant_id FROM assessment_findings af JOIN assessments ass"
        " ON af.assessment_id=ass.id WHERE af.id=?", fid)
    result = engine.transition(fid, body.to_state, p.user_id, rank,
                               reason=body.reason, evidence_ref=body.evidence_ref,
                               warrant_id=(a or {}).get("warrant_id"))
    f = engine.get_finding(fid)
    return {**result, "lifecycle": f["lifecycle"] if f else body.to_state}


@router.post("/{fid}/retest")
async def start_retest(request: Request, fid: str, bg: BackgroundTasks,
                       p: Principal = Depends(require_analyst)):
    f = engine.get_finding(fid)
    if not f:
        raise CWBError("Finding not found", status=404)
    require_totp_stepup(request, p)
    bg.add_task(_run_retest, fid, p.user_id)
    chain.append(p.user_id, "finding.retest.dispatch", fid, {"lifecycle": f["lifecycle"]})
    return {"ok": True, "status": "DISPATCHED", "finding_id": fid}


async def _run_retest(fid: str, actor: str) -> None:
    try:
        await engine.retest(fid, actor)
    except Exception as e:
        chain.safe_append(actor, "finding.retest.worker_crash", fid, {"error": str(e)[:300]})