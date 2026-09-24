"""Tools console API — simple: pick tool, enter target, press RUN, get result.

Passive tools need ANALYST. Active tools additionally need a live vuln_scan
warrant whose scope covers the target (auto-matched server-side; never trust
the client's claim) + step-up gate (lab-skipped) + audit row. Fail-closed.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, field_validator

from app.audit import chain
from app.core.errors import RefusedOutOfWork
from app.gateway.deps import Principal, require_analyst, require_totp_stepup, warrant_gate
from app.modules.tools import service

router = APIRouter(prefix="/api/v1/tools", tags=["tools"])


@router.get("")
async def list_tools(p: Principal = Depends(require_analyst)):
    out = []
    for tid, spec in service.TOOLS.items():
        info = service.installed(tid)
        out.append({"id": tid, "label": spec["label"], "purpose": spec["purpose"],
                    "input": spec["input"], "active": spec["active"], **info})
    return {"tools": out}


@router.get("/status")
async def tool_status(p: Principal = Depends(require_analyst)):
    ids = list(service.TOOLS)
    probed = dict(zip(ids, await asyncio.gather(*(service._ver(t) for t in ids))))
    return {"versions": {t: (probed[t] if service.installed(t).get("installed") else "missing")
                         for t in ids}}


class RunBody(BaseModel):
    tool: str
    target: str
    authorization_confirmed: bool = False

    @field_validator("tool")
    @classmethod
    def known(cls, v):
        if v not in service.TOOLS:
            raise ValueError("unknown tool")
        return v


@router.post("/run")
async def run(request: Request, body: RunBody, p: Principal = Depends(require_analyst)):
    spec = service.TOOLS[body.tool]
    target = body.target.strip().lower()
    if spec["active"]:
        if body.authorization_confirmed is not True:
            raise RefusedOutOfWork("written authorization must be confirmed for active tools")
        scope_target = service.host_for_scope(body.tool, target)
        w = service.find_warrant(p.user_id, scope_target)
        if w is None:
            warrant_gate(request, p, "", "vuln_scan", scope_target)  # audits + raises
        warrant_gate(request, p, w["id"], "vuln_scan", scope_target)
        require_totp_stepup(request, p)
    if not service.installed(body.tool).get("installed"):
        raise RefusedOutOfWork(f"{body.tool} binary not vendored — run vendor/install_tools.py")
    result = await service.execute(body.tool, target)
    chain.append(p.user_id, "tools.run", body.tool,
                 {"target": target, "count": result["count"], "exit": result["exit"]})
    return result
