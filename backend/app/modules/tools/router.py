"""Tools console API — simple: pick tool, enter target, press RUN, get result.

Passive tools need ANALYST. Active tools additionally need a live vuln_scan
warrant whose scope covers the target (auto-matched server-side; never trust
the client's claim) + step-up gate (lab-skipped) + audit row. Fail-closed.
"""
from __future__ import annotations

import asyncio

import json

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, field_validator
from starlette.responses import StreamingResponse

from app.audit import chain
from app.core.config import get_settings
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


def _gate(request: Request, p: Principal, body: RunBody) -> str:
    """All pre-run checks; returns the normalized target. Fail-closed."""
    spec = service.TOOLS[body.tool]
    target = body.target.strip().lower()
    if spec["active"]:
        if body.authorization_confirmed is not True:
            raise RefusedOutOfWork("written authorization must be confirmed for active tools")
        scope_target = service.host_for_scope(body.tool, target)
        if get_settings().warrant_required:
            w = service.find_warrant(p.user_id, scope_target)
            if w is None:
                warrant_gate(request, p, "", "vuln_scan", scope_target)  # audits + raises
            warrant_gate(request, p, w["id"], "vuln_scan", scope_target)
        else:
            # lab-only: CWB_WARRANT_ENFORCE=auto/off. The operator's checkbox above
            # is the authorization claim; production can never reach this branch.
            chain.safe_append(p.user_id, "gate.warrant_lab_skip",
                              f"{body.tool}:{scope_target}")
        require_totp_stepup(request, p)
    if not service.installed(body.tool).get("installed"):
        raise RefusedOutOfWork(f"{body.tool} binary not vendored — run vendor/install_tools.py")
    spec["validate"](target)
    return target


@router.post("/run")
async def run(request: Request, body: RunBody, p: Principal = Depends(require_analyst)):
    target = _gate(request, p, body)
    result = await service.execute(body.tool, target)
    chain.append(p.user_id, "tools.run", body.tool,
                 {"target": target, "count": result["count"], "exit": result["exit"]})
    return result


@router.post("/run/stream")
async def run_stream(request: Request, body: RunBody,
                     p: Principal = Depends(require_analyst)):
    """Same gate as /run, but every stdout/stderr line of the real process is
    forwarded as an SSE event while it runs; the final result event carries the
    identical payload /run returns. Silent stretches emit keepalive pings."""
    target = _gate(request, p, body)

    async def gen():
        audited = False
        try:
            async for ev in service.stream_execute(body.tool, target):
                if ev["k"] == "result":
                    chain.append(p.user_id, "tools.run", body.tool,
                                 {"target": target, "count": ev["v"]["count"],
                                  "exit": ev["v"]["exit"], "streamed": True})
                    audited = True
                yield f"data: {json.dumps(ev, default=str)}\n\n"
        finally:
            if not audited:
                chain.append(p.user_id, "tools.run", body.tool,
                             {"target": target, "count": 0, "exit": -2,
                              "streamed": True, "aborted": True})

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache, no-transform",
                                      "X-Accel-Buffering": "no"})
