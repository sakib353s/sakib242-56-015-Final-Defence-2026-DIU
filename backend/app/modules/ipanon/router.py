"""IP Anonymizer API — start/stop are warrant-bound, session-scoped."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.core.ids import new_id
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_analyst, require_totp_stepup
from app.modules.ipanon import service

router = APIRouter(prefix="/api/v1/ip", tags=["ipanon"])


class StartBody(BaseModel):
    warrant_id: str
    pentest_session: str | None = None


@router.post("/start")
async def start(request: Request, body: StartBody, p: Principal = Depends(require_analyst)):
    require_totp_stepup(request, p)
    return await service.start(body.warrant_id, p.sid, p.user_id, body.pentest_session)


@router.post("/stop")
async def stop(request: Request, circuit_id: str, p: Principal = Depends(require_analyst)):
    return await service.stop(circuit_id, p.user_id)


@router.get("/status")
async def status(p: Principal = Depends(require_analyst)):
    rows = sql.all_("SELECT id, status, masked_ip, started_at, last_heartbeat FROM circuits"
                    " ORDER BY started_at DESC LIMIT 20")
    return {"circuits": rows}
