"""Audit chain API — SUPER_ADMIN. Verify recomputes the full HMAC chain."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.audit import chain
from app.gateway.deps import Principal, require_super
import asyncio

router = APIRouter(prefix="/api/v1/admin/audit", tags=["audit"])


@router.get("")
async def list_audit(limit: int = 200, actor: str | None = None, action: str | None = None,
                     p: Principal = Depends(require_super)):
    return {"entries": chain.query(min(limit, 500), actor, action)}


class VerifyIn(BaseModel):
    trigger_source: str = "api"


@router.post("/verify")
async def verify(request: Request, body: VerifyIn, p: Principal = Depends(require_super)):
    result = await asyncio.to_thread(chain.verify_chain)
    chain.append(p.user_id, "audit.verify.run", "chain", {**result, **body.model_dump()})
    return result
