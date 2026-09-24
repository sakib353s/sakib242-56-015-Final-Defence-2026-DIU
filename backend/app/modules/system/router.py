"""System console routes — any authenticated operator can read its own sensor."""

from fastapi import APIRouter, Depends

from app.gateway.deps import Principal, require_any
from app.modules.system import service

router = APIRouter(prefix="/api/v1/system", tags=["system"])


@router.get("/telemetry")
async def telemetry(p: Principal = Depends(require_any)):
    return service.telemetry()


@router.get("/pulse")
async def pulse(limit: int = 30, p: Principal = Depends(require_any)):
    return {"events": service.pulse(min(max(limit, 1), 100))}


@router.get("/threatfeed")
async def threatfeed(p: Principal = Depends(require_any)):
    return await service.threat_feed()
