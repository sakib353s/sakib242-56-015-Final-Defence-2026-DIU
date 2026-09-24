"""Hardware Monitor API."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.core.errors import NotFound
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_analyst, require_totp_stepup
from app.modules.hwmon import service

router = APIRouter(prefix="/api/v1/hardware", tags=["hwmon"])


class AssetBody(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    kind: str = Field(pattern=r"^(server|workstation|network|iot)$")
    host: str = Field(min_length=3, max_length=253)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = Field(default="", max_length=64)
    ssh_password: str = Field(default="", max_length=128)
    snmp_community: str = Field(default="", max_length=64)
    ownership_attested: bool


@router.get("/assets")
async def list_assets(p: Principal = Depends(require_analyst)):
    return {"assets": sql.all_("SELECT id, name, kind, host, ssh_port, ssh_user, disabled,"
                               " last_check_at, created_at FROM hw_assets ORDER BY created_at DESC")}


@router.post("/assets")
async def add_asset(request: Request, body: AssetBody, p: Principal = Depends(require_analyst)):
    return service.create_asset(body.name, body.kind, body.host.lower(), body.ssh_port,
                                body.ssh_user, body.ssh_password, body.snmp_community,
                                body.ownership_attested, p.user_id)


@router.get("/assets/{asset_id}")
async def get_asset(asset_id: str, p: Principal = Depends(require_analyst)):
    a = sql.one("SELECT id, name, kind, host, ssh_port, ssh_user, disabled, last_check_json,"
                " last_check_at, created_at FROM hw_assets WHERE id=?", asset_id)
    if not a:
        raise NotFound("Asset not found")
    return a


@router.post("/assets/{asset_id}/check")
async def check(request: Request, asset_id: str, p: Principal = Depends(require_analyst)):
    require_totp_stepup(request, p)
    return await service.check_asset(asset_id, p.user_id)


@router.get("/assets/{asset_id}/diag.pdf")
async def diag(request: Request, asset_id: str, p: Principal = Depends(require_analyst)):
    require_totp_stepup(request, p)
    path = service.generate_diag_pdf(asset_id, p.user_id)
    from app.reports.signing import signed_url
    return {"download": signed_url(path, ttl_s=300)}
