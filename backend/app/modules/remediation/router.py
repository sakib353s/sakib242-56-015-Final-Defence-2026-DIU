"""Auto-Remediation API — warrant + consent dual-gated. FR-R01…R04."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, field_validator

from app.core.errors import NotFound
from app.core.scopes import is_target_like
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_super, require_totp_stepup, warrant_gate
from app.modules.remediation import saga

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])


class JobBody(BaseModel):
    finding_id: str
    host: str
    warrant_id: str
    asset_id: str | None = None
    authorization_confirmed: bool

    @field_validator("host")
    @classmethod
    def h_ok(cls, v):
        if not is_target_like(v):
            raise ValueError("host must be IP or domain")
        return v.lower()

    @field_validator("authorization_confirmed")
    @classmethod
    def attested(cls, v):
        if v is not True:
            raise ValueError("asset ownership + written authorization must be confirmed")
        return v


@router.get("/findings")
async def list_findings(limit: int = 200, p: Principal = Depends(require_super)):
    """Actionable findings the operator can raise a remediation job against —
    the UI picks from this list instead of typing raw finding IDs."""
    return {"findings": sql.all_(
        "SELECT f.id, f.source, f.source_id, f.host, f.port, f.service, f.cve, f.severity,"
        " f.cvss, f.description, f.created_at, "
        " (SELECT COUNT(*) FROM remediation_jobs rj WHERE rj.finding_id=f.id) AS job_count"
        " FROM findings f ORDER BY f.created_at DESC LIMIT ?", min(limit, 500))}


@router.post("/jobs")
async def create_job(request: Request, body: JobBody, p: Principal = Depends(require_super)):
    w = warrant_gate(request, p, body.warrant_id, "remediation", body.host)
    require_totp_stepup(request, p)
    return saga.generate_job(body.finding_id, body.host, w["id"], p.user_id, body.asset_id)


@router.get("/jobs/{job_id}/diff")
async def diff(job_id: str, p: Principal = Depends(require_super)):
    if not sql.one("SELECT id FROM remediation_jobs WHERE id=?", job_id):
        raise NotFound("Job not found")
    return saga.get_diff(job_id)


@router.get("/jobs")
async def list_jobs(p: Principal = Depends(require_super)):
    return {"jobs": sql.all_("SELECT id, finding_id, host, state, created_at, updated_at"
                             " FROM remediation_jobs ORDER BY created_at DESC LIMIT 100")}


@router.post("/jobs/{job_id}/consent")
async def consent(request: Request, job_id: str, p: Principal = Depends(require_super)):
    require_totp_stepup(request, p)  # SUPER_ADMIN + fresh TOTP — the P-07 challenge
    return saga.record_consent(job_id, p.user_id, totp_ok=True)


@router.post("/jobs/{job_id}/apply")
async def apply(request: Request, job_id: str, p: Principal = Depends(require_super)):
    require_totp_stepup(request, p)
    return await saga.apply_job(job_id, p.user_id)


@router.post("/jobs/{job_id}/rollback")
async def rollback(request: Request, job_id: str, p: Principal = Depends(require_super)):
    require_totp_stepup(request, p)
    return await saga.rollback_job(job_id, p.user_id)
