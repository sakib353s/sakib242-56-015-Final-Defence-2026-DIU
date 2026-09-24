"""Victim Support API."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.core.errors import NotFound
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_analyst, require_totp_stepup
from app.modules.victim import service

router = APIRouter(prefix="/api/v1/victim", tags=["victim"])


class CaseBody(BaseModel):
    case_type: str
    complainant: dict = Field(min_length=1)
    narrative: str = Field(min_length=20, max_length=4000)
    consent_attested: bool
    consent_doc_id: str | None = None


@router.post("/cases")
async def create(request: Request, body: CaseBody, p: Principal = Depends(require_analyst)):
    return service.create_case(body.case_type, body.complainant, body.narrative,
                               body.consent_attested, p.user_id, body.consent_doc_id)


@router.get("/cases")
async def list_cases(p: Principal = Depends(require_analyst)):
    return {"cases": sql.all_("SELECT id, case_type, status, created_at FROM victim_cases"
                              " ORDER BY created_at DESC LIMIT 100")}


@router.get("/cases/{case_id}")
async def get_case(case_id: str, p: Principal = Depends(require_analyst)):
    return service.get_case(case_id, p.user_id)


class EventBody(BaseModel):
    action: str = Field(min_length=3, max_length=120)
    evidence_ref: str | None = None


@router.post("/cases/{case_id}/timeline")
async def add_event(case_id: str, body: EventBody, p: Principal = Depends(require_analyst)):
    return service.append_event(case_id, p.user_id, body.action, body.evidence_ref)


@router.get("/cases/{case_id}/timeline")
async def timeline(case_id: str, p: Principal = Depends(require_analyst)):
    if not sql.one("SELECT id FROM victim_cases WHERE id=?", case_id):
        raise NotFound("Case not found")
    return service.verify_timeline(case_id)


@router.post("/cases/{case_id}/complaints")
async def complaints(request: Request, case_id: str, p: Principal = Depends(require_analyst)):
    require_totp_stepup(request, p)
    return service.generate_complaints(case_id, p.user_id)


@router.get("/cases/{case_id}/complaints")
async def complaint_links(case_id: str, p: Principal = Depends(require_analyst)):
    """Read-only signed download links for the case's latest BTRC/Police draft PDFs
    (mobile P-04 case viewer). No TOTP: nothing is generated or mutated here."""
    if not sql.one("SELECT id FROM victim_cases WHERE id=?", case_id):
        raise NotFound("Case not found")
    rows = sql.all_("SELECT id, kind, name, created_at FROM report_files"
                    " WHERE ref_id=? AND kind IN ('complaint_btrc','complaint_cyber_police')"
                    " ORDER BY created_at DESC", case_id)
    seen: dict[str, dict] = {}
    for r in rows:
        seen.setdefault(r["kind"], r)
    from app.reports.signing import url_for_id
    drafts = [{"agency": k.replace("complaint_", ""), "report_id": r["id"], "name": r["name"],
               "created_at": r["created_at"], "download": url_for_id(r["id"], ttl_s=300)}
              for k, r in sorted(seen.items())]
    return {"case_id": case_id, "drafts": drafts,
            "note": "DRAFT FOR SUBMISSION — human review required before filing (P-00)"}


@router.get("/osint/{case_id}")
async def attacker_osint(request: Request, case_id: str, subject: str,
                         p: Principal = Depends(require_analyst)):
    """FR-V02: PUBLIC sources only — delegates to OSINT module with case linkage."""
    from app.modules.osint import service as osint_service
    if "@" in subject:
        res = await osint_service.email_breaches(subject, p.user_id)
    else:
        res = await osint_service.domain_recon(subject, p.user_id)
    service.append_event(case_id, p.user_id, "osint.public_query",
                         {"subject_hash": osint_service.subject_hash("victim", subject),
                          "case_link": case_id})
    return res
