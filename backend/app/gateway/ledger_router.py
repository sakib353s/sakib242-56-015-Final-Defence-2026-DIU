"""Authorization ledger — the written-authorization gate's source of truth.
SUPER_ADMIN only. Every issue/revoke is chained-audited."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator

from app.audit import chain
from app.core.errors import CWBError, NotFound
from app.core.scopes import is_target_like
from app.db import sqlite as sql
from app.db.repositories import Ledger
from app.gateway.deps import Principal, require_super, require_analyst as require_analyst_role

router = APIRouter(prefix="/api/v1/admin/ledger", tags=["ledger"])

KINDS = {"pentest", "vuln_scan", "remediation", "ipanon"}


class WarrantBody(BaseModel):
    kind: str
    scope: list[str] = Field(min_length=1, max_length=32)
    purpose: str = Field(min_length=12, max_length=500)
    warrant_ref: str = Field(min_length=6, max_length=120)  # document number of written authorization
    subject_name: str = Field(default="", max_length=120)
    valid_from: str
    valid_until: str

    @field_validator("kind")
    @classmethod
    def kind_ok(cls, v):
        if v not in KINDS:
            raise ValueError(f"kind must be one of {sorted(KINDS)}")
        return v

    @field_validator("scope")
    @classmethod
    def scope_ok(cls, v):
        for t in v:
            if not is_target_like(t):
                raise ValueError(f"scope entry '{t}' is not an IP/CIDR/domain")
        return v

    @field_validator("valid_from", "valid_until")
    @classmethod
    def iso_ok(cls, v):
        datetime.fromisoformat(v)
        return v


@router.get("/available")
async def available(p: Principal = Depends(require_analyst_role)):
    """Operational subset for warrant pickers (ANALYST+): active pentest/vuln_scan/
    ipanon warrants only — remediation stays SUPER_ADMIN-managed (its picker reads
    the full ledger). Never exposes owner."""
    from app.gateway.deps import warrant_window_active

    rows = [w for w in Ledger.active()
            if w["kind"] in ("pentest", "vuln_scan", "ipanon") and warrant_window_active(w)]
    return {"warrants": [{"id": w["id"], "kind": w["kind"], "scope": __import__("json").loads(w["scope_json"]),
                          "purpose": w["purpose"], "subject_name": w["subject_name"],
                          "warrant_ref": w["warrant_ref"], "valid_until": w["valid_until"]}
                         for w in rows]}


@router.get("")
async def list_ledger(p: Principal = Depends(require_super)):
    return {"warrants": Ledger.all_(), "as_of": datetime.now(timezone.utc).isoformat()}


@router.get("/active")
async def active(p: Principal = Depends(require_super)):
    return {"warrants": Ledger.active()}


@router.post("")
async def create_warrant(request: Request, body: WarrantBody, p: Principal = Depends(require_super)):
    if body.valid_from >= body.valid_until:
        raise CWBError("valid_from must precede valid_until", status=422)
    until = datetime.fromisoformat(body.valid_until)
    if until <= datetime.now(timezone.utc):
        raise CWBError("warrant expiry is already in the past", status=422)
    if until > datetime.now(timezone.utc) + timedelta(days=90):
        raise CWBError("warrants are capped at 90 days — re-attest after expiry", status=422)
    w = Ledger.create(body.kind, body.scope, body.purpose, body.warrant_ref,
                      p.user_id, body.subject_name, body.valid_from, body.valid_until)
    chain.append(p.user_id, "ledger.warrant_issue", w["id"],
                 {"kind": w["kind"], "scope": body.scope, "ref": body.warrant_ref,
                  "until": body.valid_until})
    return w


@router.post("/{warrant_id}/revoke")
async def revoke_warrant(request: Request, warrant_id: str, p: Principal = Depends(require_super)):
    if not Ledger.revoke(warrant_id):
        raise NotFound("Active warrant not found")
    chain.append(p.user_id, "ledger.warrant_revoke", warrant_id)
    # live offensive sessions bound to this warrant are terminated by their workers
    # via the warrant-expiry watchdog (pentest/vuln/ipanon poll valid_until).
    return {"ok": True, "revoked_at": sql.scalar("SELECT revoked_at FROM auth_ledger WHERE id=?", warrant_id)}
