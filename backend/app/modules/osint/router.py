"""OSINT API — role-based, public-data-only. Non-public targets refused (P-00 #2)."""

import re

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from app.audit import chain
from app.core.errors import RefusedOutOfWork
from app.gateway.deps import Principal, require_analyst
from app.modules.osint import service

router = APIRouter(prefix="/api/v1/osint", tags=["osint"])
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


@router.get("/email")
async def email(request: Request, e: str = Query(min_length=5, max_length=254),
                p: Principal = Depends(require_analyst)):
    if not EMAIL_RE.match(e):
        raise RefusedOutOfWork("Not a valid email — and only public breach data is in scope")
    return await service.email_breaches(e.lower(), p.user_id)


class PasswordIn(BaseModel):
    password: str


@router.post("/password")
async def password(request: Request, body: PasswordIn, p: Principal = Depends(require_analyst)):
    """FREE k-anonymity exposure check (Pwned Passwords). The secret never leaves
    the wire in the clear and only a 5-char SHA-1 prefix is transmitted."""
    if len(body.password) < 4:
        raise RefusedOutOfWork("password too short to query the corpus")
    return await service.password_exposure(body.password, p.user_id)


@router.get("/domain")
async def domain(request: Request, d: str = Query(min_length=4, max_length=253),
                 p: Principal = Depends(require_analyst)):
    d = d.lower()
    if not DOMAIN_RE.match(d) or "://" in d:
        raise RefusedOutOfWork("Provide a bare public domain (e.g. example.com)")
    return await service.domain_recon(d, p.user_id)


@router.get("/url")
async def url(request: Request, u: str = Query(min_length=8, max_length=2048),
              p: Principal = Depends(require_analyst)):
    return await service.url_report(u, p.user_id)


@router.get("/profile")
async def profile(request: Request, u: str = Query(min_length=3, max_length=64,
                                                   pattern=r"^[a-zA-Z0-9._@-]+$"),
                  p: Principal = Depends(require_analyst)):
    """Username exposure across public breach corpus only (no auth-bypass, no scraping)."""
    signals: dict = {}
    # email-format usernames get a real breach lookup via configured HIBP
    if EMAIL_RE.match(u):
        res = await service.email_breaches(u.lower(), p.user_id)
        signals = {"email_breached": res["breach_count"] > 0, "breach_count": res["breach_count"]}
    else:
        signals = {"note": "The public breach corpus is matched on email addresses, so a plain "
                           "username cannot be scored here."}
    score = service.exposure_score(signals)
    chain.safe_append(p.user_id, "osint.query.profile", u,
                      {"subject_hash": service.subject_hash("profile", u), "score": score})
    return {"username_hash": service.subject_hash("profile", u), "exposure_score": score,
            "signals": signals, "rubric": service.rubric_for(signals)}


@router.get("/leaks")
async def leaks(request: Request, p: Principal = Depends(require_analyst)):
    return await service.leak_scan(p.user_id)


class WatchBody(BaseModel):
    query: str


@router.post("/leaks/watch")
async def add_watch(body: WatchBody, p: Principal = Depends(require_analyst)):
    return service.create_watch(body.query[:64], p.user_id)
