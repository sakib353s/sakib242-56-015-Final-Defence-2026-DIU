"""Auth lifecycle: login (argon2 + lockout), TOTP verify, rotating refresh, logout.
TOTP is step-up for SUPER_ADMIN/ANALYST; login itself consumes password + current TOTP."""

import uuid as uuidlib
from datetime import datetime, timedelta, timezone

import hashlib
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field, field_validator

from app.audit import chain
from app.core.config import get_settings
from app.core.errors import Forbidden, Unauthorized
from app.core.security import (dec_field, enc_field, make_access,
                               totp_provisioning_uri, totp_valid, verify_password)
from app.db.repositories import Sessions, Users
from app.db import sqlite as sql
from app.gateway.deps import Principal, authenticate
from app.gateway.middleware import limiter

S = get_settings()
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

ACCESS_COOKIE = "cwb_refresh"


def _wants_mobile_refresh(request: Request) -> bool:
    """Native mobile clients (P-04) cannot persist httpOnly cookies across app
    restarts, so they declare `X-Client: mobile` and receive the rotating refresh
    token in the JSON body to keep in the platform keystore (SecureStore)."""
    return request.headers.get("x-client", "").strip().lower() == "mobile"


class LoginBody(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9._-]+$")
    password: str = Field(min_length=8, max_length=128)
    totp: str | None = Field(default=None, pattern=r"^\d{6}$")

    @field_validator("username")
    @classmethod
    def lc(cls, v):
        return v.lower()


@router.post("/login")
@limiter.limit(S.rate_limit_login)
async def login(request: Request, response: Response, body: LoginBody):
    user = Users.by_username(body.username)
    audit_base = {"username": body.username}
    if not user:
        chain.safe_append("anonymous", "auth.login_unknown_user", body.username, audit_base)
        raise Unauthorized("Invalid credentials")
    locked_until = user["locked_until"]
    if locked_until and datetime.fromisoformat(locked_until) > datetime.now(timezone.utc):
        raise Forbidden("Account temporarily locked after failed attempts", audit_ref=chain.safe_append(
            user["id"], "auth.login_locked", user["id"], audit_base))
    if not verify_password(body.password, user["password_hash"]):
        until = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        Users.register_failed_login(user["id"], until)
        chain.safe_append(user["id"], "auth.login_failed", user["id"], audit_base)
        raise Unauthorized("Invalid credentials")

    totp_ok = False
    if user["totp_enrolled"]:
        # TOTP at login is OPTIONAL by design: unverified sessions carry
        # totp_ok=False and every offensive/privileged operation then demands
        # a fresh single-use X-TOTP step-up (gateway/deps.require_totp_stepup).
        if body.totp:
            if not totp_valid(dec_field(user["totp_secret_enc"]), body.totp):
                until = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
                Users.register_failed_login(user["id"], until)
                chain.safe_append(user["id"], "auth.login_totp_failed", user["id"], audit_base)
                raise Unauthorized("Invalid credentials")
            totp_ok = True
    Users.register_success(user["id"])

    refresh = str(uuidlib.uuid4())
    sess = Sessions.create(user["id"], hashlib.sha256(refresh.encode()).hexdigest(),
                           request.headers.get("user-agent", "")[:256],
                           request.client.host if request.client else "")
    access = make_access(user["id"], user["role"], sess["id"], totp_ok)
    response.set_cookie(
        ACCESS_COOKIE, refresh, httponly=True, secure=S.is_production,
        samesite="strict", max_age=S.refresh_token_ttl_days * 86400, path="/api/v1/auth",
    )
    ref = chain.append(user["id"], "auth.login", sess["id"], {"role": user["role"], "totp_ok": totp_ok})
    out = {"access_token": access, "role": user["role"], "user_id": user["id"],
           "session_id": sess["id"], "audit_ref": ref}
    if _wants_mobile_refresh(request):
        out["refresh_token"] = refresh
    return out


@router.post("/refresh")
@limiter.limit("10/minute")
async def refresh(request: Request, response: Response):
    refresh_tok = request.cookies.get(ACCESS_COOKIE)
    if not refresh_tok:
        raise Unauthorized("Refresh cookie absent")
    sess = Sessions.by_refresh_hash(hashlib.sha256(refresh_tok.encode()).hexdigest())
    if not sess:
        raise Unauthorized("Refresh token invalid or rotated away")
    user = Users.get(sess["user_id"])
    if not user:
        raise Unauthorized("Principal gone")
    new_refresh = str(uuidlib.uuid4())
    Sessions.rotate(sess["id"], hashlib.sha256(new_refresh.encode()).hexdigest())
    response.set_cookie(ACCESS_COOKIE, new_refresh, httponly=True, secure=S.is_production,
                        samesite="strict", max_age=S.refresh_token_ttl_days * 86400,
                        path="/api/v1/auth")
    chain.safe_append(user["id"], "auth.refresh", sess["id"])
    # totp claim stays FALSE across refresh: enrolment is not verification. The
    # claim is display-only; operation gates always re-check the X-TOTP header.
    out = {"access_token": make_access(user["id"], user["role"], sess["id"], False),
           "expires_in": S.access_token_ttl_min * 60}
    if _wants_mobile_refresh(request):
        out["refresh_token"] = new_refresh
    return out


@router.post("/logout")
async def logout(request: Request, response: Response, p: Principal = Depends(authenticate)):
    Sessions.revoke(p.sid)
    response.delete_cookie(ACCESS_COOKIE, path="/api/v1/auth")
    chain.safe_append(p.user_id, "auth.logout", p.sid)
    return {"ok": True}


class TOTPEnroll(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


@router.post("/totp/enroll")
async def totp_enroll(request: Request, p: Principal = Depends(authenticate),
                      body: TOTPEnroll | None = None):
    """Two-step enrollment. Step 1 issues a server-held pending secret (10 min TTL);
    step 2 verifies a code against THAT secret. The client can never enroll a secret
    it supplied itself — the pending value never leaves the server."""
    user = Users.get(p.user_id)
    if body is None:
        from pyotp import random_base32
        secret = random_base32()
        exp = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(timespec="seconds")
        with sql.get_db() as c:
            c.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?,?,datetime('now'))",
                      (f"pending_totp:{p.user_id}", f"{enc_field(secret)}|{exp}"))
        ref = chain.append(p.user_id, "auth.totp.enroll_start", p.user_id)
        return {"secret": secret, "uri": totp_provisioning_uri(secret, user["username"]),
                "expires_at": exp, "audit_ref": ref}
    row = sql.one("SELECT value FROM settings WHERE key=?", f"pending_totp:{p.user_id}")
    if not row:
        chain.safe_append(p.user_id, "auth.totp.enroll_no_pending", p.user_id)
        raise Unauthorized("No pending enrollment — request a secret first")
    blob, _, exp = row["value"].partition("|")
    if datetime.fromisoformat(exp) < datetime.now(timezone.utc):
        with sql.get_db() as c:
            c.execute("DELETE FROM settings WHERE key=?", (f"pending_totp:{p.user_id}",))
        raise Unauthorized("Pending enrollment expired — request a new secret")
    if not totp_valid(dec_field(blob), body.code):
        chain.safe_append(p.user_id, "auth.totp.enroll_failed", p.user_id)
        raise Unauthorized("TOTP code invalid for pending secret")
    Users.set_totp_secret(p.user_id, blob)  # store the SAME enc blob; no re-encrypt
    with sql.get_db() as c:
        c.execute("DELETE FROM settings WHERE key=?", (f"pending_totp:{p.user_id}",))
    chain.append(p.user_id, "auth.totp.enrolled", p.user_id)
    return {"ok": True, "enrolled": True}


@router.get("/me")
async def me(p: Principal = Depends(authenticate)):
    u = Users.get(p.user_id)
    return {"id": p.user_id, "username": u["username"], "role": p.role,
            "totp_ok": p.totp_ok, "session_id": p.sid}
