"""Injected gateway dependencies: authentication, RBAC, warrant & consent gates.

Gates are server-side and fail-closed. TOTP step-up codes are single-use
(replay cache) and must be within the ±1 × 30 s drift window.
"""
from __future__ import annotations

import time

import jwt as pyjwt
from fastapi import Request

from app.audit import chain
from app.core.config import get_settings
from app.core.errors import Forbidden, StepUpRequired, Unauthorized, WarrantMissing, ScopeDrift
from app.core.scopes import matches
from app.core.security import decode_access, totp_valid
from app.db.repositories import Ledger, Users

S = get_settings()
ROLE_ORDER = {"READ_ONLY": 0, "ANALYST": 1, "SUPER_ADMIN": 2}
_used_totp: dict[str, float] = {}  # code-key -> expiry ts


class Principal:
    def __init__(self, claims: dict):
        self.user_id: str = claims["sub"]
        self.role: str = claims["role"]
        self.sid: str = claims["sid"]
        self.totp_ok: bool = bool(claims.get("totp"))

    @property
    def username(self) -> str:
        u = Users.get(self.user_id)
        return u["username"] if u else self.user_id


def _sweep_used():
    now = time.time()
    for k, exp in list(_used_totp.items()):
        if exp < now:
            _used_totp.pop(k, None)


def authenticate(request: Request) -> Principal:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise Unauthorized("Bearer access token required")
    try:
        claims = decode_access(header[7:])
    except pyjwt.ExpiredSignatureError:
        raise Unauthorized("Access token expired")
    except pyjwt.InvalidTokenError:
        raise Unauthorized("Invalid access token")
    return Principal(claims)


def require_role(minimum: str):
    """Factory: dependency enforcing RBAC trie order READ_ONLY < ANALYST < SUPER_ADMIN."""

    def dep(request: Request) -> Principal:
        p = authenticate(request)
        if ROLE_ORDER.get(p.role, -1) < ROLE_ORDER[minimum]:
            chain.safe_append(p.user_id, "gate.rbac_denied", request.url.path,
                              {"have": p.role, "need": minimum})
            raise Forbidden(f"Role {p.role} insufficient — {minimum} required")
        request.state.principal = p
        return p

    return dep


require_any = require_role("READ_ONLY")
require_analyst = require_role("ANALYST")
require_super = require_role("SUPER_ADMIN")


def require_totp_stepup(request: Request, p: Principal) -> None:
    """Fresh-TOTP gate for mutating offensive actions and privileged consent.
    Production always requires and verifies the code. In lab mode
    (CWB_TOTP_ENFORCE=auto/off) the gate is skipped and audited; any code a lab
    client still sends is ignored."""
    if not S.totp_stepup_required:
        chain.safe_append(p.user_id, "gate.totp_stepup_lab_skip", request.url.path)
        return
    code = request.headers.get("x-totp", "").strip()
    if not code or len(code) not in (6, 8):
        raise StepUpRequired("X-TOTP header with current code required")
    user = Users.get(p.user_id)
    if not user or not user["totp_enrolled"]:
        chain.safe_append(p.user_id, "gate.totp_not_enrolled", request.url.path)
        raise StepUpRequired("Account has no TOTP enrollment — provision it first")
    from app.core.security import dec_field

    if not totp_valid(dec_field(user["totp_secret_enc"]), code):
        chain.safe_append(p.user_id, "gate.totp_failed", request.url.path)
        raise StepUpRequired("TOTP verification failed")
    _sweep_used()
    # Replay is defined per (user, code, operation): the same code cannot re-fire the
    # SAME mutating operation (double-apply/double-consent), and each distinct
    # operation still requires a live, verified code.
    key = f"{p.user_id}:{code}:{request.method}:{request.url.path}"
    if key in _used_totp:
        chain.safe_append(p.user_id, "gate.totp_replay", request.url.path)
        raise StepUpRequired("TOTP code already used (replay blocked)")
    _used_totp[key] = time.time() + 90


def warrant_window_active(w: dict) -> bool:
    """Chronological (not lexicographic) validity-window check, tz-safe."""
    from datetime import datetime, timezone

    from app.core.security import to_utc_iso

    now = datetime.now(timezone.utc)
    try:
        return (datetime.fromisoformat(to_utc_iso(w["valid_from"])) <= now
                <= datetime.fromisoformat(to_utc_iso(w["valid_until"])))
    except (ValueError, KeyError, TypeError):
        return False


def warrant_gate(request: Request, p: Principal, warrant_id: str, kind: str, target: str):
    """Server-side written-authorization gate. Missing/expired/revoked/out-of-scope
    => 403 + audit row. Returns the warrant row on success."""
    w = Ledger.get(warrant_id) if warrant_id else None
    if not w:
        chain.safe_append(p.user_id, "gate.warrant_missing", target, {"kind": kind})
        raise WarrantMissing(f"No warrant record {warrant_id or '(blank)'} in auth_ledger")
    if w["revoked_at"]:
        chain.safe_append(p.user_id, "gate.warrant_revoked", target, {"warrant": w["id"]})
        raise WarrantMissing("Warrant has been revoked")
    if not warrant_window_active(w):
        chain.safe_append(p.user_id, "gate.warrant_expired", target, {"warrant": w["id"]})
        raise WarrantMissing("Warrant outside validity window")
    if w["kind"] != kind:
        chain.safe_append(p.user_id, "gate.warrant_kind_mismatch", target,
                          {"warrant": w["id"], "have": w["kind"], "need": kind})
        raise WarrantMissing(f"Warrant kind {w['kind']} does not authorize {kind}")
    import json

    scope = json.loads(w["scope_json"])
    if not matches(scope, target):
        chain.safe_append(p.user_id, "gate.scope_denied", target, {"warrant": w["id"], "scope": scope})
        raise ScopeDrift(f"Target '{target}' is outside warrant scope — operation refused")
    return w
