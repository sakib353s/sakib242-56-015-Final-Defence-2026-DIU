"""Mobile registry (P-04) — push-token enrollment for CYBERWATCH-BD Android.

POST /api/v1/mobile/register {push_token} stores the Expo/FCM token in the
settings table under `mobile_tokens:<user_id>` (most recent first, capped) and
writes a chained audit entry containing only a SHA-256 fingerprint of the token.
"""
import hashlib
import json

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.audit import chain
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_any

router = APIRouter(prefix="/api/v1/mobile", tags=["mobile"])

MAX_TOKENS = 10


class PushRegister(BaseModel):
    push_token: str = Field(min_length=16, max_length=256)


@router.post("/register")
async def register_push(body: PushRegister, p: Principal = Depends(require_any)):
    key = f"mobile_tokens:{p.user_id}"
    with sql.write_db() as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        tokens = json.loads(row["value"]) if row else []
        already = body.push_token in tokens
        tokens = ([body.push_token] + [t for t in tokens if t != body.push_token])[:MAX_TOKENS]
        c.execute("INSERT INTO settings (key, value, updated_at) VALUES (?,?,datetime('now'))"
                  " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                  (key, json.dumps(tokens)))
    ref = chain.append(p.user_id, "mobile.push.register", key,
                       {"token_fp": hashlib.sha256(body.push_token.encode()).hexdigest()[:16],
                        "deduped": already, "count": len(tokens)})
    return {"ok": True, "registered": not already, "count": len(tokens), "audit_ref": ref}
