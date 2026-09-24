"""Boot WS endpoint + single-use boot token issuance."""

import asyncio

from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.boot import BootRunner
from app.core.config import get_settings
from app.core.ids import new_token
from app.core.security import now_iso
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_super
from app.gateway.middleware import limiter

router = APIRouter(prefix="/api/v1/boot", tags=["boot"])
S = get_settings()


@router.post("/token")
@limiter.limit(S.rate_limit_login)
async def issue_boot_token(request: Request):
    """Single-use token binding one browser to one authenticated boot run."""
    tok = new_token(16)
    with sql.get_db() as c:
        c.execute("INSERT INTO boot_tokens (token, created_at) VALUES (?,?)", (tok, now_iso()))
        from datetime import datetime, timedelta, timezone

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="milliseconds")
        c.execute("DELETE FROM boot_tokens WHERE used_at IS NULL AND created_at < ?", (cutoff,))
        c.execute("DELETE FROM boot_tokens WHERE used_at IS NOT NULL AND used_at < ?", (cutoff,))
    return {"boot_token": tok, "ttl_s": 30}


async def handle_boot_ws(ws: WebSocket, token: str) -> None:
    """Streams the S1–S8 attestation sequence. Single-use token enforced."""
    with sql.get_db() as c:
        row = c.execute("SELECT used_at FROM boot_tokens WHERE token=?", (token,)).fetchone()
        if row is None or row["used_at"] is not None:
            await ws.send_json({"seq": 0, "ts": "0000.000", "label": "boot token invalid or spent",
                                "status": "FAIL", "detail": "request a new token"})
            await ws.close(code=4403)
            return
        c.execute("UPDATE boot_tokens SET used_at=? WHERE token=?", (now_iso(), token))
    runner = BootRunner()
    try:
        async for line in runner.stages():
            await ws.send_json(line.as_dict())
    except WebSocketDisconnect:
        return
    except Exception as e:  # fail-closed: surface, freeze
        await ws.send_json({"seq": runner.seq + 1, "ts": "9999.999", "label": f"boot runner error: {e}",
                            "status": "FAIL", "detail": "halted"})
    await ws.close()
