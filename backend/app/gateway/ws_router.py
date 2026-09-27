"""WebSocket endpoints: /ws/boot (single-use token), /ws/alerts, /ws/jobs (origin-guarded)."""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.config import get_settings
from app.gateway.boot_router import handle_boot_ws
from app.gateway.wsmanager import manager

S = get_settings()
router = APIRouter()


def _origin_ok(ws: WebSocket) -> bool:
    origin = ws.headers.get("origin", "")
    if not origin:  # non-browser clients (mobile native, tests)
        return True
    if origin in S.origins or origin.startswith("exp://") or origin.startswith("capacitor://"):
        return True
    if not S.is_production:
        # lab mode: any loopback port is a local dev server — loud, but usable
        return origin.startswith("http://localhost:") or origin.startswith("http://127.0.0.1:")
    return False


@router.websocket("/ws/boot")
async def ws_boot(ws: WebSocket):
    if not _origin_ok(ws):
        await ws.close(code=4403)
        return
    await ws.accept()
    token = ws.query_params.get("token", "")
    await handle_boot_ws(ws, token)


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    if not _origin_ok(ws):
        await ws.close(code=4403)
        return
    await ws.accept()
    await manager.subscribe("alerts", ws)
    try:
        while True:
            await ws.receive_text()  # keepalive pings from client
    except WebSocketDisconnect:
        await manager.unsubscribe("alerts", ws)


@router.websocket("/ws/jobs")
async def ws_jobs(ws: WebSocket):
    if not _origin_ok(ws):
        await ws.close(code=4403)
        return
    await ws.accept()
    await manager.subscribe("jobs", ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.unsubscribe("jobs", ws)
