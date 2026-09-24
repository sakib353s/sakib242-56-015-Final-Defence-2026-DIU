"""WebSocket fan-out manager for /ws/alerts and /ws/jobs (boot has its own runner).

Envelopes are HMAC-signed: {channel, seq, ts, type, payload, hmac}.
"""
from __future__ import annotations

import asyncio
import json
from collections import defaultdict

from app.core.security import now_iso, sign_envelope


class WSManager:
    def __init__(self):
        self._subs: dict[str, set] = defaultdict(set)
        self._seq: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def subscribe(self, channel: str, ws) -> None:
        async with self._lock:
            self._subs[channel].add(ws)

    async def unsubscribe(self, channel: str, ws) -> None:
        async with self._lock:
            self._subs[channel].discard(ws)

    async def publish(self, channel: str, type_: str, payload: dict) -> None:
        async with self._lock:
            self._seq[channel] += 1
            env = sign_envelope({
                "channel": channel, "seq": self._seq[channel],
                "ts": now_iso(), "type": type_, "payload": payload,
            })
            msg = json.dumps(env, default=str)
            dead = []
            for ws in list(self._subs[channel]):
                try:
                    await ws.send_text(msg)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._subs[channel].discard(ws)


manager = WSManager()
