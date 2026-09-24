"""Idempotency-Key replay guard (P-04).

Offline-first mobile clients retry writes with a stable uuid key. The first
execution stores its serialized response; any duplicate key replays the stored
response with 200 so retries are exactly-once end-to-end (the ack mutation and
its chained audit row run at most once).
"""
from __future__ import annotations

import json

from app.core.security import now_iso
from app.db import sqlite as sql


def lookup(key: str) -> dict | None:
    row = sql.one("SELECT response_json FROM idempotency_keys WHERE key=?", key)
    return json.loads(row["response_json"]) if row else None


def store(key: str, response: dict) -> None:
    with sql.get_db() as c:
        c.execute("INSERT OR IGNORE INTO idempotency_keys (key, response_json, created_at)"
                  " VALUES (?,?,?)", (key, json.dumps(response, sort_keys=True), now_iso()))
