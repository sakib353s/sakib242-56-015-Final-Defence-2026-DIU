"""Tamper-evident HMAC hash-chained audit log.

Row: hmac = HMAC-SHA256(audit_key, prev_hash || payload_hash || ts || actor)
Chain is append-only under a process-wide write lock; the hourly verifier recomputes
every link and reports the first broken seq. Genesis link uses sha256("CWB-GENESIS").
"""
from __future__ import annotations

import hashlib
import json
import time

from app.core.ids import new_id
from app.core.security import audit_hmac, canonical_json, constant_time_eq
from app.db import sqlite as sql

GENESIS = hashlib.sha256(b"CWB-GENESIS").hexdigest()


def append(actor: str, action: str, object_ref: str, payload: dict | None = None) -> str:
    """Append one chained row; returns audit row id. Fail-closed: raises on write error."""
    payload = payload or {}
    payload_hash = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    ts = int(time.time() * 1000)
    rid = new_id()
    with sql.write_db() as conn:
        row = conn.execute("SELECT hmac FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hmac"] if row else GENESIS
        mac = audit_hmac(payload_hash, prev, ts, actor)
        conn.execute(
            "INSERT INTO audit_log (id, ts_ms, actor, action, object_ref, payload_json,"
            " payload_hash, prev_hash, hmac) VALUES (?,?,?,?,?,?,?,?,?)",
            (rid, ts, actor, action, object_ref, canonical_json(payload), payload_hash, prev, mac),
        )
    _fanout(actor, action, object_ref, ts)
    return rid


_fanout_tasks: set = set()  # strong refs: the loop keeps tasks only weakly


def _fanout(actor: str, action: str, object_ref: str, ts: int) -> None:
    """Best-effort live mirror of the audit stream on /ws/alerts; never masks auditing."""
    try:
        import asyncio

        from app.gateway.wsmanager import manager

        task = asyncio.get_running_loop().create_task(manager.publish(
            "alerts", "audit.event",
            {"actor": actor, "action": action, "object_ref": str(object_ref)[:80], "ts_ms": ts},
        ))
        _fanout_tasks.add(task)
        task.add_done_callback(_fanout_tasks.discard)
    except Exception:
        pass


def safe_append(actor: str, action: str, object_ref: str, payload: dict | None = None) -> str:
    """Audit must never mask the primary error; on failure return sentinel."""
    try:
        return append(actor, action, object_ref, payload)
    except Exception:
        return "AUDIT-UNAVAILABLE"


def verify_chain() -> dict:
    rows = sql.all_(
        "SELECT seq, ts_ms, actor, payload_json, payload_hash, prev_hash, hmac FROM audit_log"
        " ORDER BY seq ASC"
    )
    prev = GENESIS
    for r in rows:
        if not constant_time_eq(r["prev_hash"], prev):
            return {"ok": False, "broken_at": r["seq"], "reason": "prev_hash mismatch (chain surgery)"}
        # Recompute payload hash from the stored JSON — detects payload edits that
        # keep the payload_hash column intact.
        try:
            recomputed = hashlib.sha256(
                canonical_json(json.loads(r["payload_json"])).encode()).hexdigest()
        except json.JSONDecodeError:
            return {"ok": False, "broken_at": r["seq"], "reason": "payload_json corrupt"}
        if not constant_time_eq(recomputed, r["payload_hash"]):
            return {"ok": False, "broken_at": r["seq"], "reason": "payload tamper (hash mismatch)"}
        expect = audit_hmac(r["payload_hash"], r["prev_hash"], r["ts_ms"], r["actor"])
        if not constant_time_eq(r["hmac"], expect):
            return {"ok": False, "broken_at": r["seq"], "reason": "hmac mismatch (payload/key tamper)"}
        prev = r["hmac"]
    return {"ok": True, "verified": len(rows), "head": prev[:16]}


def query(limit: int = 200, actor: str | None = None, action: str | None = None) -> list[dict]:
    sql_txt = "SELECT * FROM audit_log"
    conds, args = [], []
    if actor:
        conds.append("actor=?")
        args.append(actor)
    if action:
        conds.append("action LIKE ?")
        args.append(f"{action}%")
    if conds:
        sql_txt += " WHERE " + " AND ".join(conds)
    sql_txt += " ORDER BY seq DESC LIMIT ?"
    args.append(limit)
    return sql.all_(sql_txt, *args)
