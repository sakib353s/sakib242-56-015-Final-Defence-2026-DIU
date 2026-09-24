"""Background job ledger + WS progress fan-out (/ws/jobs)."""
from __future__ import annotations

from app.core.ids import new_id
from app.core.security import canonical_json, now_iso
from app.db import sqlite as sql
from app.gateway.wsmanager import manager


async def job_start(kind: str, ref_id: str, payload: dict) -> str:
    jid = new_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO jobs (id, kind, ref_id, status, payload_json, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (jid, kind, ref_id, "running", canonical_json(payload), now_iso(), now_iso()),
        )
    await manager.publish("jobs", "job.start", {"job_id": jid, "kind": kind, "ref_id": ref_id, "progress": 0})
    return jid


async def job_progress(job_id: str, progress: float, message: str = "") -> None:
    with sql.get_db() as c:
        c.execute("UPDATE jobs SET progress=?, message=?, updated_at=? WHERE id=?",
                  (progress, message, now_iso(), job_id))
    await manager.publish("jobs", "job.progress", {"job_id": job_id, "progress": round(progress, 3),
                                                   "message": message})


async def job_finish(job_id: str, status: str = "done", message: str = "") -> None:
    with sql.get_db() as c:
        c.execute("UPDATE jobs SET status=?, progress=?, message=?, updated_at=? WHERE id=?",
                  (status, 1.0, message, now_iso(), job_id))
    await manager.publish("jobs", "job.finish", {"job_id": job_id, "status": status, "message": message})
