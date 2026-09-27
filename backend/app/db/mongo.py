"""MongoDB Atlas client — real driver. Absent URI in production = boot FAIL (S5).
In lab mode events route to the SQLite `event_log` fallback, attested loudly at boot."""
from __future__ import annotations

import json
from datetime import datetime

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from app.core.config import get_settings
from app.db import sqlite as sql

S = get_settings()
_client: MongoClient | None = None

COLLECTIONS = {
    "traffic_events": ("trafficevents", 90),
    "alerts": ("alerts", 365),
    "scan_raw": ("scanraw", 90),
    "crawl_results": ("crawlresults", 365),
    "ws_events": ("wsevents", 30),
    "app_logs": ("app_logs", 30),
}


def client() -> MongoClient | None:
    global _client
    if not S.mongo_uri:
        return None
    if _client is None:
        _client = MongoClient(S.mongo_uri, serverSelectionTimeoutMS=3000, tls=True)
    return _client


def ping() -> bool:
    c = client()
    if c is None:
        return False
    try:
        c.admin.command("ping")
        return True
    except PyMongoError:
        return False


def _ensure_ttl(db, coll_name: str, days: int):
    if coll_name in getattr(db, "_cwb_ttl_done", set()):
        return
    try:
        db[coll_name].create_index("ts", expireAfterSeconds=days * 86400)
        if not hasattr(db, "_cwb_ttl_done"):
            db._cwb_ttl_done = set()
        db._cwb_ttl_done.add(coll_name)
    except PyMongoError:
        pass


def store(kind: str, doc: dict) -> None:
    coll_name, days = COLLECTIONS[kind]
    c = client()
    if c is not None:
        try:
            db = c.get_database("cyberwatch")
            _ensure_ttl(db, coll_name, days)
            doc.setdefault("ts", datetime.utcnow())
            db[coll_name].insert_one(doc)
            return
        except PyMongoError:
            pass  # fall through to lab fallback; never swallow silently in prod
    if S.is_production:
        raise RuntimeError(f"mongo unavailable in production for {kind} — fail-closed")
    with sql.write_db() as conn:
        conn.execute(
            "INSERT INTO event_log (channel, ts, type, payload_json) VALUES (?,?,?,?)",
            (kind, datetime.utcnow().isoformat(), doc.get("type", "doc"), json.dumps(doc, default=str)),
        )


def recent(kind: str, limit: int = 50) -> list[dict]:
    coll_name, _ = COLLECTIONS[kind]
    c = client()
    if c is not None:
        try:
            cur = c.get_database("cyberwatch")[coll_name].find({}, {"_id": 0}).sort("ts", -1).limit(limit)
            return [json.loads(json.dumps(d, default=str)) for d in cur]
        except PyMongoError:
            pass
    rows = sql.all_(
        "SELECT payload_json FROM event_log WHERE channel=? ORDER BY seq DESC LIMIT ?", kind, str(limit)
    )
    return [json.loads(r["payload_json"]) for r in rows]
