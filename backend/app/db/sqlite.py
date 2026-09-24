"""SQLite access layer — WAL, foreign keys, per-call connections (thread-safe)."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager

from app.core.config import get_settings

S = get_settings()
_write_lock = threading.Lock()  # serializes audit appends chain-wide


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(S.database_path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def get_db():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def write_db():
    """Exclusive write path — required for audit-chain appends."""
    with _write_lock:
        with get_db() as conn:
            yield conn


def run_migrations() -> list[str]:
    applied = []
    mig_dir = Path(__file__).parent / "migrations"
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT)")
        for f in sorted(mig_dir.glob("*.sql")):
            row = conn.execute("SELECT 1 FROM schema_migrations WHERE name=?", (f.name,)).fetchone()
            if not row:
                conn.executescript(f.read_text())
                conn.execute(
                    "INSERT INTO schema_migrations (name, applied_at) VALUES (?, datetime('now'))",
                    (f.name,),
                )
                applied.append(f.name)
    return applied


def scalar(sql: str, *args):
    with get_db() as conn:
        r = conn.execute(sql, args).fetchone()
        return r[0] if r else None


def one(sql: str, *args) -> dict | None:
    with get_db() as conn:
        r = conn.execute(sql, args).fetchone()
        return dict(r) if r else None


def all_(sql: str, *args) -> list[dict]:
    with get_db() as conn:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
