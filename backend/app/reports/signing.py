"""Signed, traversal-safe report downloads. Paths are never accepted from clients —
only report ids resolved server-side; signatures carry id+expiry (HMAC)."""
from __future__ import annotations

import hashlib
import hmac
import time
from pathlib import Path
from urllib.parse import urlencode

from app.core.config import get_settings
from app.core.errors import CWBError
from app.core.security import now_iso

S = get_settings()


def register_report(path: str, name: str, kind: str, ref_id: str, created_by: str) -> str:
    from app.core.ids import new_id
    from app.db import sqlite as sql
    rid = new_id()
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    with sql.get_db() as c:
        c.execute("INSERT INTO report_files (id, name, path, sha256, kind, ref_id, created_by, created_at)"
                  " VALUES (?,?,?,?,?,?,?,?)",
                  (rid, Path(name).name, str(Path(path).resolve()), digest, kind, ref_id, created_by, now_iso()))
    return rid


def signed_url(path: str, ttl_s: int = 300) -> str:
    from app.db import sqlite as sql
    row = sql.one("SELECT id FROM report_files WHERE path=?", str(Path(path).resolve()))
    if not row:
        raise CWBError("Report not registered", status=500)
    return _sign(row["id"], ttl_s)


def url_for_id(id_: str, ttl_s: int = 300) -> str:
    """Sign a download link for an already-resolved report id (never a client path)."""
    from app.db import sqlite as sql
    if not sql.one("SELECT id FROM report_files WHERE id=?", id_):
        raise CWBError("Report not registered", status=500)
    return _sign(id_, ttl_s)


def _sign(id_: str, ttl_s: int) -> str:
    exp = int(time.time()) + ttl_s
    sig = hmac.new(S.report_signing_key.encode(), f"{id_}|{exp}".encode(), hashlib.sha256).hexdigest()
    return f"/api/v1/reports/{id_}/download?" + urlencode({"exp": exp, "sig": sig})


def verify_and_get(id_: str, exp: int, sig: str) -> dict:
    from app.db import sqlite as sql
    if exp < time.time():
        raise CWBError("Signed link expired", status=403)
    expect = hmac.new(S.report_signing_key.encode(), f"{id_}|{exp}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig or ""):
        raise CWBError("Bad signature", status=403)
    row = sql.one("SELECT * FROM report_files WHERE id=?", id_)
    if not row:
        raise CWBError("Report not found", status=404)
    resolved = Path(row["path"]).resolve()
    reports_root = Path(S.reports_dir).resolve()
    if not str(resolved).startswith(str(reports_root) + "/"):
        raise CWBError("Path traversal refused", status=403)
    if not resolved.exists():
        raise CWBError("Report file missing on disk", status=410)
    return row
