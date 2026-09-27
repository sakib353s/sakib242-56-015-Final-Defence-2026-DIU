"""Unified report index + signed downloads (traversal-safe: ids only, never paths)."""

import time
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse

from app.core.config import get_settings
from app.core.errors import CWBError, Forbidden
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_any
from app.reports import signing

S = get_settings()
router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("")
async def index(kind: str | None = None, p: Principal = Depends(require_any)):
    if kind:
        rows = sql.all_("SELECT id, name, kind, ref_id, created_at, sha256 FROM report_files"
                        " WHERE kind=? ORDER BY created_at DESC LIMIT 200", kind)
    else:
        rows = sql.all_("SELECT id, name, kind, ref_id, created_at, sha256 FROM report_files"
                        " ORDER BY created_at DESC LIMIT 200")
    return {"reports": rows}


@router.post("/{report_id}/link")
async def mint_link(request: Request, report_id: str, p: Principal = Depends(require_any)):
    """Generic 300 s signed-link issuance for any registered artifact id.
    Traversal-safe (id only), RBAC = same as the index, every mint is audited."""
    row = sql.one("SELECT id, name, kind FROM report_files WHERE id=?", report_id)
    if not row:
        raise CWBError("Report not registered", status=404)
    from app.audit import chain
    chain.append(p.user_id, "reports.link_mint", report_id, {"kind": row["kind"]})
    return {"download": signing.url_for_id(report_id, ttl_s=300), "kind": row["kind"],
            "name": row["name"], "ttl_s": 300}


@router.get("/{report_id}/download")
async def download(request: Request, report_id: str, exp: int = Query(...), sig: str = Query(...)):
    """Signed URL required. Optional X-Date header must be within replay window (300 s)."""
    xdate = request.headers.get("x-date")
    if xdate:
        try:
            if abs(time.time() - int(xdate)) > S.replay_window_s:
                raise Forbidden("X-Date outside replay window")
        except ValueError:
            raise Forbidden("Malformed X-Date")
    row = signing.verify_and_get(report_id, exp, sig)
    return FileResponse(row["path"], media_type="application/pdf",
                        filename=Path(row["name"]).name,
                        headers={"X-Content-Sha256": row["sha256"]})
