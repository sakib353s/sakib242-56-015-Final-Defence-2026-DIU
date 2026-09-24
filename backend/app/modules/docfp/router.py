"""Doc Fingerprint API."""

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Request, UploadFile
from pydantic import BaseModel, Field

from app.audit import chain
from app.core.errors import CWBError, NotFound
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_analyst, require_totp_stepup
from app.modules.docfp import service

router = APIRouter(prefix="/api/v1/document", tags=["docfp"])


@router.post("/upload")
async def upload(request: Request, file: UploadFile = File(...),
                 ownership_confirmed: bool = Form(False),
                 p: Principal = Depends(require_analyst)):
    data = await file.read()
    if len(data) == 0:
        raise CWBError("Empty file", status=422)
    res = await __import__("asyncio").to_thread(
        service.ingest, file.filename or "doc.bin", data, p.user_id, ownership_confirmed)
    return res


class CrawlBody(BaseModel):
    seed_urls: list[str] = Field(min_length=1, max_length=10)


@router.post("/{doc_id}/crawl")
async def crawl(request: Request, doc_id: str, body: CrawlBody, bg: BackgroundTasks,
                p: Principal = Depends(require_analyst)):
    require_totp_stepup(request, p)
    for u in body.seed_urls:
        if not u.startswith(("http://", "https://")):
            raise CWBError("only public http(s) seeds", status=422)
    from app.core.jobs import job_finish, job_start

    async def run():
        jid = await job_start("docfp.crawl", doc_id, {"seeds": body.seed_urls})
        res = await service.crawl(doc_id, body.seed_urls, p.user_id)
        await job_finish(jid, "done", f"visited {res['visited']}")
        return res

    bg.add_task(run)
    return {"status": "CRAWL_QUEUED", "doc_id": doc_id}


@router.get("")
async def list_docs(p: Principal = Depends(require_analyst)):
    """DB-driven document index — the UI never keeps its own list."""
    return {"documents": sql.all_(
        "SELECT id, filename, sha256, md5, watermark_id, size, mime, created_at"
        " FROM docfingerprints ORDER BY created_at DESC LIMIT 200")}


@router.get("/{doc_id}")
async def get_doc(doc_id: str, p: Principal = Depends(require_analyst)):
    doc = sql.one("SELECT id, filename, sha256, md5, watermark_id, size, mime, created_at"
                  " FROM docfingerprints WHERE id=?", doc_id)
    if not doc:
        raise NotFound("Document not found")
    copies = sql.all_("SELECT url, verdict, found_at FROM crawlresults WHERE doc_id=?"
                      " ORDER BY found_at DESC LIMIT 200", doc_id)
    return {"document": doc, "copies": copies}


@router.get("/{doc_id}/evidence")
async def evidence(request: Request, doc_id: str, p: Principal = Depends(require_analyst)):
    require_totp_stepup(request, p)  # legal artifact — step-up enforced
    path = service.evidence_pack(doc_id, p.user_id)
    from app.reports.signing import signed_url
    chain.append(p.user_id, "doc.evidence.download", doc_id)
    return {"download": signed_url(path, ttl_s=300)}
