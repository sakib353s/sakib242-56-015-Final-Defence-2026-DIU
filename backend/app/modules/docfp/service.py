"""Doc Fingerprint — integrity pipeline for user-owned documents (FR-D01…D04).
Upload attestation → SHA-256/MD5 → invisible watermark → robots-respecting copy
crawler → per-copy evidence PDF with chain of custody."""
from __future__ import annotations

import hashlib
import io
import re
import secrets
import asyncio
import urllib.robotparser
from pathlib import Path

import httpx
from PIL import Image

from app.audit import chain
from app.core.config import get_settings
from app.core.errors import CWBError
from app.core.ids import new_id
from app.core.security import now_iso, sha256_file
from app.core.ssrf import guard_public_url
from app.db import sqlite as sql

S = get_settings()
MIME = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "pdf": "application/pdf"}


def ingest(filename: str, data: bytes, owner: str, attested: bool) -> dict:
    if not attested:
        raise CWBError("ownership attestation checkbox is mandatory", status=403)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in MIME:
        raise CWBError(f"unsupported type .{ext} — png/jpg/jpeg/pdf only", status=415)
    if len(data) > 50 * 1024 * 1024:
        raise CWBError("50 MB cap per document", status=413)
    doc_id = new_id()
    wm_id = f"CWB-WM-{secrets.token_hex(6).upper()}"
    path = Path(S.uploads_dir) / f"{doc_id}.{ext}"
    marked = watermark(data, ext, wm_id)
    path.write_bytes(marked)
    sha, md5 = sha256_file(str(path))
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO docfingerprints (id, owner_user_id, filename, sha256, md5, watermark_id,"
            " size, mime, stored_path, ownership_attested, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (doc_id, owner, Path(filename).name, sha, md5, wm_id, len(marked), MIME[ext],
             str(path), 1, now_iso()),
        )
    chain.append(owner, "doc.upload", doc_id, {"sha256": sha, "watermark_id": wm_id})
    return {"id": doc_id, "sha256": sha, "md5": md5, "watermark_id": wm_id,
            "size": len(marked), "mime": MIME[ext]}


def watermark(data: bytes, ext: str, wm_id: str) -> bytes:
    """Real watermarks: LSB pixel stego for images, XMP+Info metadata for PDFs."""
    if ext == "pdf":
        return _pdf_meta(data, wm_id)
    img = Image.open(io.BytesIO(data)).convert("RGBA")
    bits = "".join(f"{b:08b}" for b in wm_id.encode()[:32])
    px = img.load()
    w, h = img.size
    i = 0
    for y in range(h):
        for x in range(w):
            if i >= len(bits):
                break
            r, g, b, a = px[x, y]
            px[x, y] = (r & ~1 | int(bits[i]), g, b, a)
            i += 1
        if i >= len(bits):
            break
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def read_watermark(data: bytes) -> str | None:
    """Extract the LSB-stamped id from a (re-encoded) PNG, if intact."""
    img = Image.open(io.BytesIO(data)).convert("RGBA")
    px = img.load()
    w, h = img.size
    acc, out_bytes = 0, []
    i = 0
    for y in range(h):
        for x in range(w):
            acc = (acc << 1) | (px[x, y][0] & 1)
            i += 1
            if i % 8 == 0:
                ch = acc & 0xFF
                if not (32 <= ch < 127):
                    break
                out_bytes.append(ch)
                if len(out_bytes) >= 32:
                    break
        else:
            continue
        break
    s = bytes(out_bytes).decode(errors="ignore")
    m = re.search(r"CWB-WM-[0-9A-F]{12}", s)
    return m.group(0) if m else None


def _pdf_meta(data: bytes, wm_id: str) -> bytes:
    from pypdf import PdfReader, PdfWriter
    try:
        r = PdfReader(io.BytesIO(data))
        w = PdfWriter()
        w.append(r)
        w.add_metadata({"/Producer": "CYBERWATCH-BD DocFP", "/Keywords": wm_id,
                        "/CreationDate": now_iso()})
        w.set_custom_metadata({"cwb_watermark_id": wm_id})
        out = io.BytesIO()
        w.write(out)
        return out.getvalue()
    except Exception as e:
        raise CWBError(f"PDF is not parseable: {e}", status=422)


async def _egress_guard_hook(response: httpx.Response) -> None:
    """Checked on EVERY hop: a public seed that 302s into 169.254.0.0/16 is the
    classic metadata-SSRF chain, so guarding only the seed URL is not enough."""
    await asyncio.to_thread(guard_public_url, str(response.url))


async def crawl(doc_id: str, seed_urls: list[str], actor: str, progress=None) -> dict:
    """FR-D03: scheduled copy detection. Robots-respecting, 1 req/s, depth 1."""
    doc = sql.one("SELECT * FROM docfingerprints WHERE id=?", doc_id)
    if not doc:
        raise CWBError("Document not found", status=404)
    chain.append(actor, "crawl.start", doc_id, {"seeds": seed_urls[:5]})
    for seed in seed_urls[:10]:
        await asyncio.to_thread(guard_public_url, seed)
    findings = []
    visited: set[str] = set()
    rp_cache: dict[str, urllib.robotparser.RobotFileParser] = {}
    async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                 event_hooks={"response": [_egress_guard_hook]},
                                 headers={"user-agent": "cwb-docfp/5.0 (research crawler)"}) as h:
        queue = seed_urls[:10]
        while queue and len(visited) < 100:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            origin = re.match(r"https?://[^/]+", url).group(0) if re.match(r"https?://[^/]+", url) else url
            if origin not in rp_cache:
                rp = urllib.robotparser.RobotFileParser()
                try:
                    rr = await h.get(origin + "/robots.txt")
                    rp.parse(rr.text.splitlines() if rr.status_code == 200 else [])
                except httpx.HTTPError:
                    rp.parse(["Disallow: /"])  # fail-closed for robots
                rp_cache[origin] = rp
            if not rp_cache[origin].can_fetch("cwb-docfp/5.0", url):
                findings.append({"url": url, "verdict": "skipped_robots"})
                continue
            try:
                r = await h.get(url)
            except httpx.HTTPError:
                findings.append({"url": url, "verdict": "error"})
                continue
            verdict, snap = _compare(doc, r)
            cid = new_id()
            with sql.get_db() as c:
                c.execute("INSERT INTO crawlresults (id, doc_id, url, snapshot_sha256, verdict,"
                          " detail, found_at) VALUES (?,?,?,?,?,?,?)",
                          (cid, doc_id, url[:1000], snap, verdict, f"http {r.status_code}", now_iso()))
            findings.append({"url": url, "verdict": verdict, "snapshot_sha256": snap})
            if verdict == "match":
                chain.append(actor, "copy.found", doc_id, {"url": url})
            await asyncio.sleep(1.0)  # politeness — must NOT block the event loop
            if progress:
                await progress(len(visited), 100)
    return {"doc_id": doc_id, "visited": len(visited), "findings": findings}


def _compare(doc: dict, resp: httpx.Response) -> tuple[str, str]:
    body = resp.content
    sha = hashlib.sha256(body).hexdigest()
    if sha == doc["sha256"]:
        return "match", sha
    if b"%PDF" in body[:8] and _pdf_hashes_equal(doc, body):
        return "variant_match", sha
    return "no_match", sha


def _pdf_hashes_equal(doc: dict, body: bytes) -> bool:
    try:
        from pypdf import PdfReader
        r = PdfReader(io.BytesIO(body))
        kw = r.metadata.get("/Keywords", "") if r.metadata else ""
        return doc["watermark_id"] in str(kw)
    except Exception:
        return False


def evidence_pack(doc_id: str, actor: str) -> str:
    matches = sql.all_("SELECT * FROM crawlresults WHERE doc_id=? AND verdict IN ('match','variant_match')", doc_id)
    doc = sql.one("SELECT * FROM docfingerprints WHERE id=?", doc_id)
    if not doc:
        raise CWBError("Document not found", status=404)
    from app.reports import docfp_pdf
    path = docfp_pdf.build(doc, matches)
    from app.reports.signing import register_report
    rid = register_report(path, Path(path).name, "evidence", doc_id, actor)
    chain.append(actor, "evidence.generate", doc_id, {"copies": len(matches), "report": rid})
    return path
