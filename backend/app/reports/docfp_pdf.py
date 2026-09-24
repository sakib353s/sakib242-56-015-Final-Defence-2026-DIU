"""Doc-Fingerprint evidence-pack PDF (FR-D04)."""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.audit import chain
from app.core.config import get_settings
from app.core.security import now_iso

S = get_settings()


def build(doc: dict, copies: list[dict]) -> str:
    out = str(Path(S.reports_dir) / f"evidence-{doc['id']}.pdf")
    Path(S.reports_dir).mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("CYBERWATCH-BD // DOCUMENT INFRINGEMENT EVIDENCE PACK", styles["Title"]),
        Paragraph(f"Original file: {doc['filename']}", styles["Normal"]),
        Paragraph(f"SHA-256: {doc['sha256']}", styles["Code"]),
        Paragraph(f"MD5: {doc['md5']}", styles["Code"]),
        Paragraph(f"Watermark ID: {doc['watermark_id']} (LSB-embedded)", styles["Code"]),
        Spacer(1, 4 * mm),
        Paragraph("Unauthorized copies detected:", styles["Heading2"]),
    ]
    if copies:
        data = [["URL", "Verdict", "Snapshot SHA-256", "Found"]]
        data += [[Paragraph(c["url"][:90], styles["Code"]), c["verdict"],
                  (c["snapshot_sha256"] or "")[:24] + "…", c["found_at"]] for c in copies[:60]]
        tbl = Table(data, colWidths=[62 * mm, 22 * mm, 42 * mm, 42 * mm])
        tbl.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                 ("FONTSIZE", (0, 0), (-1, -1), 7)]))
        story.append(tbl)
    else:
        story.append(Paragraph("No detections at time of export.", styles["Normal"]))
    story += [
        Spacer(1, 4 * mm),
        Paragraph("Chain of custody:", styles["Heading3"]),
        Paragraph("Crawl respected robots.txt at 1 req/s; snapshot hashes recorded at detection "
                  "time in crawlresults (SQLite) and mirrored to Mongo.", styles["Normal"]),
        Paragraph(f"Verification: audit_ref={chain.append('system:report', 'report.generate', doc['id'], {'kind': 'evidence'})} · {now_iso()}",
                  styles["Code"]),
    ]
    SimpleDocTemplate(out, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm).build(story)
    return out
