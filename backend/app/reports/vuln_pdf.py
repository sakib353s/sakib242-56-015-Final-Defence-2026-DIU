"""Vulnerability scan report PDF — auto-generated on scan completion (P-05b)."""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.audit import chain
from app.core.config import get_settings
from app.core.security import now_iso
from app.db import sqlite as sql

S = get_settings()
SEV_COLORS = {"CRITICAL": colors.HexColor("#FF2A2A"), "HIGH": colors.HexColor("#FF7A00"),
              "MEDIUM": colors.HexColor("#FFB000"), "LOW": colors.HexColor("#00BFFF")}


def build(scan_id: str) -> str:
    scan = sql.one("SELECT * FROM vuln_scans WHERE id=?", scan_id)
    warrant = sql.one("SELECT * FROM auth_ledger WHERE id=?", scan["warrant_id"])
    findings = sql.all_("SELECT * FROM findings WHERE source='vuln' AND source_id=?"
                        " ORDER BY cvss DESC", scan_id)
    out = str(Path(S.reports_dir) / f"vuln-{scan_id}.pdf")
    doc = SimpleDocTemplate(out, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    term = ParagraphStyle("term", parent=styles["Code"], fontSize=8.5)
    risk = scan["risk_score"] if scan["risk_score"] is not None else 0
    story = [
        Paragraph("CYBERWATCH-BD // VULNERABILITY ASSESSMENT REPORT", styles["Title"]),
        Paragraph(f"Scan {scan_id} · Target {scan['target']} · Status {scan['status']} · "
                  f"Risk score {risk}/100 · Findings {len(findings)}", term),
        Paragraph("Warrant-of-record (written authorization):", styles["Normal"]),
        Paragraph(f"ref <b>{warrant['warrant_ref']}</b> · scope {warrant['scope_json']} · "
                  f"valid {warrant['valid_from']} → {warrant['valid_until']}", term),
        Spacer(1, 6 * mm),
        Paragraph("Findings correlated with the public NVD CVE corpus", styles["Heading2"]),
    ]
    if findings:
        data = [["Sev", "CVE", "CVSS", "Host:Port", "Service", "Description"]]
        data += [[f["severity"], f["cve"] or "—", f"{f['cvss']:.1f}" if f["cvss"] is not None else "—",
                  f"{f['host']}:{f['port'] or ''}", f["service"] or "",
                  Paragraph((f["description"] or "")[:160], term)]
                 for f in findings]
        tbl = Table(data, colWidths=[16 * mm, 28 * mm, 12 * mm, 32 * mm, 24 * mm, 58 * mm])
        tbl.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            *[("TEXTCOLOR", (0, i + 1), (0, i + 1), SEV_COLORS.get(f["severity"], colors.black))
              for i, f in enumerate(findings[:300])],
        ]))
        story.append(tbl)
    else:
        story.append(Paragraph("No CVEs were mapped to the discovered services in this run.", styles["Normal"]))
    story += [
        Spacer(1, 8 * mm),
        Paragraph("Remediation guidance: patch or upgrade each affected service to the version "
                  "recommended by its vendor; where a finding repeats across hosts, prioritize by "
                  "exposure (public-facing first) and CVSS score. Authorized remediation jobs can be "
                  "raised from the CYBERWATCH-BD console against any finding listed here.", styles["Normal"]),
        Spacer(1, 3 * mm),
        Paragraph("Compliance: passive version correlation against public NVD data, performed strictly "
                  "within the recorded written authorization under the Bangladesh Cyber Safety Ordinance "
                  "2025 and ICT Act 2006.", styles["Normal"]),
        Spacer(1, 4 * mm),
        Paragraph(f"Generated {now_iso()} · audit_ref "
                  f"{chain.append('system:report', 'report.generate', scan_id, {'kind': 'vuln'})}", term),
    ]
    doc.build(story)
    return out
