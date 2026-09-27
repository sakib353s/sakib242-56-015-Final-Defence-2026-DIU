"""Remediation job report PDF — auto-generated when a saga reaches a terminal state."""
from __future__ import annotations

import json
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from app.audit import chain
from app.core.config import get_settings
from app.core.security import now_iso
from app.db import sqlite as sql

S = get_settings()


def build(job_id: str) -> str:
    job = sql.one("SELECT * FROM remediation_jobs WHERE id=?", job_id)
    finding = sql.one("SELECT * FROM findings WHERE id=?", job["finding_id"])
    warrant = sql.one("SELECT * FROM auth_ledger WHERE id=?", job["warrant_id"])
    asset = sql.one("SELECT name, host FROM hw_assets WHERE id=?", job["asset_id"]) if job["asset_id"] else None
    consent = json.loads(job["consent_json"]) if job["consent_json"] else None
    out = str(Path(S.reports_dir) / f"remediation-{job_id}.pdf")
    doc = SimpleDocTemplate(out, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    term = ParagraphStyle("term", parent=styles["Code"], fontSize=8.5)
    diff_json = json.loads(job["diff_json"])
    diff_lines = "\n".join(diff_json.get("diff", []))[:4000]
    story = [
        Paragraph("CYBERWATCH-BD // REMEDIATION CHANGE RECORD", styles["Title"]),
        Paragraph(f"Job {job_id} · Host {job['host']} · State {job['state']}", term),
        Spacer(1, 4 * mm),
        Paragraph("Change window", styles["Heading2"]),
        Paragraph(f"Created {job['created_at']} · Last updated {job['updated_at']}", term),
        Spacer(1, 4 * mm),
        Paragraph("Authorization gates (both enforced server-side, fail-closed)", styles["Heading2"]),
        Paragraph(f"Warrant <b>{warrant['warrant_ref']}</b> · scope {warrant['scope_json']} · "
                  f"valid {warrant['valid_from']} → {warrant['valid_until']}", term),
        Paragraph(f"Consent recorded: {consent['ts']} by {consent['user_id'][:8]} · "
                  f"totp_ok={consent['totp_ok']} · scope echo {consent['scope_echo']}"
                  if consent else "Consent: NOT RECORDED — job never left draft.", term),
        Spacer(1, 4 * mm),
        Paragraph("Finding addressed", styles["Heading2"]),
        Paragraph(f"{finding['cve'] or finding['id']} · {finding['severity']} · "
                  f"{finding['host']}:{finding['port'] or ''} · {finding['service'] or ''}", term),
        Spacer(1, 4 * mm),
        Paragraph("Applied change (preview diff)", styles["Heading2"]),
        Paragraph(f"Fix script: {job['script']}", term),
        Paragraph(diff_lines.replace("\n", "<br/>") or "(no diff captured)", term),
        Spacer(1, 4 * mm),
        Paragraph("Execution log and verification", styles["Heading2"]),
        Paragraph((job["apply_log"] or "(none)").replace("\n", "<br/>")[:3000], term),
        Paragraph(f"Post-apply verification: {job['verify_result'] or '—'} · "
                  f"Snapshot: {job['snapshot_ref'] or '—'} · Asset: "
                  f"{asset['name'] + ' (' + asset['host'] + ')' if asset else '—'}", term),
        Spacer(1, 6 * mm),
        Paragraph("Compliance: the change was applied only to an asset whose owner attested "
                  "authorization in the CYBERWATCH-BD ledger, under the Bangladesh Cyber Safety "
                  "Ordinance 2025 and ICT Act 2006. Every state transition of this job is recorded "
                  "in the HMAC hash-chained audit log.", styles["Normal"]),
        Spacer(1, 4 * mm),
        Paragraph(f"Generated {now_iso()} · audit_ref "
                  f"{chain.append('system:report', 'report.generate', job_id, {'kind': 'remediation'})}", term),
    ]
    doc.build(story)
    return out
