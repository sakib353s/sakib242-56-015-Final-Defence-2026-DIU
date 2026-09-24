"""Hardware diagnostic PDF (P-05i): metrics, anomalies, recommendations, audit footer."""
from __future__ import annotations

import json
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


def build(asset: dict) -> str:
    out = str(Path(S.reports_dir) / f"diag-{asset['id']}.pdf")
    Path(S.reports_dir).mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    last = json.loads(asset["last_check_json"] or "{}")
    story = [
        Paragraph("CYBERWATCH-BD // HARDWARE DIAGNOSTIC REPORT", styles["Title"]),
        Paragraph(f"Asset {asset['name']} ({asset['kind']}) · {asset['host']}:{asset['ssh_port']}",
                  styles["Normal"]),
        Paragraph(f"Last check: {asset['last_check_at'] or 'never'}", styles["Code"]),
        Spacer(1, 3 * mm),
        Paragraph("Metrics:", styles["Heading2"]),
    ]
    checks = last.get("checks") or {}
    if checks:
        data = [["Source", "Key", "Value"]]
        for src, kv in checks.items():
            if isinstance(kv, dict):
                for k, v in kv.items():
                    data.append([src, str(k), str(v)[:80]])
        story.append(Table(data, colWidths=[30 * mm, 40 * mm, 100 * mm],
                           style=TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                             ("FONTSIZE", (0, 0), (-1, -1), 8)])))
    anomalies = last.get("anomalies") or []
    if anomalies:
        story += [Paragraph("Anomalies:", styles["Heading2"])] + [
            Paragraph(f"• <font color='#FF2A2A'>{a}</font>", styles["Normal"]) for a in anomalies]
        story.append(Paragraph("Recommendations: review disk pressure (log rotation/purge), profile "
                               "top consumers, verify thermal headroom (sensors) this week.",
                               styles["Normal"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        f"Verification: audit_ref={chain.append('system:report', 'report.generate', asset['id'], {'kind': 'diag'})} · {now_iso()}",
        styles["Code"]))
    SimpleDocTemplate(out, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm).build(story)
    return out
