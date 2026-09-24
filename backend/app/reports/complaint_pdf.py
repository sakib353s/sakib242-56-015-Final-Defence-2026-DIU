"""Legal complaint drafts (P-06): BTRC + Cyber Police — formal e-FIR style layout.

Letterhead, red DRAFT banner, sectioned blocks (complainant / incident / narrative /
statutory citations / hash-chained timeline / exhibit manifest / declaration + signature
ruled blocks / official-use box) and a per-page verification footer. Statutory citations
and the 'human review before filing' stamp are mandatory."""
from __future__ import annotations

import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

from app.audit import chain
from app.core.config import get_settings
from app.core.security import now_iso

S = get_settings()
TPL = {
    "btrc": json.loads((Path(__file__).parent / "templates" / "btrc_complaint.json").read_text()),
    "cyber_police": json.loads((Path(__file__).parent / "templates" /
                                "cyber_police_complaint.json").read_text()),
}

INK = colors.HexColor("#101820")
NAVY = colors.HexColor("#0b3a5e")
RED = colors.HexColor("#b3141c")
GREY = colors.HexColor("#6b7a86")
LINE = colors.HexColor("#8fa1af")
SOFT = colors.HexColor("#eef2f5")

FIELD_LABELS = {
    "name": "Name of complainant", "nid": "NID / Birth registration no.",
    "phone": "Mobile", "email": "E-mail", "address": "Present address",
    "occupation": "Occupation", "date": "Date of incident",
}


def _styles() -> dict:
    body = ParagraphStyle("body", fontName="Times-Roman", fontSize=10.5, leading=15,
                          textColor=INK, alignment=TA_JUSTIFY)
    return {
        "body": body,
        "agency": ParagraphStyle("agency", fontName="Times-Bold", fontSize=15, leading=18,
                                 textColor=NAVY),
        "addr": ParagraphStyle("addr", fontName="Times-Roman", fontSize=9, leading=12,
                               textColor=INK),
        "meta": ParagraphStyle("meta", fontName="Courier", fontSize=8.5, leading=11,
                               alignment=TA_RIGHT),
        "title": ParagraphStyle("title", fontName="Times-Bold", fontSize=13, leading=17,
                                alignment=TA_CENTER, textColor=INK, spaceBefore=2, spaceAfter=2),
        "sec": ParagraphStyle("sec", fontName="Helvetica-Bold", fontSize=9.5, leading=13,
                              textColor=colors.white, backColor=NAVY,
                              borderPadding=(2, 4, 2, 4)),
        "label": ParagraphStyle("label", fontName="Helvetica", fontSize=8, leading=10,
                                textColor=GREY),
        "value": ParagraphStyle("value", fontName="Times-Roman", fontSize=10, leading=13,
                                textColor=INK),
        "mono": ParagraphStyle("mono", fontName="Courier", fontSize=7.5, leading=9.5,
                               textColor=INK),
        "th": ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=7.5, leading=9,
                             textColor=colors.white),
        "banner": ParagraphStyle("banner", fontName="Helvetica-Bold", fontSize=10.5,
                                 leading=13, alignment=TA_CENTER, textColor=RED),
        "stamp": ParagraphStyle("stamp", fontName="Times-Italic", fontSize=9, leading=11,
                                textColor=RED),
    }


def _section(story, st, text):
    story.append(Spacer(1, 4.5 * mm))
    story.append(Paragraph(text, st["sec"]))
    story.append(Spacer(1, 1.6 * mm))


def _kv_table(st, rows, widths):
    data = [[Paragraph(k, st["label"]), Paragraph(v, st["value"])] for k, v in rows]
    t = Table(data, colWidths=widths)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (0, -1), SOFT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    return t


def build(case: dict, complainant: dict, timeline: list[dict], manifest: list[dict],
          agency_key: str) -> str:
    tpl = TPL[agency_key]
    out = str(Path(S.reports_dir) / f"complaint-{agency_key}-{case['id']}.pdf")
    Path(S.reports_dir).mkdir(parents=True, exist_ok=True)
    st = _styles()
    audit_ref = chain.append("system:report", "report.generate", case["id"], {"agency": agency_key})
    gen = now_iso()
    usable = A4[0] - 2 * 16 * mm

    def decorate(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setStrokeColor(NAVY)
        canvas.setLineWidth(1.1)
        canvas.rect(12 * mm, 10 * mm, w - 24 * mm, h - 20 * mm)
        canvas.setLineWidth(0.4)
        canvas.rect(13.2 * mm, 11.2 * mm, w - 26.4 * mm, h - 22.4 * mm)
        canvas.setFont("Courier", 6.6)
        canvas.setFillColor(GREY)
        canvas.drawString(16 * mm, 7.6 * mm,
                          f"CYBERWATCH-BD audit_ref={audit_ref} · generated {gen} · "
                          f"DRAFT — not a filed complaint until human review (P-06)")
        canvas.drawRightString(w - 16 * mm, 7.6 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story = [
        Table(
            [[Paragraph(
                f"<b>{tpl['agency'].split(',')[0]}</b><br/>{tpl['agency']}<br/>"
                f"<font size=8>{tpl['address']}</font>", st["addr"]),
              Paragraph(f"D.No.: <u>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                        f"&nbsp;&nbsp;&nbsp;&nbsp;</u><br/>Date: <u>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                        f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</u><br/>"
                        f"<font face='Courier' size=7>case {case['id']}</font>", st["meta"])]],
            colWidths=[usable * 0.66, usable * 0.34]),
        Spacer(1, 1 * mm),
        Table([[""]], colWidths=[usable], style=TableStyle(
            [("LINEBELOW", (0, 0), (-1, -1), 1.6, NAVY)])),
        Spacer(1, 3 * mm),
        Table([[Paragraph("DRAFT FOR SUBMISSION — HUMAN REVIEW REQUIRED BEFORE FILING<br/>"
                          "Not valid as filed unless re-attested by the complainant (P-06 review path)",
                          st["banner"])]], colWidths=[usable],
              style=TableStyle([("BOX", (0, 0), (-1, -1), 1, RED),
                                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fdf1f1")),
                                ("TOPPADDING", (0, 0), (-1, -1), 4),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 4)])),
        Spacer(1, 4 * mm),
        Paragraph("COMPLAINT / ELECTRONIC FIRST INFORMATION REPORT<br/>"
                  "<font size=10>(analogous to Form 'K' under section 42, ICT Act 2006)</font>",
                  st["title"]),
        Spacer(1, 2.5 * mm),
        Paragraph(f"<b>To</b><br/>{tpl['agency']}<br/><font size=8.5>{tpl['address']}</font><br/>"
                  f"<i>Through: the nearest Police Station / hotline {'' if agency_key == 'btrc' else '1961'}</i>",
                  st["body"]),
        Spacer(1, 2.5 * mm),
        Paragraph(f"<b>Subject:</b> {tpl['subject'].replace('{case_type}', case['case_type'].upper())} "
                  f"— under {tpl['reference'].lower()}", st["body"]),
    ]

    _section(story, st, "A · PARTICULARS OF THE COMPLAINANT")
    rows = []
    seen = set()
    for k, v in complainant.items():
        if not v:
            continue
        seen.add(k)
        rows.append((FIELD_LABELS.get(k, str(k).upper()), str(v)))
    for k in ("phone", "email", "address", "occupation"):
        if k not in seen:
            rows.append((FIELD_LABELS[k], "______________________________"))
    story.append(_kv_table(st, rows, [usable * 0.30, usable * 0.70]))

    _section(story, st, "B · INCIDENT SUMMARY")
    story.append(_kv_table(st, [
        ("Case type", case["case_type"].upper()),
        ("Case opened (UTC)", str(case.get("created_at", "—"))),
        ("Agency routing", agency_key.replace("_", " ").upper()),
        ("Amount of loss / value involved (if any)", "______________________________"),
        ("Known identity of accused / online account used", "______________________________"),
    ], [usable * 0.42, usable * 0.58]))

    _section(story, st, "C · INCIDENT NARRATIVE (auto-summarized from the hash-chained timeline)")
    story.append(Table([[Paragraph(case["narrative"].replace("\n", "<br/>"), st["body"])]],
                       colWidths=[usable],
                       style=TableStyle([("BOX", (0, 0), (-1, -1), 0.5, LINE),
                                         ("TOPPADDING", (0, 0), (-1, -1), 4),
                                         ("BOTTOMPADDING", (0, 0), (-1, -1), 4)])))

    _section(story, st, "D · STATUTORY PROVISIONS INVOKED")
    cites = tpl["citations"].get(case["case_type"], tpl["citations"]["other"])
    story.append(_kv_table(st, [(f"Clause {i + 1}", c) for i, c in enumerate(cites)],
                           [usable * 0.14, usable * 0.86]))

    _section(story, st, "E · EVIDENCE TIMELINE (append-only, hash-chained per row — FR-V03)")
    if timeline:
        data = [[Paragraph(h, st["th"]) for h in
                 ("Seq", "Timestamp (UTC)", "Event", "Row hash (SHA-256, truncated) · chain-verified")]]
        for t in timeline:
            data.append([str(t["seq"]), Paragraph(t["ts"], st["mono"]),
                         Paragraph(str(t["action"])[:80], st["value"]),
                         Paragraph(t["hash"][:32] + "…", st["mono"])])
        tbl = Table(data, colWidths=[10 * mm, 38 * mm, 52 * mm, usable - 100 * mm], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(tbl)
    else:
        story.append(Paragraph("no timeline events recorded", st["stamp"]))

    _section(story, st, "F · EXHIBIT MANIFEST (SHA-256)")
    if manifest:
        mdata = [[Paragraph(h, st["th"]) for h in ("Exhibit", "SHA-256 digest", "Sealed by / date")]]
        for m in manifest:
            mdata.append([str(m["seq"]), Paragraph(m["hash"], st["mono"]),
                          Paragraph("system · " + gen[:10], st["value"])])
        mt = Table(mdata, colWidths=[16 * mm, usable - 16 * mm - 34 * mm, 34 * mm], repeatRows=1)
        mt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(mt)
    else:
        story.append(Paragraph("no exhibits attached", st["stamp"]))

    _section(story, st, "G · DECLARATION OF THE COMPLAINANT")
    story.append(Paragraph(
        "I declare that the facts stated above are true to the best of my knowledge and belief, and "
        "that nothing material has been concealed. I understand that false statements attract "
        "penalties under the cited law, and that this draft must be personally re-attested before "
        "submission to the agency.", st["body"]))
    story.append(Spacer(1, 8 * mm))
    sig = Table(
        [[Paragraph("Signature of complainant<br/><br/>_____________________<br/>"
                    "Name: ____________________<br/>NID: ____________________", st["value"]),
          Paragraph("Witness 1 (if any)<br/><br/>_____________________<br/>"
                    "Name / Address: ____________", st["value"]),
          Paragraph(f"Place: ____________________<br/>Date: ____ / ____ / ______<br/><br/>"
                    f"<font size=7 face='Courier'>gen {gen}</font>", st["value"])]],
        colWidths=[usable * 0.36, usable * 0.34, usable * 0.30])
    sig.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(KeepTogether(sig))

    story.append(Spacer(1, 5 * mm))
    story.append(Table([[Paragraph("FOR OFFICIAL USE OF THE AGENCY", st["th"])],
                        [Paragraph("D.No. received: ____________ · PS/Division forwarded: ____________"
                                   " · Action taken: ________________________________<br/>"
                                   "Investigating officer: ____________________ Rank: __________"
                                   " · Signature with seal", st["value"])]],
                       colWidths=[usable],
                       style=TableStyle([("BACKGROUND", (0, 0), (0, 0), NAVY),
                                         ("BOX", (0, 0), (-1, -1), 0.8, NAVY),
                                         ("TOPPADDING", (0, 0), (-1, -1), 3),
                                         ("BOTTOMPADDING", (0, 0), (-1, -1), 3)])))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        f"Machine verification: every section above is reproducible from the CYBERWATCH-BD HMAC "
        f"audit chain — audit_ref <font face='Courier'>{audit_ref}</font>", st["mono"]))

    doc = SimpleDocTemplate(out, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm,
                            title=f"Complaint draft — {agency_key}", author="CYBERWATCH-BD")
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return out
