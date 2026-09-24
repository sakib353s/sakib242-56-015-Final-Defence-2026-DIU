"""Victim Support — official channels only (FR-V01…V04).
Complaints are DRAFTS for human review, routed to BTRC / Cyber Police.
Timeline is append-only with per-row hash chaining (FR-V03)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.audit import chain
from app.core.errors import CWBError
from app.core.ids import new_id
from app.core.security import canonical_json, dec_field, enc_field, now_iso
from app.db import sqlite as sql

GEN = hashlib.sha256(b"CWB-VICTIM-GEN").hexdigest()


def create_case(case_type: str, complainant: dict, narrative: str, consent_attested: bool,
                actor: str, consent_doc_id: str | None = None) -> dict:
    if case_type not in ("fraud", "harassment", "leak", "other"):
        raise CWBError("case_type must be fraud|harassment|leak|other", status=422)
    if not consent_attested:
        raise CWBError("victim consent record is mandatory before case creation", status=403)
    cid = new_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO victim_cases (id, case_type, complainant_json_enc, narrative,"
            " consent_attested, consent_doc_id, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (cid, case_type, enc_field(canonical_json(complainant)), narrative[:4000],
             1, consent_doc_id, actor, now_iso()),
        )
    append_event(cid, actor, "case.create", {"case_type": case_type})
    return {"case_id": cid, "status": "OPEN"}


def append_event(case_id: str, actor: str, action: str, evidence_ref: str | dict | None = None) -> dict:
    """Immutable timeline append — hash chain per case."""
    if not sql.one("SELECT id FROM victim_cases WHERE id=?", case_id):
        raise CWBError("Case not found", status=404)
    last = sql.one("SELECT seq, hash FROM victim_timeline WHERE case_id=? ORDER BY seq DESC LIMIT 1", case_id)
    seq = (last["seq"] + 1) if last else 1
    prev = last["hash"] if last else GEN
    payload = evidence_ref if isinstance(evidence_ref, dict) else {"evidence_ref": evidence_ref}
    ts = now_iso()
    row_hash = hashlib.sha256(f"{prev}|{ts}|{actor}|{action}|{canonical_json(payload)}".encode()).hexdigest()
    eid = new_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO victim_timeline (id, case_id, seq, ts, actor, action, evidence_ref,"
            " payload_hash, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (eid, case_id, seq, ts, actor, action, json.dumps(payload)[:2000],
             hashlib.sha256(canonical_json(payload).encode()).hexdigest(), prev, row_hash),
        )
    chain.safe_append(actor, "victim.timeline.append", case_id, {"seq": seq, "action": action})
    return {"event_id": eid, "seq": seq, "hash": row_hash}


def verify_timeline(case_id: str) -> dict:
    rows = sql.all_("SELECT * FROM victim_timeline WHERE case_id=? ORDER BY seq ASC", case_id)
    prev = GEN
    for r in rows:
        recomputed = hashlib.sha256(
            f"{r['prev_hash']}|{r['ts']}|{r['actor']}|{r['action']}|"
            f"{canonical_json(json.loads(r['evidence_ref']))}".encode()).hexdigest()
        if r["prev_hash"] != prev or recomputed != r["hash"]:
            return {"ok": False, "broken_at_seq": r["seq"]}
        prev = r["hash"]
    return {"ok": True, "events": len(rows)}


def get_case(case_id: str, actor: str) -> dict:
    case = sql.one("SELECT * FROM victim_cases WHERE id=?", case_id)
    if not case:
        raise CWBError("Case not found", status=404)
    complainant = json.loads(dec_field(case["complainant_json_enc"]))
    timeline = sql.all_("SELECT seq, ts, actor, action, evidence_ref, hash FROM victim_timeline"
                        " WHERE case_id=? ORDER BY seq ASC", case_id)
    chain.safe_append(actor, "victim.case.view", case_id)
    return {"case": {k: case[k] for k in ("id", "case_type", "narrative", "status", "created_at")},
            "complainant": complainant, "timeline": timeline}


def generate_complaints(case_id: str, actor: str) -> dict:
    """FR-V04 + P-06: BTRC and Cyber Police draft PDFs. Consent required; citations
    mandatory; regeneration byte-stable except timestamp block."""
    case = sql.one("SELECT * FROM victim_cases WHERE id=?", case_id)
    if not case:
        raise CWBError("Case not found", status=404)
    if not case["consent_attested"]:
        raise CWBError("Missing consent form — complaint generation blocked", status=403)
    timeline = sql.all_("SELECT * FROM victim_timeline WHERE case_id=? ORDER BY seq ASC", case_id)
    manifest = [{"seq": t["seq"], "hash": t["hash"]} for t in timeline]
    from app.reports import complaint_pdf
    from app.reports.signing import register_report, signed_url
    drafts = {}
    for agency in ("btrc", "cyber_police"):
        p = complaint_pdf.build(case, json.loads(dec_field(case["complainant_json_enc"])),
                                timeline, manifest, agency)
        rid = register_report(p, Path(p).name, f"complaint_{agency}", case_id, actor)
        drafts[agency] = {"report_id": rid, "download": signed_url(p, ttl_s=300)}
    chain.append(actor, "victim.complaint.generate", case_id,
                 {"agencies": ["BTRC", "Cyber Police"], "exhibits": len(manifest)})
    append_event(case_id, actor, "complaint.generate", {"agencies": ["btrc", "cyber_police"]})
    return {"case_id": case_id, "drafts": drafts,
            "note": "DRAFT FOR SUBMISSION — human review required before filing (P-00)"}
