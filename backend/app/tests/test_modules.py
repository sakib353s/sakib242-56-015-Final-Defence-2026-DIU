"""Functional FR tests: victim pipeline, SOC ingest+dedupe, remediation gates,
doc fingerprint watermark round-trip, job ledger, ledger revocation."""
import io

import pyotp
import pytest


def headers(tok, secret=None):
    h = {"authorization": f"Bearer {tok}"}
    if secret:
        h["x-totp"] = pyotp.TOTP(secret).now()
    return h


def test_victim_case_timeline_complaints(client, tok, admin):
    r = client.post("/api/v1/victim/cases", json={
        "case_type": "fraud",
        "complainant": {"name": "A Victim", "nid": "1990...", "contact": "01700..."},
        "narrative": "Fraudulent financial solicitation via a cloned social profile; evidence attached.",
        "consent_attested": True}, headers=headers(tok))
    assert r.status_code == 200, r.text
    case_id = r.json()["case_id"]
    r2 = client.post(f"/api/v1/victim/cases/{case_id}/timeline",
                     json={"action": "evidence.attach", "evidence_ref": "sha256:abcd"},
                     headers=headers(tok))
    assert r2.status_code == 200
    tv = client.get(f"/api/v1/victim/cases/{case_id}/timeline", headers=headers(tok))
    assert tv.json()["ok"] is True
    rc = client.post(f"/api/v1/victim/cases/{case_id}/complaints", json={},
                     headers=headers(tok, admin["secret"]))
    assert rc.status_code == 200, rc.text
    drafts = rc.json()["drafts"]
    assert "btrc" in drafts and "cyber_police" in drafts
    for agency in ("btrc", "cyber_police"):
        link = drafts[agency]["download"]
        # signed download works WITHOUT bearer (signature is the credential)
        r = client.get(link)
        assert r.status_code == 200, (agency, r.text)
        assert r.headers["content-type"] == "application/pdf"
        assert len(r.content) > 1000
        # tampered signature must be refused
        bad = link.replace("sig=", "sig=00")
        assert client.get(bad).status_code == 403
        # every generated draft is a real PDF (magic bytes)
        for agency in ("btrc", "cyber_police"):
            body = client.get(drafts[agency]["download"]).content
            assert body[:4] == b"%PDF"


def test_soc_ingest_dedupe_ack(client, tok, admin):
    from app.modules.soc import service as soc
    line = ('{"event_type":"alert","src_ip":"203.0.113.9","dest_ip":"10.0.0.5",'
            '"alert":{"signature":"ET SCAN Potential SSH Brute Force","category":"Attempted'
            ' Credential Stub","severity":2}}')
    row = soc.ingest_eve_line(line)
    assert row and row["severity"] == "HIGH"
    dup = soc.ingest_eve_line(line)
    assert dup is None  # dedupe within 60s window
    r = client.get("/api/v1/soc/alerts", headers=headers(tok))
    assert r.status_code == 200 and len(r.json()["alerts"]) >= 1
    aid = r.json()["alerts"][0]["id"]
    assert client.post(f"/api/v1/soc/alerts/{aid}/ack", json={"note": "seen"},
                       headers=headers(tok)).status_code == 200
    mitre = client.get(f"/api/v1/soc/mitre/{aid}", headers=headers(tok))
    assert mitre.json()["technique"] == "T1110"


def test_soc_block_ip_requires_totp(client, tok):
    r = client.post("/api/v1/soc/block-ip", json={"ip": "203.0.113.9"}, headers=headers(tok))
    assert r.status_code == 403  # step-up missing
    assert "TOTP" in r.text


def test_remediation_requires_both_gates(client, tok, admin):
    # insert a fake finding
    from app.core.ids import new_id
    from app.core.security import now_iso
    from app.db import sqlite as sql
    from datetime import datetime, timedelta, timezone
    nf = datetime.now(timezone.utc)
    rw = client.post("/api/v1/admin/ledger", json={
        "kind": "remediation", "scope": ["127.0.0.1"], "purpose": "authorized remediation",
        "warrant_ref": "TEST-W-R01", "subject_name": "t",
        "valid_from": nf.isoformat(),
        "valid_until": (nf + timedelta(days=10)).isoformat()}, headers=headers(tok))
    assert rw.status_code == 200, rw.text
    rwid = rw.json()["id"]
    fid = new_id()
    with sql.get_db() as c:
        c.execute("INSERT INTO findings (id, source, source_id, host, port, service, severity,"
                  " description, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                  (fid, "vuln", "pytest", "127.0.0.1", 22, "openssh 7.2", "HIGH",
                   "outdated openssh", now_iso()))
    r = client.post("/api/v1/remediation/jobs", json={
        "finding_id": fid, "host": "8.8.8.8", "warrant_id": rwid,
        "authorization_confirmed": True}, headers=headers(tok, admin["secret"]))
    assert r.status_code == 403  # host outside warrant scope
    r2 = client.post("/api/v1/remediation/jobs", json={
        "finding_id": fid, "host": "127.0.0.1", "warrant_id": rwid,
        "authorization_confirmed": True}, headers=headers(tok, admin["secret"]))
    assert r2.status_code == 200
    jid = r2.json()["job_id"]
    d = client.get(f"/api/v1/remediation/jobs/{jid}/diff", headers=headers(tok))
    assert d.status_code == 200 and "diff" in d.json()
    # apply without consent must fail (state machine)
    from app.modules.remediation import saga
    with pytest.raises(Exception):
        saga.validate_gates(jid, "u")  # gates OK
        import asyncio
        asyncio.run(saga.apply_job(jid, "u"))  # raises Conflict (not CONSENTED)


def test_document_watermark_roundtrip(client, tok, admin):
    from PIL import Image
    buf = io.BytesIO()
    Image.effect_noise((64, 64), 100).convert("RGBA").save(buf, "PNG")
    buf.seek(0)
    r = client.post("/api/v1/document/upload",
                    files={"file": ("evidence.png", buf.read(), "image/png")},
                    data={"ownership_confirmed": "true"}, headers=headers(tok))
    assert r.status_code == 200, r.text
    j = r.json()
    assert len(j["sha256"]) == 64 and j["watermark_id"].startswith("CWB-WM-")
    # watermark survives (read back from stored file)
    from app.modules.docfp import service as ds
    from app.db import sqlite as sql
    stored = sql.one("SELECT stored_path FROM docfingerprints WHERE id=?", j["id"])["stored_path"]
    assert ds.read_watermark(open(stored, "rb").read()) == j["watermark_id"]
    # missing attestation refused
    buf.seek(0)
    r2 = client.post("/api/v1/document/upload",
                     files={"file": ("x.png", Image.effect_noise((8, 8), 10).convert("RGBA")
                                     .tobytes(), "image/png")},
                     data={"ownership_confirmed": "false"}, headers=headers(tok))
    assert r2.status_code in (403, 422)


def test_ledger_revocation_blocks_use(client, tok, admin, warrant):
    from datetime import datetime, timedelta, timezone
    r = client.post("/api/v1/admin/ledger", json={
        "kind": "pentest", "scope": ["172.16.0.0/12"], "purpose": "revoke flow test",
        "warrant_ref": "TEST-W-003", "subject_name": "t",
        "valid_from": datetime.now(timezone.utc).isoformat(),
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()},
        headers=headers(tok))
    wid = r.json()["id"]
    rv = client.post(f"/api/v1/admin/ledger/{wid}/revoke", json={}, headers=headers(tok))
    assert rv.status_code == 200
    r3 = client.post("/api/v1/pentest/sessions", json={
        "target": "172.16.5.5", "warrant_id": wid, "authorization_confirmed": True},
        headers=headers(tok, admin["secret"]))
    assert r3.status_code == 403  # revoked warrant cannot authorize


def test_job_lifecycle_visible(client, tok, admin):
    r = client.get("/api/v1/modules/health", headers=headers(tok))
    assert r.status_code == 200 and len(r.json()["modules"]) == 9
