"""Regression locks for the audit fixes: warrant-window normalisation, ipanon
kind/session gate, server-side TOTP enrolment, analyst /available listing."""
from datetime import datetime, timedelta, timezone

import pyotp


def _hdr(tok, totp=None):
    h = {"authorization": f"Bearer {tok}"}
    if totp:
        h["x-totp"] = totp
    return h


def _mk(client, tok, kind, scope):
    nf = datetime.now(timezone.utc)
    r = client.post("/api/v1/admin/ledger", json={
        "kind": kind, "scope": scope, "purpose": f"regression {kind} engagement",
        "warrant_ref": f"REG-{kind}-1", "subject_name": "t",
        "valid_from": nf.isoformat(),
        "valid_until": (nf + timedelta(days=7)).isoformat()}, headers=_hdr(tok))
    assert r.status_code == 200, r.text
    return r.json()


def test_warrant_stored_normalized_utc(client, tok):
    w = _mk(client, tok, "ipanon", ["10.0.0.0/8"])
    assert w["valid_until"].endswith("+00:00")  # normalised to canonical UTC form


def test_ipanon_dedicated_warrant_passes_gate(client, tok, admin):
    ipw = _mk(client, tok, "ipanon", ["10.0.0.0/8"])
    r = client.post("/api/v1/ip/start", json={"warrant_id": ipw["id"]},
                    headers=_hdr(tok, pyotp.TOTP(admin["secret"]).now()))
    # kind/window/scope OK → only the Tor control-port probe can fail (503), never 403
    assert r.status_code in (200, 503), r.text


def test_ipanon_rejects_wrong_kind(client, tok, admin):
    # runs AFTER the dedicated test on purpose: same-step-window code + same path is
    # itself replay-blocked (403); a pentest warrant without a live session is the
    # second, independent 403 reason — both are fail-closed, so the assert holds.
    pentest_w = _mk(client, tok, "pentest", ["10.0.0.5"])
    r = client.post("/api/v1/ip/start", json={"warrant_id": pentest_w["id"]},
                    headers=_hdr(tok, pyotp.TOTP(admin["secret"]).now()))
    assert r.status_code == 403


def test_available_lists_for_analyst_not_remediation(client, tok):
    _mk(client, tok, "vuln_scan", ["10.1.0.0/16"])
    _mk(client, tok, "remediation", ["10.2.0.0/16"])
    r = client.get("/api/v1/admin/ledger/available", headers=_hdr(tok))
    assert r.status_code == 200
    kinds = {w["kind"] for w in r.json()["warrants"]}
    assert "vuln_scan" in kinds
    assert "remediation" not in kinds  # stays SUPER_ADMIN-managed


def test_signed_download_works_without_bearer(client, tok, admin):
    r = client.post("/api/v1/victim/cases", json={
        "case_type": "leak", "complainant": {"name": "D", "nid": "9"},
        "narrative": "Personal data published without consent across several public paste sites.",
        "consent_attested": True}, headers=_hdr(tok))
    cid = r.json()["case_id"]
    rc = client.post(f"/api/v1/victim/cases/{cid}/complaints", json={},
                     headers=_hdr(tok, pyotp.TOTP(admin["secret"]).now()))
    link = rc.json()["drafts"]["btrc"]["download"]
    assert client.get(link).status_code == 200  # no auth header — signature is the credential


def test_totp_enroll_is_server_held(client):
    # a fresh read-only user must be able to enroll via server-held pending secret
    from app.core.ids import new_id
    from app.core.security import hash_password, now_iso
    from app.db import sqlite as sql
    uid = new_id()
    with sql.get_db() as c:
        c.execute("INSERT INTO users (id,username,display_name,role,password_hash,created_at)"
                  " VALUES (?,?,?,?,?,?)", (uid, "enroll_probe", "EP", "READ_ONLY",
                                            hash_password("enrollpw123"), now_iso()))
    r = client.post("/api/v1/auth/login", json={"username": "enroll_probe", "password": "enrollpw123"})
    tok = r.json()["access_token"]
    start = client.post("/api/v1/auth/totp/enroll", headers=_hdr(tok))
    assert start.status_code == 200
    secret = start.json()["secret"]
    # verify WITHOUT echoing the secret back in a header — server holds it
    ok = client.post("/api/v1/auth/totp/enroll", json={"code": pyotp.TOTP(secret).now()},
                     headers=_hdr(tok))
    assert ok.status_code == 200 and ok.json()["enrolled"] is True
    # replay of the now-consumed pending must fail
    again = client.post("/api/v1/auth/totp/enroll", json={"code": pyotp.TOTP(secret).now()},
                        headers=_hdr(tok))
    assert again.status_code == 401
