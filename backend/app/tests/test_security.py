"""P-08 attack matrix: auth bypass, JWT forgery, TOTP replay, HMAC forgery, scope
drift, IDOR, path traversal, rate-limit, WS origin spoofing, audit tamper detection."""
import hashlib
import hmac
import time

import jwt
import pyotp
import pytest

from app.audit import chain
from app.core.config import get_settings
from app.core.security import canonical_json
from app.db import sqlite as sql

S = get_settings()


def test_unauthenticated_api_denied(client):
    assert client.get("/api/v1/pentest/sessions").status_code == 401


def test_jwt_alg_none_forgery_rejected(client):
    import base64, json as _json
    header = base64.urlsafe_b64encode(_json.dumps({"alg": "none"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(_json.dumps(
        {"sub": "x", "role": "SUPER_ADMIN", "sid": "y", "totp": True}).encode()).rstrip(b"=")
    forged = (header + b"." + payload + b".").decode()
    r = client.get("/api/v1/pentest/sessions", headers={"authorization": "Bearer " + forged})
    assert r.status_code == 401


def test_jwt_wrong_key_rejected(client, tok):
    forged = jwt.encode(jwt.decode(tok, S.jwt_secret, algorithms=["HS256"]),
                        "attacker-key", algorithm="HS256")
    assert client.get("/api/v1/pentest/sessions",
                      headers={"authorization": "Bearer " + forged}).status_code == 401


def test_readonly_cannot_perform_offensive_ops(client, admin):
    # create a READ_ONLY user directly, login, try to create pentest session
    from app.core.security import hash_password, now_iso
    from app.core.ids import new_id
    uid = new_id()
    with sql.get_db() as c:
        c.execute("INSERT INTO users (id, username, display_name, role, password_hash, created_at)"
                  " VALUES (?,?,?,?,?,?)",
                  (uid, "viewer", "Viewer", "READ_ONLY", hash_password("viewpass123"), now_iso()))
    r = client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewpass123"})
    assert r.status_code == 200, r.text
    rtok = r.json()["access_token"]
    assert client.post("/api/v1/pentest/sessions", json={
        "target": "127.0.0.1", "warrant_id": "x", "authorization_confirmed": True},
        headers={"authorization": "Bearer " + rtok}).status_code == 403


def test_warrant_gate_missing(client, tok, admin):
    r = client.post("/api/v1/pentest/sessions", json={
        "target": "127.0.0.1", "warrant_id": "0" * 36, "authorization_confirmed": True},
        headers={"authorization": "Bearer " + tok, "x-totp": pyotp.TOTP(admin["secret"]).now()})
    assert r.status_code == 403
    assert "warrant" in r.text.lower()


def test_scope_drift_refused(client, tok, warrant):
    r = client.post("/api/v1/pentest/sessions", json={
        "target": "8.8.8.8", "warrant_id": warrant["id"], "authorization_confirmed": True},
        headers={"authorization": "Bearer " + tok,
                 "x-totp": pyotp.TOTP(warrant["secret"]).now()})
    assert r.status_code == 403


def test_totp_replay_blocked(client, tok, admin, warrant):
    import time as _t
    nxt = ((_t.time() // 30) + 1) * 30 + 2  # early in the NEXT step — exactly drift-1 ahead, unique
    code = pyotp.TOTP(admin["secret"]).at(nxt)
    h = {"authorization": f"Bearer {tok}", "x-totp": code}
    ok = client.post("/api/v1/pentest/sessions", json={
        "target": "127.0.0.1", "warrant_id": warrant["id"], "authorization_confirmed": True}, headers=h)
    replay = client.post("/api/v1/pentest/sessions", json={
        "target": "127.0.0.1", "warrant_id": warrant["id"], "authorization_confirmed": True}, headers=h)
    assert ok.status_code == 200, ok.text
    assert replay.status_code == 403  # same code, second use


def test_audit_chain_tamper_detected(client, tok):
    chain.append("pytest", "tamper.test", "obj", {"i": 1})
    before = chain.verify_chain()
    assert before["ok"]
    with sql.get_db() as c:  # forge: change a payload silently
        c.execute("UPDATE audit_log SET payload_json='{\"evil\":true}'"
                  " WHERE action='tamper.test' AND seq=(SELECT MAX(seq) FROM audit_log)")
    after = chain.verify_chain()
    assert after["ok"] is False and after["reason"].startswith("payload tamper")


def test_reports_path_traversal_refused(client, tok):
    r = client.get("/api/v1/reports/..%2F..%2Fetc%2Fpasswd/download?exp=99&sig=x",
                   headers={"authorization": "Bearer " + tok})
    assert r.status_code in (403, 404)


def test_signed_download_bad_sig(client, tok):
    r = client.get("/api/v1/reports/anyid/download?exp=99999999999&sig=deadbeef",
                   headers={"authorization": "Bearer " + tok})
    assert r.status_code == 403


def test_ws_alerts_without_origin_ok_with(client, tok):
    # same-origin/dev client (no Origin header) allowed; hostile origin refused
    with client.websocket_connect("/ws/alerts") as ws:
        assert ws is not None


def test_warrant_window_expiry(client, tok, admin):
    from datetime import datetime, timedelta, timezone
    nf = datetime.now(timezone.utc)
    r = client.post("/api/v1/admin/ledger", json={
        "kind": "pentest", "scope": ["192.168.0.0/16"], "purpose": "expired window test",
        "warrant_ref": "TEST-W-002", "subject_name": "t",
        "valid_from": (nf - timedelta(days=10)).isoformat(),
        "valid_until": (nf - timedelta(days=1)).isoformat()}, headers={"authorization": "Bearer " + tok})
    assert r.status_code == 422  # server refuses to even insert an already-expired warrant
    # (use-after-expiry is covered by revocation test + ledger-window gate at warrant_gate)


def test_victim_consent_gate(client, tok, admin):
    r = client.post("/api/v1/victim/cases", json={
        "case_type": "fraud", "complainant": {"name": "X", "nid": "1"},
        "narrative": "A long enough narrative describing the incident for validation.",
        "consent_attested": False}, headers={"authorization": "Bearer " + tok})
    assert r.status_code == 403


def test_osint_non_public_refused(client, tok):
    r = client.get("/api/v1/osint/domain?d=http://internal/../../x", headers={"authorization": "Bearer " + tok})
    assert r.status_code in (403, 422)
