"""P-04 mobile contract tests: ack exactly-once via Idempotency-Key, push-token
registration (settings + chained audit), mobile refresh-token rotation."""
import pyotp


def H(tok, **extra):
    h = {"authorization": f"Bearer {tok}"}
    h.update(extra)
    return h


def test_soc_ack_idempotency_exactly_once(client, tok):
    from app.audit import chain
    from app.modules.soc import service as soc
    line = ('{"event_type":"alert","src_ip":"203.0.113.66","dest_ip":"10.0.0.9",'
            '"alert":{"signature":"ET POLICY Unauthorized SMB relay attempt","category":"'
            'Potential Private Information Leak","severity":1}}')
    row = soc.ingest_eve_line(line)
    assert row and row["severity"] == "CRITICAL"
    aid, key = row["id"], "0f47b1e0-1111-2222-3333-444455556666"
    h = H(tok, **{"Idempotency-Key": key})
    r1 = client.post(f"/api/v1/soc/alerts/{aid}/ack", json={"note": "seen-mobile"}, headers=h)
    assert r1.status_code == 200, r1.text
    r2 = client.post(f"/api/v1/soc/alerts/{aid}/ack", json={"note": "seen-mobile"}, headers=h)
    assert r2.status_code == 200
    assert r1.json() == r2.json()  # byte-identical replay of the stored response
    acks = [e for e in chain.query(200, action="soc.alert.ack") if e["object_ref"] == aid]
    assert len(acks) == 1  # mutation + audit ran exactly once
    # a distinct key is a distinct operation (new uuid = new attempt allowed)
    r3 = client.post(f"/api/v1/soc/alerts/{aid}/ack", json={"note": "again"},
                     headers=H(tok, **{"Idempotency-Key": "0f47b1e0-aaaa-bbbb-cccc-ddddeeeeffff"}))
    assert r3.status_code == 200 and r3.json()["audit_ref"] != r1.json()["audit_ref"]


def test_soc_ack_rejects_malformed_key(client, tok):
    r = client.post("/api/v1/soc/alerts/whatever/ack", json={"note": "x"},
                    headers=H(tok, **{"Idempotency-Key": "short"}))
    assert r.status_code == 422


def test_mobile_push_register(client, tok):
    from app.audit import chain
    from app.db import sqlite as sql
    body = {"push_token": "ExponentPushToken[testmobilepytest0001]"}
    r = client.post("/api/v1/mobile/register", json=body, headers=H(tok))
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["ok"] and j["registered"] is True and j["count"] == 1
    row = sql.one("SELECT value FROM settings WHERE key='mobile_tokens:' || "
                  "(SELECT id FROM users WHERE username='admin')")
    import json
    assert json.loads(row["value"]) == [body["push_token"]]
    # duplicate registration dedupes (no list growth)
    r2 = client.post("/api/v1/mobile/register", json=body, headers=H(tok))
    assert r2.json()["registered"] is False and r2.json()["count"] == 1
    acts = [e["action"] for e in chain.query(50, action="mobile.push")]
    assert acts.count("mobile.push.register") == 2
    # audit rows carry only the fingerprint, never the raw token
    assert all(body["push_token"] not in e["payload_json"] for e in chain.query(50, action="mobile.push"))
    assert client.post("/api/v1/mobile/register", json=body).status_code == 401


def test_mobile_login_refresh_rotation(client, admin):
    # login declares X-Client: mobile -> refresh token returned in body (SecureStore on device)
    r = client.post("/api/v1/auth/login", json={"username": admin["username"],
                                                "password": admin["password"],
                                                "totp": pyotp.TOTP(admin["secret"]).now()},
                    headers={"x-client": "mobile"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get("refresh_token"), "mobile login must include refresh_token"
    cookie = {"cookie": f"cwb_refresh={j['refresh_token']}", "x-client": "mobile"}
    rf = client.post("/api/v1/auth/refresh", headers=cookie)
    assert rf.status_code == 200, rf.text
    rj = rf.json()
    assert rj.get("access_token") and rj["refresh_token"] != j["refresh_token"]  # rotated
    # old refresh is dead (rotation) — replay refused
    assert client.post("/api/v1/auth/refresh", headers=cookie).status_code == 401
    # rotated token works; browser (non-mobile) client gets no body token
    r2 = client.post("/api/v1/auth/refresh",
                     headers={"cookie": f"cwb_refresh={rj['refresh_token']}"})
    assert r2.status_code == 200 and "refresh_token" not in r2.json()
