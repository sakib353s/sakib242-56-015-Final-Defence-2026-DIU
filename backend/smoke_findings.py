import json
import time
import urllib.request

BASE = "http://127.0.0.1:8471/api/v1"


def req(method, path, token=None, body=None, totp=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("content-type", "application/json")
    if token:
        r.add_header("authorization", f"Bearer {token}")
    if totp:
        r.add_header("x-totp", totp)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


from app.db import sqlite as sql
from app.core.security import dec_field
import pyotp

_, login = req("POST", "/auth/login", body={"username": "admin", "password": "yC99hFdTVZ6BcEhi56"})
tok = login.get("access_token")
assert tok, f"login failed: {login}"

sec = dec_field(sql.one("SELECT totp_secret_enc FROM users WHERE username='admin'")["totp_secret_enc"])
code = lambda: pyotp.TOTP(sec).now()

_, led = req("GET", "/admin/ledger", token=tok)
warrants = [w for w in led.get("warrants", []) if w["kind"] == "pentest"]
wid = warrants[0]["id"]

st, created = req("POST", "/assessment", token=tok, totp=code(),
                  body={"target": "https://example.com", "warrant_id": wid,
                        "profile": "quick", "authorization_confirmed": True})
aid = created.get("id")
assert aid, f"create failed: {created}"
req("POST", f"/assessment/{aid}/start", token=tok, totp=code())

for _ in range(15):
    time.sleep(2)
    _, d = req("GET", f"/assessment/{aid}", token=tok)
    if d["assessment"]["status"] in ("COMPLETED", "FAILED", "PARTIAL", "UNKNOWN_RESULT"):
        break

findings = d["findings"]
print(f"assessment={d['assessment']['status']} findings={len(findings)}")
assert findings, "no findings produced — cannot test lifecycle"
fid = findings[0]["id"]

print("--- queue view ---")
st, q = req("GET", "/findings/queue?min_severity=informational&limit=50", token=tok)
print("queue HTTP", st, "| entries:", len(q.get("queue", [])))

print("--- get one ---")
st, one = req("GET", f"/findings/{fid}", token=tok)
print("get HTTP", st, "| lifecycle:", one["finding"]["lifecycle"], "| warrant:", one.get("warrant_id"))

print("--- transition detected -> triaged (ANALYST ok) ---")
st, tr = req("POST", f"/findings/{fid}/transition", token=tok,
             body={"to_state": "triaged", "reason": "smoke-test triage"})
print("HTTP", st, "->", tr.get("lifecycle") or tr.get("detail"))

print("--- transition triaged -> validating ---")
st, tr = req("POST", f"/findings/{fid}/transition", token=tok,
             body={"to_state": "validating", "reason": "repro pending"})
print("HTTP", st, "->", tr.get("lifecycle") or tr.get("detail"))

print("--- invalid edge triaged -> verified_fixed must be refused ---")
st, bad = req("POST", f"/findings/{fid}/transition", token=tok,
              body={"to_state": "verified_fixed", "reason": "should not be allowed"})
print("HTTP", st, "(expect 4xx)", "->", bad.get("title"), "/", bad.get("detail", "")[:80])

print("--- transition validating -> confirmed ---")
st, tr = req("POST", f"/findings/{fid}/transition", token=tok,
             body={"to_state": "confirmed", "reason": "manually reproduced"})
print("HTTP", st, "->", tr.get("lifecycle") or tr.get("detail"))

print("--- retest dispatch (real adapter re-check) ---")
st, rt = req("POST", f"/findings/{fid}/retest", token=tok, totp=code())
print("dispatch HTTP", st, "->", rt.get("status"))
time.sleep(6)
st, after = req("GET", f"/findings/{fid}", token=tok)
f = after["finding"]
print("after retest: lifecycle=", f["lifecycle"], "| verify_result=", (f.get("verify_result") or "")[:90],
      "| retest_count=", f.get("retest_count"))

print("--- history ---")
st, hist = req("GET", f"/findings/{fid}", token=tok)
print("transitions recorded:", len(hist.get("history", [])),
      [(h["from_lifecycle"], h["to_lifecycle"]) for h in hist.get("history", [])])