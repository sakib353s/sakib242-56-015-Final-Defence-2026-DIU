"""FREE-tier OSINT path tests (T-O01/T-O04 spirit) — no paid keys anywhere.
Network-guarded: skips cleanly when the sandbox has no outbound access."""
import secrets

import httpx
import pytest


def _online() -> bool:
    try:
        return httpx.get("https://haveibeenpwned.com/api/v3/breaches",
                         headers={"user-agent": "cwb-test"}, timeout=8).status_code == 200
    except Exception:
        return False


requires_net = pytest.mark.skipif(not _online(), reason="no outbound network")


@requires_net
def test_email_free_tier_domain_level(client, tok):
    r = client.get("/api/v1/osint/email?e=student@adobe.com",
                   headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert "FREE" in j["mode"] or "domain-level" in j["mode"]
    assert j["domain"] == "adobe.com"
    assert any(b["Name"] == "Adobe" for b in j["breaches"])  # real registry data
    assert j["registry_total"] and j["registry_total"] > 500


@requires_net
def test_password_k_anonymity_both_directions(client, tok):
    h = {"authorization": f"Bearer {tok}"}
    r = client.post("/api/v1/osint/password", json={"password": "password123"}, headers=h)
    assert r.status_code == 200 and r.json()["pwned"] is True
    assert r.json()["approximate_exposures"] > 1000
    secret = "Xz" + secrets.token_urlsafe(14)
    r2 = client.post("/api/v1/osint/password", json={"password": secret}, headers=h)
    assert r2.status_code == 200 and r2.json()["pwned"] is False


@requires_net
def test_no_pii_in_audit_rows(client, tok):
    """Audit must carry subject hashes only — never the email/password itself."""
    from app.audit import chain
    email = f"probe{secrets.token_hex(3)}@adobe.com"
    r = client.get(f"/api/v1/osint/email?e={email}",
                   headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    for row in chain.query(20, action="osint.query.email"):
        assert email not in row["payload_json"]
        assert "subject_hash" in row["payload_json"]


@requires_net
def test_osint_handshake_free_first(client, tok):
    r = client.get("/api/v1/modules/health", headers={"authorization": f"Bearer {tok}"})
    hs = {m["module"]: m for m in r.json()["modules"]}
    assert hs["osint"]["status"] in ("OK", "WARN")  # never FAIL without paid keys
    assert "free" in hs["osint"]["detail"] or "HIBP registry" in hs["osint"]["detail"]
