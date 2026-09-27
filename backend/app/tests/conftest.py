import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="cwb-test-")
os.environ["CWB_ENV"] = "lab"
os.environ["CWB_TOTP_ENFORCE"] = "on"  # tests must keep exercising the step-up gate
os.environ["CWB_WARRANT_ENFORCE"] = "on"  # tests must keep exercising the warrant gate
os.environ["CWB_DATABASE_PATH"] = str(Path(_tmp) / "test.db")
os.environ["CWB_REPORTS_DIR"] = str(Path(_tmp) / "reports")
os.environ["CWB_UPLOADS_DIR"] = str(Path(_tmp) / "uploads")
os.environ["CWB_MONGO_URI"] = ""
os.environ["CWB_SURICATA_EVE_PATH"] = ""
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:  # context manager runs lifespan (migrations!)
        yield c


@pytest.fixture(scope="session")
def admin(client):
    from app.scripts import seed
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        seed.main()
    text = buf.getvalue()
    pw = [l.split(": ")[1].strip() for l in text.splitlines() if l.strip().startswith("password")][0]
    sec = [l.split(": ")[1].strip() for l in text.splitlines() if l.strip().startswith("totp")][0]
    return {"username": "admin", "password": pw, "secret": sec}


@pytest.fixture(scope="session")
def tok(client, admin):
    import pyotp
    r = client.post("/api/v1/auth/login", json={"username": admin["username"],
                                                "password": admin["password"],
                                                "totp": pyotp.TOTP(admin["secret"]).now()})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def hdr(tok, totp=None):
    h = {"authorization": f"Bearer {tok}"}
    if totp:
        h["x-totp"] = totp
    return h


@pytest.fixture()
def warrant(client, tok, admin):
    from datetime import datetime, timedelta, timezone
    nf = datetime.now(timezone.utc)
    r = client.post("/api/v1/admin/ledger", json={
        "kind": "pentest", "scope": ["127.0.0.1", "10.0.0.0/8"],
        "purpose": "pytest authorized engagement", "warrant_ref": "TEST-W-001",
        "subject_name": "test lab", "valid_from": nf.isoformat(),
        "valid_until": (nf + timedelta(days=30)).isoformat(),
    }, headers=hdr(tok))
    assert r.status_code == 200, r.text
    return {"id": r.json()["id"], "secret": admin["secret"]}
