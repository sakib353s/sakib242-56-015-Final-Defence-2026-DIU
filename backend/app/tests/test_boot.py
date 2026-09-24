"""T-MB01 + boot fail-closed (P-01 acceptance: no cosmetic checks; freeze on FAIL)."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app.core import boot as boot_mod
from app.main import app


def _collect_boot(client, monkeypatch=None, break_probe=None):
    """Runs the boot WS and returns (status_list, raw_lines)."""
    tok = client.post("/api/v1/boot/token").json()["boot_token"]
    statuses, lines = [], []
    with client.websocket_connect(f"/ws/boot?token={tok}") as ws:
        while True:
            try:
                msg = ws.receive_json()
            except Exception:
                break
            lines.append(msg)
            statuses.append(msg["status"])
            if msg["status"] == "FAIL":
                break
    return statuses, lines


def test_boot_streams_full_sequence(client):
    statuses, lines = _collect_boot(client)
    assert "FAIL" not in statuses, lines[-1]
    joined = "\n".join(l["label"] for l in lines)
    # grammar + stage coverage
    assert "CWB-BIOS" in joined
    assert "Entropy pool seeded" in joined
    assert "HMAC audit chain armed" in joined
    assert "MODULE Pentest Engine" in joined
    assert "COMPLIANCE" in joined
    assert "READY" in joined  # S8 attestation-complete hand-off
    assert "SESSION" in joined and "minted" in joined  # reached S8 in lab mode


def test_boot_fail_closed_freeze(client, monkeypatch):
    """Inject a real failure: entropy check must freeze before AUTH GATE (S8)."""
    real_open = open

    def fake_open(path, mode="r", *a, **k):
        if str(path) == "/dev/urandom":
            raise OSError("injected entropy failure")
        return real_open(path, mode, *a, **k)

    monkeypatch.setattr(boot_mod, "open", fake_open, raising=False)
    statuses, lines = _collect_boot(client)
    assert "FAIL" in statuses
    assert "READY" not in "\n".join(l["label"] for l in lines)
    fail_line = next(l for l in lines if l["status"] == "FAIL")
    assert "audit_ref=" in fail_line["detail"]  # remediation + audit reference


def test_boot_token_single_use(client):
    tok = client.post("/api/v1/boot/token").json()["boot_token"]
    with client.websocket_connect(f"/ws/boot?token={tok}") as ws:
        ws.receive_json()
    with client.websocket_connect(f"/ws/boot?token={tok}") as ws2:
        msg = ws2.receive_json()
        assert msg["status"] == "FAIL"


def test_health_and_request_id(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["asgi_ready"] is True
    assert r.headers["x-request-id"].startswith("cwb-")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
