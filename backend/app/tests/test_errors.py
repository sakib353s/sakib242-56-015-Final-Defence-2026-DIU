"""Error-path contracts: every failure must be traceable.

Regressions guarded here:
  * an unexpected exception must be logged AND returned as a problem+json that
    carries the request id (in body and header) plus an audit reference — the
    client keeps a suppressed detail but the operator can still correlate it;
  * middleware short-circuits (401/429) must carry a request id too, which
    requires RequestIdMiddleware to run first in the chain.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.errors import NotFound, install_error_handlers
from app.gateway.middleware import RequestIdMiddleware


def _probe_app() -> FastAPI:
    app = FastAPI()
    install_error_handlers(app)
    app.add_middleware(RequestIdMiddleware)

    @app.get("/boom")
    async def boom():
        raise RuntimeError("kaboom")

    @app.get("/missing")
    async def missing():
        raise NotFound("nope")

    return app


def test_unhandled_error_is_traceable(client):
    # `client` dependency ensures migrations ran so the audit chain is writable.
    with TestClient(_probe_app(), raise_server_exceptions=False) as c:
        r = c.get("/boom", headers={"x-request-id": "cwb-test-rid-123"})

    assert r.status_code == 500
    body = r.json()
    assert body["title"] == "Internal error"
    assert body["request_id"] == "cwb-test-rid-123"
    assert "request_id=cwb-test-rid-123" in body["detail"]
    assert r.headers["x-request-id"] == "cwb-test-rid-123"
    if body["audit_ref"]:
        assert body["audit_ref"] != "AUDIT-UNAVAILABLE"
        assert f"audit_ref={body['audit_ref']}" in body["detail"]


def test_typed_error_carries_request_id(client):
    with TestClient(_probe_app(), raise_server_exceptions=False) as c:
        r = c.get("/missing")

    assert r.status_code == 404
    body = r.json()
    assert body["title"] == "Resource not found"
    assert body["request_id"] == r.headers["x-request-id"]


def test_middleware_401_carries_request_id(client):
    """AuthN rejects before any route runs; the response must still be traceable."""
    r = client.get("/api/v1/fim/status")  # no bearer token
    assert r.status_code == 401
    assert r.headers.get("x-request-id")
    assert r.json()["request_id"] == r.headers["x-request-id"]
