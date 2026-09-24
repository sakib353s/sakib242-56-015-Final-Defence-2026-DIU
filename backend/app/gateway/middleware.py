"""Gateway middleware — exact chain per P-02:

CORS → RateLimit(slowapi) → AuthN(JWT) → [RBAC via deps] → [Audit via services] → Router
plus SecurityHeaders + UUIDv7 request-id propagation.
"""
from __future__ import annotations

import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import get_settings
from app.core.errors import TooFast
from app.core.ids import new_id
from app.core.security import decode_access

S = get_settings()

limiter = Limiter(key_func=get_remote_address, headers_enabled=False)


class GlobalRateLimit(BaseHTTPMiddleware):
    """100 req/min/IP sliding window on /api/v1 — the spec's default tier.
    Per-route tiers (login 5/min) stack on top via slowapi decorators."""

    def __init__(self, app, limit: int = 100, window_s: int = 60):
        super().__init__(app)
        self.limit, self.window = limit, window_s
        self._hits: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api/v1"):
            return await call_next(request)
        ip = (request.client.host if request.client else "unknown")
        now = time.time()
        hits = [t for t in self._hits.get(ip, []) if now - t < self.window]
        if len(hits) >= self.limit:
            return JSONResponse(
                {"type": "https://cwb.bd/err/rate-limited", "title": "Rate limit exceeded",
                 "status": 429, "detail": f"{self.limit}/min/IP", "audit_ref": None,
                 "request_id": getattr(request.state, "request_id", "")},
                status_code=429,
                headers={"Retry-After": str(int(self.window - (now - hits[0])) or 1)},
            )
        hits.append(now)
        self._hits[ip] = hits
        return await call_next(request)

# Exact paths that may pass unauthenticated. /auth/refresh authenticates with the
# rotating httpOnly cookie (or X-Client: mobile header flow) — a Bearer check here
# would deadlock the 15-min expiry cycle, so it stays out of the gate.
PUBLIC_API = {"/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/boot/token", "/api/v1/health",
              "/api/v1/config", "/api/v1/app-release", "/api/v1/app-release/download"}
PUBLIC_PREFIX = ("/docs", "/openapi.json", "/redoc")


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id") or f"cwb-{new_id()}"
        request.state.request_id = rid
        start = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        response.headers["X-Elapsed-Ms"] = f"{(time.perf_counter() - start) * 1000:.1f}"
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response


class AuthNMiddleware(BaseHTTPMiddleware):
    """Coarse boundary: everything under /api/v1 requires a valid JWT unless public.
    Fine-grained RBAC is enforced per-route via require_role deps."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Signed report downloads authenticate by HMAC(expiry) in the query string —
        # the signature IS the credential (works for browser tabs, mobile, email links).
        if path.startswith("/api/v1/reports/") and path.endswith("/download"):
            return await call_next(request)
        if path.startswith("/api/v1") and path not in PUBLIC_API and not path.startswith(PUBLIC_PREFIX):
            header = request.headers.get("authorization", "")
            claims = None
            if header.startswith("Bearer "):
                try:
                    claims = decode_access(header[7:])
                except Exception:
                    claims = None
            if claims is None:
                return JSONResponse(
                    {
                        "type": "https://cwb.bd/err/unauthorized",
                        "title": "Authentication required",
                        "status": 401,
                        "detail": "Valid bearer access token required for this route",
                        "audit_ref": None,
                        "request_id": getattr(request.state, "request_id", ""),
                    },
                    status_code=401,
                    media_type="application/problem+json",
                )
            request.state.claims = claims
        return await call_next(request)


def install(app: FastAPI) -> None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    # NOTE Starlette applies middleware bottom-up; add in REVERSE of the spec chain
    # so the runtime order is CORS → RateLimit → AuthN → RequestID → SecurityHeaders.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(AuthNMiddleware)
    app.add_middleware(GlobalRateLimit, limit=100, window_s=60)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=S.origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-TOTP", "X-Request-ID", "X-Date",
                       "X-Client", "Idempotency-Key"],
    )
