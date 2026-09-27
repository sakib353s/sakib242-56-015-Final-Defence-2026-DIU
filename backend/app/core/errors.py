"""RFC 7807 problem+json errors for CYBERWATCH-BD."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("cwb.errors")


class CWBError(Exception):
    type_uri = "https://cwb.bd/err/internal"
    title = "Internal error"
    status = 500

    def __init__(self, detail: str = "", audit_ref: str = "", request_id: str = "",
                 status: int | None = None):
        self.detail = detail
        self.audit_ref = audit_ref
        self.request_id = request_id
        if status is not None:
            self.status = status
            self.title = detail or self.title
        super().__init__(detail)

    def problem(self) -> dict:
        return {
            "type": self.type_uri,
            "title": self.title,
            "status": self.status,
            "detail": self.detail or self.title,
            "instance": None,
            "audit_ref": self.audit_ref or None,
            "request_id": self.request_id or None,
        }


class Unauthorized(CWBError):
    type_uri, title, status = "https://cwb.bd/err/unauthorized", "Authentication required", 401


class Forbidden(CWBError):
    type_uri, title, status = "https://cwb.bd/err/forbidden", "Authorization denied", 403


class WarrantMissing(Forbidden):
    type_uri = "https://cwb.bd/err/warrant-missing"
    title = "Active written-authorization warrant required"


class ScopeDrift(Forbidden):
    type_uri = "https://cwb.bd/err/scope-drift"
    title = "Target outside warrant scope — operation aborted"


class NotFound(CWBError):
    type_uri, title, status = "https://cwb.bd/err/not-found", "Resource not found", 404


class Conflict(CWBError):
    type_uri, title, status = "https://cwb.bd/err/conflict", "Resource state conflict", 409


class TooFast(CWBError):
    type_uri, title, status = "https://cwb.bd/err/rate-limited", "Rate limit exceeded", 429


class StepUpRequired(Forbidden):
    type_uri = "https://cwb.bd/err/totp-stepup"
    title = "Fresh TOTP step-up required for this action"


class RefusedOutOfWork(CWBError):
    type_uri = "https://cwb.bd/err/out-of-scope"
    title = "Refused: action is outside CYBERWATCH-BD legal scope"
    status = 422


def _rid(request: Request) -> str:
    return getattr(request.state, "request_id", "") or ""


def _problem_response(prob: CWBError, status: int, request: Request) -> JSONResponse:
    """Always echo the request id in both the body and the header, so a client that
    only kept the HTTP response can still quote a traceable reference."""
    rid = _rid(request)
    resp = JSONResponse(prob.problem(), status_code=status,
                        media_type="application/problem+json")
    if rid:
        resp.headers["X-Request-ID"] = rid
    return resp


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(CWBError)
    async def _cwb(request: Request, exc: CWBError):
        exc.request_id = _rid(request)
        return _problem_response(exc, exc.status, request)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        prob = CWBError(str(exc.detail), request_id=_rid(request))
        prob.__class__ = type("HTTPAdapted", (CWBError,),
                             {"type_uri": "https://cwb.bd/err/http",
                              "title": exc.detail if isinstance(exc.detail, str) else "HTTP error",
                              "status": exc.status_code})
        return _problem_response(prob, exc.status_code, request)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        prob = CWBError("Request validation failed: " + str(exc.errors()[:3]))
        prob.type_uri = "https://cwb.bd/err/validation"
        prob.title = "Request validation failed"
        prob.status = 422
        prob.request_id = _rid(request)
        return _problem_response(prob, 422, request)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        rid = _rid(request)
        # Never swallow the trace: the client keeps a suppressed detail, but the
        # operator MUST be able to correlate request_id -> stack trace.
        log.exception("unhandled %s on %s %s (request_id=%s)",
                      type(exc).__name__, request.method, request.url.path, rid or "-")
        ref = ""
        try:
            from app.audit import chain
            ref = chain.safe_append(
                "system:error", "system.error.unhandled", request.url.path,
                {"request_id": rid, "error": type(exc).__name__,
                 "message": str(exc)[:200]},
            )
        except Exception:  # audit must never mask the primary failure
            ref = ""
        trace = f"request_id={rid}" if rid else "request_id unavailable"
        if ref and ref != "AUDIT-UNAVAILABLE":
            trace += f" · audit_ref={ref}"
        prob = CWBError(f"Unhandled internal error (details suppressed) · {trace}",
                        audit_ref=ref, request_id=rid)
        return _problem_response(prob, 500, request)
