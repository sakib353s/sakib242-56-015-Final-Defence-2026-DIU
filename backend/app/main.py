"""CYBERWATCH-BD cwb-core — FastAPI application assembly (P-02).

Middleware chain (spec order): CORS → RateLimit → AuthN → RBAC(deps) → Audit(services)
→ Router; plus SecurityHeaders + UUIDv7 request-id propagation.
Lifespan: migrations, policy-hash pin, background workers (EVE tail, audit verifier,
block-expiry watchdog, circuit heartbeat/watchdog).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.audit import chain, verifier
from app.audit.router import router as audit_router
from app.core.boot import BootRunner  # noqa: F401 (attested import)
from app.core.config import get_settings
from app.core.errors import install_error_handlers
from app.core.security import now_iso as _now_iso
from app.db import sqlite as sql
from app.gateway import middleware
from app.gateway.app_router import router as app_release_router
from app.gateway.auth_router import router as auth_router
from app.gateway.boot_router import router as boot_router
from app.gateway.deps import Principal, require_analyst
from app.gateway.ledger_router import router as ledger_router
from app.gateway.mobile_router import router as mobile_router
from app.gateway.ws_router import router as ws_router
from app.modules.docfp.router import router as docfp_router
from app.modules.hwmon.router import router as hwmon_router
from app.modules.ipanon import service as ipanon_service
from app.modules.ipanon.router import router as ipanon_router
from app.modules.osint.router import router as osint_router
from app.modules.pentest.router import router as pentest_router
from app.modules.remediation.router import router as remediation_router
from app.modules.soc import service as soc_service
from app.modules.soc.router import router as soc_router
from app.modules.system import service as system_service
from app.modules.tools.router import router as tools_router
from app.modules.system.router import router as system_router
from app.modules.victim.router import router as victim_router
from app.modules.vuln.router import router as vuln_router
from app.modules.assessment.router import router as assessment_router
from app.modules.findings.router import router as findings_router
from app.modules.threatintel.router import router as ti_router
from app.modules.fim.router import router as fim_router
from app.modules.fim import scanner as fim_scanner
from app.reports.router import router as reports_router

S = get_settings()
log = logging.getLogger("cwb.main")


def _pin_policy_hash() -> tuple[str, str]:
    """First boot pins sha256(rulepack) into settings + audit ('immutable constant').
    Later boots compare against it. CWB_POLICY_HASH_CONSTANT env wins if set."""
    rulepack = Path(__file__).parent / "core" / "policy_rulepack.json"
    actual = hashlib.sha256(rulepack.read_bytes()).hexdigest()
    stored = sql.scalar("SELECT value FROM settings WHERE key='policy_hash'")
    if S.policy_hash_constant:
        if S.policy_hash_constant != actual:
            raise RuntimeError("policy rulepack does not match pinned constant — refuse to start")
        return actual, "env"
    if stored is None:
        with sql.get_db() as c:
            c.execute("INSERT INTO settings (key, value, updated_at) VALUES ('policy_hash',?, "
                      "datetime('now'))", (actual,))
        chain.append("system:boot", "policy.hash_pin", "policy_rulepack", {"sha256": actual,
                                                                           "note": "first-boot pin"})
        return actual, "pinned"
    if stored != actual:
        raise RuntimeError("policy rulepack tampered vs pinned setting — refuse to start")
    return actual, "verified"


@asynccontextmanager
async def lifespan(app: FastAPI):
    applied = sql.run_migrations()
    if applied:
        log.info("migrations applied: %s", applied)
    _pin_policy_hash()
    app.state.asgi_ready = True
    tasks = [
        asyncio.create_task(verifier.verifier_loop()),
        asyncio.create_task(soc_service.eve_tail()),
        asyncio.create_task(soc_service.block_expiry_watchdog()),
        asyncio.create_task(_ipanon_heartbeat_loop()),
        asyncio.create_task(system_service.sampler_loop()),
        asyncio.create_task(fim_scanner.scanner_loop()),
    ]
    log.info("cwb-core %s online (env=%s)", S.version, S.env)
    yield
    for t in tasks:
        t.cancel()


async def _ipanon_heartbeat_loop():
    while True:
        try:
            await ipanon_service.heartbeat()
        except Exception:
            log.exception("ipanon heartbeat")
        await asyncio.sleep(300)


app = FastAPI(
    title="CYBERWATCH-BD // cwb-core",
    description="Unified Offensive-Defensive Cyber Intelligence Platform — BD Edition. "
                "CSO-2025 + ICT-2006 compliance enforced fail-closed.",
    version=S.version,
    lifespan=lifespan,
    default_response_class=JSONResponse,
    docs_url=None if S.is_production else "/docs",
    redoc_url=None if S.is_production else "/redoc",
    openapi_url=None if S.is_production else "/openapi.json",
)
middleware.install(app)
install_error_handlers(app)

api = APIRouter(prefix="/api/v1")


@api.get("/health")
async def health():
    return {"ok": True, "core": S.version, "env": S.env,
            "policy_hash": hashlib.sha256(
                (Path(__file__).parent / "core" / "policy_rulepack.json").read_bytes()).hexdigest()[:16],
            "asgi_ready": getattr(app.state, "asgi_ready", False)}


@api.get("/config")
async def public_config():
    return {"env": S.env, "version": S.version, "totp_stepup_required": S.totp_stepup_required,
            "warrant_required": S.warrant_required}


@api.get("/settings/policy")
async def policy(p: Principal = Depends(require_analyst)):
    rp = Path(__file__).parent / "core" / "policy_rulepack.json"
    import json
    return {"rulepack": json.loads(rp.read_text()),
            "sha256": hashlib.sha256(rp.read_bytes()).hexdigest(),
            "ledger_active": [w["id"] for w in sql.all_(
                "SELECT id FROM auth_ledger WHERE revoked_at IS NULL AND valid_until > ?",
                _now_iso())]}


@api.get("/modules/health")
async def modules_health(p: Principal = Depends(require_analyst)):
    from app.modules import handshakes
    out = []
    for key, (display, probe) in handshakes.HANDSHAKES.items():
        try:
            status, detail = await probe()
        except Exception as e:
            status, detail = "FAIL", str(e)[:80]
        out.append({"module": key, "display": display, "status": status, "detail": detail})
    return {"modules": out}


_ROOT_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CYBERWATCH-BD cwb-core</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         background: #0a0d12; color: #e6edf3;
         font: 14px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  main { width: min(560px, calc(100vw - 32px)); background: #12171f;
         border: 1px solid #262d38; border-radius: 8px; padding: 28px;
         box-shadow: 0 16px 40px rgba(0, 0, 0, 0.5); }
  h1 { margin: 0 0 4px; font-size: 20px; letter-spacing: 0.3px; }
  h1 .v { color: #4c8dff; }
  .sub { color: #8b949e; margin: 0 0 20px; }
  .chips { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }
  .chip { display: inline-block; padding: 3px 10px; border-radius: 999px;
          font-size: 12px; border: 1px solid #262d38; background: #0f141b; color: #9da7b3; }
  .chip.ok { color: #3fb950; border-color: rgba(63, 185, 80, 0.4); }
  .chip.lab { color: #d29922; border-color: rgba(210, 153, 34, 0.4); }
  a.list { display: block; padding: 12px 14px; margin-bottom: 8px; text-decoration: none;
           color: #e6edf3; background: #0f141b; border: 1px solid #262d38; border-radius: 6px;
           transition: border-color 120ms ease, background 120ms ease; }
  a.list:hover { border-color: #4c8dff; background: rgba(76, 141, 255, 0.08); }
  a.list b { color: #4c8dff; font-weight: 600; }
  a.list span { display: block; color: #7d8896; font-size: 12px; }
  .mono { font-family: ui-monospace, "SFMono", SFMono-Regular, Menlo, Consolas, monospace; }
  footer { margin-top: 16px; color: #7d8896; font-size: 12px; }
</style></head>
<body><main>
  <h1>CYBERWATCH-BD <span class="v">cwb-core __VERSION__</span></h1>
  <p class="sub">API backend. This origin serves JSON under <span class="mono">/api/v1</span> — the web console is a separate app.</p>
  <div class="chips">
    <span class="chip ok">online</span>
    <span class="chip lab">env: __ENV__</span>
    <span class="chip">v__VERSION__</span>
  </div>
  <a class="list" href="http://127.0.0.1:3000"><b>Web console</b><span>http://127.0.0.1:3000 — the operator UI</span></a>
  <a class="list" href="/docs"><b>API docs</b><span class="mono">/docs — interactive OpenAPI reference</span></a>
  <a class="list" href="/api/v1/health"><b>Health</b><span class="mono">/api/v1/health — liveness, policy hash, ASGI state</span></a>
  <footer>CSO-2025 + ICT-2006 compliance enforced fail-closed.</footer>
</main></body></html>"""


@app.get("/", include_in_schema=False)
async def root(request: Request):
    info = {"name": "CYBERWATCH-BD cwb-core", "version": S.version, "env": S.env,
            "api": "/api/v1", "health": "/api/v1/health", "docs": "/docs",
            "console": "http://127.0.0.1:3000"}
    if "text/html" in request.headers.get("accept", ""):
        html = _ROOT_HTML.replace("__VERSION__", S.version).replace("__ENV__", S.env)
        return HTMLResponse(html)
    return info


app.include_router(boot_router)
app.include_router(auth_router)
app.include_router(ledger_router)
app.include_router(mobile_router)
app.include_router(app_release_router)
app.include_router(pentest_router)
app.include_router(vuln_router)
app.include_router(assessment_router)
app.include_router(findings_router)
app.include_router(ti_router)
app.include_router(fim_router)
app.include_router(soc_router)
app.include_router(remediation_router)
app.include_router(osint_router)
app.include_router(tools_router)
app.include_router(system_router)
app.include_router(docfp_router)
app.include_router(victim_router)
app.include_router(ipanon_router)
app.include_router(hwmon_router)
app.include_router(reports_router)
app.include_router(audit_router)
app.include_router(api)
app.include_router(ws_router)
