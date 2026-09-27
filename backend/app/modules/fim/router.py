"""FIM + detection-rules API. Role-based defensive surface (no warrant needed)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.core.errors import CWBError
from app.db import sqlite as sql
from app.gateway.deps import Principal, require_analyst
from app.modules.fim import scanner
from app.modules.soc import detection

router = APIRouter(prefix="/api/v1", tags=["fim-detection"])


class PolicyBody(BaseModel):
    path: str = Field(min_length=2, max_length=400)
    name: str = Field(min_length=2, max_length=120)
    recursive: bool = True
    max_depth: int = Field(default=4, ge=1, le=10)
    interval_s: int = Field(default=300, ge=60, le=86400)
    exclude_globs: list[str] = Field(default_factory=list, max_length=50)


@router.get("/fim/status")
async def fim_status(p: Principal = Depends(require_analyst)):
    return scanner.policy_status()


@router.post("/fim/policies")
async def fim_create(body: PolicyBody, p: Principal = Depends(require_analyst)):
    return scanner.create_policy(body.path, body.name, p.user_id,
                                 recursive=body.recursive, max_depth=body.max_depth,
                                 interval_s=body.interval_s,
                                 exclude_globs=body.exclude_globs)


@router.post("/fim/policies/{pid}/scan")
async def fim_scan(pid: str, request: Request, p: Principal = Depends(require_analyst)):
    return await scanner.scan_policy_async(pid, p.user_id)


@router.post("/fim/policies/{pid}/disable")
async def fim_disable(pid: str, p: Principal = Depends(require_analyst)):
    from app.audit import chain
    if not sql.one("SELECT id FROM fim_policies WHERE id=?", pid):
        raise CWBError("policy not found", status=404)
    with sql.get_db() as c:
        c.execute("UPDATE fim_policies SET enabled=0 WHERE id=?", (pid,))
    chain.append(p.user_id, "fim.policy.disable", pid, {})
    return {"ok": True}


@router.get("/fim/events")
async def fim_events(policy_id: str | None = None, event_type: str | None = None,
                     limit: int = 100, p: Principal = Depends(require_analyst)):
    where, args = [], []
    if policy_id:
        where.append("policy_id=?"); args.append(policy_id)
    if event_type:
        where.append("event_type=?"); args.append(event_type)
    q = "SELECT * FROM fim_events"
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY detected_at DESC LIMIT ?"
    args.append(min(limit, 500))
    return {"events": sql.all_(q, *args)}


# ------------------------------------------------------------- detection rules


class RuleBody(BaseModel):
    rule_key: str = Field(min_length=3, max_length=80)
    name: str = Field(min_length=3, max_length=200)
    source: str
    matcher: dict
    severity: str
    confidence: float = Field(default=0.6, ge=0, le=1)
    description: str = Field(default="", max_length=1000)
    correlate: dict | None = None
    mitre: str | None = Field(default=None, max_length=20)


@router.get("/soc/rules")
async def rules_list(include_disabled: bool = False, p: Principal = Depends(require_analyst)):
    return {"rules": detection.list_rules(include_disabled)}


@router.post("/soc/rules")
async def rules_create(body: RuleBody, p: Principal = Depends(require_analyst)):
    return detection.create_rule(body.rule_key, body.name, body.source, body.matcher,
                                 body.severity, body.confidence, p.user_id,
                                 description=body.description, correlate=body.correlate,
                                 mitre=body.mitre)


@router.post("/soc/rules/{rid}/enable")
async def rules_enable(rid: str, p: Principal = Depends(require_analyst)):
    return detection.set_enabled(rid, True, p.user_id)


@router.post("/soc/rules/{rid}/disable")
async def rules_disable(rid: str, p: Principal = Depends(require_analyst)):
    return detection.set_enabled(rid, False, p.user_id)


class TestBody(BaseModel):
    matcher: dict
    sample: dict


@router.post("/soc/rules/test")
async def rules_test(body: TestBody, p: Principal = Depends(require_analyst)):
    return detection.test_rule(body.matcher, body.sample)
