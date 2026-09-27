"""Threat Intelligence Engine API.

All intelligence is stored inert. Ingestion is size/entry limited; values only
inform matching/decisions. No endpoint executes, authorizes, or applies policy
from TI content."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from fastapi import APIRouter
from pydantic import BaseModel, Field, field_validator

from app.audit import chain
from app.core.errors import CWBError
from app.gateway.deps import Principal, require_analyst
from app.modules.threatintel import service as ti

router = APIRouter(prefix="/api/v1/ti", tags=["threat-intel"])

_TYPES = {"indicator", "malware", "threat-actor", "campaign", "tool", "attack-pattern",
          "infrastructure", "vulnerability", "report", "observed-data", "intrusion-set",
          "course-of-action", "identity"}
_TLPS = {"CLEAR", "GREEN", "AMBER", "RED"}


class ObjectBody(BaseModel):
    stix_type: str
    name: str = Field(min_length=2, max_length=400)
    description: str = Field(default="", max_length=4000)
    pattern: str = Field(default="", max_length=4000)
    tlp: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    valid_until: str | None = Field(default=None, max_length=40)

    @field_validator("stix_type")
    @classmethod
    def _type_ok(cls, v):
        v = v.lower().strip()
        if v not in _TYPES:
            raise ValueError(f"stix_type must be one of {sorted(_TYPES)}")
        return v

    @field_validator("tlp")
    @classmethod
    def _tlp_ok(cls, v):
        if v is None or v == "":
            return None
        v = v.upper().strip()
        if v not in _TLPS:
            raise ValueError("tlp must be CLEAR/GREEN/AMBER/RED")
        return v


@router.get("/stats")
async def stats(p: Principal = Depends(require_analyst)):
    return ti.stats()


@router.get("/objects")
async def list_objects(type: str | None = None, q: str | None = None,
                       include_revoked: bool = False, limit: int = 100,
                       p: Principal = Depends(require_analyst)):
    if type and type.lower() not in _TYPES:
        raise CWBError("Unknown stix_type", status=422)
    return {"objects": ti.list_objects((type or "").lower() or None, q,
                                       include_revoked, limit)}


@router.post("/objects")
async def create_object(body: ObjectBody, p: Principal = Depends(require_analyst)):
    return ti.create_object(body.stix_type, body.name, p.user_id,
                            description=body.description, pattern=body.pattern,
                            tlp=body.tlp, confidence=body.confidence,
                            valid_until=body.valid_until)


@router.get("/objects/{oid}")
async def get_object(oid: str, p: Principal = Depends(require_analyst)):
    return ti.object_detail(oid)


@router.post("/objects/{oid}/archive")
async def archive(oid: str, request: Request, p: Principal = Depends(require_analyst)):
    return ti.archive_object(oid, p.user_id)


class BundleBody(BaseModel):
    bundle: dict | str
    source_label: str = Field(min_length=2, max_length=120, default="manual-bundle")


@router.post("/bundles")
async def ingest_bundle(body: BundleBody, p: Principal = Depends(require_analyst)):
    try:
        return ti.ingest_bundle(body.bundle, p.user_id, body.source_label.strip())
    except ValueError as e:
        raise CWBError(f"Bundle rejected: {e}", status=422)


class LinkBody(BaseModel):
    source_kind: str
    source_id: str
    target_kind: str
    target_id: str
    relationship_type: str = Field(default="related-to", min_length=2, max_length=80)
    description: str = Field(default="", max_length=1000)


@router.post("/links")
async def create_link(body: LinkBody, p: Principal = Depends(require_analyst)):
    return ti.link(body.source_kind, body.source_id, body.target_kind, body.target_id,
                   body.relationship_type, p.user_id, description=body.description)


@router.get("/match")
async def match(value: str, p: Principal = Depends(require_analyst)):
    return ti.match_value(value)


@router.get("/export/{assessment_id}")
async def export(assessment_id: str, p: Principal = Depends(require_analyst)):
    bundle = ti.export_assessment_bundle(assessment_id)
    chain.append(p.user_id, "ti.bundle.export", assessment_id,
                 {"objects": len(bundle.get("objects", []))})
    return JSONResponse(bundle, headers={
        "content-disposition": f'attachment; filename="cwb-{assessment_id[:8]}.stix2.json"'})
