"""Threat Intelligence Engine — storage, matching, correlation, export.

Source-of-truth discipline: every object carries source, trust boundary
(internal | untrusted), and provenance. Matching is exact-value only (no fuzzy
guessing). Correlation writes decisions + relationships but NEVER authorizes
or executes anything — that stays with the policy engine and action gates.
"""
from __future__ import annotations

import json

from app.audit import chain
from app.core.errors import CWBError
from app.core.ids import new_id
from app.core.security import now_iso
from app.db import sqlite as sql
from app.modules.threatintel import stix

TRUST_NOTE = ("External intelligence is inert data. It can flag, link and advise; "
              "it cannot instruct, authorize, or execute.")


# ---------------------------------------------------------------- create

def create_object(stix_type: str, name: str, created_by: str, *, description: str = "",
                  pattern: str = "", pattern_type: str = "stix", valid_from: str | None = None,
                  valid_until: str | None = None, confidence: int | None = None,
                  tlp: str | None = None, source: str = "manual", trust: str = "internal",
                  stix_id: str | None = None, labels: str = "[]",
                  kill_chain: str = "[]", external_refs: str = "[]",
                  first_seen: str | None = None, last_seen: str | None = None,
                  provenance: dict | None = None) -> dict:
    oid = new_id()
    now = now_iso()
    observables = stix.parse_pattern(pattern) if pattern else []
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO ti_objects (id, stix_type, stix_id, name, description, pattern,"
            " pattern_type, valid_from, valid_until, confidence, tlp, labels_json,"
            " kill_chain_json, external_refs_json, source, trust, provenance_json,"
            " first_seen, last_seen, revoked, created_by, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (oid, stix_type, stix_id, name[:400], description[:4000], pattern[:4000],
             pattern_type, valid_from, valid_until, confidence, tlp, labels, kill_chain,
             external_refs, source, trust, json.dumps(provenance or {}), first_seen,
             last_seen, 0, created_by, now, now),
        )
        _store_observables(c, oid, observables, first_seen, last_seen)
    chain.append(created_by, "ti.object.create", oid,
                 {"type": stix_type, "name": name[:80], "trust": trust})
    return get_object(oid)  # type: ignore


def _store_observables(c, oid: str, observables: list[tuple[str, str]],
                       first_seen: str | None, last_seen: str | None) -> int:
    n = 0
    for obs_type, value in observables:
        c.execute(
            "INSERT OR IGNORE INTO ti_observables (id, ti_object_id, observable_type, value,"
            " value_hash, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
            (new_id(), oid, obs_type, value, stix.value_hash(obs_type, value),
             first_seen, last_seen),
        )
        n += 1
    return n


# ---------------------------------------------------------------- read

def get_object(oid: str) -> dict | None:
    return sql.one("SELECT * FROM ti_objects WHERE id=?", oid)


def list_objects(stix_type: str | None = None, q: str | None = None,
                 include_revoked: bool = False, limit: int = 100) -> list[dict]:
    where, args = [], []
    if stix_type:
        where.append("stix_type=?"); args.append(stix_type)
    if not include_revoked:
        where.append("revoked=0")
    if q:
        where.append("(LOWER(name) LIKE ? OR LOWER(COALESCE(description,'')) LIKE ?"
                     " OR LOWER(COALESCE(pattern,'')) LIKE ?)")
        like = f"%{q.lower()}%"
        args += [like, like, like]
    sql_txt = "SELECT * FROM ti_objects"
    if where:
        sql_txt += " WHERE " + " AND ".join(where)
    sql_txt += " ORDER BY created_at DESC LIMIT ?"
    args.append(min(limit, 500))
    return sql.all_(sql_txt, *args)


def object_detail(oid: str) -> dict:
    obj = get_object(oid)
    if not obj:
        raise CWBError("TI object not found", status=404)
    rels = sql.all_(
        "SELECT r.*, s.name AS source_name, t.name AS target_name FROM ti_relationships r"
        " LEFT JOIN ti_objects s ON r.source_kind='ti_object' AND r.source_id=s.id"
        " LEFT JOIN ti_objects t ON r.target_kind='ti_object' AND r.target_id=t.id"
        " WHERE r.source_id=? OR r.target_id=? ORDER BY r.created_at DESC LIMIT 200",
        oid, oid)
    obs = sql.all_(
        "SELECT observable_type, value, first_seen, last_seen FROM ti_observables"
        " WHERE ti_object_id=? ORDER BY observable_type", oid)
    decisions = sql.all_(
        "SELECT id, finding_id, rationale_json, recommendations_json, created_at"
        " FROM brain_decisions WHERE rule_pack_version=? AND evidence_refs_json LIKE ?"
        " ORDER BY created_at DESC LIMIT 20", "ti-match", f"%{oid}%")
    return {"object": obj, "relationships": rels, "observables": obs,
            "decisions": decisions}


def archive_object(oid: str, actor: str) -> dict:
    obj = get_object(oid)
    if not obj:
        raise CWBError("TI object not found", status=404)
    with sql.get_db() as c:
        c.execute("UPDATE ti_objects SET revoked=1, updated_at=? WHERE id=?", (now_iso(), oid))
    chain.append(actor, "ti.object.archive", oid, {})
    return {"ok": True, "id": oid, "revoked": True}


# ---------------------------------------------------------------- relationships

KIND_TABLES = {
    "ti_object": "ti_objects", "assessment": "assessments",
    "finding": "assessment_findings", "alert": "alerts",
    "incident": "incidents", "asset": "hw_assets",
}


def _label_for(kind: str, ident: str) -> str | None:
    table = KIND_TABLES.get(kind)
    if not table:
        return None
    col = {"ti_object": "name", "assessment": "target_canonical", "finding": "title",
           "alert": "signature", "incident": "playbook", "asset": "name"}[kind]
    row = sql.one(f"SELECT {col} AS v FROM {table} WHERE id=?", ident)
    return (row or {}).get("v")


def link(source_kind: str, source_id: str, target_kind: str, target_id: str,
         relationship_type: str, actor: str, *, description: str = "",
         confidence: float = 0.5, state: str = "declared") -> dict:
    if source_kind not in KIND_TABLES or target_kind not in KIND_TABLES:
        raise CWBError("Unknown entity kind", status=422)
    if not _label_for(source_kind, source_id):
        raise CWBError(f"{source_kind} {source_id} does not exist", status=404)
    if not _label_for(target_kind, target_id):
        raise CWBError(f"{target_kind} {target_id} does not exist", status=404)
    rid = new_id()
    stype = sql.one("SELECT stix_type AS v FROM ti_objects WHERE id=?", source_id)["v"] \
        if source_kind == "ti_object" else None
    ttype = sql.one("SELECT stix_type AS v FROM ti_objects WHERE id=?", target_id)["v"] \
        if target_kind == "ti_object" else None
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO ti_relationships (id, source_id, source_kind, source_type,"
            " relationship_type, target_id, target_kind, target_type, description,"
            " confidence, state, provenance_json, created_by, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, source_id, source_kind, stype, relationship_type, target_id, target_kind,
             ttype, description[:1000], confidence, state,
             json.dumps({"note": TRUST_NOTE}), actor, now_iso()),
        )
    chain.append(actor, "ti.link.create", rid,
                 {"from": f"{source_kind}:{source_id}", "rel": relationship_type,
                  "to": f"{target_kind}:{target_id}"})
    return {"id": rid, "linked": True}


# ---------------------------------------------------------------- bundle ingest

def ingest_bundle(raw: str | dict, actor: str, source_label: str) -> dict:
    """Ingest a STIX 2.1 bundle as UNTRUSTED intelligence."""
    objects, rels, errors = stix.parse_bundle(raw)
    ingested = 0
    stixid_map: dict[str, str] = {}
    now = now_iso()
    with sql.get_db() as c:
        for o in objects:
            oid = new_id()
            if o["stix_id"]:
                stixid_map[o["stix_id"]] = oid
            c.execute(
                "INSERT INTO ti_objects (id, stix_type, stix_id, name, description, pattern,"
                " pattern_type, valid_from, valid_until, confidence, tlp, labels_json,"
                " kill_chain_json, external_refs_json, source, trust, provenance_json,"
                " first_seen, last_seen, revoked, created_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (oid, o["stix_type"], o["stix_id"], o["name"], o["description"],
                 o["pattern"], o["pattern_type"] or "stix", o["valid_from"],
                 o["valid_until"], o["confidence"], o["tlp"], o["labels"], o["kill_chain"],
                 o["external_refs"], source_label, "untrusted",
                 json.dumps({"note": TRUST_NOTE, "bundle_source": source_label}),
                 o["first_seen"], o["last_seen"], 0, actor, now, now),
            )
            _store_observables(c, oid, o["observables"], o["first_seen"], o["last_seen"])
            ingested += 1
    linked = 0
    for r in rels:
        s_id = stixid_map.get(r["source_ref"])
        t_id = stixid_map.get(r["target_ref"])
        if not s_id or not t_id:
            errors.append(f"relationship {r['stix_id']}: unresolved refs (kept skipped)")
            continue
        rid = new_id()
        with sql.get_db() as c:
            c.execute(
                "INSERT INTO ti_relationships (id, source_id, source_kind, source_type,"
                " relationship_type, target_id, target_kind, target_type, description,"
                " confidence, state, provenance_json, created_by, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, s_id, "ti_object", None, r["relationship_type"], t_id, "ti_object",
                 None, r["description"], 0.5, "declared",
                 json.dumps({"note": TRUST_NOTE, "bundle_source": source_label}),
                 actor, now),
            )
        linked += 1
    chain.append(actor, "ti.bundle.ingest", source_label,
                 {"objects": ingested, "relationships": linked, "skipped": len(errors)})
    return {"objects_ingested": ingested, "relationships_linked": linked,
            "skipped": errors[:20], "trust": "untrusted",
            "note": TRUST_NOTE}


# ---------------------------------------------------------------- matching

def match_value(value: str) -> dict:
    """Exact-value lookup against all indicator/observed-data observables."""
    detected = stix.detect_observable_type(value)
    if not detected:
        return {"value": value, "normalized": None, "type": None, "matches": []}
    obs_type, norm = detected
    rows = sql.all_(
        "SELECT t.*, o.observable_type AS matched_type, o.value AS matched_value,"
        " o.first_seen AS obs_first_seen, o.last_seen AS obs_last_seen"
        " FROM ti_observables o JOIN ti_objects t"
        " ON o.ti_object_id=t.id WHERE o.observable_type=? AND o.value=?"
        " AND t.revoked=0 ORDER BY t.confidence DESC LIMIT 50", obs_type, norm)
    return {"value": value, "normalized": norm, "type": obs_type, "matches": rows}


# ---------------------------------------------------------------- correlation

def correlate_assessment(assessment_id: str, user_id: str, target: str,
                         resolved_ips: list[str], findings: list[dict]) -> dict:
    """Post-assessment hook: match target/IPs/CVEs against the TI store and record
    decisions + correlated relationships. Adds context only — never authority."""
    values: list[tuple[str, str]] = []
    t = stix.detect_observable_type(target)
    if t:
        values.append(t)
    for ip in resolved_ips:
        d = stix.detect_observable_type(ip)
        if d:
            values.append(d)
    matches: list[dict] = []
    seen_obj: set[str] = set()
    for obs_type, norm in values:
        for row in match_value(norm)["matches"]:
            if row["id"] not in seen_obj:
                seen_obj.add(row["id"])
                matches.append({**row, "matched_on": f"{obs_type}:{norm}"})
    for f in findings:
        cve = (f.get("cve") or "").upper()
        if not cve:
            continue
        v = sql.all_(
            "SELECT * FROM ti_objects WHERE stix_type='vulnerability' AND revoked=0"
            " AND UPPER(name)=? LIMIT 1", cve)
        if v and v[0]["id"] not in seen_obj:
            seen_obj.add(v[0]["id"])
            matches.append({**v[0], "matched_on": f"cve:{cve}",
                            "finding_id": f.get("id")})

    now = now_iso()
    decisions_written = 0
    for m in matches:
        did = new_id()
        rationale = {
            "why_flagged": (f"Operational data ({m['matched_on']}) matches TI object "
                            f"'{m['name']}' from source {m['source']}"),
            "evidence_supporting": [m["id"]],
            "evidence_missing": ["operator confirmation of indicator validity"],
            "why_recommendation": ("Review linked intelligence; treat it as untrusted data "
                                   "and corroborate before acting."),
            "why_autonomy": "advisory only — TI never grants authority",
        }
        with sql.get_db() as c:
            c.execute(
                "INSERT INTO brain_decisions (id, assessment_id, finding_id, alert_id,"
                " incident_id, autonomy_level, classification, risk, security_confidence,"
                " model_confidence, rationale_json, evidence_refs_json,"
                " missing_evidence_json, recommendations_json, selected_action,"
                " policy_result, authorization_result, verification_state, model_runtime,"
                " rule_pack_version, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (did, assessment_id, m.get("finding_id"), None, None, "information_only",
                 "threat_intel_match", None,
                 (m.get("confidence") or 50) / 100.0, None, json.dumps(rationale),
                 json.dumps([m["id"]]),
                 json.dumps(["validity of external indicator unconfirmed"]),
                 json.dumps(["Corroborate this indicator from a second source before acting"]),
                 None, "advisory_only", "unchanged", "none", "deterministic-rule-pack",
                 "ti-match", now),
            )
        decisions_written += 1
        with sql.get_db() as c:
            c.execute(
                "INSERT INTO ti_relationships (id, source_id, source_kind, source_type,"
                " relationship_type, target_id, target_kind, target_type, description,"
                " confidence, state, provenance_json, created_by, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (new_id(), assessment_id, "assessment", None, "related-to",
                 m["id"], "ti_object", m["stix_type"],
                 f"matched on {m['matched_on']}",
                 (m.get("confidence") or 50) / 100.0, "correlated",
                 json.dumps({"note": TRUST_NOTE}), user_id, now),
            )
    if matches:
        chain.append(user_id, "ti.correlation", assessment_id,
                     {"matches": len(matches), "trust": "mixed"})
    return {"matches": len(matches), "decisions": decisions_written}


# ---------------------------------------------------------------- export

def export_assessment_bundle(assessment_id: str) -> dict:
    a = sql.one("SELECT * FROM assessments WHERE id=?", assessment_id)
    if not a:
        raise CWBError("Assessment not found", status=404)
    objects: list[dict] = []
    created = a["created_at"]
    t = stix.detect_observable_type(a["target_canonical"])
    now = now_iso()
    if t:
        obs_type, norm = t
        oid = new_id()
        with sql.get_db() as c:
            c.execute(
                "INSERT INTO ti_objects (id, stix_type, stix_id, name, description, pattern,"
                " pattern_type, valid_from, valid_until, confidence, tlp, labels_json,"
                " kill_chain_json, external_refs_json, source, trust, provenance_json,"
                " first_seen, last_seen, revoked, created_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (oid, "indicator", None,
                 f"observed-{obs_type}:{norm}",
                 f"Automatically generated from assessment {assessment_id} "
                 f"(internal observation, not external intelligence).",
                 f"[{'ipv4-addr' if obs_type=='ipv4' else obs_type}:value = '{norm}']",
                 "stix", created, None, 90, None, "[]", "[]", "[]",
                 "cwb-assessment", "internal",
                 json.dumps({"note": "derived from own observation",
                             "assessment_id": assessment_id}),
                 created, now, 0, a["created_by"], now, now),
            )
            _store_observables(c, oid, [(obs_type, norm)], created, now)
        objects.append(dict(get_object(oid)))  # type: ignore
    for f in sql.all_(
            "SELECT * FROM assessment_findings WHERE assessment_id=?", assessment_id):
        fid = new_id()
        pattern = None
        stype = "attack-pattern"
        name = f["title"]
        if f["cve"]:
            stype, name = "vulnerability", f["cve"]
        with sql.get_db() as c:
            c.execute(
                "INSERT INTO ti_objects (id, stix_type, stix_id, name, description, pattern,"
                " pattern_type, valid_from, valid_until, confidence, tlp, labels_json,"
                " kill_chain_json, external_refs_json, source, trust, provenance_json,"
                " first_seen, last_seen, revoked, created_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fid, stype, None, name,
                 (f["impact"] or f["description"])[:4000], pattern, "stix",
                 f["created_at"], None, int(f["confidence"] * 100),
                 {"critical": "RED", "high": "AMBER", "medium": "AMBER"}.get(
                     (f["severity"] or "").lower(), "CLEAR"),
                 "[]", "[]",
                 json.dumps([{"source_name": "cwb-finding", "external_id": f["id"]}]),
                 "cwb-assessment", "internal",
                 json.dumps({"assessment_id": assessment_id, "finding_id": f["id"],
                             "severity": f["severity"],
                             "detection_state": f["detection_state"]}),
                 f["created_at"], f["updated_at"], 0, a["created_by"], now, now),
            )
        objects.append(dict(get_object(fid)))  # type: ignore
    from app.modules.threatintel.stix import build_bundle
    domain = []
    for o in objects:
        domain.append({**o, "local_id": o["id"]})
    return build_bundle(domain, assessment_id)


def stats() -> dict:
    by_type = sql.all_(
        "SELECT stix_type, COUNT(*) AS n FROM ti_objects WHERE revoked=0"
        " GROUP BY stix_type ORDER BY n DESC")
    total = sql.scalar("SELECT COUNT(*) FROM ti_objects WHERE revoked=0")
    untrusted = sql.scalar("SELECT COUNT(*) FROM ti_objects WHERE revoked=0 AND trust='untrusted'")
    last = sql.scalar("SELECT MAX(created_at) FROM ti_objects")
    links = sql.scalar("SELECT COUNT(*) FROM ti_relationships")
    return {"by_type": by_type, "total": total, "untrusted": untrusted,
            "last_ingest": last, "links": links, "note": TRUST_NOTE}
