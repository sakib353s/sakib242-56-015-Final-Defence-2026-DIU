"""Security Assessment Studio pipeline orchestrator.

Vertical slice: target canonicalization -> authorization/scope validation ->
stage planning -> real discovery (DNS/TLS/HTTP/tech) -> observation persistence ->
evidence capture -> finding normalization -> Brain analysis -> risk -> report.

Every stage is persistent and observable. Worker loss never becomes fake success:
on exception the assessment lands in FAILED/UNKNOWN_RESULT with an audit row, and
already-collected evidence is preserved. No simulated progress percentages; the
frontend reads actual stage state from the backend.
"""
from __future__ import annotations

import asyncio
import json

from app.audit import chain
from app.core.ids import new_id
from app.core.jobs import job_finish, job_progress, job_start
from app.core.security import now_iso
from app.db import sqlite as sql
from app.gateway.wsmanager import manager
from app.modules.assessment import adapters, brain

STAGE_PLAN = [
    ("canonicalize", "Target Canonicalization"),
    ("dns", "DNS Analysis"),
    ("tls", "TLS / Certificate Analysis"),
    ("http", "HTTP Response Analysis"),
    ("tech", "Technology Identification"),
    ("normalize", "Finding Normalization"),
    ("brain", "Brain Correlation & Decision"),
    ("finalize", "Risk Calculation & Finalize"),
]


def _persist_evidence(assessment_id: str, ev_rows: list[dict], engine: str,
                      version: str) -> list[str]:
    ids: list[str] = []
    if not ev_rows:
        return ids
    with sql.get_db() as c:
        for e in ev_rows:
            eid = new_id()
            c.execute(
                "INSERT INTO evidence (id, assessment_id, finding_id, observation_id, kind,"
                " ref, sha256, size, mime, storage_path, redacted, description, produced_by,"
                " produced_version, captured_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (eid, assessment_id, None, None, e["kind"], e["ref"], e.get("sha256"),
                 e.get("size"), e.get("mime"), None, e.get("redacted", 0),
                 e.get("description", ""), engine, version, now_iso()),
            )
            ids.append(eid)
    return ids


def _persist_observations(assessment_id: str, obs_rows: list[dict], engine: str,
                          version: str, target: str, evidence_ids: list[str]) -> list[str]:
    ids: list[str] = []
    if not obs_rows:
        return ids
    prov = json.dumps({"engine": engine, "version": version, "target": target})
    with sql.get_db() as c:
        for o in obs_rows:
            oid = new_id()
            c.execute(
                "INSERT INTO observations (id, assessment_id, kind, entity_type, entity_value,"
                " target, confidence, source_engine, source_version, provenance, payload_json,"
                " evidence_ids_json, state, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (oid, assessment_id, o["kind"], o["entity_type"], o["entity_value"], target,
                 o.get("confidence", 0.5), engine, version, prov,
                 json.dumps(o.get("payload", {})), json.dumps(evidence_ids),
                 o.get("state", "observed"), now_iso()),
            )
            ids.append(oid)
    return ids


async def _set_stage(assessment_id: str, seq: int, status: str, message: str = "",
                     engine: str | None = None, version: str | None = None) -> None:
    with sql.get_db() as c:
        c.execute(
            "UPDATE assessment_stages SET status=?, message=?, engine=?, engine_version=?,"
            " started_at=CASE WHEN ?='running' AND started_at IS NULL THEN ? ELSE started_at END,"
            " finished_at=CASE WHEN ? IN ('completed','failed','skipped','degraded') THEN ?"
            " ELSE finished_at END WHERE assessment_id=? AND seq=?",
            (status, message, engine, version, status, now_iso(), status, now_iso(),
             assessment_id, seq),
        )
    await manager.publish("jobs", "assessment.stage", {
        "assessment_id": assessment_id, "seq": seq, "status": status, "message": message})


def create_assessment(target_raw: str, warrant_id: str, user_id: str, session_id: str,
                      profile: str = "standard") -> dict:
    canonical, ttype = adapters.canonicalize(target_raw)
    aid = new_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO assessments (id, warrant_id, target_raw, target_canonical, target_type,"
            " profile, status, created_by, bound_session, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (aid, warrant_id, target_raw, canonical, ttype, profile, "AUTHORIZED",
             user_id, session_id, now_iso()),
        )
        for seq, (key, label) in enumerate(STAGE_PLAN):
            sid = new_id()
            c.execute(
                "INSERT INTO assessment_stages (id, assessment_id, stage_key, label, seq, status)"
                " VALUES (?,?,?,?,?,?)",
                (sid, aid, key, label, seq, "pending"),
            )
    return {"id": aid, "target": canonical, "target_type": ttype, "profile": profile,
            "status": "AUTHORIZED"}


async def run_assessment(assessment_id: str, user_id: str) -> None:
    try:
        await _run(assessment_id, user_id)
    except Exception as e:
        with sql.get_db() as c:
            c.execute(
                "UPDATE assessments SET status='UNKNOWN_RESULT', aborted_reason=?, finished_at=?"
                " WHERE id=?", (str(e)[:300], now_iso(), assessment_id))
        chain.safe_append(user_id, "assessment.worker_crash", assessment_id,
                          {"error": str(e)[:300]})
        await manager.publish("jobs", "assessment.status", {
            "assessment_id": assessment_id, "status": "UNKNOWN_RESULT"})


async def _run(assessment_id: str, user_id: str) -> None:
    row = sql.one("SELECT * FROM assessments WHERE id=?", assessment_id)
    jid = await job_start("assessment.run", assessment_id, {"target": row["target_canonical"]})
    with sql.get_db() as c:
        c.execute("UPDATE assessments SET status='RUNNING', job_id=?, started_at=? WHERE id=?",
                  (jid, now_iso(), assessment_id))
        c.execute("UPDATE assessment_stages SET status='running' WHERE assessment_id=? AND seq=0",
                  (assessment_id,))
    await manager.publish("jobs", "assessment.status", {
        "assessment_id": assessment_id, "status": "RUNNING"})

    target = row["target_canonical"]
    ttype = row["target_type"]
    all_obs: list[dict] = []
    resolved_ips: list[str] = []

    # Stage 1: DNS
    await _set_stage(assessment_id, 1, "running")
    await job_progress(jid, 0.15, "dns resolution")
    dns = await adapters.dns_analyze(target, ttype)
    if dns.get("error"):
        await _set_stage(assessment_id, 1, "degraded", dns["error"])
    else:
        resolved_ips = dns["resolved_ips"]
        ev_ids = _persist_evidence(assessment_id, dns["evidence"], "dnspython",
                                   dns["engine_version"])
        ob_ids = _persist_observations(assessment_id, dns["observations"], "dnspython",
                                       dns["engine_version"], target, ev_ids)
        for o, oid in zip(dns["observations"], ob_ids):
            o["id"] = oid
            o["target"] = target
            o["evidence_ids"] = ev_ids
        all_obs.extend(dns["observations"])
        await _set_stage(assessment_id, 1, "completed",
                         f"{len(dns['observations'])} records", "dnspython",
                         dns["engine_version"])

    # Stage 2: TLS (only when https reachable)
    await _set_stage(assessment_id, 2, "running")
    await job_progress(jid, 0.35, "tls handshake")
    host_for_tls = resolved_ips[0] if resolved_ips else target
    tls = await adapters.tls_analyze(host_for_tls, 443)
    if tls.get("error"):
        await _set_stage(assessment_id, 2, "skipped", tls["error"])
    else:
        ev_ids = _persist_evidence(assessment_id, tls["evidence"], "stdlib-ssl",
                                   tls["engine_version"])
        ob_ids = _persist_observations(assessment_id, tls["observations"], "stdlib-ssl",
                                       tls["engine_version"], target, ev_ids)
        for o, oid in zip(tls["observations"], ob_ids):
            o["id"] = oid
            o["target"] = target
            o["evidence_ids"] = ev_ids
        all_obs.extend(tls["observations"])
        await _set_stage(assessment_id, 2, "completed",
                         f"{len(tls['observations'])} tls facts", "stdlib-ssl",
                         tls["engine_version"])

    # Stage 3: HTTP
    await _set_stage(assessment_id, 3, "running")
    await job_progress(jid, 0.55, "http request")
    http_url = target if ttype == "url" else f"https://{target}"
    http = await adapters.http_analyze(http_url)
    if http.get("error"):
        await _set_stage(assessment_id, 3, "degraded", http["error"])
    else:
        ev_ids = _persist_evidence(assessment_id, http["evidence"], "httpx",
                                   http["engine_version"])
        ob_ids = _persist_observations(assessment_id, http["observations"], "httpx",
                                       http["engine_version"], target, ev_ids)
        for o, oid in zip(http["observations"], ob_ids):
            o["id"] = oid
            o["target"] = target
            o["evidence_ids"] = ev_ids
        all_obs.extend(http["observations"])
        await _set_stage(assessment_id, 3, "completed",
                         f"HTTP {http.get('status')}", "httpx", http["engine_version"])

    # Stage 4: Technology
    await _set_stage(assessment_id, 4, "running")
    await job_progress(jid, 0.7, "technology fingerprint")
    tech = await adapters.tech_identify(http_url)
    if tech.get("error"):
        await _set_stage(assessment_id, 4, "degraded", tech["error"])
    else:
        ev_ids = _persist_evidence(assessment_id, tech["evidence"], "sig-match",
                                   tech["engine_version"])
        ob_ids = _persist_observations(assessment_id, tech["observations"], "sig-match",
                                       tech["engine_version"], target, ev_ids)
        for o, oid in zip(tech["observations"], ob_ids):
            o["id"] = oid
            o["target"] = target
            o["evidence_ids"] = ev_ids
        all_obs.extend(tech["observations"])
        await _set_stage(assessment_id, 4, "completed",
                         f"{len(tech['technologies'])} technologies", "sig-match",
                         tech["engine_version"])

    # Stage 5: Normalize findings
    await _set_stage(assessment_id, 5, "running")
    await job_progress(jid, 0.8, "normalizing findings")
    candidates = brain.analyze_observations(all_obs)
    finding_ids: list[str] = []
    with sql.get_db() as c:
        for cand in candidates:
            fid = new_id()
            c.execute(
                "INSERT INTO assessment_findings (id, assessment_id, fingerprint, title, category,"
                " severity, cvss, confidence, detection_state, lifecycle, cve, cwe, mitre, host,"
                " port, endpoint, parameter, technology, description, impact, remediation_hint,"
                " source_engine, source_version, evidence_ids_json, observation_ids_json,"
                " retest_def_json, before_snapshot_json, after_snapshot_json, verify_result,"
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fid, assessment_id, cand["fingerprint"], cand["title"], cand["category"],
                 cand["severity"], None, cand["confidence"], "detected", "detected",
                 None, cand.get("cwe"), None, cand.get("host"), None, cand.get("endpoint"),
                 None, cand.get("technology"), cand["description"], cand["impact"],
                 cand["remediation_hint"], "brain-rule-pack", brain.RULE_PACK_VERSION,
                 json.dumps(cand["evidence_ids"]),
                 json.dumps([cand["observation_id"]] if cand["observation_id"] else []),
                 cand["retest_def_json"], json.dumps(cand), None, None,
                 now_iso(), now_iso()),
            )
            cand["id"] = fid
            finding_ids.append(fid)
        c.execute("UPDATE assessments SET observations_count=?, findings_count=? WHERE id=?",
                  (len(all_obs), len(finding_ids), assessment_id))
    await _set_stage(assessment_id, 5, "completed", f"{len(finding_ids)} findings")

    # Stage 6: Brain decisions
    await _set_stage(assessment_id, 6, "running")
    await job_progress(jid, 0.9, "brain correlation")
    risk, risk_ver = brain.compute_risk(candidates)
    decisions = brain.decide(assessment_id, candidates, risk, risk_ver,
                             autonomy_cap="recommendation")
    with sql.get_db() as c:
        for d in decisions:
            c.execute(
                "INSERT INTO brain_decisions (id, assessment_id, finding_id, alert_id, incident_id,"
                " autonomy_level, classification, risk, security_confidence, model_confidence,"
                " rationale_json, evidence_refs_json, missing_evidence_json, recommendations_json,"
                " selected_action, policy_result, authorization_result, verification_state,"
                " model_runtime, rule_pack_version, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (d["id"], d["assessment_id"], d["finding_id"], None, None,
                 d["autonomy_level"], d["classification"], d["risk"],
                 d["security_confidence"], d["model_confidence"], d["rationale_json"],
                 d["evidence_refs_json"], d["missing_evidence_json"],
                 d["recommendations_json"], d["selected_action"], d["policy_result"],
                 d["authorization_result"], d["verification_state"], d["model_runtime"],
                 d["rule_pack_version"], d["created_at"]),
            )
        c.execute("UPDATE assessments SET risk_score=?, risk_version=? WHERE id=?",
                  (risk, risk_ver, assessment_id))
    await _set_stage(assessment_id, 6, "completed", f"{len(decisions)} decisions")

    # Stage 7: Finalize
    await _set_stage(assessment_id, 7, "running")
    await job_progress(jid, 0.97, "finalizing")
    with sql.get_db() as c:
        c.execute("UPDATE assessments SET status='COMPLETED', progress=1.0, finished_at=? WHERE id=?",
                  (now_iso(), assessment_id))
    await _set_stage(assessment_id, 7, "completed", "done")
    chain.append(user_id, "assessment.complete", assessment_id,
                 {"findings": len(finding_ids), "risk": risk})
    await job_finish(jid, "done", f"risk {risk}/100 · {len(finding_ids)} findings")
    await manager.publish("jobs", "assessment.status", {
        "assessment_id": assessment_id, "status": "COMPLETED", "risk": risk,
        "findings_count": len(finding_ids)})

    if any(cand["severity"].lower() in ("critical", "high") for cand in candidates):
        await manager.publish("alerts", "assessment.material", {
            "assessment": assessment_id, "target": target,
            "count": sum(1 for cand in candidates
                         if cand["severity"].lower() in ("critical", "high"))})


def get_full(assessment_id: str) -> dict | None:
    a = sql.one("SELECT * FROM assessments WHERE id=?", assessment_id)
    if not a:
        return None
    stages = sql.all_("SELECT * FROM assessment_stages WHERE assessment_id=? ORDER BY seq",
                      assessment_id)
    findings = sql.all_(
        "SELECT * FROM assessment_findings WHERE assessment_id=? ORDER BY severity, created_at",
        assessment_id)
    observations = sql.all_(
        "SELECT id, kind, entity_type, entity_value, confidence, source_engine, state,"
        " collected_at, payload_json, evidence_ids_json FROM observations WHERE assessment_id=?",
        assessment_id)
    evidence = sql.all_(
        "SELECT id, kind, ref, sha256, size, mime, redacted, description, produced_by,"
        " produced_version, captured_at FROM evidence WHERE assessment_id=?", assessment_id)
    decisions = sql.all_(
        "SELECT id, finding_id, autonomy_level, classification, risk, security_confidence,"
        " rationale_json, recommendations_json, verification_state, rule_pack_version, created_at"
        " FROM brain_decisions WHERE assessment_id=? ORDER BY created_at", assessment_id)
    return {"assessment": a, "stages": stages, "findings": findings,
            "observations": observations, "evidence": evidence, "decisions": decisions}


def get_finding(finding_id: str) -> dict | None:
    f = sql.one("SELECT * FROM assessment_findings WHERE id=?", finding_id)
    if not f:
        return None
    ev_ids = json.loads(f["evidence_ids_json"] or "[]")
    evidence = sql.all_("SELECT * FROM evidence WHERE id IN (%s)" % ",".join("?" * len(ev_ids)),
                        *ev_ids) if ev_ids else []
    decisions = sql.all_(
        "SELECT * FROM brain_decisions WHERE finding_id=? ORDER BY created_at DESC LIMIT 1",
        finding_id)
    return {"finding": f, "evidence": evidence, "decision": decisions[0] if decisions else None}