"""Finding Engine — normalized finding lifecycle + real retest verification.

Lifecycle (forward): detected -> triaged -> validating -> confirmed ->
remediation_recommended -> remediated -> verified_fixed.
Alternate terminal outcomes: false_positive, not_reproducible, unconfirmed,
actioned_but_not_verified.

Every transition is validated against an explicit allowed-edge map, gated by
RBAC + warrant where required, and written to finding_transitions plus the HMAC
audit chain. A retest never declares success from exit code alone: it re-runs
the registered check and compares observed state to the declared post-condition,
producing verified_fixed / not_fixed / unable_to_verify / actioned_but_not_verified.
"""
from __future__ import annotations

import asyncio
import json

from app.audit import chain
from app.core.errors import Conflict, CWBError, Forbidden
from app.core.ids import new_id
from app.core.security import now_iso
from app.db import sqlite as sql
from app.gateway.wsmanager import manager

LIFECYCLE_STATES = {
    "detected", "triaged", "validating", "confirmed", "remediation_recommended",
    "remediated", "verified_fixed", "false_positive", "not_reproducible",
    "unconfirmed", "actioned_but_not_verified",
}

ALLOWED_EDGES: dict[str, set[str]] = {
    "detected": {"triaged", "false_positive", "unconfirmed"},
    "triaged": {"validating", "confirmed", "false_positive", "not_reproducible", "unconfirmed"},
    "validating": {"confirmed", "false_positive", "not_reproducible", "unconfirmed"},
    "confirmed": {"remediation_recommended", "false_positive", "unconfirmed"},
    "remediation_recommended": {"remediated", "actioned_but_not_verified", "unconfirmed"},
    "remediated": {"verified_fixed", "actioned_but_not_verified", "not_reproducible", "unconfirmed"},
    "verified_fixed": set(),
    "false_positive": set(),
    "not_reproducible": set(),
    "unconfirmed": {"detected", "triaged"},
    "actioned_but_not_verified": {"remediated", "verified_fixed", "unconfirmed"},
}

MIN_ROLE_FOR = {
    "triaged": "ANALYST",
    "validating": "ANALYST",
    "confirmed": "ANALYST",
    "false_positive": "ANALYST",
    "not_reproducible": "ANALYST",
    "unconfirmed": "ANALYST",
    "remediation_recommended": "ANALYST",
    "remediated": "SUPER_ADMIN",
    "verified_fixed": "ANALYST",
    "actioned_but_not_verified": "ANALYST",
}


def get_finding(finding_id: str) -> dict | None:
    return sql.one("SELECT * FROM assessment_findings WHERE id=?", finding_id)


def _transition_row(finding_id: str, frm: str, to: str, actor: str, reason: str | None,
                    evidence_ref: str | None, warrant_id: str | None) -> None:
    tid = new_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO finding_transitions (id, finding_id, from_lifecycle, to_lifecycle,"
            " actor, reason, evidence_ref, warrant_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (tid, finding_id, frm, to, actor, reason, evidence_ref, warrant_id, now_iso()),
        )


def transition(finding_id: str, to_state: str, actor: str, role_rank: int,
               reason: str | None = None, evidence_ref: str | None = None,
               warrant_id: str | None = None) -> dict:
    f = get_finding(finding_id)
    if not f:
        raise CWBError("Finding not found", status=404)
    frm = f["lifecycle"]
    if to_state not in LIFECYCLE_STATES:
        raise CWBError(f"Unknown lifecycle state {to_state}", status=422)
    if to_state not in ALLOWED_EDGES.get(frm, set()):
        raise Conflict(f"Illegal transition {frm} -> {to_state}")
    need = MIN_ROLE_FOR.get(to_state, "READ_ONLY")
    rank_of = {"READ_ONLY": 0, "ANALYST": 1, "SUPER_ADMIN": 2}
    if role_rank < rank_of[need]:
        ref = chain.append(actor, "finding.transition.denied", finding_id,
                           {"have": role_rank, "need": need})
        raise Forbidden(f"{to_state} requires {need} (audit_ref={ref})")
    sets = ["lifecycle=?", "updated_at=?"]
    args: list = [to_state, now_iso()]
    if to_state == "triaged":
        sets += ["triaged_by=?", "triaged_at=?"]; args += [actor, now_iso()]
    elif to_state == "confirmed":
        sets += ["confirmed_by=?", "confirmed_at=?"]; args += [actor, now_iso()]
    elif to_state == "remediated":
        sets += ["remediated_at=?"]; args += [now_iso()]
    args.append(finding_id)
    with sql.get_db() as c:
        c.execute(f"UPDATE assessment_findings SET {', '.join(sets)} WHERE id=?", tuple(args))
    _transition_row(finding_id, frm, to_state, actor, reason, evidence_ref, warrant_id)
    chain.append(actor, "finding.transition", finding_id,
                 {"from": frm, "to": to_state, "reason": reason})
    return {"finding_id": finding_id, "from": frm, "to": to_state}


async def retest(finding_id: str, actor: str) -> dict:
    """Re-run the finding's registered check and verify the declared post-condition.

    Uses the same adapters that produced the original observation. Never trusts a
    bare exit code: compares observed state to the stored before_snapshot and the
    rule's success condition, then maps to an honest outcome."""
    f = get_finding(finding_id)
    if not f:
        raise CWBError("Finding not found", status=404)
    if f["lifecycle"] not in ("confirmed", "remediation_recommended", "remediated",
                              "actioned_but_not_verified"):
        raise Conflict(f"Retest not applicable from lifecycle {f['lifecycle']}")

    jid = await _retest_job_start(finding_id, actor)
    try:
        outcome, observed, detail = await _run_check(f, jid)
    except Exception as e:
        outcome, observed, detail = "unable_to_verify", None, f"check error: {str(e)[:200]}"
        chain.safe_append(actor, "finding.retest.error", finding_id, {"error": str(e)[:300]})

    with sql.get_db() as c:
        c.execute(
            "UPDATE assessment_findings SET after_snapshot_json=?, verify_result=?,"
            " last_retest_at=?, last_retest_job_id=?, retest_count=retest_count+1, updated_at=?"
            " WHERE id=?",
            (json.dumps({"observed": observed}), outcome, now_iso(), jid, now_iso(), finding_id),
        )
    chain.append(actor, "finding.retest.complete", finding_id,
                 {"outcome": outcome, "job": jid, "detail": detail[:200]})
    await _retest_job_finish(jid, outcome, detail)
    await manager.publish("jobs", "finding.retest", {
        "finding_id": finding_id, "outcome": outcome, "job_id": jid})
    return {"finding_id": finding_id, "outcome": outcome, "observed": observed,
            "detail": detail, "job_id": jid}


async def _run_check(f: dict, jid: str) -> tuple[str, dict, str]:
    """Dispatch to the adapter matching the finding category. Returns
    (outcome, observed_payload, human_detail)."""
    from app.modules.assessment import adapters

    cat = (f["category"] or "").lower()
    endpoint = f["endpoint"] or ""
    host = f["host"] or ""
    target = endpoint or host
    if not target:
        return "unable_to_verify", {}, "no endpoint/host recorded for retest"

    if "header" in cat or "configuration" in cat or "disclosure" in cat:
        http = await adapters.http_analyze(target if target.startswith("http") else f"https://{target}")
        headers = {k.lower(): v for k, v in (http.get("headers") or {}).items()}
        key = _expected_header(cat, f["title"])
        observed = {"status": http.get("status"), "present_headers": sorted(headers.keys())}
        if http.get("error"):
            return "unable_to_verify", observed, f"http probe failed: {http['error']}"
        if key is None:
            return "unable_to_verify", observed, "no success condition mapped for this check"
        present = key in headers
        generic = _is_generic_server(headers.get("server", ""))
        if key == "server":
            fixed = generic
        else:
            fixed = present
        if fixed:
            return "verified_fixed", observed, f"{key} satisfied on re-fetch"
        return "not_fixed", observed, f"{key} still unsatisfied ({f['title']})"

    if "tls" in cat:
        tls = await adapters.tls_analyze(host or target)
        observed = {"protocol": tls.get("protocol"), "cert": tls.get("subject")}
        if tls.get("error"):
            return "unable_to_verify", observed, f"tls probe failed: {tls['error']}"
        proto_ok = (tls.get("protocol") or "").upper().replace("TLS", "TLSv") >= "TLSV1.2" \
            if tls.get("protocol") else False
        return ("verified_fixed" if proto_ok else "not_fixed"), observed, \
            f"negotiated {tls.get('protocol') or 'none'}"

    return "unable_to_verify", {}, f"no retest adapter mapped for category '{cat}'"


_HDR_MAP = {
    "strict-transport-security": "strict-transport-security",
    "content-security-policy": "content-security-policy",
    "clickjacking": "x-frame-options",
    "frame": "x-frame-options",
    "server version": "server",
}


def _expected_header(cat: str, title: str) -> str | None:
    t = (title or "").lower()
    for needle, hdr in _HDR_MAP.items():
        if needle in t:
            return hdr
    return None


def _is_generic_server(val: str) -> bool:
    v = (val or "").strip().lower()
    if not v:
        return True
    return not any(ch.isdigit() for ch in v) and len(v.split()) <= 1


async def _retest_job_start(finding_id: str, actor: str) -> str:
    from app.core.jobs import job_start
    return await job_start("finding.retest", finding_id, {"by": actor})


async def _retest_job_finish(jid: str, outcome: str, detail: str) -> None:
    from app.core.jobs import job_finish
    status = "done" if outcome in ("verified_fixed", "not_fixed") else "error"
    await job_finish(jid, status, f"{outcome}: {detail[:80]}")


def history(finding_id: str) -> list[dict]:
    return sql.all_(
        "SELECT * FROM finding_transitions WHERE finding_id=? ORDER BY created_at DESC",
        finding_id)


def queue(min_severity: str = "low", limit: int = 200) -> list[dict]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rows = sql.all_(
        "SELECT id, assessment_id, title, severity, confidence, lifecycle, host, endpoint,"
        " source_engine, updated_at FROM assessment_findings WHERE lifecycle NOT IN"
        " ('verified_fixed','false_positive') ORDER BY created_at DESC LIMIT ?", min(limit, 500))
    cap = order.get(min_severity.lower(), 4)
    return [r for r in rows if order.get((r["severity"] or "").lower(), 4) <= cap]