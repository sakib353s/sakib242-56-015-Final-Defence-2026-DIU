"""Local Cyber Intelligence Brain — deterministic security reasoning.

Consumes observations, correlates them against registered rules, computes risk,
and produces evidence-backed recommendations. No external LLM, no API keys.
The Brain may never invent authorization, change policy, or declare verification.
Every decision carries rationale, evidence refs, missing-evidence markers, and
an explicit autonomy level bounded by policy.
"""
from __future__ import annotations

import hashlib
import json

from app.core.ids import new_id
from app.core.security import now_iso

RULE_PACK_VERSION = "brain-rules-1.0.0"

_SEV_WEIGHT = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 2.0, "informational": 0.5}


def _h(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


OBS_RULES = [
    {
        "key": "weak_tls",
        "match": lambda o: o["kind"] == "tls.weak_protocol",
        "title": "Deprecated TLS protocol enabled",
        "category": "transport_security",
        "severity": "high",
        "cwe": "CWE-326",
        "impact": "Legacy protocols expose the channel to downgrade and interception attacks.",
        "remediation": "Disable SSLv3/TLS1.0/TLS1.1; enforce TLS1.2+ with modern cipher suites.",
        "retest": "Re-run tls_analyze; success when negotiated protocol >= TLSv1.2.",
        "confidence": 0.85,
    },
    {
        "key": "missing_hsts",
        "match": lambda o: o["kind"] == "http.missing_hsts",
        "title": "Strict-Transport-Security header absent",
        "category": "web_configuration",
        "severity": "medium",
        "cwe": "CWE-319",
        "impact": "Without HSTS a first visit can be stripped to plaintext (MITM).",
        "remediation": "Emit Strict-Transport-Security: max-age>=31536000; includeSubDomains.",
        "retest": "Re-fetch endpoint; success when the header is present with long max-age.",
        "confidence": 0.8,
    },
    {
        "key": "missing_csp",
        "match": lambda o: o["kind"] == "http.missing_csp",
        "title": "Content-Security-Policy header absent",
        "category": "web_configuration",
        "severity": "low",
        "cwe": "CWE-1021",
        "impact": "No CSP means XSS mitigation depends entirely on application encoding.",
        "remediation": "Deploy a Content-Security-Policy tuned to the app's resource origins.",
        "retest": "Re-fetch endpoint; success when a non-trivial CSP header is present.",
        "confidence": 0.75,
    },
    {
        "key": "missing_xfo",
        "match": lambda o: o["kind"] == "http.missing_xfo",
        "title": "Clickjacking protection absent",
        "category": "web_configuration",
        "severity": "low",
        "cwe": "CWE-1021",
        "impact": "Page can be framed by an attacker for UI redress / clickjacking.",
        "remediation": "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
        "retest": "Re-fetch endpoint; success when framing restriction is present.",
        "confidence": 0.75,
    },
    {
        "key": "server_banner_disclosure",
        "match": lambda o: o["kind"] == "http.server_banner",
        "title": "Server version banner disclosed",
        "category": "information_disclosure",
        "severity": "informational",
        "cwe": "CWE-200",
        "impact": "Precise product/version aids attackers in targeting known CVEs.",
        "remediation": "Suppress or generalize the Server response header.",
        "retest": "Re-fetch endpoint; success when Server header is absent or generic.",
        "confidence": 0.6,
    },
]


def _fingerprint(rule_key: str, obs: dict) -> str:
    return _h(rule_key, obs.get("target", ""), obs.get("entity_value", ""))


def analyze_observations(observations: list[dict]) -> list[dict]:
    """Turn raw observations into candidate findings via registered rules."""
    candidates: list[dict] = []
    seen_fp: set[str] = set()
    for o in observations:
        for rule in OBS_RULES:
            try:
                if not rule["match"](o):
                    continue
            except Exception:
                continue
            fp = _fingerprint(rule["key"], o)
            if fp in seen_fp:
                continue
            seen_fp.add(fp)
            candidates.append({
                "fingerprint": fp,
                "rule_key": rule["key"],
                "title": rule["title"],
                "category": rule["category"],
                "severity": rule["severity"],
                "cwe": rule.get("cwe"),
                "description": rule["impact"],
                "impact": rule["impact"],
                "remediation_hint": rule["remediation"],
                "retest_def_json": json.dumps({"method": rule["retest"], "rule_key": rule["key"]}),
                "confidence": rule["confidence"],
                "observation_id": o.get("id"),
                "host": o.get("target"),
                "endpoint": o.get("entity_value"),
                "technology": None,
                "evidence_ids": o.get("evidence_ids", []),
            })
    return candidates


def compute_risk(findings: list[dict]) -> tuple[float, str]:
    """Deterministic posture score 0–100 from documented inputs. Carries a
    calculation version so the same inputs always reproduce the same number."""
    if not findings:
        return 0.0, RULE_PACK_VERSION
    total = sum(_SEV_WEIGHT.get(f["severity"].lower(), 1.0) for f in findings)
    peak = max(_SEV_WEIGHT.get(f["severity"].lower(), 1.0) for f in findings)
    raw = min(100.0, total * 2.0 + peak * 3.0)
    return round(raw, 1), RULE_PACK_VERSION


def decide(assessment_id: str, findings: list[dict], risk: float,
           risk_version: str, autonomy_cap: str = "recommendation") -> list[dict]:
    """Produce one persisted Brain decision per material finding plus a summary
    decision. Recommendations are bounded by the supplied autonomy cap; the Brain
    never elevates autonomy on its own."""
    order = ["information_only", "recommendation", "preparation",
             "approval_request", "approved_automation", "bounded_autonomous_defense"]
    cap_idx = order.index(autonomy_cap) if autonomy_cap in order else 1
    decisions: list[dict] = []
    for f in findings:
        sev = f["severity"].lower()
        needs_approval = sev in ("critical", "high")
        want_level = "approval_request" if needs_approval else "recommendation"
        chosen = order[min(order.index(want_level), cap_idx)]
        rationale = [{
            "point": f"{f['title']} flagged at severity {sev}.",
            "supports": f.evidence_refs if hasattr(f, "evidence_refs") else f.get("evidence_ids", []),
        }]
        decisions.append({
            "id": new_id(),
            "assessment_id": assessment_id,
            "finding_id": f.get("id"),
            "autonomy_level": chosen,
            "classification": f.get("category", "unknown"),
            "risk": risk,
            "security_confidence": f.get("confidence", 0.5),
            "model_confidence": None,
            "rationale_json": json.dumps({
                "why_flagged": f["title"],
                "evidence_supporting": f.get("evidence_ids", []),
                "evidence_missing": ([] if f.get("detection_state") == "confirmed"
                                     else ["active validation not yet performed"]),
                "why_recommendation": f.get("remediation_hint", ""),
                "why_autonomy": ("elevated actions require approval for high/critical"
                                 if needs_approval else "advisory only"),
            }),
            "evidence_refs_json": json.dumps(f.get("evidence_ids", [])),
            "missing_evidence_json": json.dumps([]),
            "recommendations_json": json.dumps([f.get("remediation_hint", "")]),
            "selected_action": None,
            "policy_result": "allowed_within_cap",
            "authorization_result": "unchanged",
            "verification_state": "none",
            "model_runtime": "deterministic-rule-pack",
            "rule_pack_version": risk_version,
            "created_at": now_iso(),
        })
    crit = sum(1 for f in findings if f["severity"].lower() == "critical")
    high = sum(1 for f in findings if f["severity"].lower() == "high")
    decisions.append({
        "id": new_id(),
        "assessment_id": assessment_id,
        "finding_id": None,
        "autonomy_level": order[min(cap_idx, 1)],
        "classification": "summary",
        "risk": risk,
        "security_confidence": 0.9 if findings else 0.5,
        "model_confidence": None,
        "rationale_json": json.dumps({
            "posture": risk,
            "material_findings": len(findings),
            "critical": crit, "high": high,
            "next_best_step": ("prioritize validation of critical/high items"
                               if crit or high else
                               "no material issues detected; maintain monitoring"),
        }),
        "evidence_refs_json": "[]",
        "missing_evidence_json": "[]",
        "recommendations_json": json.dumps(
            ["Validate high/critical findings before remediation"] if (crit or high) else []),
        "selected_action": None,
        "policy_result": "allowed_within_cap",
        "authorization_result": "unchanged",
        "verification_state": "none",
        "model_runtime": "deterministic-rule-pack",
        "rule_pack_version": risk_version,
        "created_at": now_iso(),
    })
    return decisions