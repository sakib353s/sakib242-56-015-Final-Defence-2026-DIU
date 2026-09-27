"""SOC detection engine — versioned rules, suppression, correlation.

Events from any source (EVE alerts, FIM events, assessment material findings)
are evaluated against enabled detection_rules. A rule matches on declared
fields only; no shell, no templates, no executed content from the event.
Correlation counts matching events per key inside a window and escalates to an
incident once min_count is reached. Rule changes are versioned: editing a rule
inserts a new version row; the alert records which version fired.
"""
from __future__ import annotations

import json
import re
import time

from app.audit import chain
from app.core.errors import CWBError
from app.core.ids import new_id
from app.core.security import now_iso
from app.db import sqlite as sql

_cache: dict | None = None
_cache_ts: float = 0.0
_CACHE_TTL = 10.0


def _rules() -> list[dict]:
    global _cache, _cache_ts
    now = time.monotonic()
    if _cache is not None and now - _cache_ts < _CACHE_TTL:
        return _cache
    rows = sql.all_("SELECT * FROM detection_rules WHERE enabled=1")
    for r in rows:
        for col, key in (("matcher_json", "matcher"), ("correlate_json", "correlate"),
                         ("suppress_json", "suppress")):
            try:
                r[key] = json.loads(r[col] or "null")
            except json.JSONDecodeError:
                r[key] = None
    _cache, _cache_ts = rows, now
    return rows


def invalidate_cache() -> None:
    global _cache
    _cache = None


def _field(event: dict, dotted: str):
    cur = event
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _match(rule: dict, event: dict) -> bool:
    m = rule.get("matcher") or {}
    src = rule["source"]
    if src != "any" and event.get("source") != src:
        return False
    for k, cond in m.items():
        if k == "signature_regex":
            hay = str(event.get("signature") or event.get("title") or "")
            if not re.search(cond, hay, re.I):
                return False
        elif k == "severity":
            vals = cond if isinstance(cond, list) else [cond]
            if str(event.get("severity", "")).lower() not in [str(v).lower() for v in vals]:
                return False
        elif k == "src_ip_required":
            if cond and not event.get("src_ip"):
                return False
        elif k == "event_type":
            vals = cond if isinstance(cond, list) else [cond]
            if event.get("event_type") not in vals:
                return False
        elif k == "path_regex":
            hay = str(event.get("file_path") or event.get("path") or "")
            if not re.search(cond, hay):
                return False
        else:
            if str(_field(event, k) or "").lower() != str(cond).lower():
                return False
    return True


def _suppressed(rule: dict, event: dict, now_iso_str: str) -> bool:
    sup = rule.get("suppress") or {}
    entries = sup.get("rules") if isinstance(sup, dict) else None
    for s in entries or []:
        until = s.get("until", "")
        if until and until < now_iso_str:
            continue
        if s.get("src_ip") and s.get("src_ip") == event.get("src_ip"):
            return True
        rx = s.get("signature_regex")
        if rx and re.search(rx, str(event.get("signature") or event.get("title") or ""), re.I):
            return True
    return False


def _correlate(rule: dict, event: dict) -> dict | None:
    corr = rule.get("correlate")
    if not corr:
        return None
    key = corr.get("key", "src_ip")
    val = event.get(key)
    if not val:
        return None
    window = int(corr.get("window_s", 300))
    min_count = int(corr.get("min_count", 3))
    # Timestamps are stored as ISO-8601 with a 'T' separator and '+00:00' offset;
    # comparing them to datetime('now') as raw strings mis-orders around the 'T',
    # so both sides are normalised through datetime(). Column names come from a
    # whitelist — never interpolate a caller-supplied key into SQL.
    if rule["source"] == "fim":
        col = key if key in ("file_path", "event_type", "policy_id") else "file_path"
        cnt = sql.scalar(
            f"SELECT COUNT(*) FROM fim_events WHERE {col}=?"
            " AND datetime(detected_at) > datetime('now', ?)",
            event.get(col), f"-{window} seconds") or 0
    else:
        col = "src_ip" if key == "src_ip" else "signature"
        cnt = sql.scalar(
            f"SELECT COUNT(*) FROM alerts WHERE {col}=?"
            " AND datetime(ts) > datetime('now', ?)",
            val, f"-{window} seconds") or 0
    if cnt >= min_count:
        return {"key": key, "value": val, "count": cnt, "window_s": window}
    return None


def evaluate(event: dict, *, already_alerted: bool = False) -> list[dict]:
    """Run all enabled rules against one event dict. Returns fired results and,
    for events without an existing alert row, creates the alert + incident rows.
    Never raises — a broken rule must never stall an ingestion path."""
    out: list[dict] = []
    now = now_iso()
    for rule in _rules():
        try:
            if not _match(rule, event):
                continue
            if _suppressed(rule, event, now):
                out.append({"rule": rule["rule_key"], "suppressed": True})
                continue
            corr = _correlate(rule, event)
            fired = {"rule": rule["rule_key"], "rule_id": rule["id"],
                     "rule_version": rule["version"], "severity": rule["severity"],
                     "confidence": rule["confidence"], "correlation": corr}
            alert_id = event.get("alert_id") or event.get("id")
            if not already_alerted:
                alert_id = new_id()
                mitre = rule.get("mitre") or event.get("mitre")
                with sql.get_db() as c:
                    c.execute(
                        "INSERT INTO alerts (id, source, signature, category, severity, src_ip,"
                        " dest_ip, mitre, status, ts, raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (alert_id, rule["source"],
                         f"{rule['name']} [{rule['rule_key']} v{rule['version']}]"[:400],
                         rule["rule_key"], rule["severity"].upper(),
                         event.get("src_ip"), event.get("dest_ip"), mitre, "new", now,
                         json.dumps(event, default=str)[:8000]),
                    )
                fired["alert_id"] = alert_id
            if corr and corr.get("count") and rule.get("correlate", {}).get("escalate") == "incident":
                iid = new_id()
                with sql.get_db() as c:
                    c.execute(
                        "INSERT INTO incidents (id, alert_ref, playbook, status, payload_json,"
                        " opened_at) VALUES (?,?,?,?,?,?)",
                        (iid, alert_id, "detection-correlation", "open",
                         json.dumps({"rule": rule["rule_key"], "correlation": corr,
                                     "event": {k: event.get(k) for k in
                                               ("src_ip", "dest_ip", "file_path", "signature",
                                              "title") if event.get(k)}},
                                    default=str)[:4000], now),
                    )
                fired["incident_id"] = iid
                chain.safe_append("system:detect", "soc.incident.opened", iid,
                                  {"rule": rule["rule_key"], "corr": corr})
            out.append(fired)
        except Exception:
            continue
    return out


# ------------------------------------------------------------- rule management

def list_rules(include_disabled: bool = False) -> list[dict]:
    where = "" if include_disabled else "WHERE enabled=1"
    return sql.all_(
        f"SELECT * FROM detection_rules {where} ORDER BY rule_key, version DESC")


def create_rule(rule_key: str, name: str, source: str, matcher: dict, severity: str,
                confidence: float, actor: str, *, description: str = "",
                correlate: dict | None = None, mitre: str | None = None) -> dict:
    if source not in ("suricata", "fim", "assessment", "any"):
        raise CWBError("unknown source", status=422)
    if severity not in ("critical", "high", "medium", "low", "informational"):
        raise CWBError("unknown severity", status=422)
    if not isinstance(matcher, dict) or not matcher:
        raise CWBError("matcher must be a non-empty object", status=422)
    for cond in matcher.values():
        if isinstance(cond, str) and cond not in ("true", "false"):
            try:
                re.compile(cond)
            except re.error as e:
                raise CWBError(f"invalid regex in matcher: {e}", status=422)
    last = sql.scalar("SELECT MAX(version) FROM detection_rules WHERE rule_key=?", rule_key)
    version = (last or 0) + 1
    rid = new_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO detection_rules (id, rule_key, version, name, description, source,"
            " matcher_json, severity, confidence, correlate_json, mitre, enabled, created_by,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, rule_key, version, name[:200], description[:1000], source,
             json.dumps(matcher)[:4000], severity, confidence,
             json.dumps(correlate) if correlate else None, mitre, 1, actor,
             now_iso(), now_iso()),
        )
        c.execute("UPDATE detection_rules SET enabled=0, updated_at=? WHERE rule_key=? AND id<>?",
                  (now_iso(), rule_key, rid))
    invalidate_cache()
    chain.append(actor, "soc.rule.create", rid,
                 {"rule_key": rule_key, "version": version, "source": source})
    return {"id": rid, "rule_key": rule_key, "version": version}


def set_enabled(rid: str, enabled: bool, actor: str) -> dict:
    row = sql.one("SELECT * FROM detection_rules WHERE id=?", rid)
    if not row:
        raise CWBError("rule not found", status=404)
    with sql.get_db() as c:
        c.execute("UPDATE detection_rules SET enabled=?, updated_at=? WHERE id=?",
                  (1 if enabled else 0, now_iso(), rid))
    invalidate_cache()
    chain.append(actor, "soc.rule.enabled" if enabled else "soc.rule.disabled", rid,
                 {"rule_key": row["rule_key"], "version": row["version"]})
    return {"id": rid, "enabled": enabled}


def test_rule(matcher: dict, sample: dict) -> dict:
    """Dry-run a matcher against a supplied sample event — evaluation only."""
    fake = {"source": sample.get("source", "any"), "matcher": matcher}
    matched = _match({"source": "any", "matcher": matcher, "rule_key": "test"}, sample) \
        if fake["matcher"] else False
    return {"matcher": matcher, "would_match": bool(matched)}
