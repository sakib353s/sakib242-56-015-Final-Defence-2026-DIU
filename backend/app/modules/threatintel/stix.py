"""STIX 2.1 subset parser for CYBERWATCH-BD Threat Intelligence.

Everything coming through this module is UNTRUSTED DATA. Parsed fields are kept
as inert text values: they are never executed, never treated as instructions,
and never widen scope or policy. Hard limits stop oversized/hostile bundles:
max 2 MiB body, 1000 objects, 4000 chars per text field.

Supported: indicator (pattern -> observables), vulnerability, malware,
threat-actor, campaign, tool, attack-pattern, infrastructure, intrusion-set,
course-of-action, report, observed-data (embedded observables), identity, and
`relationship` objects which become internal links when both ends are present.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_OBJECTS = 1000
MAX_TEXT = 4000

ALLOWED_TYPES = {
    "indicator", "malware", "threat-actor", "campaign", "tool", "attack-pattern",
    "infrastructure", "vulnerability", "report", "observed-data", "intrusion-set",
    "course-of-action", "identity",
}

_TLP_RE = re.compile(r"^tlp:(clear|green|amber|red)$", re.I)
_CONF_WORDS = {"low": 25, "medium": 50, "high": 75}

# [ipv4-addr:value = '1.2.3.4'] / [file:hashes.'SHA-256' = 'abc'] style comparisons
_CMP_RE = re.compile(
    r"([A-Za-z][\w-]*)(?::([A-Za-z][\w-]*))?(?:\.'?([^']*)'?)?\s*=\s*'([^']*)'")

_OBS_TYPE_MAP = {
    "ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "domain",
    "url": "url", "file": "hash", "email-addr": "email",
}


def _clean(v, limit: int = MAX_TEXT) -> str:
    if not isinstance(v, str):
        return ""
    return v[:limit].strip()


def normalize_value(observable_type: str, value: str) -> str:
    v = value.strip().lower().rstrip(".") if observable_type == "domain" else value.strip()
    if observable_type == "hash":
        return v
    if observable_type in ("ipv4", "ipv6"):
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return ""
    if observable_type == "domain":
        if not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+", v):
            return ""
    if observable_type == "email" and "@" not in v:
        return ""
    return v


def value_hash(observable_type: str, value: str) -> str:
    return hashlib.sha256(f"{observable_type}|{value}".encode()).hexdigest()


def detect_observable_type(value: str) -> tuple[str, str] | None:
    """For operator searches and assessment correlation: classify a raw value."""
    v = value.strip()
    try:
        ip = ipaddress.ip_address(v)
        return ("ipv6" if ip.version == 6 else "ipv4", str(ip))
    except ValueError:
        pass
    low = v.lower()
    if low.startswith(("http://", "https://")):
        return ("url", low)
    if "@" in v and "." in v.split("@")[-1]:
        return ("email", low)
    if re.fullmatch(r"[a-f0-9]{32}", low) or re.fullmatch(r"[a-f0-9]{40}", low) \
            or re.fullmatch(r"[a-f0-9]{64}", low):
        return ("hash", low)
    if re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+", low):
        return ("domain", low.rstrip("."))
    return None


def parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """Extract (observable_type, normalized_value) pairs from STIX patterns.
    Unsupported comparisons are dropped silently — never guessed."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in _CMP_RE.finditer(pattern or ""):
        stix_type, field, subfield, value = m.group(1), (m.group(2) or "").lower(), \
            (m.group(3) or ""), m.group(4)
        obs_type = _OBS_TYPE_MAP.get(stix_type.lower())
        if not obs_type:
            continue
        if stix_type.lower() == "file":
            if "hash" not in ((field or "") + (subfield or "")).lower():
                continue
        norm = normalize_value(obs_type, value)
        if not norm or (obs_type, norm) in seen:
            continue
        seen.add((obs_type, norm))
        out.append((obs_type, norm))
    return out


def _confidence(raw) -> int | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)) and 0 <= raw <= 100:
        return int(raw)
    if isinstance(raw, str) and raw.lower() in _CONF_WORDS:
        return _CONF_WORDS[raw.lower()]
    return None


def _tlp(labels) -> str | None:
    for lb in labels if isinstance(labels, list) else []:
        m = _TLP_RE.match(str(lb).strip())
        if m:
            return m.group(1).upper()
    return None


def _embedded_observables(obj: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    inner = obj.get("objects")
    if not isinstance(inner, dict):
        return out
    for so in inner.values():
        if not isinstance(so, dict):
            continue
        t = str(so.get("type", "")).lower()
        obs_type = _OBS_TYPE_MAP.get(t)
        if not obs_type:
            continue
        if obs_type == "hash":
            hashes = so.get("hashes") or {}
            if isinstance(hashes, dict):
                for h in hashes.values():
                    norm = normalize_value("hash", str(h))
                    if norm:
                        out.append(("hash", norm))
        else:
            norm = normalize_value(obs_type, str(so.get("value", "")))
            if norm:
                out.append((obs_type, norm))
    return out


def parse_bundle(raw: str | dict) -> tuple[list[dict], list[dict], list[str]]:
    """Return (objects, relationships, errors). objects entries carry:
    stix_type, stix_id, name, description, pattern, pattern_type, valid_from,
    valid_until, confidence, tlp, labels, kill_chain, external_refs,
    first_seen, last_seen, observables[(type,value)]."""
    errors: list[str] = []
    if isinstance(raw, str):
        if len(raw.encode(errors="ignore")) > MAX_BODY_BYTES:
            raise ValueError(f"bundle exceeds {MAX_BODY_BYTES} bytes")
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid JSON: {e}") from e
    if not isinstance(raw, dict) or raw.get("type") != "bundle":
        raise ValueError("not a STIX 2.1 bundle (missing type=bundle)")
    items = raw.get("objects")
    if not isinstance(items, list):
        raise ValueError("bundle.objects must be a list")
    if len(items) > MAX_OBJECTS:
        raise ValueError(f"bundle exceeds {MAX_OBJECTS} objects")

    objects: list[dict] = []
    relationships: list[dict] = []
    for i, o in enumerate(items):
        if not isinstance(o, dict):
            errors.append(f"objects[{i}]: not an object")
            continue
        stype = str(o.get("type", "")).lower()
        if stype == "relationship":
            relationships.append({
                "stix_id": _clean(str(o.get("id", "")), 200),
                "relationship_type": _clean(str(o.get("relationship_type", "related-to")), 80)
                or "related-to",
                "source_ref": _clean(str(o.get("source_ref", "")), 200),
                "target_ref": _clean(str(o.get("target_ref", "")), 200),
                "description": _clean(o.get("description", "")),
            })
            continue
        if stype not in ALLOWED_TYPES:
            errors.append(f"objects[{i}]: unsupported type '{stype}' (kept as skipped)")
            continue
        labels = o.get("labels") if isinstance(o.get("labels"), list) else []
        labels = [_clean(str(x), 120) for x in labels][:20]
        name = _clean(o.get("name") or o.get("title") or o.get("value")
                      or o.get("id") or f"{stype}-{i}", 400)
        observables = parse_pattern(_clean(o.get("pattern", "")))
        if stype == "observed-data" and not observables:
            observables = _embedded_observables(o)
        objects.append({
            "stix_type": stype,
            "stix_id": _clean(str(o.get("id", "")), 200),
            "name": name,
            "description": _clean(o.get("description", "")),
            "pattern": _clean(o.get("pattern", "")),
            "pattern_type": _clean(str(o.get("pattern_type", "")), 40),
            "valid_from": _clean(str(o.get("valid_from", "")), 40) or None,
            "valid_until": _clean(str(o.get("valid_until", "")), 40) or None,
            "confidence": _confidence(o.get("confidence")),
            "tlp": _tlp(labels),
            "labels": json.dumps(labels),
            "kill_chain": json.dumps(o.get("kill_chain_phases") if isinstance(
                o.get("kill_chain_phases"), list) else [])[:MAX_TEXT],
            "external_refs": json.dumps(o.get("external_references") if isinstance(
                o.get("external_references"), list) else [])[:MAX_TEXT],
            "first_seen": _clean(str(o.get("created", "")), 40) or None,
            "last_seen": _clean(str(o.get("modified", "")), 40) or None,
            "observables": observables,
        })
    return objects, relationships, errors


def build_bundle(domain_objects: list[dict], bundle_id_seed: str) -> dict:
    """Emit a valid STIX 2.1 bundle from internal objects (export path).
    Uses deterministic uuid5 ids derived from bundle seed + local id."""
    import uuid
    NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")

    def stix_for(o: dict) -> dict:
        suid = uuid.uuid5(NS, o["local_id"])
        so = {"type": o["stix_type"],
              "id": f"{o['stix_type']}--{suid}",
              "spec_version": "2.1",
              "created": o.get("created_at") or "1970-01-01T00:00:00.000Z",
              "modified": o.get("updated_at") or o.get("created_at") or "1970-01-01T00:00:00.000Z",
              "name": o.get("name", "")}
        if o.get("description"):
            so["description"] = o["description"]
        if o.get("pattern"):
            so["pattern"] = o["pattern"]
            so["pattern_type"] = o.get("pattern_type") or "stix"
            if o.get("valid_from"):
                so["valid_from"] = o["valid_from"]
        if o.get("confidence") is not None:
            so["confidence"] = o["confidence"]
        labels = []
        if o.get("tlp"):
            labels.append(f"tlp:{o['tlp'].lower()}")
        try:
            labels += [x for x in json.loads(o.get("labels_json") or "[]") if x]
        except json.JSONDecodeError:
            pass
        if labels:
            so["labels"] = labels
        for key, col in (("kill_chain_phases", "kill_chain_json"),
                         ("external_references", "external_refs_json")):
            try:
                v = json.loads(o.get(col) or "[]")
                if v:
                    so[key] = v
            except json.JSONDecodeError:
                pass
        if o.get("revoked"):
            so["revoked"] = True
        return so

    objects = [stix_for(o) for o in domain_objects]
    return {"type": "bundle",
            "id": f"bundle--{uuid.uuid5(NS, bundle_id_seed)}",
            "spec_version": "2.1",
            "objects": objects}
