"""File Integrity Monitoring — real polling scanner.

Baseline per policy: (path, size, mtime_ns, mode, uid, gid, sha256<=8MiB).
Diff on every scan produces create/modify/hash_change/delete/rename/
permission_change/ownership_change. Content hashing runs only when mtime or
size changed (cheap steady-state). Symlinks and special files are skipped.
Every event flows through the SOC detection engine like any other source.
"""
from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import os
import stat
from pathlib import Path

from app.audit import chain
from app.core.errors import CWBError
from app.core.ids import new_id
from app.core.security import now_iso
from app.db import sqlite as sql
from app.gateway.wsmanager import manager

HASH_LIMIT = 8 * 1024 * 1024


def _hash_file(path: str) -> str | None:
    try:
        if os.path.getsize(path) > HASH_LIMIT:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _walk(policy: dict) -> dict[str, dict]:
    root = policy["path"]
    excludes = _json_list(policy["exclude_globs_json"])
    max_depth = int(policy["max_depth"])
    max_files = int(policy["max_files"])
    recursive = bool(policy["recursive"])
    out: dict[str, dict] = {}
    stack: list[tuple[str, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        try:
            entries = list(os.scandir(cur))
        except OSError:
            continue
        for e in entries:
            if len(out) >= max_files:
                return out
            p = e.path
            if any(fnmatch.fnmatch(p, g) for g in excludes):
                continue
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if recursive and depth + 1 < max_depth:
                        stack.append((p, depth + 1))
                    continue
                if not e.is_file(follow_symlinks=False):
                    continue
                st = e.stat(follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode):
                    continue
                out[p] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns,
                          "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid,
                          "gid": st.st_gid}
            except OSError:
                continue
    return out


def _json_list(raw) -> list[str]:
    try:
        v = json_loads(raw, [])
    except Exception:
        v = []
    return [str(x) for x in v if isinstance(x, str)][:50]


def json_loads(raw, default):
    import json
    if raw in (None, ""):
        return default
    return json.loads(raw)


def scan_policy(policy_id: str, actor: str = "system:fim") -> dict:
    """One full scan+diff+baseline-update cycle. Returns counts."""
    pol = sql.one("SELECT * FROM fim_policies WHERE id=?", policy_id)
    if not pol:
        raise CWBError("policy not found", status=404)
    root = pol["path"]
    if not Path(root).is_dir():
        with sql.get_db() as c:
            c.execute("UPDATE fim_policies SET last_scan_at=?, last_scan_status=? WHERE id=?",
                      (now_iso(), f"path unavailable: {root}", policy_id))
        return {"status": "path_unavailable", "path": root}

    current = _walk(pol)
    base_rows = sql.all_(
        "SELECT file_path, sha256, size, mode, uid, gid, mtime_ns FROM fim_baseline"
        " WHERE policy_id=?", policy_id)
    base = {r["file_path"]: r for r in base_rows}
    is_baseline = not pol["baseline_ready"]

    events: list[dict] = []
    now = now_iso()

    if is_baseline:
        with sql.get_db() as c:
            for p, meta in current.items():
                c.execute(
                    "INSERT OR REPLACE INTO fim_baseline (id, policy_id, file_path, sha256,"
                    " size, mode, uid, gid, mtime_ns, last_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (new_id(), policy_id, p, _hash_file(p), meta["size"], meta["mode"],
                     meta["uid"], meta["gid"], meta["mtime_ns"], now),
                )
            c.execute(
                "UPDATE fim_policies SET baseline_ready=1, files_baseline=?, last_scan_at=?,"
                " last_scan_status='baseline built' WHERE id=?",
                (len(current), now, policy_id))
        chain.append(actor, "fim.baseline.built", policy_id,
                     {"path": root, "files": len(current)})
        return {"status": "baseline_built", "files": len(current)}

    deleted: dict[str, dict] = {}
    created: dict[str, dict] = {}
    for p, meta in current.items():
        b = base.get(p)
        if not b:
            created[p] = meta
            continue
        changes = []
        if b["mode"] is not None and b["mode"] != meta["mode"]:
            changes.append(("permission_change", b["mode"], meta["mode"]))
        if b["uid"] is not None and (b["uid"] != meta["uid"] or b["gid"] != meta["gid"]):
            changes.append(("ownership_change", (b["uid"], b["gid"]),
                            (meta["uid"], meta["gid"])))
        if b["mtime_ns"] != meta["mtime_ns"] or b["size"] != meta["size"]:
            new_sha = _hash_file(p)
            if new_sha and new_sha != b["sha256"]:
                changes.append(("hash_change", b["sha256"], new_sha))
                changes.append(("modify", b["size"], meta["size"]))
            elif new_sha is not None:
                continue  # touched, content identical — not an integrity event
        for kind, old_v, new_v in changes:
            ev = {"source": "fim", "event_type": kind, "file_path": p,
                  "policy_id": policy_id, "detected_at": now}
            if kind == "permission_change":
                ev.update({"old_mode": old_v, "new_mode": new_v})
            elif kind == "ownership_change":
                ev.update({"old_uid": old_v[0], "new_uid": new_v[0]})
            elif kind == "hash_change":
                ev.update({"old_sha256": old_v, "new_sha256": new_v})
            elif kind == "modify":
                ev.update({"old_size": old_v, "new_size": new_v})
                continue  # hash_change already carries the signal
            events.append(ev)
    for p, b in base.items():
        if p not in current:
            deleted[p] = b

    # rename detection: created file whose hash matches a deleted file
    deleted_by_hash = {}
    for p, b in deleted.items():
        if b["sha256"]:
            deleted_by_hash.setdefault(b["sha256"], []).append(p)
    for p, meta in created.items():
        sha = _hash_file(p)
        cands = deleted_by_hash.get(sha or "", [])
        if cands and meta["size"] == next((deleted[c]["size"] for c in cands
                                          if deleted[c]["size"] == meta["size"]), None):
            old_p = cands.pop(0)
            events.append({"source": "fim", "event_type": "rename", "file_path": p,
                           "prev_path": old_p, "new_sha256": sha,
                           "policy_id": policy_id, "detected_at": now})
            deleted.pop(old_p, None)
            continue
        events.append({"source": "fim", "event_type": "create", "file_path": p,
                       "new_sha256": sha, "new_size": meta["size"],
                       "policy_id": policy_id, "detected_at": now})
    for p, b in deleted.items():
        events.append({"source": "fim", "event_type": "delete", "file_path": p,
                       "old_sha256": b["sha256"], "old_size": b["size"],
                       "policy_id": policy_id, "detected_at": now})

    alert_links: dict[str, str] = {}
    with sql.get_db() as c:
        for ev in events:
            eid = new_id()
            c.execute(
                "INSERT INTO fim_events (id, policy_id, event_type, file_path, prev_path,"
                " old_sha256, new_sha256, old_size, new_size, old_mode, new_mode, old_uid,"
                " new_uid, detected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (eid, policy_id, ev["event_type"], ev["file_path"], ev.get("prev_path"),
                 ev.get("old_sha256"), ev.get("new_sha256"), ev.get("old_size"),
                 ev.get("new_size"), ev.get("old_mode"), ev.get("new_mode"),
                 ev.get("old_uid"), ev.get("new_uid"), now),
            )
            ev["fim_event_id"] = eid
        # baseline upsert
        for p, meta in current.items():
            b = base.get(p)
            sha = None
            if p in created or p not in base:
                sha = _hash_file(p)
            elif b and (b["mtime_ns"] != meta["mtime_ns"] or b["size"] != meta["size"]):
                sha = _hash_file(p) or b["sha256"]
            else:
                sha = b["sha256"] if b else None
            c.execute(
                "INSERT INTO fim_baseline (id, policy_id, file_path, sha256, size, mode, uid,"
                " gid, mtime_ns, last_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(policy_id, file_path) DO UPDATE SET sha256=excluded.sha256,"
                " size=excluded.size, mode=excluded.mode, uid=excluded.uid,"
                " gid=excluded.gid, mtime_ns=excluded.mtime_ns, last_seen_at=excluded.last_seen_at",
                (new_id(), policy_id, p, sha, meta["size"], meta["mode"], meta["uid"],
                 meta["gid"], meta["mtime_ns"], now))
        for p in deleted:
            c.execute("DELETE FROM fim_baseline WHERE policy_id=? AND file_path=?",
                      (policy_id, p))
        c.execute("UPDATE fim_policies SET last_scan_at=?, last_scan_status=?, files_baseline=?"
                  " WHERE id=?", (now, f"{len(events)} events", len(current), policy_id))

    # detection engine pass (outside the write tx to allow its own inserts)
    from app.modules.soc import detection
    for ev in events:
        fired = detection.evaluate(ev, already_alerted=False)
        for f in fired:
            if f.get("alert_id"):
                alert_links[ev["fim_event_id"]] = f["alert_id"]
                with sql.get_db() as c:
                    c.execute("UPDATE fim_events SET alert_id=? WHERE id=?",
                              (f["alert_id"], ev["fim_event_id"]))
    if events:
        chain.safe_append(actor, "fim.scan.events", policy_id, {"count": len(events)})
    return {"status": "ok", "events": len(events), "files": len(current),
            "event_rows": events}


async def scan_policy_async(policy_id: str, actor: str = "system:fim") -> dict:
    result = await asyncio.to_thread(scan_policy, policy_id, actor)
    for ev in result.get("event_rows", [])[:50]:
        await manager.publish("alerts", "fim.event", ev)
    return result


async def scanner_loop():
    """Background worker: honour per-policy interval_s; degrade honestly."""
    await asyncio.sleep(8)  # let boot finish
    while True:
        try:
            due = sql.all_(
                "SELECT * FROM fim_policies WHERE enabled=1 AND"
                " (last_scan_at IS NULL OR"
                " datetime(last_scan_at) <= datetime('now', '-' || interval_s || ' seconds'))")
            for pol in due:
                await scan_policy_async(pol["id"])
        except Exception as e:
            chain.safe_append("system:fim", "fim.loop_error", "fim", {"error": str(e)[:200]})
        await asyncio.sleep(20)


def create_policy(path: str, name: str, actor: str, *, recursive: bool = True,
                  max_depth: int = 4, interval_s: int = 300, severity: str = "medium",
                  exclude_globs: list[str] | None = None) -> dict:
    p = Path(path).expanduser().resolve()
    if not p.is_dir():
        raise CWBError(f"path is not an accessible directory: {path}", status=422)
    if interval_s < 60:
        raise CWBError("interval_s must be >= 60", status=422)
    import json
    pid = new_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO fim_policies (id, name, path, recursive, max_depth, max_files,"
            " exclude_globs_json, interval_s, severity, enabled, baseline_ready, created_by,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, name[:120], str(p), 1 if recursive else 0, max(1, min(max_depth, 10)),
             5000, json.dumps(exclude_globs or []), max(60, interval_s), severity, 1, 0,
             actor, now_iso()),
        )
    chain.append(actor, "fim.policy.create", pid, {"path": str(p)})
    result = scan_policy(pid, actor)  # build baseline immediately
    return {"id": pid, "baseline": result}


def policy_status() -> dict:
    pols = sql.all_("SELECT * FROM fim_policies ORDER BY created_at")
    events_24h = sql.scalar(
        "SELECT COUNT(*) FROM fim_events WHERE detected_at > datetime('now','-1 day')")
    return {"policies": pols, "events_24h": events_24h,
            "engine": "polling baseline diff", "note":
            "Events reflect real filesystem state between scans; changes smaller than"
            " the interval that revert before a scan may not be observed."}
