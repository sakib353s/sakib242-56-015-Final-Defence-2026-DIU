"""Tools console — REAL vendored engines (GitHub release binaries), one gate.

Every tool runs as a fixed argv (no shell), with a hard timeout, and its stdout
is parsed into simple rows for the UI. Active (touch-the-target) tools require
a live vuln_scan warrant covering the target — auto-matched from the ledger so
the UI stays "input + button + result" while the gate stays fail-closed.
"""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
from pathlib import Path

from app.core.errors import RefusedOutOfWork
from app.core.scopes import is_target_like, matches

VENDOR = Path(__file__).resolve().parents[3] / "vendor"
BIN = VENDOR / "bin"
WORDLIST = VENDOR / "wordlists" / "common.txt"
SQLMAP = VENDOR / "sqlmap" / "sqlmap.py"

URL_RE = re.compile(r"^https?://[^\s]+$")


def _host_of(url: str) -> str:
    return url.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()


def _ok_host(t: str):
    if not is_target_like(t):
        raise RefusedOutOfWork("target must be an IP or domain")


def _ok_url(t: str):
    if not URL_RE.match(t) or not is_target_like(_host_of(t)):
        raise RefusedOutOfWork("target must be a full http(s) URL with an IP/host")


def _lines(out: str):
    return [{"item": ln.strip()} for ln in out.splitlines() if ln.strip()]


def _jsonl(out: str, pick):
    rows = []
    for ln in out.splitlines():
        try:
            d = json.loads(ln)
        except json.JSONDecodeError:
            continue
        r = pick(d)
        if r:
            rows.append(r)
    return rows


def _sev(d):
    return (d.get("info") or {}).get("severity", "?")


TOOLS: dict[str, dict] = {
    # ---- passive: public sources only, no packet to target ----
    "subfinder": {
        "label": "subfinder", "purpose": "Passive subdomain enumeration",
        "input": "domain", "active": False, "timeout": 90,
        "validate": _ok_host,
        "argv": lambda t, env: [str(BIN / "subfinder"), "-d", t, "-silent"],
        "parse": _lines,
    },
    # ---- active recon ----
    "naabu": {
        "label": "naabu", "purpose": "TCP port scan, top 1000 ports",
        "input": "host", "active": True, "timeout": 150,
        "validate": _ok_host,
        "argv": lambda t, env: [str(BIN / "naabu"), "-host", t,
                                "-top-ports", "1000", "-rate", "500", "-json", "-silent"],
        "parse": lambda out: _jsonl(out, lambda d: {"item": f"tcp/{d.get('port')} open",
                                                    "port": d.get("port"),
                                                    "service": d.get("service", "")}),
    },
    "httpx": {
        "label": "httpx", "purpose": "HTTP/TLS probe with technology detection",
        "input": "url", "active": True, "timeout": 90,
        "validate": _ok_url,
        "argv": lambda t, env: [str(BIN / "httpx"), "-u", t, "-json", "-silent",
                                "-title", "-tech-detect", "-follow-redirects"],
        "parse": lambda out: _jsonl(out, lambda d: {
            "item": f"{d.get('status_code')} {d.get('url')}",
            "title": d.get("title", ""), "tech": ",".join(d.get("tech-detect", []) or [])}),
    },
    "katana": {
        "label": "katana", "purpose": "Web crawler, depth 2",
        "input": "url", "active": True, "timeout": 150,
        "validate": _ok_url,
        "argv": lambda t, env: [str(BIN / "katana"), "-u", t, "-jsonl", "-silent",
                                "-depth", "2", "-timeout", "5", "-concurrency", "20"],
        "parse": lambda out: _jsonl(out, lambda d: {
            "item": d.get("url") or (d.get("request") or {}).get("endpoint", "")}),
    },
    "ffuf": {
        "label": "ffuf", "purpose": "Content fuzzing (SecLists common, 60 s cap)",
        "input": "url", "active": True, "timeout": 120,
        "validate": _ok_url,
        "argv": None,  # custom: JSON report to temp file (stdout envelope unreliable on -maxtime exit)
        "parse": lambda out: [],
    },
    "nuclei": {
        "label": "nuclei", "purpose": "Template scanner, 9000+ CVE and misconfiguration checks",
        "input": "url", "active": True, "timeout": 300,
        "validate": _ok_url,
        "argv": lambda t, env: [str(BIN / "nuclei"), "-u", t, "-jsonl", "-silent",
                                "-severity", "info,low,medium,high,critical",
                                "-ni", "-duc"],
        "parse": lambda out: _jsonl(out, lambda d: {
            "item": (d.get("info") or {}).get("name", "?"),
            "severity": _sev(d), "matched": d.get("matched", ""),
            "id": (d.get("info") or {}).get("template-id", d.get("template-id", ""))}),
    },
    "dalfox": {
        "label": "dalfox", "purpose": "Cross-site scripting scan",
        "input": "url", "active": True, "timeout": 180,
        "validate": _ok_url,
        "argv": None,  # custom: writes JSON report to temp file
        "parse": lambda out: _lines(out),
    },
    "sqlmap": {
        "label": "sqlmap", "purpose": "SQL injection check (level 1, batch)",
        "input": "url", "active": True, "timeout": 240,
        "validate": _ok_url,
        "argv": lambda t, env: [env["python"], str(SQLMAP), "-u", t, "--batch",
                                "--level", "1", "--risk", "1", "--timeout", "20",
                                "--threads", "2", "--technique", "BEU"],
        "parse": lambda out: [{"item": ln.strip()} for ln in out.splitlines()
                              if any(k in ln for k in ("is vulnerable", "might be injectable",
                                                       "parameter", "back-end DBMS", "No parameter"))],
    },
}


def installed(tool: str) -> dict:
    if tool == "sqlmap":
        return {"installed": SQLMAP.exists()}
    p = BIN / tool
    return {"installed": p.exists(), "size_mb": round(p.stat().st_size / 1e6, 1) if p.exists() else 0}


ANSI = re.compile(r"\x1b\[[0-9;]*m")
VERSION_RE = re.compile(r"v?\d+\.\d+(?:\.\d+)*(?:[-+#][0-9A-Za-z.]+)?")

# `dalfox version` starts a scan, so every probe uses an explicit version flag.
VERSION_ARGV: dict[str, list[str]] = {
    "subfinder": ["-version"], "naabu": ["-version"], "httpx": ["-version"],
    "katana": ["-version"], "nuclei": ["-version"], "ffuf": ["-V"],
    "dalfox": ["--version"], "sqlmap": ["--version"],
}


def pick_version(raw: str) -> str:
    lines = [ln.strip() for ln in ANSI.sub("", raw).splitlines() if ln.strip()]
    for want_version_line in (True, False):
        for ln in lines:
            if ("ersion" in ln) == want_version_line:
                m = VERSION_RE.search(ln)
                if m:
                    return m.group(0)
    return "unknown"


async def _ver(tool: str) -> str:
    """Version is fixed for the lifetime of the process, so probe once."""
    cached = TOOLS[tool].get("version")
    if cached:
        return cached
    argv = ([__import__("sys").executable, str(SQLMAP)] if tool == "sqlmap"
            else [str(BIN / tool)]) + VERSION_ARGV[tool]
    try:
        r = await asyncio.create_subprocess_exec(*argv,
                                                 stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(r.communicate(), timeout=30)
        ver = pick_version(out.decode(errors="replace"))
    except Exception:
        ver = "unknown"
    TOOLS[tool]["version"] = ver
    return ver


def host_for_scope(tool: str, target: str) -> str:
    return _host_of(target) if TOOLS[tool]["input"] == "url" else target


def find_warrant(user_id: str, target: str) -> dict | None:
    """Newest live vuln_scan warrant owned/usable by anyone whose scope covers target."""
    from app.gateway.deps import warrant_window_active
    from app.db import sqlite as sql

    for w in sql.all_("SELECT * FROM auth_ledger WHERE kind='vuln_scan' "
                      "AND revoked_at IS NULL AND valid_until > datetime('now') "
                      "ORDER BY valid_until DESC LIMIT 50"):
        try:
            if warrant_window_active(w) and matches(json.loads(w["scope_json"]), target):
                return w
        except (ValueError, KeyError):
            continue
    return None


async def run_dalfox(target: str, timeout: int):
    """dalfox needs a report file; everything else is a plain argv run."""
    with tempfile.TemporaryDirectory() as td:
        rep = Path(td) / "report.jsonl"
        argv = [str(BIN / "dalfox"), "scan", target, "--no-color", "-f", "jsonl",
                "-o", str(rep)]
        rc, out, err = await _exec(argv, {}, timeout)
        rows = []
        if rep.exists():
            for ln in rep.read_text().splitlines():
                try:
                    d = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                if "meta" in d:
                    continue
                rows.append({"item": str(d.get("vuln_id") or d.get("type") or d.get("message") or "finding"),
                             "severity": str(d.get("sev") or d.get("severity") or ""),
                             "param": str(d.get("param", "")),
                             "inject": str(d.get("inject") or d.get("payload") or "")[:80]})
        return rc, out or err, rows


async def run_ffuf(target: str, timeout: int):
    with tempfile.TemporaryDirectory() as td:
        rep = Path(td) / "ffuf.json"
        argv = [str(BIN / "ffuf"), "-u", target.rstrip("/") + "/FUZZ",
                "-w", str(WORDLIST), "-mc", "200,204,301,302,403",
                "-t", "40", "-timeout", "8", "-maxtime", "60",
                "-s", "-o", str(rep), "-of", "json"]
        rc, out, err = await _exec(argv, {}, timeout)
        rows = []
        if rep.exists():
            try:
                for r in (json.loads(rep.read_text() or "{}").get("results") or []):
                    rows.append({"item": str((r.get("input") or {}).get("FUZZ", "")),
                                 "status": r.get("status"), "length": r.get("length"),
                                 "words": r.get("words")})
            except (json.JSONDecodeError, ValueError):
                pass
        return {"tool": "ffuf", "exit": rc, "count": len(rows), "rows": rows[:200],
                "raw_tail": err[-2000:]}


async def _exec(argv, env, timeout: int):
    import os

    child_env = {**os.environ, "HOME": str(Path.home()),
                 "PATH": f"{BIN}{os.pathsep}{os.environ.get('PATH', '')}"}
    child_env.update(env or {})
    proc = await asyncio.create_subprocess_exec(*argv,
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.PIPE,
                                                env=child_env)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", f"killed after {timeout}s timeout"


async def execute(tool: str, target: str):
    spec = TOOLS[tool]
    spec["validate"](target)
    if tool == "dalfox":
        rc, raw, rows = await run_dalfox(target, spec["timeout"])
        return {"tool": tool, "exit": rc, "count": len(rows), "rows": rows[:200],
                "raw_tail": raw[-2000:]}
    if tool == "ffuf":
        return await run_ffuf(target, spec["timeout"])
    argv = spec["argv"](target, {"python": __import__("sys").executable})
    rc, out, err = await _exec(argv, {}, spec["timeout"])
    try:
        rows = spec["parse"](out)
    except json.JSONDecodeError:
        rows = _lines(out)
    rows = [{"item": str(r.get("item", r)) if isinstance(r, dict) else str(r)} | r
            for r in rows][:200]
    return {"tool": tool, "exit": rc, "count": len(rows), "rows": rows,
            "raw_tail": (out if rc == 0 else err)[-2000:]}
