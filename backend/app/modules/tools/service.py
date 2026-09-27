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
import sys
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
    # authority = everything up to path/query/fragment, userinfo stripped LAST-separator
    # so it yields the REAL connect host. Stripping ?/# first is what closes the scope
    # drift where "http://good.com?x=@evil.com" was scoped as evil.com but scanned good.com.
    rest = url.split("://", 1)[-1]  # scheme may be absent on garbage input — never crash
    rest = rest.split("#", 1)[0].split("?", 1)[0]
    return rest.split("/", 1)[0].split("@")[-1].split(":")[0].lower()


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


def _naabu_rows(out: str) -> list[dict]:
    """naabu re-emits the same open port on retry; keep the first sighting only."""
    seen: set[object] = set()
    rows: list[dict] = []
    for r in _jsonl(out, lambda d: {"item": f"tcp/{d.get('port')} open",
                                    "port": d.get("port"),
                                    "service": d.get("service", "")}):
        if r["port"] in seen:
            continue
        seen.add(r["port"])
        rows.append(r)
    return rows


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
        "parse": _naabu_rows,
    },
    "httpx": {
        "label": "httpx", "purpose": "HTTP/TLS probe with technology detection",
        "input": "url", "active": True, "timeout": 90,
        "validate": _ok_url,
        "argv": lambda t, env: [str(BIN / "httpx"), "-u", t, "-json", "-silent",
                                "-title", "-tech-detect", "-follow-redirects"],
        "parse": lambda out: _jsonl(out, lambda d: {
            "item": f"{d.get('status_code')} {d.get('url')}",
            "title": d.get("title", ""), "tech": ",".join(d.get("tech", []) or [])}),
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
        "input": "url", "active": True, "timeout": 600,
        "validate": _ok_url,
        # The installed template store is ~18k templates; a full pass needs >5 min
        # on a healthy host, so the cap and per-request budget are explicit.
        "argv": lambda t, env: [str(BIN / "nuclei"), "-u", t, "-jsonl", "-silent",
                                "-severity", "info,low,medium,high,critical",
                                "-timeout", "5", "-retries", "0", "-ni", "-duc"],
        # `matcher-name` is what separates one finding from the next: this template
        # fires ~10 matchers per URL (one per missing header), all sharing info.name
        # and matched-at. Dropping it renders 10 identical rows that look like dupes.
        "parse": lambda out: _jsonl(out, lambda d: {
            "item": (d.get("info") or {}).get("name", "?"),
            "severity": _sev(d), "matched": d.get("matched-at", ""),
            "matcher": d.get("matcher-name", "") or "",
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
        # "[CRITICAL]" kept so early aborts (404 target, WAF block, unreachable)
        # are visible as rows instead of a silent count=0 exit!=0
        "parse": lambda out: [{"item": ln.strip()} for ln in out.splitlines()
                              if any(k in ln for k in ("is vulnerable", "might be injectable",
                                                       "parameter", "back-end DBMS", "No parameter",
                                                       "CRITICAL"))],
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
    argv = ([sys.executable, str(SQLMAP)] if tool == "sqlmap"
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


def _dalfox_argv(target: str, rep: Path) -> list[str]:
    return [str(BIN / "dalfox"), "scan", target, "--no-color", "-f", "jsonl", "-o", str(rep)]


def _ffuf_argv(target: str, rep: Path) -> list[str]:
    return [str(BIN / "ffuf"), "-u", target.rstrip("/") + "/FUZZ",
            "-w", str(WORDLIST), "-mc", "200,204,301,302,403",
            "-t", "40", "-timeout", "8", "-maxtime", "60",
            "-s", "-o", str(rep), "-of", "json"]


def _report_rows(tool: str, rep: Path) -> list[dict]:
    """Rows from the file-report tools (dalfox jsonl, ffuf json)."""
    if not rep.exists():
        return []
    if tool == "ffuf":
        try:
            return [{"item": str((r.get("input") or {}).get("FUZZ", "")),
                     "status": r.get("status"), "length": r.get("length"),
                     "words": r.get("words")}
                    for r in (json.loads(rep.read_text() or "{}").get("results") or [])]
        except (json.JSONDecodeError, ValueError):
            return []
    rows = []
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
    return rows


async def run_dalfox(target: str, timeout: int):
    """dalfox needs a report file; everything else is a plain argv run."""
    with tempfile.TemporaryDirectory() as td:
        rep = Path(td) / "report.jsonl"
        rc, out, err = await _exec(_dalfox_argv(target, rep), {}, timeout)
        rows = _report_rows("dalfox", rep)
        return rc, out or err, rows


async def run_ffuf(target: str, timeout: int):
    with tempfile.TemporaryDirectory() as td:
        rep = Path(td) / "ffuf.json"
        rc, out, err = await _exec(_ffuf_argv(target, rep), {}, timeout)
        rows = _report_rows("ffuf", rep)
        return {"tool": "ffuf", "exit": rc, "count": len(rows), "rows": rows[:200],
                "raw_tail": err[-2000:]}


def _child_env(extra: dict | None) -> dict:
    import os

    env = {**os.environ, "HOME": str(Path.home()),
           "PATH": f"{BIN}{os.pathsep}{os.environ.get('PATH', '')}"}
    env.update(extra or {})
    return env


async def _exec(argv, env, timeout: int):
    child_env = _child_env(env)
    # stdin MUST be closed: the ProjectDiscovery engines (httpx, naabu, katana,
    # nuclei) auto-read targets from stdin whenever it is not a TTY. Under the
    # server stdin is an inherited pipe that never reaches EOF, so without this
    # they block until the hard timeout and return nothing.
    proc = await asyncio.create_subprocess_exec(*argv,
                                                stdin=asyncio.subprocess.DEVNULL,
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
    argv = spec["argv"](target, {"python": sys.executable})
    rc, out, err = await _exec(argv, {}, spec["timeout"])
    try:
        rows = spec["parse"](out)
    except json.JSONDecodeError:
        rows = _lines(out)
    rows = [{"item": str(r.get("item", r)) if isinstance(r, dict) else str(r)} | r
            for r in rows][:200]
    return {"tool": tool, "exit": rc, "count": len(rows), "rows": rows,
            "raw_tail": (out if rc == 0 else err)[-2000:]}


async def stream_execute(tool: str, target: str):
    """Live variant of execute(): yields events as the process speaks.

    {"k":"start","tool","argv","timeout"} then one {"k":"line","v":...} per
    stdout/stderr line, {"k":"ping"} keepalives while the tool is silent (keeps
    dev-proxy sockets alive on long scans), and a final {"k":"result","v":...}
    with the same payload shape as execute().
    """
    spec = TOOLS[tool]
    spec["validate"](target)
    timeout = spec["timeout"]
    td: tempfile.TemporaryDirectory | None = None
    rep: Path | None = None
    if tool == "dalfox":
        td = tempfile.TemporaryDirectory()
        rep = Path(td.name) / "report.jsonl"
        argv = _dalfox_argv(target, rep)
    elif tool == "ffuf":
        td = tempfile.TemporaryDirectory()
        rep = Path(td.name) / "ffuf.json"
        argv = _ffuf_argv(target, rep)
    else:
        argv = spec["argv"](target, {"python": sys.executable})

    proc = None
    try:
        yield {"k": "start", "tool": tool, "argv": argv, "timeout": timeout}
        # stdin DEVNULL: PD engines block forever reading targets from an
        # inherited pipe (see _exec). stderr merged so progress is visible live.
        proc = await asyncio.create_subprocess_exec(*argv,
                                                    stdin=asyncio.subprocess.DEVNULL,
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.STDOUT,
                                                    env=_child_env({}))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        collected: list[str] = []
        timed_out = False
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                timed_out = True
                break
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(),
                                             timeout=min(10.0, remaining))
            except asyncio.TimeoutError:
                yield {"k": "ping"}
                continue
            if not raw:
                break
            ln = ANSI.sub("", raw.decode(errors="replace")).rstrip("\r\n")
            collected.append(ln + "\n")
            yield {"k": "line", "v": ln}
        if timed_out:
            proc.kill()
            tail = f"killed after {timeout}s timeout"
            collected.append(tail + "\n")
            yield {"k": "line", "v": tail}
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=10)
        except asyncio.TimeoutError:
            proc.kill()
            rc = -1
        if timed_out:
            rc = -1
        out = "".join(collected)
        if rep is not None:
            rows = _report_rows(tool, rep)
        else:
            try:
                rows = spec["parse"](out)
            except json.JSONDecodeError:
                rows = _lines(out)
        rows = [{"item": str(r.get("item", r)) if isinstance(r, dict) else str(r)} | r
                for r in rows][:200]
        yield {"k": "result", "v": {"tool": tool, "exit": rc, "count": len(rows),
                                    "rows": rows, "raw_tail": out[-2000:]}}
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
        if td is not None:
            td.cleanup()
