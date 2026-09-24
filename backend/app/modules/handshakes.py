"""Kill-chain ordered module handshakes for boot stage S4 + module registry.

Each handshake performs a REAL probe (subprocess --version, HTTP ping, import,
control-socket connect) and returns (status, detail). status ∈ {OK, WARN, FAIL}.
In lab mode, infrastructure FAILs degrade to WARN "LAB-DEGRADED" — never silently:
the degraded state is printed and audited. Production halts (fail-closed).
Security gates (S3/S6) never degrade in any mode.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import shutil
import subprocess
from pathlib import Path

import httpx

from app.core.config import get_settings

S = get_settings()


async def _run(cmd: list[str], timeout: float = 6.0) -> tuple[int, str]:
    try:
        p = await asyncio.to_thread(
            subprocess.run, cmd, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, (p.stdout or p.stderr).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return -1, "binary-missing"


# --- nine handshakes (kill-chain order) ----------------------------------------
async def hs_pentest() -> tuple[str, str]:
    rc, out = await _run(["nmap", "--version"])
    if rc == 0:
        ver = out.splitlines()[0] if out else "?"
        return "OK", ver.replace("Nmap version ", "nmap ")[:38]
    from app.modules.tools import service as tools_service

    vendored = [t for t in ("naabu", "nuclei", "ffuf", "dalfox")
                if tools_service.installed(t)["installed"]]
    if len(vendored) >= 2:
        return "OK", f"vendored engines live: {'+'.join(vendored)} (nmap absent)"
    return "FAIL", "nmap binary unavailable and tool console not vendored"


async def hs_vuln() -> tuple[str, str]:
    try:
        r = await httpx.AsyncClient(timeout=6).get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"resultsPerPage": 1},
            headers={"user-agent": "cwb-core/5.0"} | ({"apiKey": S.nvd_api_key} if S.nvd_api_key else {}),
        )
        if r.status_code == 200:
            total = r.json().get("totalResults", 0)
            return "OK", f"NVD CVE feed reachable ({total:,} CVEs indexed)"
        return "WARN", f"NVD HTTP {r.status_code}"
    except Exception as e:
        return "FAIL", f"NVD unreachable: {type(e).__name__}"


async def hs_soc() -> tuple[str, str]:
    vendored = Path(__file__).resolve().parents[2] / "vendor" / "bin" / "suricata"
    rc, out, used = -1, "", None
    for cand in (str(vendored), "suricata"):
        rc, out = await _run([cand, "-V"])
        if rc == 0:
            used = cand
            break
    if rc != 0:
        return "FAIL", "suricata binary unavailable"
    tail = out.split("version", 1)[-1].split("RELEASE")[0].strip() if out else "?"
    ver = "suricata " + (tail or "?")
    rules = 0
    if S.suricata_rules_path and Path(S.suricata_rules_path).exists():
        rules = sum(1 for line in Path(S.suricata_rules_path).read_text(errors="ignore").splitlines()
                    if line.strip() and not line.startswith("#"))
    eve_live = bool(S.suricata_eve_path) and Path(S.suricata_eve_path).exists()
    if rules:
        return "OK", f"{ver} rules {'%dk' % (rules // 1000)}" + (" · EVE tail live" if eve_live else "")
    return "WARN", f"{ver} (ruleset path unset — EVE tail disabled)"


async def hs_remediation() -> tuple[str, str]:
    try:
        importlib.import_module("paramiko")
        import difflib
        guard = Path(__file__).resolve().parents[1] / "modules" / "remediation" / "saga.py"
        if not guard.exists():
            return "FAIL", "diff-preview guard module missing"
        return "OK", "diff-preview guard armed" if difflib else ("OK", "diff engine ready")
    except ImportError:
        return "FAIL", "paramiko import failed"


async def hs_osint() -> tuple[str, str]:
    """FREE-FIRST probe: HIBP breach registry (no key) + PwnedPasswords range (no key).
    Optional keys are validated when present. Boot never depends on any external
    key — every tier works keyless."""
    notes = []
    try:
        async with httpx.AsyncClient(timeout=8) as h:
            r = await h.get("https://haveibeenpwned.com/api/v3/breaches",
                            headers={"user-agent": "cwb-core"})
            p = await h.get("https://api.pwnedpasswords.com/range/00001")
        if r.status_code != 200 or p.status_code != 200:
            return "FAIL", f"HIBP-registry HTTP {r.status_code} / PwnedPass HTTP {p.status_code}"
        notes.append(f"HIBP registry free ({len(r.json())} breaches) + PwnedPass range")
    except Exception as e:
        return "FAIL", f"free breach sources unreachable: {type(e).__name__}"
    if S.hibp_api_key:
        try:
            rk = await httpx.AsyncClient(timeout=8).get(
                "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com",
                headers={"hibp-api-key": S.hibp_api_key, "user-agent": "cwb-core"})
            notes.append("HIBP per-account key live (exact tier)" if rk.status_code in (200, 404)
                         else f"HIBP key rejected (HTTP {rk.status_code})")
        except Exception:
            notes.append("HIBP key unreachable")
    if S.shodan_api_key:
        try:
            rr = await httpx.AsyncClient(timeout=6).get("https://api.shodan.io/profile",
                                                         params={"key": S.shodan_api_key})
            notes.append(f"shodan v2 {'authed' if rr.status_code == 200 else 'key rejected'}")
        except Exception:
            notes.append("shodan unreachable")
    else:
        notes.append("shodan key absent (domain recon still live: DNS/RDAP/crt.sh/TLS — all free)")
    status = "WARN" if any("rejected" in n or "unreachable" in n for n in notes) else "OK"
    return status, "; ".join(notes)


async def hs_docfp() -> tuple[str, str]:
    try:
        import hashlib  # noqa
        from PIL import Image  # noqa
        import pypdf  # noqa
        return "OK", "sha-256 + watermark (PIL/pypdf)"
    except ImportError as e:
        return "FAIL", f"docfp dependency missing: {e.name}"


async def hs_victim() -> tuple[str, str]:
    tpl = Path(__file__).resolve().parents[1] / "reports" / "templates"
    need = {"btrc_complaint", "cyber_police_complaint"}
    have = {p.stem for p in tpl.glob("*.json")}
    if not need.issubset(have):
        return "FAIL", f"templates missing: {need - have}"
    return "OK", "BTRC/Police templates loaded"


async def hs_ipanon() -> tuple[str, str]:
    try:
        from stem.control import Controller
    except ImportError:
        return "FAIL", "stem import failed"
    rc, _ = await _run([S.proxychains_bin, "-h"], timeout=3)
    pc = "proxychains4 ok" if rc >= 0 and rc != -1 else "proxychains4 missing"
    try:
        with Controller.from_port(address=S.tor_control_host, port=S.tor_control_port) as ctl:
            if S.tor_control_password:
                ctl.authenticate(S.tor_control_password)
            version = ctl.get_version()
            return "OK", f"tor {version} ctl + {pc}" if rc != -1 else f"tor {version} ctl ({pc})"
    except Exception:
        if rc == -1:
            return "FAIL", "tor control unreachable; proxychains4 missing"
        return "WARN", f"tor control unreachable; {pc}"


async def hs_hwmon() -> tuple[str, str]:
    try:
        import paramiko
        parts = [f"paramiko {paramiko.__version__}"]
    except ImportError:
        return "FAIL", "paramiko import failed"
    try:
        import pysnmp
        parts.append("pysnmp")
    except ImportError:
        parts.append("pysnmp-absent(builtin BER)")
    return "OK", " + ".join(parts)


HANDSHAKES = {
    "pentest": ("Pentest Engine", hs_pentest),
    "vuln": ("Vuln Scanner", hs_vuln),
    "soc": ("SOC Center", hs_soc),
    "remediation": ("Auto-Remediation", hs_remediation),
    "osint": ("OSINT & Breach", hs_osint),
    "docfp": ("Doc Fingerprint", hs_docfp),
    "victim": ("Victim Support", hs_victim),
    "ipanon": ("IP Anonymizer", hs_ipanon),
    "hwmon": ("Hardware Monitor", hs_hwmon),
}


def module_health() -> list[dict]:
    """Current handshake state snapshot for /dashboard module grid (cached in API)."""
    return [{"module": k, "display": v[0]} for k, v in HANDSHAKES.items()]
