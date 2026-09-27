"""Shared recon primitives for offensive modules (P-05a/P-05b).

naabu drives TCP port discovery (vendored binary); service identification is a
pure-python banner grab + well-known-port mapping, so the pipeline stays real on
hosts where nmap is absent. Banner probing is version observation only — no
exploit payloads, no brute force.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
from pathlib import Path

VENDORED_BIN = Path(__file__).resolve().parents[2] / "vendor" / "bin"
NAABU = VENDORED_BIN / "naabu"

DEFAULT_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,2375,3306," \
                "3389,5432,5900,6379,8000,8080,8443,8888,9090,9200,11211,27017"

WELL_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
    445: "microsoft-ds", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9090: "http", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}


async def naabu_ports(ip: str, ports: str = DEFAULT_PORTS, timeout: int = 150) -> list[int] | None:
    """TCP connect scan via vendored naabu. Returns sorted open ports, or None
    when the engine is unavailable (caller must degrade honestly, never fabricate)."""
    if not NAABU.exists():
        return None
    proc = await asyncio.create_subprocess_exec(
        str(NAABU), "-host", ip, "-port", ports, "-rate", "300", "-timeout", "1500",
        "-json", "-silent",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return None
    found: list[int] = []
    for line in out.decode(errors="replace").splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d.get("port"):
            found.append(int(d["port"]))
    return sorted(set(found))


def _recv_until(cli: socket.socket, max_bytes: int = 1024) -> str:
    cli.settimeout(3)
    chunks = []
    try:
        while len(b"".join(chunks)) < max_bytes:
            b = cli.recv(512)
            if not b:
                break
            chunks.append(b)
    except (socket.timeout, ssl.SSLError, ConnectionResetError, OSError):
        pass
    return b"".join(chunks).decode(errors="replace").strip()


PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
# canonical product name -> NVD CPE "vendor:product" (400 responses fall back to keyword)
CPE_PARTS = {
    "mariadb": "mariadb:mariadb", "mysql": "mysql:mysql", "nginx": "f5:nginx",
    "apache": "apache:http_server", "openssh": "openbsd:openssh", "openssl": "openssl:openssl",
    "proftpd": "proftpd:proftpd", "vsftpd": "vsftpd:vsftpd", "redis": "redis:redis",
    "postgresql": "postgresql:postgresql", "mongodb": "mongodb:mongodb",
    "memcached": "memcached:memcached", "elasticsearch": "elastic:elasticsearch",
    "tomcat": "apache:tomcat", "lighttpd": "lighttpd:lighttpd", "haproxy": "haproxy:haproxy",
    "caddy": "caddyserver:caddy", "dropbear": "matt_mckinstry:dropbear",
}
_KNOWN_TOKENS = ["mariadb", "mysql", "nginx", "apache httpd", "httpd", "openssh",
                 "openssl", "proftpd", "vsftpd", "redis", "postgresql", "postgres",
                 "mongodb", "memcached", "elasticsearch", "tomcat", "lighttpd",
                 "haproxy", "caddy", "dropbear", "bind", "dhcpd"]
_CANON = {"httpd": "apache", "apache httpd": "apache", "postgres": "postgresql"}


def _version_from_banner(first: str) -> tuple[str, str]:
    """Product + version from a greeting line, including binary-wrapped protocol
    banners like MySQL's '5.5.5-10.4.28-MariaDB' (protocol ver + real ver + name)."""
    low = first.lower()
    for p in _KNOWN_TOKENS:
        idx = low.find(p)
        if idx < 0:
            continue
        name = _CANON.get(p, p)
        after = low[idx + len(p): idx + len(p) + 24]
        m = re.match(r"[^\d]{1,12}(\d+(?:\.\d+){1,3})", after)
        if m:
            return name, m.group(1)
        before = re.findall(r"\d+(?:\.\d+){1,3}", low[:idx])  # trailing dotted version before name
        if before:
            return name, before[-1]
        return name, ""
    m = re.match(r"^([\w.+-]{2,20})[/ ](\d+(?:\.\d+){1,3})", low)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"^(\d+(?:\.\d+){1,3})[\w.-]*-([a-z][\w.+-]{2,20})", low)
    if m:
        return m.group(2), m.group(1)
    return "", ""


def _banner_text(raw_bytes: bytes) -> str:
    """MySQL/MariaDB/Postgres greetings are binary-wrapped protocol packets;
    pull printable runs out so the version string survives decoding."""
    runs = PRINTABLE.findall(raw_bytes)
    if not runs:
        return raw_bytes.decode(errors="replace").strip()
    longest = max(runs, key=len)
    text = longest.decode(errors="ignore").strip(" \t\r\n\x00")
    return text or raw_bytes.decode(errors="replace").strip()


def grab_banner(ip: str, port: int) -> dict:
    """Single-connection version observation. TLS handshake SNI + certificate
    subject for https ports; plain probe elsewhere. Never sends payloads."""
    out: dict = {"service": WELL_KNOWN.get(port, ""), "product": "", "extrainfo": "",
                 "tunnel": "", "state": "open"}
    try:
        raw = socket.create_connection((ip, port), timeout=4)
    except OSError:
        return out
    try:
        if port in (443, 8443, 993, 995) or out["service"].startswith("https"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            cli = ctx.wrap_socket(raw, server_hostname=ip)
            out["tunnel"] = "tls"
            banner = ""
            try:
                cli.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                banner = _recv_until(cli, 600)
            except OSError:
                pass
            _apply_http(out, banner)
            try:
                der_ctx = ssl.create_default_context()
                der_ctx.check_hostname = False
                der_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=4) as s2:
                    with der_ctx.wrap_socket(s2, server_hostname=ip) as tls2:
                        der = tls2.getpeercert(True)
                        if der:
                            out["extrainfo"] = _cert_subject(der)
            except OSError:
                pass
            cli.close()
        else:
            banner = ""
            raw_bytes = b""
            if out["service"] in ("http", "http-alt", "http-proxy"):
                raw.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                banner = _recv_until(raw, 600)
                _apply_http(out, banner)
            else:
                # passive read first (many services greet), then one harmless newline
                raw.settimeout(3)
                try:
                    raw_bytes = raw.recv(1024)
                except OSError:
                    raw_bytes = b""
                banner = _banner_text(raw_bytes)
                if not banner.strip():
                    try:
                        raw.sendall(b"\r\n")
                        raw_bytes = raw.recv(1024)
                        banner = _banner_text(raw_bytes)
                    except OSError:
                        pass
                first = banner.splitlines()[0] if banner else ""
                if first:
                    out["extrainfo"] = first[:160]
                    prod, ver = _version_from_banner(first)
                    if not prod and ver:
                        prod = WELL_KNOWN.get(port, "")  # bare-version greeting on known port
                    if prod:
                        out["product"] = f"{prod} {ver}".strip()
                        known = WELL_KNOWN.get(port, "")
                        if known and (prod.lower() in known or known in prod.lower()):
                            out["service"] = known
                        else:
                            out["service"] = out["service"] or prod.lower()
                    elif out["service"] == "":
                        out["service"] = "unknown"
            raw.close()
    except OSError:
        pass
    return out


def _apply_http(out: dict, banner: str) -> None:
    m = re.search(r"^HTTP/\d(?:\.\d)? (\d{3})", banner, re.M)
    srv = re.search(r"^Server: (.+)$", banner, re.M | re.I)
    if m:
        out["extrainfo"] = f"HTTP {m.group(1)}"
    if srv:
        out["product"] = srv.group(1).strip()[:120]
        mv = re.match(r"^([\w.-]+)/([\d][\w.]*)", out["product"])
        if mv:
            out["product"] = f"{mv.group(1)} {mv.group(2)}"


def _cert_subject(der: bytes) -> str:
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        issuer = c.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return f"cert CN={cn[0].value if cn else '?'} issuer={issuer[0].value if issuer else '?'}"
    except Exception:
        return ""


def service_inventory(ip: str, port: int) -> dict:
    """Blocking helper — run via asyncio.to_thread from module workers."""
    return grab_banner(ip, port)


def resolve(target: str) -> str | None:
    import ipaddress

    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except (socket.gaierror, OSError):
        return None


async def fingerprint_many(ip: str, ports: list[int], limit: int = 64) -> list[dict]:
    tasks = [asyncio.to_thread(grab_banner, ip, p) for p in ports[:limit]]
    # return_exceptions: one banner thread blowing up must not cancel (and thus
    # lose) the other ports' fingerprints — the whole vuln/pentest session
    # would otherwise be marked FAILED because of a single odd socket.
    rows = await asyncio.gather(*tasks, return_exceptions=True)
    return [{"portid": p, **(r if isinstance(r, dict) else {})}
            for p, r in zip(ports[:limit], rows)]
