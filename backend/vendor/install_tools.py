#!/usr/bin/env python3
"""Vendor red-team binaries from GitHub releases into backend/vendor/bin.

Downloads the darwin/amd64 (Intel macOS) asset of each pinned tool, extracts
the single binary, chmods it, and smoke-tests --version. Idempotent: skips
binaries that already answer --version.
"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin")
os.makedirs(BIN, exist_ok=True)

# repo, asset-substring (darwin amd64 only), final binary name
TOOLS = [
    ("projectdiscovery/naabu", "macOS_amd64", "naabu"),
    ("projectdiscovery/nuclei", "macOS_amd64", "nuclei"),
    ("projectdiscovery/subfinder", "macOS_amd64", "subfinder"),
    ("projectdiscovery/httpx", "macOS_amd64", "httpx"),
    ("projectdiscovery/katana", "macOS_amd64", "katana"),
    ("ffuf/ffuf", "macOS_amd64", "ffuf"),
    ("hahwul/dalfox", "macos-x86_64", "dalfox"),
]


def api(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cwb-vendor"})
    return json.load(urllib.request.urlopen(req, timeout=60))


def download(url, dest):
    with urllib.request.urlopen(url, timeout=300) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def extract(archive, name, target):
    with tempfile.TemporaryDirectory() as td:
        if archive.endswith(".zip"):
            with zipfile.ZipFile(archive) as z:
                z.extractall(td)
        else:
            with tarfile.open(archive) as t:
                t.extractall(td)
        for root, _, files in os.walk(td):
            if name in files:
                shutil.copy2(os.path.join(root, name), target)
                return True
    return False


# Per-tool version flag. `ffuf -version` and `dalfox -version` are NOT valid —
# ffuf wants -V, dalfox wants --version; anything else exits 2 with a usage dump,
# which would make every probe lie. Must stay in step with VERSION_ARGV in
# app/modules/tools/service.py.
VERSION_ARGV = {
    "subfinder": ["-version"], "naabu": ["-version"], "httpx": ["-version"],
    "katana": ["-version"], "nuclei": ["-version"], "ffuf": ["-V"],
    "dalfox": ["--version"],
}


def probe(name, target=None):
    """Run the tool's real version flag. Returns (rc, first_nonempty_output_line).

    The projectdiscovery banners start with a blank line, so the first *non-empty*
    line is the version line — not splitlines()[0].
    """
    argv = [target or os.path.join(BIN, name)] + VERSION_ARGV[name]
    try:
        r = subprocess.run(argv, capture_output=True, timeout=20)
    except Exception:
        return -1, ""
    out = (r.stdout + r.stderr).decode(errors="replace")
    for line in out.splitlines():
        if line.strip():
            return r.returncode, line.strip()[:80]
    return r.returncode, ""


def already_ok(name):
    p = os.path.join(BIN, name)
    if not os.path.exists(p):
        return False
    rc, line = probe(name)
    return rc == 0 and bool(line)


def main():
    results = {}
    for repo, want, name in TOOLS:
        if already_ok(name):
            results[name] = "present"
            continue
        try:
            rel = api(f"https://api.github.com/repos/{repo}/releases/latest")
            asset = next(a for a in rel["assets"]
                         if want in a["name"] and not a["name"].endswith((".sig", ".sha256", ".minisig")))
            arc = os.path.join(BIN, asset["name"])
            print(f"downloading {asset['name']} ...", flush=True)
            download(asset["browser_download_url"], arc)
            target = os.path.join(BIN, name)
            if not extract(arc, name, target):
                results[name] = "extract-failed"
                continue
            os.chmod(target, 0o755)
            os.remove(arc)
            rc, line = probe(name)
            if rc != 0 or not line:
                results[name] = f"FAIL: smoke test exited {rc}"
            else:
                results[name] = "ok: " + line
        except Exception as e:
            results[name] = f"FAIL: {e}"
        print(f"{name}: {results[name]}", flush=True)

    # sqlmap: pure-python, git clone
    sqlmap_dir = os.path.join(HERE, "sqlmap")
    if not os.path.exists(os.path.join(sqlmap_dir, "sqlmap.py")):
        r = subprocess.run(["git", "clone", "--depth", "1",
                            "https://github.com/sqlmapproject/sqlmap", sqlmap_dir],
                           capture_output=True, timeout=600)
        line = "ok" if r.returncode == 0 else "FAIL: " + r.stderr.decode()[:200]
        print("sqlmap clone:", line, flush=True)
        if r.returncode != 0:
            results["sqlmap"] = "FAIL: git clone failed"
    else:
        print("sqlmap: present", flush=True)
        r = subprocess.run([sys.executable, os.path.join(sqlmap_dir, "sqlmap.py"), "--version"],
                           capture_output=True, timeout=30)
        out = (r.stdout + r.stderr).decode(errors="replace").strip()
        results["sqlmap"] = (("ok: " + out.splitlines()[0][:80]) if r.returncode == 0 and out
                             else f"FAIL: sqlmap --version exited {r.returncode}")

    # ffuf wordlist (SecLists common.txt, ~46KB)
    wl = os.path.join(HERE, "wordlists", "common.txt")
    os.makedirs(os.path.dirname(wl), exist_ok=True)
    if not os.path.exists(wl):
        download("https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
                 "Discovery/Web-Content/common.txt", wl)
    print("wordlist lines:", sum(1 for _ in open(wl)), flush=True)

    bad = [k for k, v in results.items() if v.startswith("FAIL") or v == "extract-failed"]
    print(json.dumps(results, indent=1))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
