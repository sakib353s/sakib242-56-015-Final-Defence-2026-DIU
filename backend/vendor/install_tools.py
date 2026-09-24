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


def already_ok(name):
    p = os.path.join(BIN, name)
    if not os.path.exists(p):
        return False
    try:
        r = subprocess.run([p, "-version"], capture_output=True, timeout=20)
        return r.returncode == 0 or bool(r.stdout or r.stderr)
    except Exception:
        return False


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
            r = subprocess.run([target, "-version"], capture_output=True, timeout=20)
            out = (r.stdout + r.stderr).decode(errors="replace")
            results[name] = "ok: " + out.splitlines()[0][:80] if out else "ok"
        except Exception as e:
            results[name] = f"FAIL: {e}"
        print(f"{name}: {results[name]}", flush=True)

    # sqlmap: pure-python, git clone
    sqlmap_dir = os.path.join(HERE, "sqlmap")
    if not os.path.exists(os.path.join(sqlmap_dir, "sqlmap.py")):
        r = subprocess.run(["git", "clone", "--depth", "1",
                            "https://github.com/sqlmapproject/sqlmap", sqlmap_dir],
                           capture_output=True, timeout=600)
        print("sqlmap clone:", "ok" if r.returncode == 0 else r.stderr.decode()[:200], flush=True)
    else:
        print("sqlmap: present", flush=True)

    # ffuf wordlist (SecLists common.txt, ~46KB)
    wl = os.path.join(HERE, "wordlists", "common.txt")
    os.makedirs(os.path.dirname(wl), exist_ok=True)
    if not os.path.exists(wl):
        download("https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
                 "Discovery/Web-Content/common.txt", wl)
    print("wordlist lines:", sum(1 for _ in open(wl)), flush=True)

    bad = [k for k, v in results.items() if v.startswith("FAIL")]
    print(json.dumps(results, indent=1))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
