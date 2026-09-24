"""Android app release endpoint (public, no auth — the login gate advertises it).

The signed APK produced by `eas build --platform android` is dropped into
backend/data/apk/cyberwatch-bd.apk. This module serves real facts about that
file (size, SHA-256, build time) — never invented numbers. When no APK has been
uploaded yet the UI honestly shows the build command instead of a dead button.
"""
import hashlib
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

from app.core.config import get_settings

S = get_settings()
APK_DIR = Path(S.database_path).parent / "apk"
APK_PATH = APK_DIR / "cyberwatch-bd.apk"
META_PATH = APK_DIR / "release.json"

router = APIRouter(prefix="/api/v1/app-release", tags=["app"])


def _meta() -> dict:
    """Version label comes from the build pipeline's release.json when present."""
    if META_PATH.exists():
        try:
            import json
            return json.loads(META_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


@router.get("")
async def info():
    exists = APK_PATH.exists()
    stat = APK_PATH.stat() if exists else None
    m = _meta()
    return {
        "available": exists,
        "version": m.get("version"),
        "channel": m.get("channel"),
        "built_at": m.get("built_at"),
        "size_bytes": stat.st_size if stat else None,
        "sha256": _sha256() if exists else None,
        "download": "/api/v1/app-release/download" if exists else None,
        "build_hint": "eas build --platform android --profile production",
    }


_cached: dict | None = None


def _sha256() -> str:
    """APK digests are GB-scale; recompute only when the file actually changed."""
    global _cached
    st = APK_PATH.stat()
    stamp = (int(st.st_mtime), st.st_size)
    if _cached and _cached["stamp"] == stamp:
        return _cached["sha256"]
    h = hashlib.sha256()
    with open(APK_PATH, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    _cached = {"stamp": stamp, "sha256": digest}
    return digest


@router.get("/download")
async def download():
    if not APK_PATH.exists():
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "APK not uploaded on this server yet"}, status_code=404)
    return FileResponse(APK_PATH, media_type="application/vnd.android.package-archive",
                        filename="CYBERWATCH-BD.apk",
                        headers={"X-Content-Sha256": _sha256()})
