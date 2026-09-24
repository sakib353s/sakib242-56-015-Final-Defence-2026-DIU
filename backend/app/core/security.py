"""CYBERWATCH-BD security primitives: Argon2id, JWT HS256, TOTP, AES-256-GCM, HMAC."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone

import jwt
from argon2.low_level import Type, hash_secret, verify_secret
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyotp import TOTP

from app.core.config import get_settings

S = get_settings()

# --- passwords (Argon2id, OWASP 2024 minimums) --------------------------------
_ARGON_KW = dict(time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32, type=Type.ID)


def hash_password(plain: str) -> str:
    return hash_secret(plain.encode(), salt=uuid.uuid4().bytes, **_ARGON_KW).decode()


def verify_password(plain: str, encoded: str) -> bool:
    try:
        return verify_secret(encoded.encode(), plain.encode(), type=Type.ID)
    except Exception:
        return False


# --- JWT -----------------------------------------------------------------------
def make_access(user_id: str, role: str, session_id: str, totp_ok: bool) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": user_id,
            "role": role,
            "sid": session_id,
            "totp": totp_ok,
            "iat": now,
            "exp": now + S.access_token_ttl_min * 60,
            "iss": "cwb-core",
            "jti": str(uuid.uuid4()),
        },
        S.jwt_secret,
        algorithm="HS256",
    )


def decode_access(token: str) -> dict:
    # algorithms is pinned — kills alg=none and alg-confusion forgery classes.
    return jwt.decode(token, S.jwt_secret, algorithms=["HS256"], issuer="cwb-core")


# --- TOTP ----------------------------------------------------------------------
def totp_now(secret: str, at: float | None = None) -> str:
    t = TOTP(secret)
    return t.at(at) if at is not None else t.now()


def totp_valid(secret: str, code: str, drift: int = 1) -> bool:
    return TOTP(secret).verify(code, valid_window=drift)


def totp_provisioning_uri(secret: str, username: str) -> str:
    return TOTP(secret).provisioning_uri(username, issuer_name="CYBERWATCH-BD")


# --- field encryption (AES-256-GCM) -------------------------------------------
def _aes() -> AESGCM:
    return AESGCM(bytes.fromhex(S.field_enc_key))


def enc_field(plain: str) -> str:
    nonce = uuid.uuid4().bytes[:12]
    ct = _aes().encrypt(nonce, plain.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def dec_field(blob: str) -> str:
    raw = base64.b64decode(blob)
    return _aes().decrypt(raw[:12], raw[12:], None).decode()


# --- HMAC utilities ------------------------------------------------------------
def hmac_bytes(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def audit_hmac(payload_hash: str, prev_hash: str, ts: int, actor: str) -> str:
    msg = f"{prev_hash}|{payload_hash}|{ts}|{actor}".encode()
    return hmac_bytes(S.audit_hmac_key.encode(), msg)


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_file(path: str | uuid.UUID) -> tuple[str, str]:  # noqa: PYI (path is str)
    h256, h5 = hashlib.sha256(), hashlib.md5()
    with open(str(path), "rb") as f:
        while chunk := f.read(1 << 20):
            h256.update(chunk)
            h5.update(chunk)
    return h256.hexdigest(), h5.hexdigest()


def sign_envelope(payload: dict) -> dict:
    body = canonical_json(payload)
    return {**payload, "hmac": hmac_bytes(S.envelope_hmac_key.encode(), body.encode())}


def now_iso() -> str:
    dt = datetime.now(timezone.utc)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{dt.microsecond // 1000:03d}+00:00"


def to_utc_iso(s: str) -> str:
    """Normalize any ISO-8601 (incl. +06:00 BD time or Z) to the canonical
    fixed-precision UTC form — makes lexicographic == chronological everywhere."""
    from datetime import timezone as _tz

    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_tz.utc)
    dt = dt.astimezone(_tz.utc)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{dt.microsecond // 1000:03d}+00:00"
