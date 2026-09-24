"""CYBERWATCH-BD UUIDv7 + id minting (RFC 9562)."""
from __future__ import annotations

import os
import time
import uuid

_last_ms = -1
_seq = 0
_seq_lock_bytes = 12


def uuid7() -> uuid.UUID:
    """Time-ordered UUIDv7, monotonic per process."""
    global _last_ms, _seq
    ms = int(time.time() * 1000)
    if ms == _last_ms:
        _seq += 1
        if _seq >= (1 << _seq_lock_bytes):
            ms += 1
            _last_ms, _seq = ms, 0
    else:
        _last_ms, _seq = ms, 0
    rand = os.urandom(10)
    val = ms << 80
    val |= 0x7 << 76
    val |= (_seq & ((1 << _seq_lock_bytes) - 1)) << 64
    val |= int.from_bytes(rand, "big") & ((1 << 62) - 1)
    val |= 0x8 << 60
    return uuid.UUID(int=val)  # version/variant bits already embedded in val


def new_id() -> str:
    return str(uuid7())


def new_token(nbytes: int = 32) -> str:
    return os.urandom(nbytes).hex()
