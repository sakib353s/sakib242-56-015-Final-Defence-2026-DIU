"""Seed: migrate DB, create initial SUPER_ADMIN with enrolled TOTP, pin policy hash.
Prints the one-time credentials to stdout — nothing is hardcoded anywhere."""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pyotp

from app.audit import chain
from app.core.security import enc_field, hash_password, now_iso
from app.db import sqlite as sql

# ambiguous-char-free alphabet (no 0/O, 1/l/I) — seeded passwords must survive
# manual transcription onto a login screen
UNAMBIG = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def main():
    applied = sql.run_migrations()
    print(f"migrations: {applied or 'already applied'}")
    with sql.get_db() as c:
        if c.execute("SELECT 1 FROM users WHERE role='SUPER_ADMIN'").fetchone():
            print("SUPER_ADMIN exists — seed aborted (idempotent)")
            return
    password = "".join(secrets.choice(UNAMBIG) for _ in range(18))
    secret = pyotp.random_base32()
    from app.core.ids import new_id
    uid = new_id()
    with sql.get_db() as c:
        c.execute(
            "INSERT INTO users (id, username, display_name, role, password_hash, totp_secret_enc,"
            " totp_enrolled, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (uid, "admin", "MD Rafshan Rahman Sakib", "SUPER_ADMIN", hash_password(password),
             enc_field(secret), 1, now_iso()),
        )
        c.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES"
                  " ('seed_version', '5.0', datetime('now'))")
    chain.append("system:seed", "user.bootstrap", uid, {"username": "admin", "role": "SUPER_ADMIN"})
    print("=" * 64)
    print("  CYBERWATCH-BD initial SUPER_ADMIN (one-time display — store now)")
    print(f"  username : admin")
    print(f"  password : {password}")
    print(f"  totp b32 : {secret}")
    print(f"  otpauth  : {pyotp.TOTP(secret).provisioning_uri('admin', issuer_name='CYBERWATCH-BD')}")
    print("=" * 64)


if __name__ == "__main__":
    main()
