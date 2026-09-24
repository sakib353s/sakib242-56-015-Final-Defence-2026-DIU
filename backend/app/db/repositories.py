"""Repository pattern over SQLite — typed accessors for core tables."""
from __future__ import annotations

from datetime import datetime, timezone

from app.core.ids import new_id
from app.core.security import hash_password, now_iso
from app.db import sqlite as sql


def _row(d: dict | None) -> dict | None:
    return d


# --- users ---------------------------------------------------------------------
class Users:
    @staticmethod
    def create(username: str, display_name: str, role: str, password: str) -> dict:
        uid = new_id()
        with sql.get_db() as c:
            c.execute(
                "INSERT INTO users (id, username, display_name, role, password_hash, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (uid, username, display_name, role, hash_password(password), now_iso()),
            )
        return Users.get(uid)  # type: ignore

    @staticmethod
    def get(uid: str) -> dict | None:
        return _row(sql.one("SELECT * FROM users WHERE id=?", uid))

    @staticmethod
    def by_username(username: str) -> dict | None:
        return _row(sql.one("SELECT * FROM users WHERE username=?", username))

    @staticmethod
    def register_failed_login(uid: str, lock_until: str, threshold: int = 5):
        """Lock only after `threshold` consecutive failures; lock_until is the horizon
        that becomes effective when the threshold is reached."""
        with sql.get_db() as c:
            c.execute("UPDATE users SET failed_logins = failed_logins + 1 WHERE id=?", (uid,))
            row = c.execute("SELECT failed_logins FROM users WHERE id=?", (uid,)).fetchone()
            if row and row["failed_logins"] >= threshold:
                c.execute("UPDATE users SET locked_until=?, failed_logins=0 WHERE id=?", (lock_until, uid))

    @staticmethod
    def register_success(uid: str):
        with sql.get_db() as c:
            c.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?", (uid,))

    @staticmethod
    def set_totp_secret(uid: str, enc_secret: str):
        with sql.get_db() as c:
            c.execute("UPDATE users SET totp_secret_enc=?, totp_enrolled=1 WHERE id=?", (enc_secret, uid))

    @staticmethod
    def list_() -> list[dict]:
        return sql.all_("SELECT id, username, display_name, role, totp_enrolled, created_at FROM users")


# --- sessions (auth) -------------------------------------------------------------
class Sessions:
    @staticmethod
    def create(user_id: str, refresh_hash: str, ua: str, ip: str) -> dict:
        sid = new_id()
        with sql.get_db() as c:
            c.execute(
                "INSERT INTO sessions (id, user_id, refresh_hash, created_at, last_seen, user_agent, ip)"
                " VALUES (?,?,?,?,?,?,?)",
                (sid, user_id, refresh_hash, now_iso(), now_iso(), ua, ip),
            )
        return {"id": sid}

    @staticmethod
    def by_refresh_hash(h: str) -> dict | None:
        return sql.one("SELECT * FROM sessions WHERE refresh_hash=? AND revoked_at IS NULL", h)

    @staticmethod
    def rotate(sid: str, new_hash: str):
        with sql.get_db() as c:
            c.execute("UPDATE sessions SET refresh_hash=?, last_seen=? WHERE id=?", (new_hash, now_iso(), sid))

    @staticmethod
    def revoke(sid: str):
        with sql.get_db() as c:
            c.execute("UPDATE sessions SET revoked_at=? WHERE id=?", (now_iso(), sid))


# --- authorization ledger ---------------------------------------------------------
class Ledger:
    @staticmethod
    def create(kind: str, scope: list[str], purpose: str, warrant_ref: str, owner_user_id: str,
               subject_name: str, valid_from: str, valid_until: str) -> dict:
        from app.core.security import to_utc_iso

        lid = new_id()
        valid_from, valid_until = to_utc_iso(valid_from), to_utc_iso(valid_until)
        import json
        with sql.get_db() as c:
            c.execute(
                "INSERT INTO auth_ledger (id, kind, scope_json, purpose, warrant_ref, owner_user_id,"
                " subject_name, valid_from, valid_until, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (lid, kind, json.dumps(scope), purpose, warrant_ref, owner_user_id,
                 subject_name, valid_from, valid_until, now_iso()),
            )
        return Ledger.get(lid)  # type: ignore

    @staticmethod
    def get(lid: str) -> dict | None:
        return sql.one("SELECT * FROM auth_ledger WHERE id=?", lid)

    @staticmethod
    def revoke(lid: str) -> bool:
        with sql.get_db() as c:
            cur = c.execute(
                "UPDATE auth_ledger SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now_iso(), lid)
            )
            return cur.rowcount > 0

    @staticmethod
    def active() -> list[dict]:
        return sql.all_(
            "SELECT * FROM auth_ledger WHERE revoked_at IS NULL AND valid_until > ?"
            " ORDER BY valid_until ASC", now_iso(),
        )

    @staticmethod
    def all_() -> list[dict]:
        return sql.all_("SELECT * FROM auth_ledger ORDER BY created_at DESC")
