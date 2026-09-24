"""Operator password rotation: python app/scripts/reset_password.py [username]

Writes the new credential to data/ADMIN_CREDENTIALS.txt (gitignored) and prints it
once. Every rotation is chained-audited; failed-login counters are cleared.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.audit import chain
from app.core.security import hash_password
from app.db import sqlite as sql

UNAMBIG = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def main() -> None:
    username = sys.argv[1] if len(sys.argv) > 1 else "admin"
    if not sql.one("SELECT id FROM users WHERE username=?", username):
        sys.exit(f"user '{username}' not found — run app/scripts/seed.py first")
    pw = "".join(secrets.choice(UNAMBIG) for _ in range(18))
    with sql.get_db() as c:
        c.execute("UPDATE users SET password_hash=?, failed_logins=0, locked_until=NULL WHERE username=?",
                  (hash_password(pw), username))
    ref = chain.append("system:admin", "user.password_admin_reset", username,
                       {"rotation": "operator script"})
    out = Path(__file__).resolve().parents[2] / "data" / "ADMIN_CREDENTIALS.txt"
    out.write_text(f"username : {username}\npassword : {pw}\naudit_ref: {ref}\n")
    print(f"password rotated for '{username}': {pw}")
    print(f"saved to {out} (0600 recommended) · audit_ref={ref}")


if __name__ == "__main__":
    main()
