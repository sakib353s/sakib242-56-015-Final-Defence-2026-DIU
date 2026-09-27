"""Detection-rule correlation must actually escalate.

Regression: the FIM correlation query bound the column *name* as a value
(`WHERE ?=?`) and compared ISO timestamps to `datetime('now')` as raw strings,
so the count was always 0 and `escalate: incident` never fired.
"""
import os
import tempfile

from app.db import sqlite as sql
from app.modules.fim import scanner


def test_fim_correlation_escalates_to_incident(client, admin):
    actor = sql.scalar("SELECT id FROM users WHERE username='admin'")
    d = tempfile.mkdtemp(prefix="fim-corr-")
    f = os.path.join(d, "watch.txt")
    with open(f, "w") as fh:
        fh.write("v0")

    created = scanner.create_policy(d, "corr-probe", actor)
    pid = created["id"]
    assert created["baseline"]["status"] == "baseline_built"

    before = sql.scalar("SELECT COUNT(*) FROM incidents")
    for i in range(1, 5):
        with open(f, "w") as fh:
            fh.write(f"version-{i}")
        scanner.scan_policy(pid, actor)
    after = sql.scalar("SELECT COUNT(*) FROM incidents")

    assert sql.scalar("SELECT COUNT(*) FROM alerts WHERE source='fim'") >= 3
    assert after > before, "FIM correlation never escalated to an incident"
