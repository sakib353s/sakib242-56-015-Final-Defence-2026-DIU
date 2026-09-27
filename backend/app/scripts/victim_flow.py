"""Victim Support end-to-end flow: open case -> append evidence exhibits -> verify the
hash chain -> generate BTRC + Cyber Police complaint DRAFTS. Calls the same service
layer the web UI reaches over HTTP — nothing bypasses consent or the audit chain.

python app/scripts/victim_flow.py --consent [--type fraud] [--exhibit REF]... [--complaints]

Omitting --consent refuses the case, exactly like the server rule. Default intake data
is explicitly labelled lab-demo so a scripted case can never masquerade as a real
complaint; drafts always carry "human review required before filing".
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.db import sqlite as sql
from app.modules.victim import service
DEMO_NARRATIVE = ("LAB DEMO ENTRY — automated pipeline smoke test: fictional mobile-banking "
                  "OTP-fraud complaint used to verify the intake-to-draft flow. "
                  "Not a real incident; safe to archive.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--type", default="fraud", choices=["fraud", "harassment", "leak", "other"])
    ap.add_argument("--name", default="Lab Demo (not a real complainant)")
    ap.add_argument("--phone", default="")
    ap.add_argument("--email", default="")
    ap.add_argument("--narrative", default=DEMO_NARRATIVE)
    ap.add_argument("--consent", action="store_true",
                    help="attest that victim consent was obtained (mandatory, mirrors the UI checkbox)")
    ap.add_argument("--exhibit", action="append", default=[],
                    help="evidence reference to append; repeat per exhibit")
    ap.add_argument("--complaints", action="store_true", help="generate BTRC + Cyber Police draft PDFs")
    a = ap.parse_args()

    if not a.consent:
        sys.exit("refusing: --consent is required (victim consent attestation is server-mandatory)")
    if len(a.narrative.strip()) < 20:
        sys.exit("narrative must be at least 20 characters")

    actor = sql.one("SELECT id FROM users WHERE username='admin'")
    if not actor:
        sys.exit("no 'admin' user — run app/scripts/seed.py first")
    complainant = {k: v for k, v in (("name", a.name), ("phone", a.phone), ("email", a.email)) if v}
    r = service.create_case(a.type, complainant, a.narrative, True, actor["id"])
    print(f"case opened : {r['case_id']} ({r['status']})")

    for ref in (a.exhibit or ["exhibit://demo-sms-01", "exhibit://demo-call-01"]):
        e = service.append_event(r["case_id"], actor["id"], f"Evidence received: {ref}", ref)
        print(f"  exhibit   : seq {e['seq']} · hash {e['hash'][:16]}")

    ok = service.verify_timeline(r["case_id"])
    state = "intact" if ok["ok"] else f"BROKEN at seq {ok['broken_at_seq']}"
    print(f"hash chain  : {state} ({ok['events']} events)")
    if not ok["ok"]:
        sys.exit(1)

    if a.complaints:
        d = service.generate_complaints(r["case_id"], actor["id"])
        for agency, x in d["drafts"].items():
            print(f"  draft     : {agency} · report {x['report_id']}")
        print(d["note"])


if __name__ == "__main__":
    main()
