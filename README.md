# CYBERWATCH-BD
Unified Offensive-Defensive Cyber Intelligence Platform — BD Edition
M.Sc. research project · Daffodil International University · MD Rafshan Rahman Sakib (242-56-015)
Legal frame: Bangladesh Cyber Safety Ordinance 2025 + ICT Act 2006 — compliance is enforced
server-side and fail-closed, not decorative.

## What this is
A real full-stack platform: FastAPI gateway (`cwb-core`), Next.js 14 terminal-native web SPA,
Expo SDK 51 Android app, 9 security modules, a security-attestation boot sequence, an
HMAC hash-chained audit ledger, and a written-authorization (warrant) gate in front of
every offensive capability.

```
backend/   FastAPI 0.110 · Python 3.11+ · SQLite(WAL) · Mongo Atlas (optional) · ReportLab
web/       Next.js 14 App Router · xterm.js boot console · WS /alerts /jobs /boot
mobile/    Expo SDK 51 · offline outbox (exactly-once sync) · FCM · biometric gate
```

## Quick start (lab mode)
```bash
# 1. backend
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python app/scripts/seed.py        # prints one-time admin creds + TOTP (nothing hardcoded)
.venv/bin/uvicorn app.main:app --port 8471 --timeout-keep-alive 75  # cwb-core (keep-alive must outlast the Next dev proxy's pool)

# 2. web
cd ../web && npm install && npm run dev     # http://localhost:3000/boot

# 3. tests
cd ../backend && .venv/bin/python -m pytest -q
```

## The boot screen is an instrument, not a GIF
Open `/boot`. S1–S8 run **real checks**: /dev/urandom entropy + CPU crypto flags, JWT/TOTP
self-tests, HMAC chain verification over the live audit table, tool handshakes (`nmap --version`,
NVD API ping, suricata -V, tor control port, paramiko/pysnmp imports), SQLite integrity,
Atlas ping, policy-hash pin/verify, warrant ledger load, HIBP/Shodan heartbeat, UUIDv7 session
mint **written to the audit chain before the login gate renders**.
Any `[ FAIL ]` freezes the sequence with a remediation hint + audit_ref and refuses the AUTH
GATE (fail-closed). Only S7 (threat feed) degrades — to a `[ WARN ] degraded intel mode`.

**Lab vs production**: `CWB_ENV=lab` (default) downgrades *infrastructure* handshakes
(nmap/tor/suricata/Atlas absent on a dev laptop) to loud `LAB-DEGRADED` WARNs, and skips
the TOTP step-up gate (`CWB_TOTP_ENFORCE=auto`, every skip audited as
`gate.totp_stepup_lab_skip`) so research work proceeds without an authenticator.
`CWB_ENV=production` halts on any of them, refuses to boot without all five secrets in env,
requires Mongo + HIBP key, and ALWAYS enforces TOTP step-up regardless of
`CWB_TOTP_ENFORCE`. The other security gates (warrants, RBAC, consent, audit
chain) never degrade in any mode.

## Authorization model (read this before touching offensive modules)
- `auth_ledger` holds warrants: kind, scope (IP/CIDR/domain), purpose, warrant_ref (the
  written-authorization document number), validity window (≤ 90 days), owner.
- Pentest / vuln / remediation / IP-anonymizer calls pass `warrant_id`; the server re-checks
  kind, window, revocation and target-in-scope on **every** request and again inside workers
  (scope-drift during a scan = ABORT + audit).
- Mutating offensive/privileged ops additionally require a fresh single-use TOTP step-up
  (`X-TOTP` header; replay of the same code for the same operation is rejected).
- Auto-remediation is a saga: DRAFT → CONSENTED (SUPER_ADMIN + TOTP) → APPLIED → ROLLED_BACK.
  No path applies without warrant AND consent.
- OSINT is public-data-only (HIBP, Shodan, DNS/RDAP/crt.sh, TLS, public GitHub search).
  Victim Support emits BTRC / Cyber Police complaint **drafts** with statutory citations —
  human review before filing is mandatory by design.

## Ops
- **Free by design — no payment required.** OSINT runs on keyless public sources: HIBP
  breach registry (domain-level, free), PwnedPasswords k-anonymity range (free), NVD,
  crt.sh, RDAP, DNS, GitHub public search. Optional keys only *upgrade* tiers:
  `CWB_HIBP_API_KEY` enables exact per-account email search; `CWB_SHODAN_API_KEY` adds
  the attack-surface map; `CWB_NVD_API_KEY` raises NVD rate limits. Boot S4/S7 and every
  module stay green with zero keys configured.
- Env contract: `backend/.env.example`. Secrets: lab auto-generates `backend/data/secrets.json`
  (0600); production requires env injection (JWT, audit HMAC, field-encryption AES key,
  report-signing, WS-envelope HMAC).
- Migrations: versioned SQL in `backend/app/db/migrations/`, applied on startup + seed.
- Reports: signed, traversal-safe downloads (id+expiry HMAC; paths never client-supplied).
- Background: audit-chain verifier (hourly), Suricata EVE tail, IP-block expiry rollback,
  Tor circuit heartbeat + warrant-expiry auto-teardown.
- Deploy: Railway (backend, persistent volume for SQLite), Vercel (web), EAS Build (APK).
- Mobile flight-mode test plan: `mobile/README.md`.

## Known deviations from the Build Bible (deliberate, all fail-toward-safe)
1. pypdf + PIL replace pikepdf (qpdf toolchain unavailable on the research laptop); capability
   unchanged (metadata/LSB watermarking).
2. Boot S1 CPU check is platform-aware (macOS/ARM report `AES`, not `AES-NI`) — literal x86
   flag names would brick boot on Apple Silicon.
3. Login lockout triggers after 5 failures (bible left the threshold implicit; first-attempt
   lockout was a DoS-on-your-own-account bug).
4. S8 session mint writes its audit row before the AUTH GATE renders, but the gate is shown —
   a session cannot be "pre-authorized" by typing; P-00 intent preserved.
5. TOTP step-up is lab-skippable (`CWB_TOTP_ENFORCE=auto`; skips audited per request).
   Production enforcement is unconditional. Warrant + RBAC + consent gates still never
   degrade in any mode.
