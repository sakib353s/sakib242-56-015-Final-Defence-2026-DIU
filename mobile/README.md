# CYBERWATCH-BD Mobile (P-04) — Android, Expo SDK 51

Terminal-identity companion app for `cwb-core`: live SOC alert tail, module-health
mini dashboard, **read-only** pentest status, victim case viewer with biometric-gated
complaint PDFs, and the **offline outbox engine** that makes acks survive
airplane mode with exactly-once delivery.

- `package app.bd.cyberwatch` · bg `#0B0F14` · JetBrains Mono (bundled, platform
  `monospace` fallback) · `[ OK ] / [ WARN ] / [ FAIL ]` chips · dot-leader rows.
- Navigation: `@react-navigation/native-stack` (minimal deps, no router magic).
- Deep links: `cyberwatch://alerts/detail/<id>`, `cyberwatch://pentest/session/<id>`,
  `cyberwatch://cases/detail/<id>`, `https://cwb.bd/...` equivalents.

## Layout

```
App.tsx                      font+db bootstrap, WS↔connectivity wiring, auth gate
index.ts                     registerRootComponent
src/config/env.ts            API_BASE / WS_BASE / CERT_PINS from expo-constants extra
src/theme.ts                 colors, chips, mono(font) w/ fallback
src/types.ts                 gateway row shapes
src/lib/db.ts                OFFLINE ENGINE: cache_alerts + cache_cases mirrors,
                             outbox (idempotency_key UNIQUE, retry_count,
                             next_attempt_at, pending|synced|failed), meta;
                             one SQLTransaction per write (mirror + queue);
                             tombstone deletes only (deleted_at)
src/lib/sync.ts              drain worker: FIFO, NetInfo reconnect + 60 s interval,
                             exponential backoff 30 s → 30 min, Idempotency-Key
                             per row, manual retry, useSyncExternalStore snapshot
src/lib/api.ts               bearer injection, 401→refresh→replay×1, X-TOTP and
                             Idempotency-Key header plumbing, X-Client: mobile
src/lib/auth.tsx             login (user/pass/TOTP) → access in memory, refresh in
                             expo-secure-store, 60 s watchdog re-POSTs
                             /api/v1/auth/refresh before the 15-min expiry,
                             biometric resume gate (expo-local-authentication)
src/lib/ws.ts                /ws/alerts auto-reconnect (1 s→60 s), keepalive pings,
                             alert.new → mirror write + live tail
src/lib/actions.ts           cache-first flows (alerts/cases) + ackAlert write path
src/lib/push.ts              expo push token → POST /api/v1/mobile/register
                             (see TODOs: FCM sender job + google-services.json)
src/lib/biometrics.ts        capability check + prompt wrapper
src/screens/*                Login, Unlock, Alerts, AlertDetail(modal), Dashboard,
                             Pentest, PentestSession, Case, CaseDetail, Settings
```

## Dev run

```bash
# 1. gateway (repo root: backend/)
cd ../backend && .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8471
# 2. this app — Android emulator reaches the host at 10.0.2.2 (default in app.json extra.apiBase)
npm install            # if npm's shared cache complains (EEXIST/EACCES), use:
                       #   npm_config_cache="$HOME/.npm-cache-cwb" npm install
npx expo start --android
```

Log in with the seeded `admin` (see `backend/app/scripts/seed.py`) + current TOTP.
Production bundles switch to `extra.apiBaseProd`
(`https://api.cyberwatch.railway.app`) automatically when `__DEV__ === false`;
EAS profiles live in `eas.json` (development/preview/production, Android only).

```bash
npx eas build --profile preview --platform android
```

> **npm 11 note:** a global `~/.npmrc` `allow-scripts` entry makes project-scoped
> installs hard-fail (EALLOWSCRIPTS). `mobile/.npmrc` neutralizes it
> (`allow-scripts=`); the only script-bearing optional dep here is fsevents.

## Gateway contract deltas introduced for P-04 (backend side)

| Change | Why |
| --- | --- |
| `X-Client: mobile` → login/refresh return `refresh_token` in the JSON body | RN cannot persist the httpOnly `cwb_refresh` cookie across restarts; the device stores it in SecureStore. Browser flow unchanged (cookie only). |
| `/api/v1/auth/refresh` added to `PUBLIC_API` | refresh authenticates via rotating cookie; gating it behind bearer made token expiry unrecoverable. |
| `Idempotency-Key` header on `POST /api/v1/soc/alerts/{id}/ack` + migration `0002_idempotency.sql` (`idempotency_keys(key, response_json, created_at)`) | duplicate retries replay the stored 200 response — mutation + chained audit row run at most once. |
| New `mobile_router.py`: `POST /api/v1/mobile/register {push_token}` → `settings['mobile_tokens:<user_id>']` + chained audit (token fingerprint only) | push enrollment; no plaintext token in the audit chain. |
| New `GET /api/v1/victim/cases/{id}/complaints` | signed 300-s download links for the latest BTRC/Police drafts (read-only; generation stays desktop+TOTP). |

Backend test coverage for all of the above: `app/tests/test_mobile.py`
(exactly-once ack replay, malformed-key 422, register dedupe + audit, mobile
refresh rotation) — full suite green: **29 passed**.

## Certificate pinning (prod)

`app.json > expo.extra.certPins` holds placeholder SPKI digests
(`REPLACE_WITH_SPKI_SHA256_PIN_*`); Settings shows the pin count. Enforcement is
native — after `expo prebuild`, ship `android/app/src/main/res/xml/network_security_config.xml`
(and reference it from the manifest with `android:networkSecurityConfig="@xml/network_security_config"`):

```xml
<!-- pinSet — CYBERWATCH-BD prod endpoint -->
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">api.cyberwatch.railway.app</domain>
    <pin-set expiration="2027-09-01">
      <!-- leaf/chain cert SPKI, base64(SHA-256) -->
      <pin digest="SHA-256">BASE64_SPKI_PIN_1==</pin>
      <!-- mandatory backup pin = next cert/key you will rotate to -->
      <pin digest="SHA-256">BASE64_SPKI_PIN_2==</pin>
    </pin-set>
  </domain-config>
  <!-- emulator/lab traffic stays cleartext (10.0.2.2), prod domain is pinned -->
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">10.0.2.2</domain>
  </domain-config>
</network-security-config>
```

Generate a pin from the live cert:

```bash
openssl s_client -connect api.cyberwatch.railway.app:443 -servername api.cyberwatch.railway.app </dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl enc -base64
```

Keep both pins in `extra.certPins` so the JS layer can at least assert presence.

## FLIGHT-MODE TEST PLAN (offline engine acceptance)

Precondition: app installed on a physical device or emulator, logged in, mirror
has ≥1 alert (pull-to-refresh on ALERTS once while online; or generate one via
the Suricata EVE tail / direct `ingest_eve_line`).

1. **Go dark** — enable airplane mode (NetInfo flips → header shows
   `OFFLINE`, WS dot `○ WS:OFF`).
2. **Queue an ack** — ALERTS → tap an alert → `ACK [note]` → `ACK ALERT`.
   - Instant: detail row shows local `acked` + `[QUEUED]` badge.
   - Settings → SYNC QUEUE: `#1 POST /api/v1/soc/alerts/… [QUEUED] r0` and the
     alert keeps `[QUEUED]` after pull-to-refresh (mirror merge refuses to let a
     stale server row clobber a queued ack).
   - Kill & relaunch the app mid-flight: the queue row and acked mirror survive
     (SQLite, tombstone-only deletes).
3. **Backoff proof (optional)** — keep airplane mode for >2 min: each failed
   drain bumps `r` and `next_attempt_at` grows 30 s → 1 m → 2 m → 4 m (cap 30 m).
4. **Reconnect** — disable airplane mode. Within one interval (or press
   `DRAIN NOW`): the row POSTs with its original uuid `Idempotency-Key`, the
   gateway returns 200, badge → `[SYNCED]`, queue stats move to `synced`.
5. **Exactly-once verification (server side)** — from `backend/`:
   ```bash
   .venv/bin/python - <<'EOF'
   from app.db import sqlite as sql
   print(sql.all_("SELECT key, created_at FROM idempotency_keys"))          # exactly 1 row for the key
   print(sql.all_("SELECT seq, action, object_ref FROM audit_log WHERE action='soc.alert.ack'"))  # exactly 1 ack audit row
   print(sql.one("SELECT id, status, ack_at FROM alerts WHERE id='<alert-id>'"))  # single acked row
   EOF
   ```
   Replaying the same key (manual `retry` after marking failed, or a duplicate
   network retry) returns the stored response — **no second audit row, no ack_at
   drift** — covered by `test_soc_ack_idempotency_exactly_once`.
6. **Failure UX** — ack a case where the server row was deleted → 404 parks as
   `[FAILED]`; Settings → queue → `RETRY` resets to pending (order preserved:
   no later outbox row applies before it).
7. **Biometric gate** — Settings shows `biometric resume: ON/OFF`; re-open
   app → Unlock screen (no network token touched until the fingerprint passes).
   Case detail: `OPEN PDF` / `SHARE` each re-prompt biometrics before touching
   the signed link.

## Verification record (this build)

- `npm install` ✓ (with the cache workaround above)
- `npx tsc --noEmit` ✓ clean under `strict` + `noUncheckedIndexedAccess`
- `npx expo export --platform android` ✓ — 905 modules, 2.2 MB Hermes bundle,
  JetBrains Mono TTFs present in `dist/assets`
- backend `pytest app/tests -q` ✓ 29 passed (5 new P-04 tests)

## Deliberate omissions

- **No pentest launch button, ever** (P-04 spec) — offensive ops require
  warrant + TOTP step-up on the desktop console. Complaint draft *generation*
  is likewise refused here; the mobile app only *views* drafts.
- Access token never touches disk; refresh token only in SecureStore.
