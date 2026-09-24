# CYBERWATCH-BD // web console (P-03)

Terminal-native command console for the `cwb-core` FastAPI backend. Next.js 14 App
Router + TypeScript, TanStack React Query, xterm.js boot instrument, hand-built
terminal UI (single stylesheet with design tokens — no Tailwind, no component libs).

## Run

```bash
cd web
npm install
npm run dev          # http://localhost:3000  (boot page at /boot)
```

The dev server proxies `/api/*` → `http://127.0.0.1:8471` (see `next.config.js`,
override with `CWB_API_ORIGIN`). WebSockets cannot ride that proxy — the browser
connects directly to `NEXT_PUBLIC_WS_BASE` (default `ws://127.0.0.1:8471`) for
`/ws/boot`, `/ws/alerts`, `/ws/jobs`. Copy `.env.local.example` → `.env.local`.

Open the console at **http://localhost:3000** (not `127.0.0.1`): the backend WS
origin guard allow-lists exactly `http://localhost:3000`, and browsers send the
page origin on every `/ws/*` handshake.

Backend must be up on :8471 with a seeded SUPER_ADMIN (run `python -m app.scripts.seed`
in `backend/` and keep the printed one-time credentials + TOTP secret).

## Build & typecheck

```bash
npx tsc --noEmit
npm run build
```

## Layout

- `app/boot` — flagship: xterm.js attestation stream (S1–S8), freeze-on-FAIL with
  audit_ref + re-arm, AUTH GATE (role hint / user / password / 6-digit TOTP),
  reduced-motion instant mode, ASCII-banner easter egg on keystroke.
- `app/(app)` — sidebar (RBAC-filtered groups) + topbar (wordmark, WS dot, warrant
  banner, user/role chip, logout) and the 12 routes:
  dashboard · pentest · vuln · soc · remediation · osint · document · victim · ip ·
  hardware · reports · settings.
- `lib/` — `api.ts` (Bearer + `X-TOTP` step-up headers, RFC 7807 → `ApiProblem`,
  401 → `/boot`), `auth.ts` (token in memory + sessionStorage), `rbac.ts`
  (OFFENSIVE group hidden for READ_ONLY — server still enforces), `ws.ts`
  (`useCwbSocket`), `bootline.ts` (ANSI render grammar mirroring
  `backend/app/core/boot.py`), `format.ts`, `types.ts`.
- `components/` — `ui.tsx` (panels, chips, leader rows, dot-leader loading rows,
  `[ WARN ] no rows` empties, problem banners, focus-trapped modal), `stepup.tsx`
  (global TOTP prompt for mutating/privileged calls), `toast.tsx` (aria-live),
  `chrome.tsx` (sidebar/topbar/WS hub wiring `/ws/alerts` + `/ws/jobs` envelopes
  `{channel,seq,ts,type,payload,hmac}`), `warrant.tsx` (ledger picker for
  SUPER_ADMIN; analysts get a manual-warrant lock line since `/admin/ledger` is
  tier-2-gated server-side).

No fake data anywhere: every row, chip and gauge renders from live endpoints.
