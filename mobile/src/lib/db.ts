/** OFFLINE ENGINE (core deliverable of P-04).
 *
 * expo-sqlite local database with:
 *  - `cache_alerts` / `cache_cases` mirrors (never hard-deleted — tombstoned via
 *    `deleted_at`, so the audit trail of what the device held stays intact);
 *  - `outbox` write queue: every write action runs as ONE SQLTransaction that
 *    applies the change to the local mirror AND enqueues the remote call with a
 *    stable idempotency key. The sync worker (lib/sync.ts) drains it FIFO with
 *    exponential backoff; the server replays the stored response for duplicate
 *    keys → exactly-once semantics end to end.
 */
import * as Crypto from 'expo-crypto';
import { openDatabaseSync, type SQLiteDatabase } from 'expo-sqlite';

import { isoNow } from './format';
import type {
  AlertRow,
  AlertView,
  CaseDetail,
  CaseSummary,
  OutboxRow,
  OutboxStatus,
} from '../types';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS cache_alerts (
  id TEXT PRIMARY KEY, row_json TEXT NOT NULL, fetched_at TEXT NOT NULL, deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS cache_cases (
  id TEXT PRIMARY KEY, row_json TEXT NOT NULL, fetched_at TEXT NOT NULL, deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  idempotency_key TEXT UNIQUE NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  body_json TEXT NOT NULL,
  retry_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','synced','failed')),
  created_at TEXT NOT NULL,
  synced_at TEXT,
  last_error TEXT,
  deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON cache_alerts (row_json);
`;

let db: SQLiteDatabase | null = null;
let initPromise: Promise<void> | null = null;

export function initDb(): Promise<void> {
  if (!initPromise) {
    initPromise = (async (): Promise<void> => {
      db = openDatabaseSync('cyberwatch.db');
      db.execSync('PRAGMA journal_mode=WAL;');
      db.execSync(SCHEMA);
    })();
  }
  return initPromise;
}

function handle(): SQLiteDatabase {
  if (!db) throw new Error('db not initialized — await initDb() first');
  return db;
}

/** One SQLTransaction: local mirror write + outbox insert commit atomically
 *  (BEGIN IMMEDIATE … COMMIT / ROLLBACK). All write actions go through this. */
function inTransaction<T>(fn: () => T): T {
  const d = handle();
  d.execSync('BEGIN IMMEDIATE TRANSACTION;');
  try {
    const r = fn();
    d.execSync('COMMIT;');
    return r;
  } catch (e) {
    d.execSync('ROLLBACK;');
    throw e;
  }
}

// ---------------------------------------------------------------------------
// alerts mirror
// ---------------------------------------------------------------------------

function ackEndpointFor(alertId: string): string {
  return `/api/v1/soc/alerts/${alertId}/ack`;
}

interface CacheRow {
  row_json: string;
}

/** True while a write for this endpoint is still in flight in the outbox. */
function hasPendingWrite(endpoint: string): boolean {
  const rows = handle().getAllSync<{ n: number }>(
    'SELECT COUNT(*) AS n FROM outbox WHERE endpoint = ? AND status = ? AND deleted_at IS NULL',
    [endpoint, 'pending'],
  );
  return (rows[0]?.n ?? 0) > 0;
}

function hasFailedWrite(endpoint: string): boolean {
  const rows = handle().getAllSync<{ n: number }>(
    'SELECT COUNT(*) AS n FROM outbox WHERE endpoint = ? AND status = ? AND deleted_at IS NULL',
    [endpoint, 'failed'],
  );
  return (rows[0]?.n ?? 0) > 0;
}

export function upsertAlerts(alerts: AlertRow[]): number {
  const d = handle();
  const now = isoNow();
  let written = 0;
  for (const a of alerts) {
    const existing = d.getAllSync<CacheRow>('SELECT row_json FROM cache_alerts WHERE id = ?', [a.id])[0];
    let final = a;
    if (existing) {
      try {
        const prev = JSON.parse(existing.row_json) as AlertRow;
        // Server may lag a queued ack — never let a refresh clobber an ack the
        // device has already applied locally while its write is still pending.
        if (prev.status === 'acked' && a.status !== 'acked' && hasPendingWrite(ackEndpointFor(a.id))) {
          final = prev;
        }
      } catch {
        /* corrupt local row — server copy wins */
      }
    }
    d.runSync(
      `INSERT INTO cache_alerts (id, row_json, fetched_at, deleted_at) VALUES (?, ?, ?, NULL)
       ON CONFLICT(id) DO UPDATE SET row_json = excluded.row_json, fetched_at = excluded.fetched_at, deleted_at = NULL`,
      [final.id, JSON.stringify(final), now],
    );
    written += 1;
  }
  return written;
}

function toView(a: AlertRow): AlertView {
  const ep = ackEndpointFor(a.id);
  let sync: AlertView['sync'] = 'clean';
  if (hasFailedWrite(ep)) sync = 'failed';
  else if (hasPendingWrite(ep)) sync = 'pending';
  else if (a.ack_at) {
    // acked and not pending/failed: show synced only if we ever queued it
    const done = handle().getAllSync<{ n: number }>(
      'SELECT COUNT(*) AS n FROM outbox WHERE endpoint = ? AND status = ? AND deleted_at IS NULL',
      [ep, 'synced'],
    );
    sync = (done[0]?.n ?? 0) > 0 ? 'synced' : 'clean';
  }
  return { ...a, sync };
}

export function getAlertViews(limit = 200): AlertView[] {
  const d = handle();
  const rows = d.getAllSync<CacheRow & { id: string }>(
    'SELECT id, row_json FROM cache_alerts WHERE deleted_at IS NULL ORDER BY json_extract(row_json, \'$.ts\') DESC LIMIT ?',
    [limit],
  );
  const out: AlertView[] = [];
  for (const r of rows) {
    try {
      out.push(toView(JSON.parse(r.row_json) as AlertRow));
    } catch {
      /* skip corrupt */
    }
  }
  return out;
}

export function getAlertView(alertId: string): AlertView | null {
  const r = handle().getAllSync<CacheRow>('SELECT row_json FROM cache_alerts WHERE id = ? AND deleted_at IS NULL', [
    alertId,
  ])[0];
  if (!r) return null;
  try {
    return toView(JSON.parse(r.row_json) as AlertRow);
  } catch {
    return null;
  }
}

/** Tombstone — the engine never hard-deletes rows. */
export function tombstoneAlert(alertId: string): void {
  handle().runSync('UPDATE cache_alerts SET deleted_at = ? WHERE id = ?', [isoNow(), alertId]);
}

// ---------------------------------------------------------------------------
// outbox — every write action = one transaction: mirror + queue
// ---------------------------------------------------------------------------

export interface EnqueueInput {
  endpoint: string;
  method: 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  body: unknown;
}

/** Queue an alert ack: single SQLTransaction patching the local mirror AND
 *  inserting the outbox row with a fresh uuid idempotency key. */
export function enqueueAlertAck(alertId: string, note: string): string {
  const key = Crypto.randomUUID();
  const now = isoNow();
  inTransaction(() => {
    const d = handle();
    const existing = d.getAllSync<CacheRow>('SELECT row_json FROM cache_alerts WHERE id = ?', [alertId])[0];
    if (existing) {
      try {
        const a = JSON.parse(existing.row_json) as AlertRow;
        const patched: AlertRow = { ...a, status: 'acked', ack_by: a.ack_by ?? 'device:local', ack_at: now };
        d.runSync('UPDATE cache_alerts SET row_json = ? WHERE id = ?', [JSON.stringify(patched), alertId]);
      } catch {
        /* corrupt mirror row — outbox entry still authoritative */
      }
    }
    d.runSync(
      `INSERT INTO outbox (idempotency_key, endpoint, method, body_json, next_attempt_at, created_at)
       VALUES (?, ?, 'POST', ?, ?, ?)`,
      [key, ackEndpointFor(alertId), JSON.stringify({ note }), now, now],
    );
  });
  return key;
}

/** Generic helper so any future write action follows the same one-transaction rule. */
export function enqueueWrite<TLocal>(tx: () => TLocal): TLocal {
  return inTransaction(tx);
}

export function outboxDue(now: string, limit = 25): OutboxRow[] {
  return handle().getAllSync<OutboxRow>(
    `SELECT * FROM outbox WHERE status = 'pending' AND deleted_at IS NULL AND next_attempt_at <= ?
     ORDER BY id ASC LIMIT ?`,
    [now, limit],
  );
}

export function markOutboxSynced(id: number): void {
  handle().runSync("UPDATE outbox SET status = 'synced', synced_at = ?, last_error = NULL WHERE id = ?", [
    isoNow(),
    id,
  ]);
}

/** Retryable failure: bump count + exponential backoff, stays pending. */
export function outboxBackoff(id: number, retryCount: number, error: string): string {
  const delay = Math.min(30_000 * Math.pow(2, retryCount), 30 * 60_000);
  const next = new Date(Date.now() + delay).toISOString();
  handle().runSync(
    'UPDATE outbox SET retry_count = retry_count + 1, next_attempt_at = ?, last_error = ? WHERE id = ?',
    [next, error.slice(0, 300), id],
  );
  return next;
}

/** Non-retryable (4xx): terminal state, manual retry from Settings → queue. */
export function outboxMarkFailed(id: number, error: string): void {
  handle().runSync("UPDATE outbox SET status = 'failed', last_error = ? WHERE id = ?", [
    error.slice(0, 300),
    id,
  ]);
}

export function outboxManualRetry(id: number): void {
  handle().runSync(
    `UPDATE outbox SET status = 'pending', retry_count = 0, next_attempt_at = ?, last_error = NULL
     WHERE id = ? AND status = 'failed'`,
    [isoNow(), id],
  );
}

export interface OutboxStats {
  pending: number;
  failed: number;
  synced: number;
}

export function outboxStats(): OutboxStats {
  const rows = handle().getAllSync<{ status: OutboxStatus; n: number }>(
    'SELECT status, COUNT(*) AS n FROM outbox WHERE deleted_at IS NULL GROUP BY status',
    [],
  );
  const stats: OutboxStats = { pending: 0, failed: 0, synced: 0 };
  for (const r of rows) {
    if (r.status === 'pending') stats.pending = r.n;
    else if (r.status === 'failed') stats.failed = r.n;
    else stats.synced = r.n;
  }
  return stats;
}

export function outboxList(limit = 100): OutboxRow[] {
  return handle().getAllSync<OutboxRow>(
    'SELECT * FROM outbox WHERE deleted_at IS NULL ORDER BY id DESC LIMIT ?',
    [limit],
  );
}

// ---------------------------------------------------------------------------
// cases mirror
// ---------------------------------------------------------------------------

export function upsertCases(cases: CaseSummary[]): void {
  const d = handle();
  const now = isoNow();
  for (const c of cases) {
    d.runSync(
      `INSERT INTO cache_cases (id, row_json, fetched_at, deleted_at) VALUES (?, ?, ?, NULL)
       ON CONFLICT(id) DO UPDATE SET row_json = excluded.row_json, fetched_at = excluded.fetched_at, deleted_at = NULL`,
      [c.id, JSON.stringify({ kind: 'summary', data: c } satisfies CachedCase), now],
    );
  }
}

type CachedCase = { kind: 'summary'; data: CaseSummary } | { kind: 'detail'; data: CaseDetail };

export function getCachedCases(): CaseSummary[] {
  const rows = handle().getAllSync<{ id: string; row_json: string }>(
    'SELECT id, row_json FROM cache_cases WHERE deleted_at IS NULL ORDER BY id DESC LIMIT 100',
    [],
  );
  const out: CaseSummary[] = [];
  for (const r of rows) {
    try {
      const c = JSON.parse(r.row_json) as CachedCase;
      if (c.kind === 'summary') out.push(c.data);
    } catch {
      /* skip corrupt */
    }
  }
  return out;
}

export function upsertCaseDetail(detail: CaseDetail): void {
  handle().runSync(
    `INSERT INTO cache_cases (id, row_json, fetched_at, deleted_at) VALUES (?, ?, ?, NULL)
     ON CONFLICT(id) DO UPDATE SET row_json = excluded.row_json, fetched_at = excluded.fetched_at, deleted_at = NULL`,
    [detail.case.id, JSON.stringify({ kind: 'detail', data: detail } satisfies CachedCase), isoNow()],
  );
}

export function getCachedCaseDetail(caseId: string): CaseDetail | null {
  const r = handle().getAllSync<{ row_json: string }>(
    'SELECT row_json FROM cache_cases WHERE id = ? AND deleted_at IS NULL',
    [caseId],
  )[0];
  if (!r) return null;
  try {
    const c = JSON.parse(r.row_json) as CachedCase;
    return c.kind === 'detail' ? c.data : null;
  } catch {
    return null;
  }
}

export function tombstoneCase(caseId: string): void {
  handle().runSync('UPDATE cache_cases SET deleted_at = ? WHERE id = ?', [isoNow(), caseId]);
}

// ---------------------------------------------------------------------------
// meta
// ---------------------------------------------------------------------------

export function setMeta(key: string, value: string): void {
  handle().runSync(
    'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
    [key, value],
  );
}

export function getMeta(key: string): string | null {
  return handle().getAllSync<{ value: string }>('SELECT value FROM meta WHERE key = ?', [key])[0]?.value ?? null;
}
