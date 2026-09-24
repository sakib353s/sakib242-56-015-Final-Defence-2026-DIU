/** SYNC WORKER — drains the SQLite outbox FIFO.
 *  Triggers: NetInfo reconnect, 60 s interval, and every local enqueue.
 *  Per row: POST/… with the stored Idempotency-Key (server replays the first
 *  response on duplicates → exactly-once). Retryable failures park the row with
 *  exponential backoff 30 s → 30 min and STOP the cycle (order preservation);
 *  non-retryable 4xx become `failed` (manual retry in Settings). Synced rows
 *  are marked, never hard-deleted. */
import NetInfo from '@react-native-community/netinfo';

import { ApiError, apiRequest, hasAccessToken, isNonRetryable, type HttpMethod } from './api';
import {
  markOutboxSynced,
  outboxBackoff,
  outboxList,
  outboxMarkFailed,
  outboxManualRetry,
  outboxStats,
  outboxDue,
} from './db';
import { isoNow } from './format';
import type { OutboxRow } from '../types';

const DRAIN_INTERVAL_MS = 60_000;

export interface SyncSnapshot {
  pending: number;
  failed: number;
  synced: number;
  online: boolean;
  running: boolean;
  lastRunAt: string | null;
  version: number;
}

let snapshot: SyncSnapshot = {
  pending: 0,
  failed: 0,
  synced: 0,
  online: true,
  running: false,
  lastRunAt: null,
  version: 0,
};

const listeners = new Set<() => void>();

function emit(): void {
  for (const fn of listeners) fn();
}

export function subscribeSync(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function getSyncSnapshot(): SyncSnapshot {
  return snapshot;
}

function refreshStats(): void {
  const stats = outboxStats();
  snapshot = { ...snapshot, ...stats, version: snapshot.version + 1 };
  emit();
}

let started = false;
let draining = false;

export function startSync(): void {
  if (started) return;
  started = true;
  void NetInfo.fetch().then((st) => {
    snapshot = { ...snapshot, online: st.isConnected === true, version: snapshot.version + 1 };
    emit();
  });
  NetInfo.addEventListener((st) => {
    const online = st.isConnected === true;
    snapshot = { ...snapshot, online, version: snapshot.version + 1 };
    emit();
    // drain on reconnect and on every top-up check — the cycle is cheap when the outbox is empty
    if (online) void drainNow();
  });
  setInterval(() => {
    void drainNow();
  }, DRAIN_INTERVAL_MS);
  void drainNow();
}

export async function drainNow(): Promise<void> {
  if (draining || !hasAccessToken()) return;
  draining = true;
  snapshot = { ...snapshot, running: true, version: snapshot.version + 1 };
  emit();
  try {
    const due = outboxDue(isoNow());
    for (const row of due) {
      const done = await attempt(row);
      if (!done) break; // FIFO: never apply later writes past a stuck earlier one
    }
  } finally {
    draining = false;
    snapshot = { ...snapshot, running: false, lastRunAt: isoNow(), version: snapshot.version + 1 };
    const stats = outboxStats();
    snapshot = { ...snapshot, ...stats, version: snapshot.version + 1 };
    emit();
  }
}

/** returns true → keep draining, false → park & stop */
async function attempt(row: OutboxRow): Promise<boolean> {
  let body: unknown;
  try {
    body = JSON.parse(row.body_json) as unknown;
  } catch (e) {
    outboxMarkFailed(row.id, `body_json corrupt: ${String(e)}`);
    return false;
  }
  try {
    await apiRequest<unknown>(row.endpoint, {
      method: row.method as HttpMethod,
      body,
      idempotencyKey: row.idempotency_key, // stable uuid → exactly-once on retry
      timeoutMs: 12_000,
    });
    markOutboxSynced(row.id);
    return true;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (e instanceof ApiError && e.status === 401) return false; // hook handles refresh; stop cycle
    if (isNonRetryable(e)) {
      outboxMarkFailed(row.id, msg);
      return false;
    }
    outboxBackoff(row.id, row.retry_count, msg); // 5xx/429/timeout/offline → 30s..30min
    return false;
  }
}

export function onOutboxChanged(): void {
  refreshStats();
}

export function retryOutbox(id: number): void {
  outboxManualRetry(id);
  refreshStats();
  void drainNow();
}

export function listOutbox(limit = 50): OutboxRow[] {
  return outboxList(limit);
}
