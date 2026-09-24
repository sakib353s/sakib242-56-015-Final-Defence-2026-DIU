/** Cache-first data flows shared by screens. Reads hit SQLite first (offline
 *  engine mirror), writes always go through the outbox (lib/db enqueue + drain). */
import { apiRequest } from './api';
import {
  enqueueAlertAck,
  getCachedCaseDetail,
  getCachedCases,
  getAlertView,
  getAlertViews,
  upsertAlerts,
  upsertCaseDetail,
  upsertCases,
} from './db';
import { drainNow, onOutboxChanged } from './sync';
import { isNetworkError } from './api';
import type {
  AlertRow,
  AlertView,
  CaseDetail,
  CaseSummary,
  ComplaintLink,
} from '../types';

export async function refreshAlerts(): Promise<number> {
  const r = await apiRequest<{ alerts: AlertRow[] }>('/api/v1/soc/alerts?limit=200');
  return upsertAlerts(r.alerts ?? []);
}

export function cachedAlerts(): AlertView[] {
  return getAlertViews();
}

/** Detail modal source: mirror first, REST refresh when online. */
export async function loadAlert(alertId: string): Promise<AlertView | null> {
  const cached = getAlertView(alertId);
  try {
    await refreshAlerts();
    return getAlertView(alertId) ?? cached;
  } catch (e) {
    if (isNetworkError(e) && cached) return cached;
    return cached;
  }
}

/** THE write action: one SQLTransaction (mirror patch + outbox row) then an
 *  optimistic drain attempt. Offline → the row parks as `pending`. */
export function ackAlert(alertId: string, note: string): string {
  const key = enqueueAlertAck(alertId, note);
  onOutboxChanged();
  void drainNow();
  return key;
}

export async function refreshCases(): Promise<CaseSummary[]> {
  const r = await apiRequest<{ cases: CaseSummary[] }>('/api/v1/victim/cases');
  const cases = r.cases ?? [];
  upsertCases(cases);
  return cases;
}

export function cachedCases(): CaseSummary[] {
  return getCachedCases();
}

/** Case viewer payload — fresh from server when online, mirror when not. */
export async function loadCaseDetail(caseId: string): Promise<CaseDetail> {
  try {
    const detail = await apiRequest<CaseDetail>(
      `/api/v1/victim/cases/${encodeURIComponent(caseId)}`,
    );
    upsertCaseDetail(detail);
    return detail;
  } catch (e) {
    const cached = getCachedCaseDetail(caseId);
    if (cached && isNetworkError(e)) return cached;
    if (cached) return cached; // server 4xx on an unknown id → no local copy either
    throw e;
  }
}

export function loadComplaintLinks(caseId: string): Promise<ComplaintLink[]> {
  return apiRequest<{ drafts: ComplaintLink[] }>(
    `/api/v1/victim/cases/${encodeURIComponent(caseId)}/complaints`,
  ).then((r) => r.drafts ?? []);
}
