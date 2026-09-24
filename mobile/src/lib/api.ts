/** Authenticated REST client.
 *  - injects `Authorization: Bearer <access>` (memory-only token) + `X-Client: mobile`
 *  - optional `totp` → `X-TOTP` header (step-up plumbing; mobile read-only flows
 *    never send it today, the header stays wired for future gated actions)
 *  - optional `idempotencyKey` → `Idempotency-Key` header (outbox drain)
 *  - 401 → asks the auth layer to refresh once → replays the call; else propagates
 *    so the app can drop to the login screen. */
import { API_BASE, CLIENT_HEADERS } from '../config/env';

export type HttpMethod = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface RequestOptions {
  method?: HttpMethod;
  body?: unknown;
  /** false = public endpoint (login) — no bearer header, no refresh loop */
  auth?: boolean;
  totp?: string;
  idempotencyKey?: string;
  timeoutMs?: number;
  /** extra raw headers (refresh-token cookie flow) */
  headers?: Record<string, string>;
}

let accessToken: string | null = null;
let refreshHandler: (() => Promise<boolean>) | null = null;
let authLostHandler: (() => void) | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function hasAccessToken(): boolean {
  return accessToken !== null;
}

export function getAccessToken(): string | null {
  return accessToken;
}

/** Wired by the auth provider. */
export function setAuthHooks(refresh: () => Promise<boolean>, onAuthLost: () => void): void {
  refreshHandler = refresh;
  authLostHandler = onAuthLost;
}

export function isNetworkError(e: unknown): boolean {
  if (e instanceof ApiError) return false;
  const msg = e instanceof Error ? e.message.toLowerCase() : String(e).toLowerCase();
  return msg.includes('network') || msg.includes('abort') || msg.includes('failed to fetch') || msg.includes('timeout');
}

/** Statuses where retrying the same request unchanged can never succeed —
 *  the sync worker parks these as `failed` (manual retry only). */
export function isNonRetryable(e: unknown): boolean {
  if (!(e instanceof ApiError)) return false;
  return e.status === 400 || e.status === 403 || e.status === 404 || e.status === 422;
}

interface ProblemJson {
  detail?: string;
  title?: string;
}

async function rawRequest<T>(path: string, opts: RequestOptions, attempt: 0 | 1): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 12_000);
  try {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...CLIENT_HEADERS,
    };
    if (opts.auth !== false && accessToken) headers.Authorization = `Bearer ${accessToken}`;
    if (opts.totp) headers['X-TOTP'] = opts.totp;
    if (opts.idempotencyKey) headers['Idempotency-Key'] = opts.idempotencyKey;
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    if (opts.headers) Object.assign(headers, opts.headers);

    const res = await fetch(`${API_BASE}${path}`, {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: controller.signal,
    });

    if (res.status === 401 && opts.auth !== false && attempt === 0 && refreshHandler) {
      const refreshed = await refreshHandler();
      if (refreshed) return rawRequest<T>(path, opts, 1);
      if (authLostHandler) authLostHandler();
      throw new ApiError('Session expired — re-authentication required', 401);
    }

    const text = await res.text();
    let parsed: unknown = undefined;
    if (text) {
      try {
        parsed = JSON.parse(text) as unknown;
      } catch {
        parsed = text;
      }
    }
    if (!res.ok) {
      const detail =
        (parsed && typeof parsed === 'object' ? (parsed as ProblemJson).detail : undefined) ??
        (parsed && typeof parsed === 'object' ? (parsed as ProblemJson).title : undefined) ??
        `HTTP ${res.status}`;
      throw new ApiError(String(detail), res.status, parsed);
    }
    return parsed as T;
  } finally {
    clearTimeout(timer);
  }
}

export function apiRequest<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  return rawRequest<T>(path, opts, 0);
}
