import { getToken } from "./auth";
import type { ProblemData } from "./types";

const RAW_BASE = process.env.NEXT_PUBLIC_API_BASE;
export const API_BASE = RAW_BASE ? `${RAW_BASE.replace(/\/$/, "")}/api/v1` : "/api/v1";
export const WS_BASE = (process.env.NEXT_PUBLIC_WS_BASE || "ws://127.0.0.1:8471").replace(/\/$/, "");

export class ApiProblem extends Error implements ProblemData {
  type: string;
  title: string;
  status: number;
  detail: string;
  audit_ref: string | null;
  request_id: string | null;

  constructor(data: ProblemData, fallbackStatus = 0) {
    super(data.detail || data.title || "request failed");
    this.name = "ApiProblem";
    this.type = data.type ?? "about:blank";
    this.title = data.title ?? "Request failed";
    this.status = data.status ?? fallbackStatus;
    this.detail = data.detail ?? "";
    this.audit_ref = data.audit_ref ?? null;
    this.request_id = data.request_id ?? null;
  }
}

export function toProblem(e: unknown): ApiProblem {
  if (e instanceof ApiProblem) return e;
  // A foreign error can still carry the RFC 7807 fields (e.g. one produced by a
  // different bundle instance of ApiProblem). Preserve whatever is structured
  // instead of flattening it into an opaque string.
  const p = (e ?? {}) as Partial<ProblemData>;
  const isError = e instanceof Error;
  const title = p.title ?? (isError ? "Transport failure" : "Request failed");
  return new ApiProblem({
    type: p.type,
    title,
    status: p.status,
    detail: p.detail ?? (isError ? e.message : String(e)),
    audit_ref: p.audit_ref ?? null,
    request_id: p.request_id ?? null,
  });
}

/** Human-readable default title for a bare HTTP status (no problem body present). */
function httpTitle(status: number): string {
  if (status === 401) return "Authentication required";
  if (status === 403) return "Authorization denied";
  if (status === 404) return "Resource not found";
  if (status === 409) return "Resource state conflict";
  if (status === 422) return "Request rejected";
  if (status === 429) return "Rate limit exceeded";
  if (status >= 500) return "Server error";
  return `HTTP ${status}`;
}

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export interface ApiInit {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  form?: FormData;
  totp?: string;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** set internally on the single retry after a silent refresh */
  _retried?: boolean;
}

/* ---- silent refresh ----
   Access tokens live 15 minutes; the server issues a 7-day rotating refresh
   cookie. Refreshes MUST be serialized: the cookie rotates on every call, so
   two parallel refreshes would invalidate each other and log the user out. */
let refreshing: Promise<boolean> | null = null;

export async function tryRefresh(): Promise<boolean> {
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const call = () => fetch(`${API_BASE}/auth/refresh`, {
          method: "POST",
          credentials: "same-origin",
          headers: { accept: "application/json" },
        });
        let res = await call();
        // dev-proxy keep-alive race: request never reached the backend
        // (no X-Request-ID, non-JSON body) — one retry on a fresh socket is safe.
        if (
          res.status >= 500 &&
          !res.headers.get("x-request-id") &&
          !(res.headers.get("content-type") || "").includes("json")
        ) {
          res = await call();
        }
        if (!res.ok) return false;
        const data = (await res.json()) as { access_token?: string };
        if (!data.access_token) return false;
        const { getSession, setTokenOnly } = await import("./auth");
        if (!getSession()) return false; // no session shape to patch
        setTokenOnly(data.access_token);
        return true;
      } catch {
        return false;
      }
    })().finally(() => {
      refreshing = null;
    });
  }
  return refreshing;
}

/** proactive top-up on app load: refresh quietly when the token is near its edge */
export async function maybeRefresh(): Promise<void> {
  const { getSession } = await import("./auth");
  const s = getSession();
  if (!s) return;
  if (Date.now() - s.since < 12 * 60 * 1000) return;
  await tryRefresh();
}

export async function apiFetch<T>(path: string, init: ApiInit = {}): Promise<T> {
  const headers: Record<string, string> = { accept: "application/json", ...init.headers };
  const token = getToken();
  if (token) headers.authorization = `Bearer ${token}`;
  if (init.totp) headers["x-totp"] = init.totp;
  if (init.body !== undefined && !init.form) headers["content-type"] = "application/json";

  const res = await fetch(`${API_BASE}${path}`, {
    method: init.method ?? "GET",
    headers,
    body: init.form ?? (init.body !== undefined ? JSON.stringify(init.body) : undefined),
    signal: init.signal,
    credentials: "same-origin",
  });

  /* Proxy-race recovery: the dev rewrite proxy can reuse a keep-alive socket the
     backend already closed, answering "500 Internal Server Error" (plain text)
     without the request ever arriving. A real backend response always carries
     X-Request-ID and JSON. If both are missing, retry once on a fresh socket. */
  if (
    res.status >= 500 &&
    !init._retried &&
    !res.headers.get("x-request-id") &&
    !(res.headers.get("content-type") || "").includes("json")
  ) {
    return apiFetch<T>(path, { ...init, _retried: true });
  }

  if (
    res.status === 401 &&
    !init._retried &&
    !path.startsWith("/auth/login") &&
    !path.startsWith("/auth/refresh") &&
    !path.startsWith("/auth/logout") &&
    !path.startsWith("/boot/")
  ) {
    if (typeof window !== "undefined") {
      if (await tryRefresh()) {
        return apiFetch<T>(path, { ...init, _retried: true });
      }
      const { clearSession } = await import("./auth");
      clearSession();
      if (!window.location.pathname.startsWith("/boot")) window.location.replace("/boot");
    }
  }

  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { title: `Non-JSON response (HTTP ${res.status})`, detail: text.slice(0, 300) };
    }
  }
  if (!res.ok) {
    const p = (data ?? {}) as ProblemData;
    // Normalise: never let a partial body (or a body carrying only `detail`)
    // degrade into the generic "Request failed / about:blank / HTTP —" banner.
    throw new ApiProblem(
      {
        type: p.type,
        title: p.title ?? httpTitle(res.status),
        status: p.status ?? res.status,
        detail: p.detail ?? (text.slice(0, 300) || ""),
        audit_ref: p.audit_ref ?? null,
        request_id: p.request_id ?? res.headers.get("x-request-id") ?? null,
      },
      res.status,
    );
  }
  return data as T;
}

export const get = <T>(path: string, signal?: AbortSignal) => apiFetch<T>(path, { signal });
export const post = <T>(path: string, body?: unknown, totp?: string) =>
  apiFetch<T>(path, { method: "POST", body, totp });
