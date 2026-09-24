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
  return new ApiProblem({ title: "Transport failure", detail: e instanceof Error ? e.message : String(e) });
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

  if (res.status === 401 && !path.startsWith("/auth/login") && !path.startsWith("/boot/")) {
    if (typeof window !== "undefined") {
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
    throw new ApiProblem(
      p.type || p.title || p.detail ? p : { title: `HTTP ${res.status}`, detail: text.slice(0, 300) || undefined },
      res.status,
    );
  }
  return data as T;
}

export const get = <T>(path: string, signal?: AbortSignal) => apiFetch<T>(path, { signal });
export const post = <T>(path: string, body?: unknown, totp?: string) =>
  apiFetch<T>(path, { method: "POST", body, totp });
