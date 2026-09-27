import type { LoginResult, LoginUser, Role, Session } from "./types";
import { ApiProblem, apiFetch } from "./api";

const SS_KEY = "cwb.session";

let mem: Session | null = null;

export function getSession(): Session | null {
  if (mem) return mem;
  if (typeof window === "undefined") return null;
  try {
    const raw = window.sessionStorage.getItem(SS_KEY);
    if (!raw) return null;
    mem = JSON.parse(raw) as Session;
    return mem;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  return getSession()?.token ?? null;
}

export function getRole(): Role | null {
  return getSession()?.role ?? null;
}

export function setSession(login: LoginResult, username: string): void {
  mem = {
    token: login.access_token,
    role: login.role,
    username,
    user_id: login.user_id,
    session_id: login.session_id,
    audit_ref: login.audit_ref,
    since: Date.now(),
  };
  try {
    window.sessionStorage.setItem(SS_KEY, JSON.stringify(mem));
  } catch {
    // private mode: memory-only session is acceptable
  }
}

/** patch a silently refreshed access token into the live session (role/username unchanged) */
export function setTokenOnly(token: string): void {
  const s = getSession();
  if (!s) return;
  mem = { ...s, token };
  try {
    window.sessionStorage.setItem(SS_KEY, JSON.stringify(mem));
  } catch {
    // private mode: memory-only session is acceptable
  }
}

export function clearSession(): void {
  mem = null;
  try {
    window.sessionStorage.removeItem(SS_KEY);
  } catch {
    // ignore
  }
}

export async function login(user: LoginUser): Promise<Session> {
  const body: Record<string, string> = { username: user.username, password: user.password };
  if (user.totp) body.totp = user.totp;
  const res = await apiFetch<LoginResult>("/auth/login", { method: "POST", body });
  setSession(res, user.username);
  return getSession() as Session;
}

export async function logout(): Promise<void> {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } catch (e) {
    if (!(e instanceof ApiProblem) || e.status !== 401) throw e;
  } finally {
    clearSession();
  }
}
