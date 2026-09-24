/** Auth lifecycle (P-04 spec):
 *  login (username+password+TOTP) → access token kept in memory ONLY, refresh
 *  token in expo-secure-store. 60 s watchdog auto-refreshes the 15-min access
 *  token via POST /auth/refresh before expiry (gateway rotates the refresh
 *  cookie; `X-Client: mobile` makes it return the new token in the body).
 *  401 → refresh once (api.ts hook) → else force back to login.
 *  Optional biometric gate before a saved session may be resumed. */
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import * as SecureStore from 'expo-secure-store';

import { ApiError, apiRequest, hasAccessToken, setAccessToken, setAuthHooks } from './api';
import { checkBiometrics, promptBiometric } from './biometrics';
import type { Principal } from '../types';

const REFRESH_KEY = 'cwb.refresh_token';
const PRINCIPAL_KEY = 'cwb.principal';
const BIOMETRIC_KEY = 'cwb.biometric_resume';

const ACCESS_TTL_MS = 15 * 60_000; // matches gateway access_token_ttl_min
const REFRESH_MARGIN_MS = 2 * 60_000; // renew 2 min before expiry
const WATCHDOG_MS = 60_000;

export type AuthStatus = 'booting' | 'locked' | 'anon' | 'authed';

interface LoginResponse {
  access_token: string;
  role: string;
  user_id: string;
  session_id: string;
  refresh_token?: string;
}

interface RefreshResponse {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
}

export type UnlockResult = 'ok' | 'failed' | 'unavailable';

interface AuthContextValue {
  status: AuthStatus;
  principal: Principal | null;
  loginError: string;
  biometricResume: boolean;
  biometricAvailable: boolean;
  login(username: string, password: string, totp: string): Promise<boolean>;
  refreshNow(): Promise<boolean>;
  unlock(): Promise<UnlockResult>;
  abandonSavedSession(): Promise<void>;
  setBiometricResume(on: boolean): Promise<void>;
  logout(): Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth outside AuthProvider');
  return ctx;
}

export function AuthProvider({ children }: { children: ReactNode }): React.JSX.Element {
  const [status, setStatus] = useState<AuthStatus>('booting');
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [loginError, setLoginError] = useState('');
  const [biometricResume, setBiometricResumeState] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const refreshTokenRef = useRef<string | null>(null);
  const lastRefreshAtRef = useRef<number>(0);
  const statusRef = useRef<AuthStatus>('booting');
  statusRef.current = status;

  const clearMemory = useCallback((): void => {
    setAccessToken(null);
    lastRefreshAtRef.current = 0;
  }, []);

  const wipeSession = useCallback(async (): Promise<void> => {
    clearMemory();
    refreshTokenRef.current = null;
    setPrincipal(null);
    await Promise.all([
      SecureStore.deleteItemAsync(REFRESH_KEY),
      SecureStore.deleteItemAsync(PRINCIPAL_KEY),
    ]);
  }, [clearMemory]);

  const refresh = useCallback(async (): Promise<boolean> => {
    const refreshTok = refreshTokenRef.current ?? (await SecureStore.getItemAsync(REFRESH_KEY));
    if (!refreshTok) {
      if (statusRef.current === 'authed') {
        await wipeSession();
        setStatus('anon');
      }
      return false;
    }
    try {
      const r = await apiRequest<RefreshResponse>('/api/v1/auth/refresh', {
        method: 'POST',
        auth: false,
        headers: { Cookie: `cwb_refresh=${refreshTok}` },
        timeoutMs: 10_000,
      });
      setAccessToken(r.access_token);
      lastRefreshAtRef.current = Date.now();
      if (r.refresh_token) {
        refreshTokenRef.current = r.refresh_token;
        await SecureStore.setItemAsync(REFRESH_KEY, r.refresh_token);
      }
      return true;
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
        await wipeSession();
        if (statusRef.current !== 'anon' && statusRef.current !== 'booting') setStatus('anon');
      }
      return false;
    }
  }, [wipeSession]);

  // api.ts 401 → refresh-then-retry plumbing + hard auth loss → login screen
  useEffect(() => {
    setAuthHooks(refresh, () => {
      void wipeSession().then(() => setStatus('anon'));
    });
  }, [refresh, wipeSession]);

  // 60 s watchdog: rotate the in-memory access token before its 15-min expiry
  useEffect(() => {
    const t = setInterval(() => {
      if (!hasAccessToken() || lastRefreshAtRef.current === 0) return;
      if (Date.now() - lastRefreshAtRef.current >= ACCESS_TTL_MS - REFRESH_MARGIN_MS) {
        void refresh();
      }
    }, WATCHDOG_MS);
    return () => clearInterval(t);
  }, [refresh]);

  const loadBiometricAvailability = useCallback(async (): Promise<void> => {
    const cap = await checkBiometrics();
    setBiometricAvailable(cap.hardware && cap.enrolled);
  }, []);

  // bootstrap: resume a stored session (biometric-gated when enabled)
  useEffect(() => {
    let cancelled = false;
    void (async (): Promise<void> => {
      await loadBiometricAvailability();
      const [stored, prin, bio] = await Promise.all([
        SecureStore.getItemAsync(REFRESH_KEY),
        SecureStore.getItemAsync(PRINCIPAL_KEY),
        SecureStore.getItemAsync(BIOMETRIC_KEY),
      ]);
      if (cancelled) return;
      setBiometricResumeState(bio === '1');
      if (prin) {
        try {
          setPrincipal(JSON.parse(prin) as Principal);
        } catch {
          /* fall through to login */
        }
      }
      if (!stored) {
        setStatus('anon');
        return;
      }
      refreshTokenRef.current = stored;
      if (bio === '1') {
        setStatus('locked'); // UnlockScreen must clear the biometric gate first
        return;
      }
      const ok = await refresh();
      if (!cancelled) setStatus(ok ? 'authed' : 'anon');
    })().catch(() => {
      if (!cancelled) setStatus('anon');
    });
    return () => {
      cancelled = true;
    };
  }, [loadBiometricAvailability, refresh]);

  const login = useCallback(
    async (username: string, password: string, totp: string): Promise<boolean> => {
      setLoginError('');
      try {
        const body: Record<string, string> = { username, password };
        if (/^\d{6}$/.test(totp)) body.totp = totp;
        const r = await apiRequest<LoginResponse>('/api/v1/auth/login', {
          method: 'POST',
          auth: false,
          body,
          timeoutMs: 15_000,
        });
        setAccessToken(r.access_token);
        lastRefreshAtRef.current = Date.now();
        const prin: Principal = { userId: r.user_id, username, role: r.role };
        setPrincipal(prin);
        await SecureStore.setItemAsync(PRINCIPAL_KEY, JSON.stringify(prin));
        if (r.refresh_token) {
          refreshTokenRef.current = r.refresh_token;
          await SecureStore.setItemAsync(REFRESH_KEY, r.refresh_token);
        }
        setStatus('authed');
        return true;
      } catch (e) {
        setLoginError(e instanceof Error ? e.message : String(e));
        return false;
      }
    },
    [],
  );

  const unlock = useCallback(async (): Promise<UnlockResult> => {
    const cap = await checkBiometrics();
    if (!cap.hardware || !cap.enrolled) return 'unavailable';
    const ok = await promptBiometric('Resume CYBERWATCH-BD session');
    if (!ok) return 'failed';
    const refreshed = await refresh();
    if (refreshed) setStatus('authed');
    return refreshed ? 'ok' : 'failed';
  }, [refresh]);

  const abandonSavedSession = useCallback(async (): Promise<void> => {
    await wipeSession();
    setStatus('anon');
  }, [wipeSession]);

  const setBiometricResume = useCallback(async (on: boolean): Promise<void> => {
    setBiometricResumeState(on);
    await SecureStore.setItemAsync(BIOMETRIC_KEY, on ? '1' : '0');
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    try {
      await apiRequest('/api/v1/auth/logout', { method: 'POST', timeoutMs: 8_000 });
    } catch {
      /* offline logout — local teardown still happens */
    }
    await wipeSession();
    setStatus('anon');
  }, [wipeSession]);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      principal,
      loginError,
      biometricResume,
      biometricAvailable,
      login,
      refreshNow: refresh,
      unlock,
      abandonSavedSession,
      setBiometricResume,
      logout,
    }),
    [
      status,
      principal,
      loginError,
      biometricResume,
      biometricAvailable,
      login,
      refresh,
      unlock,
      abandonSavedSession,
      setBiometricResume,
      logout,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
