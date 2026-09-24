/** Environment resolution. API_BASE comes from expo-constants `extra` so EAS
 *  profiles can override it; defaults: emulator host loopback for dev, Railway
 *  endpoint for prod bundles. certPins is a placeholder list — the actual
 *  Android networkSecurityConfig XML (pinSet) ships in the native build: the
 *  commented block lives in README.md ("Certificate pinning"). */
import Constants from 'expo-constants';
import { Platform } from 'react-native';

interface ExtraConfig {
  apiBase?: string;
  apiBaseProd?: string;
  certPins?: string[];
  easProjectId?: string;
}

const extra = (Constants.expoConfig?.extra ?? {}) as ExtraConfig;

export const IS_PROD_BUNDLE = !__DEV__;
export const CERT_PINS: readonly string[] = extra.certPins ?? [];

function resolveBase(): string {
  if (extra.apiBaseProd && IS_PROD_BUNDLE) return extra.apiBaseProd;
  if (extra.apiBase) return extra.apiBase;
  // dev fallback: Android emulator alias / desktop Metro
  return Platform.OS === 'android' ? 'http://10.0.2.2:8471' : 'http://localhost:8471';
}

export const API_BASE: string = resolveBase().replace(/\/+$/, '');
export const WS_BASE: string = API_BASE.replace(/^http/, 'ws');
/** Marks native clients so the gateway returns the rotating refresh token in the
 *  JSON body (React Native cannot persist httpOnly cookies). */
export const CLIENT_HEADERS: Record<string, string> = { 'X-Client': 'mobile' };

export function absUrl(pathOrUrl: string): string {
  return /^https?:\/\//.test(pathOrUrl) ? pathOrUrl : `${API_BASE}${pathOrUrl}`;
}
