/** Push registration (P-04).
 *
 *  Flow: expo-notifications permission → getExpoPushTokenAsync → POST the token
 *  to the gateway endpoint implemented at app/gateway/mobile_router.py
 *  (`/api/v1/mobile/register`), which persists it under the settings key
 *  `mobile_tokens:<user_id>` and writes a chained audit entry (token fingerprint).
 *
 *  TODO(BACKEND-FANOUT): the stored tokens are registered but nothing consumes
 *  them yet. Next backend ticket: an FCM sender job on alert.ack-worth events
 *  (critical severity) that fans out over settings rows matching `mobile_tokens:%`
 *  and falls back to /ws/alerts only while the analyst keeps the app foregrounded.
 *  TODO(DEVICE): ship google-services.json + `expo-notifications` android icon in
 *  the EAS build profile before real FCM delivery works. */
import Constants from 'expo-constants';
import * as Notifications from 'expo-notifications';

import { apiRequest } from './api';

export interface PushRegistration {
  ok: boolean;
  token?: string;
  detail: string;
}

function easProjectId(): string | undefined {
  const fromExtra = (Constants.expoConfig?.extra as { easProjectId?: string } | undefined)?.easProjectId;
  const fromEas = (Constants as unknown as { easConfig?: { projectId?: string } }).easConfig?.projectId;
  return fromExtra ?? fromEas;
}

export async function registerForPush(): Promise<PushRegistration> {
  try {
    const perm = await Notifications.requestPermissionsAsync();
    if (perm.status !== 'granted') {
      return { ok: false, detail: 'notification permission denied' };
    }
    const projectId = easProjectId();
    const token = await Notifications.getExpoPushTokenAsync(projectId ? { projectId } : undefined);
    const res = await apiRequest<{ ok: boolean; registered: boolean; count: number }>(
      '/api/v1/mobile/register',
      { method: 'POST', body: { push_token: token.toString() } },
    );
    return {
      ok: res.ok,
      token: token.toString(),
      detail: res.registered
        ? `registered (device #${res.count} on this account)`
        : `already registered (kept fresh)`,
    };
  } catch (e) {
    return { ok: false, detail: e instanceof Error ? e.message : String(e) };
  }
}
