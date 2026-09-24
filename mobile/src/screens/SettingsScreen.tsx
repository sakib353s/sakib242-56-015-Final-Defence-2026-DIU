/** Settings/Auth — session, biometric resume, push registration, TOTP header
 *  plumbing note, cert-pin status, and the outbox queue with per-record
 *  synced/pending/failed badges + manual retry. Logout tears the session down
 *  locally even when offline. */
import React, { useMemo, useState, useSyncExternalStore } from 'react';
import { ScrollView, View } from 'react-native';

import { API_BASE, CERT_PINS } from '../config/env';
import { SyncBadge, TopBar } from '../components/TopBar';
import { Btn, DotRow, Line, Panel, StatusChip, SyncChip, T } from '../components/ui';
import { useAuth } from '../lib/auth';
import { registerForPush, type PushRegistration } from '../lib/push';
import { drainNow, getSyncSnapshot, retryOutbox, subscribeSync, listOutbox } from '../lib/sync';
import { ago, trunc } from '../lib/format';
import { C, FS, SP } from '../theme';

export default function SettingsScreen(): React.JSX.Element {
  const { principal, logout, refreshNow, biometricResume, setBiometricResume, biometricAvailable } = useAuth();
  const snap = useSyncExternalStore(subscribeSync, getSyncSnapshot);
  const [push, setPush] = useState<PushRegistration | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const queue = useMemo(() => listOutbox(8), [snap.version]);

  const act = async (name: string, fn: () => Promise<unknown>): Promise<void> => {
    setBusy(name);
    try {
      await fn();
    } finally {
      setBusy(null);
    }
  };

  return (
    <View style={{ flex: 1, backgroundColor: C.bg }}>
      <TopBar title="CONFIG / AUTH" active="Settings" />
      <ScrollView contentContainerStyle={{ padding: SP.md, paddingBottom: SP.xl }}>
        <Panel title="ACCOUNT">
          <DotRow label="username" value={principal?.username ?? '—'} width={30} />
          <DotRow label="role" value={principal?.role ?? '—'} width={30} valueColor={C.accent} />
          <DotRow label="gateway" value={trunc(API_BASE.replace(/^\w+:\/\//, ''), 26)} width={30} />
          <View style={{ marginTop: SP.md }}>
            <Btn label="logout" tone="fail" disabled={busy === 'logout'} onPress={() => void act('logout', logout)} />
          </View>
        </Panel>
        <Line />
        <Panel title="SESSION">
          <DotRow label="access token" value="in-memory only" width={30} valueColor={C.accent} />
          <DotRow label="refresh token" value="expo-secure-store" width={30} valueColor={C.accent} />
          <DotRow label="auto-refresh" value="watchdog 60s → POST /auth/refresh before 15m expiry" width={44} />
          <View style={{ flexDirection: 'row', gap: SP.md, marginTop: SP.md }}>
            <Btn label="refresh now" tone="cyan" disabled={busy === 'refresh'} onPress={() => void act('refresh', refreshNow)} />
            <Btn
              label={`biometric resume: ${biometricResume ? 'ON' : 'OFF'}`}
              tone={biometricResume ? 'accent' : 'warn'}
              disabled={!biometricAvailable}
              onPress={() => void setBiometricResume(!biometricResume)}
            />
          </View>
          {!biometricAvailable ? <T dim size={FS.xs}>no enrolled biometrics on this device — resume gate disabled</T> : null}
        </Panel>
        <Line />
        <Panel title="TOTP STEP-UP">
          <T dim size={FS.sm} style={{ lineHeight: FS.md + 8 }}>
            {'X-TOTP plumbing is wired in lib/api (request opts.totp). Mobile flows are\nread-only + ack — complaint/pentest step-up actions stay on the desktop\nconsole where the operator holds the live authenticator.'}
          </T>
        </Panel>
        <Line />
        <Panel title="PUSH (FCM/EXPO)" right={<T dim size={FS.xs}>/api/v1/mobile/register</T>}>
          <Btn label="register device" disabled={busy === 'push'} onPress={() => void act('push', async () => setPush(await registerForPush()))} />
          {push ? (
            <T size={FS.sm} color={push.ok ? C.accent : C.warn} style={{ marginTop: SP.sm }}>
              {`${push.ok ? '[ OK ]' : '[WARN]'} ${trunc(push.detail, 44)}`}
            </T>
          ) : (
            <T dim size={FS.xs} style={{ marginTop: SP.sm }}>
              token stored in settings:mobile_tokens:&lt;user&gt; with chained audit entry
            </T>
          )}
        </Panel>
        <Line />
        <Panel title="SYNC QUEUE (OUTBOX)" right={<SyncBadge />}>
          <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
            <T size={FS.sm} color={snap.failed ? C.fail : snap.pending ? C.warn : C.accent}>
              {`pending ${snap.pending} · failed ${snap.failed} · synced ${snap.synced}`}
            </T>
            <T dim size={FS.xs}>
              {`last drain ${ago(snap.lastRunAt)}`}
            </T>
          </View>
          <View style={{ flexDirection: 'row', gap: SP.md, marginVertical: SP.sm }}>
            <Btn label="drain now" tone="cyan" onPress={() => void drainNow()} />
          </View>
          {queue.map((row) => (
            <View key={row.id} style={{ flexDirection: 'row', alignItems: 'center', gap: SP.sm, paddingVertical: SP.xs, borderTopWidth: 1, borderTopColor: C.line }}>
              <T size={FS.xs} dim>
                {`#${row.id}`}
              </T>
              <T size={FS.xs} style={{ flex: 1 }} numberOfLines={1}>
                {`${row.method} ${trunc(row.endpoint, 30)}`}
              </T>
              <T size={FS.xs} dim>
                {`r${row.retry_count}`}
              </T>
              <SyncChip status={row.status} />
              {row.status === 'failed' ? <Btn label="retry" tone="warn" onPress={() => retryOutbox(row.id)} /> : null}
            </View>
          ))}
          {queue.length === 0 ? <T dim size={FS.xs}>{'-- outbox empty --'}</T> : null}
          <T dim size={FS.xs} style={{ marginTop: SP.sm }}>
            backoff 30s→30min · FIFO · tombstones only (deleted_at), never hard-delete
          </T>
        </Panel>
        <Line />
        <Panel title="CERTIFICATE PINNING">
          <View style={{ flexDirection: 'row', gap: SP.md, alignItems: 'center' }}>
            <StatusChip status={CERT_PINS.length > 0 ? 'OK' : 'WARN'} />
            <T size={FS.sm} dim>
              {`${CERT_PINS.length} SPKI pin(s) in extra config`}
            </T>
          </View>
          <T dim size={FS.xs} style={{ marginTop: SP.sm }}>
            {'production builds enforce pins via Android network security config\n(pinSet block in README.md). Dev/emulator traffic stays cleartext.'}
          </T>
        </Panel>
      </ScrollView>
    </View>
  );
}
