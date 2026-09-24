/** Dashboard Mini — 9 module-health tiles, warrant state, WS + sync status. */
import React, { useCallback, useEffect, useState } from 'react';
import { RefreshControl, ScrollView, View } from 'react-native';

import { SyncBadge, TopBar } from '../components/TopBar';
import { Btn, DotRow, Line, Panel, StatusChip, T, WsDot } from '../components/ui';
import { apiRequest } from '../lib/api';
import { ago, trunc } from '../lib/format';
import { useNav } from '../navigation/hooks';
import { C, FS, SP } from '../theme';
import type { ModuleHealth, Warrant } from '../types';

interface LedgerActive {
  warrants: Warrant[];
}

type WarrantState = { kind: 'ok' | 'gated' | 'error'; count: number; soonest: string | null; msg: string };

function mapWarrants(warrants: Warrant[]): WarrantState {
  const soonest = [...warrants].sort((a, b) => a.valid_until.localeCompare(b.valid_until))[0];
  return { kind: 'ok', count: warrants.length, soonest: soonest?.valid_until ?? null, msg: '' };
}

export default function DashboardScreen(): React.JSX.Element {
  const nav = useNav();
  const [modules, setModules] = useState<ModuleHealth[]>([]);
  const [warrant, setWarrant] = useState<WarrantState | null>(null);
  const [fetchedAt, setFetchedAt] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(async (): Promise<void> => {
    setRefreshing(true);
    setError('');
    try {
      const h = await apiRequest<{ modules: ModuleHealth[] }>('/api/v1/modules/health', { timeoutMs: 20_000 });
      setModules(h.modules ?? []);
      setFetchedAt(new Date().toISOString());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    try {
      const l = await apiRequest<LedgerActive>('/api/v1/admin/ledger/active');
      setWarrant(mapWarrants(l.warrants ?? []));
    } catch (e) {
      const gated = typeof e === 'object' && e !== null && 'status' in e && (e as { status: number }).status === 403;
      setWarrant(
        gated
          ? { kind: 'gated', count: -1, soonest: null, msg: 'ledger visibility requires SUPER_ADMIN' }
          : { kind: 'error', count: -1, soonest: null, msg: e instanceof Error ? e.message : String(e) },
      );
    }
    setRefreshing(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const okCount = modules.filter((m) => m.status === 'OK').length;
  const failCount = modules.filter((m) => m.status === 'FAIL').length;

  return (
    <View style={{ flex: 1, backgroundColor: C.bg }}>
      <TopBar title="OPS DASHBOARD / MINI" active="Dashboard" />
      <ScrollView
        contentContainerStyle={{ padding: SP.md, paddingBottom: SP.xl }}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => void load()} tintColor={C.accent} />}>
        <Panel
          title={`MODULE HEALTH ${okCount}/${modules.length || 9} OK`}
          right={<StatusChip status={failCount > 0 ? 'FAIL' : okCount === 9 ? 'OK' : 'WARN'} />}>
          <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: SP.sm }}>
            {modules.length === 0 ? (
              <T dim size={FS.sm}>
                {error ? `! ${trunc(error, 80)}` : 'probing…'}
              </T>
            ) : null}
            {modules.map((m) => (
              <View
                key={m.module}
                style={{ width: '31.5%', borderWidth: 1, borderColor: C.line, backgroundColor: C.panelHi, padding: SP.sm, minHeight: 74 }}>
                <T size={FS.sm} bold numberOfLines={1}>
                  {m.display}
                </T>
                <View style={{ height: SP.xs }} />
                <StatusChip status={m.status} />
                <T size={FS.xs} dim numberOfLines={2} style={{ marginTop: SP.xs }}>
                  {m.detail}
                </T>
              </View>
            ))}
          </View>
        </Panel>
        <Line />
        <Panel title="WRITTEN AUTHORIZATION LEDGER">
          {warrant === null ? (
            <T dim size={FS.sm}>
              querying /admin/ledger/active…
            </T>
          ) : warrant.kind === 'gated' ? (
            <>
              <StatusChip status="WARN" />
              <DotRow label="note" value={warrant.msg} width={30} />
            </>
          ) : warrant.kind === 'error' ? (
            <>
              <StatusChip status="FAIL" />
              <DotRow label="err" value={trunc(warrant.msg, 24)} width={30} valueColor={C.fail} />
            </>
          ) : (
            <>
              <StatusChip status={warrant.count > 0 ? 'OK' : 'WARN'} />
              <DotRow label="active warrants" value={String(warrant.count)} width={30} />
              {warrant.soonest ? <DotRow label="next expiry" value={trunc(warrant.soonest, 22)} width={30} valueColor={C.warn} /> : null}
            </>
          )}
        </Panel>
        <Line />
        <Panel title="UPLINK">
          <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
            <WsDot />
            <SyncBadge />
          </View>
          <DotRow label="snapshot" value={fetchedAt ? ago(fetchedAt) : '—'} width={30} />
        </Panel>
        <View style={{ flexDirection: 'row', gap: SP.md, marginTop: SP.lg }}>
          <Btn label="alerts" tone="cyan" onPress={() => nav.navigate('Alerts')} />
          <Btn label="pentest" tone="cyan" onPress={() => nav.navigate('Pentest')} />
          <Btn label="cases" tone="cyan" onPress={() => nav.navigate('Case')} />
        </View>
      </ScrollView>
    </View>
  );
}
