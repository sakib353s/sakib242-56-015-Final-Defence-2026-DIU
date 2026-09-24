/** Alerts — live tail from /ws/alerts + GET /api/v1/soc/alerts, severity chips,
 *  deep-linkable detail modal (cyberwatch://alerts/detail/<id>), ACK write action
 *  routed through the offline outbox engine. */
import React, { useCallback, useEffect, useState, useSyncExternalStore } from 'react';
import { FlatList, Pressable, RefreshControl, View } from 'react-native';

import { API_BASE } from '../config/env';
import { TopBar } from '../components/TopBar';
import { Btn, Line, SevChip, SyncChip, T } from '../components/ui';
import { cachedAlerts, refreshAlerts } from '../lib/actions';
import { getSyncSnapshot, subscribeSync } from '../lib/sync';
import { alertsSocket } from '../lib/ws';
import { ago, clock, trunc } from '../lib/format';
import { useNav } from '../navigation/hooks';
import { C, FS, SP } from '../theme';
import type { AlertView } from '../types';

export default function AlertsScreen(): React.JSX.Element {
  const nav = useNav();
  const [rows, setRows] = useState<AlertView[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const snap = useSyncExternalStore(subscribeSync, getSyncSnapshot);

  const reload = useCallback((): void => {
    setRows(cachedAlerts());
  }, []);

  // mirror updates land from WS, REST refresh and outbox status changes
  useEffect(() => alertsSocket.subscribe((env) => {
    if (env.type === 'alert.new') reload();
  }), [reload]);
  useEffect(reload, [snap.version, reload]);
  useEffect(() => {
    if (rows.length === 0 && snap.online) void refreshAlerts().then(reload).catch((e: unknown) => setNote(String(e instanceof Error ? e.message : e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snap.online]);

  const onRefresh = async (): Promise<void> => {
    setRefreshing(true);
    try {
      await refreshAlerts();
      setNote(null);
    } catch (e) {
      setNote(`REST fetch failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      reload();
      setRefreshing(false);
    }
  };

  return (
    <View style={{ flex: 1, backgroundColor: C.bg }}>
      <TopBar title="SOC ALERT FEED" active="Alerts" />
      {note ? (
        <T size={FS.sm} color={C.warn} style={{ paddingHorizontal: SP.md }}>
          {`! ${trunc(note, 120)}`}
        </T>
      ) : null}
      <Line style={{ marginVertical: SP.sm }} />
      <FlatList
        data={rows}
        keyExtractor={(a) => a.id}
        contentContainerStyle={{ paddingHorizontal: SP.md, paddingBottom: SP.xl }}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => void onRefresh()} tintColor={C.accent} />}
        ListEmptyComponent={
          <T dim size={FS.sm}>
            {`-- no alerts in local mirror --\n-- pull to fetch GET ${API_BASE.replace(/^\w+:\/\//, '')}/api/v1/soc/alerts --`}
          </T>
        }
        renderItem={({ item }) => (
          <Pressable
            onPress={() => nav.navigate('AlertDetail', { id: item.id })}
            style={({ pressed }) => ({ backgroundColor: pressed ? C.panelHi : 'transparent', paddingVertical: SP.sm, borderBottomWidth: 1, borderBottomColor: C.line })}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: SP.sm }}>
              <T size={FS.xs} dim>
                {clock(item.ts)}
              </T>
              <SevChip severity={item.severity} />
              <T size={FS.sm} numberOfLines={1} style={{ flex: 1 }}>
                {item.signature}
              </T>
              <SyncChip status={item.sync} />
            </View>
            <T size={FS.xs} dim numberOfLines={1}>
              {`${item.src_ip ?? '?'} → ${item.dest_ip ?? '?'} · ${item.mitre ?? 'no-mitre'} · ${item.status} · ${ago(item.ts)}`}
            </T>
          </Pressable>
        )}
      />
      <View style={{ paddingHorizontal: SP.md, paddingBottom: SP.md }}>
        <Btn
          label="open newest detail"
          tone="cyan"
          disabled={rows.length === 0}
          onPress={() => {
            const first = rows[0];
            if (first) nav.navigate('AlertDetail', { id: first.id });
          }}
        />
      </View>
    </View>
  );
}
