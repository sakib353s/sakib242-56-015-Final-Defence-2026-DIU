/** Global chrome: title line, WS dot, outbox badge, and the terminal nav row. */
import React, { useSyncExternalStore } from 'react';
import { View } from 'react-native';

import { C, FS, SP } from '../theme';
import { getSyncSnapshot, subscribeSync } from '../lib/sync';
import { useNav } from '../navigation/hooks';
import type { RootStackParamList } from '../navigation/types';
import { T, WsDot } from './ui';

type NavKey = 'Alerts' | 'Dashboard' | 'Pentest' | 'Case' | 'Settings';

const NAV: ReadonlyArray<{ key: NavKey; label: string }> = [
  { key: 'Alerts', label: 'ALERTS' },
  { key: 'Dashboard', label: 'DASH' },
  { key: 'Pentest', label: 'PENTST' },
  { key: 'Case', label: 'CASES' },
  { key: 'Settings', label: 'CONF' },
];

export function SyncBadge(): React.JSX.Element {
  const snap = useSyncExternalStore(subscribeSync, getSyncSnapshot);
  const label = !snap.online
    ? 'OFFLINE'
    : snap.failed > 0
      ? `SYNC:FAIL ${snap.failed}`
      : snap.pending > 0
        ? `SYNC:QUEUE ${snap.pending}`
        : 'SYNC:IDLE';
  const color = !snap.online ? C.dim : snap.failed > 0 ? C.fail : snap.pending > 0 ? C.warn : C.accent;
  return (
    <T bold size={FS.sm} color={color}>
      {label}
    </T>
  );
}

export function TopBar({ title, active }: { title: string; active?: keyof RootStackParamList }): React.JSX.Element {
  const nav = useNav();
  return (
    <View style={{ paddingHorizontal: SP.md, paddingTop: SP.sm, backgroundColor: C.bg }}>
      <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
        <T bold color={C.accent}>
          CYBERWATCH-BD
        </T>
        <View style={{ flexDirection: 'row', gap: SP.md }}>
          <SyncBadge />
          <WsDot />
        </View>
      </View>
      <T dim size={FS.sm}>
        {`── ${title} ${'─'.repeat(Math.max(0, 34 - title.length))}`}
      </T>
      <View style={{ flexDirection: 'row', gap: SP.md, paddingVertical: SP.sm }}>
        {NAV.map((item) => (
          <T
            key={item.key}
            size={FS.sm}
            bold={item.key === active}
            color={item.key === active ? C.accent : C.dim}
            onPress={() => nav.navigate(item.key)}
            suppressHighlighting>
            {item.key === active ? `[${item.label}]` : item.label}
          </T>
        ))}
      </View>
    </View>
  );
}
