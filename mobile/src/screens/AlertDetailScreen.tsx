/** Alert detail (modal route + cyberwatch://alerts/detail/<id> deep link).
 *  ACK is the one write action: enqueueAlertAck mirrors it locally + queues the
 *  POST with a uuid Idempotency-Key; the badge tracks the queue row live. */
import React, { useCallback, useEffect, useState } from 'react';
import { ScrollView, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';

import type { RootStackParamList } from '../navigation/types';
import { Btn, DotRow, Input, Line, Panel, SevChip, SyncChip, T } from '../components/ui';
import { ackAlert, loadAlert } from '../lib/actions';
import { getAlertView } from '../lib/db';
import { ago, clock, trunc } from '../lib/format';
import { C, FS, SP } from '../theme';
import type { AlertView } from '../types';

type Props = NativeStackScreenProps<RootStackParamList, 'AlertDetail'>;

export default function AlertDetailScreen({ route, navigation }: Props): React.JSX.Element {
  const { id } = route.params;
  const [alert, setAlert] = useState<AlertView | null>(null);
  const [note, setNote] = useState('');
  const [msg, setMsg] = useState('');

  const reload = useCallback((): void => {
    const cached = getAlertView(id);
    if (cached) setAlert(cached);
  }, [id]);

  useEffect(() => {
    reload();
    void loadAlert(id).then((a) => {
      if (a) setAlert(a);
    });
  }, [id, reload]);

  // keep in sync with WS tail / sync worker while open
  useEffect(() => {
    const t = setInterval(reload, 2000);
    return () => clearInterval(t);
  }, [reload]);

  const doAck = (): void => {
    ackAlert(id, note.trim());
    setMsg('ack queued locally — sync worker will POST with idempotency key');
    reload();
  };

  if (!alert) {
    return (
      <View style={{ flex: 1, backgroundColor: C.bg, padding: SP.xl }}>
        <T dim>
          {`LOADING ${trunc(id, 24)} …`}
        </T>
        <T dim size={FS.sm}>
          {'(mirror empty + gateway unreachable → retry from ALERTS)'}
        </T>
        <View style={{ height: SP.lg }} />
        <Btn label="close" tone="fail" onPress={() => navigation.goBack()} />
      </View>
    );
  }

  const acked = alert.status === 'acked' || alert.sync === 'pending';

  return (
    <View style={{ flex: 1, backgroundColor: C.bg }}>
      <View style={{ flexDirection: 'row', justifyContent: 'space-between', padding: SP.md }}>
        <T bold color={C.accent}>
          ALERT DETAIL
        </T>
        <T dim onPress={() => navigation.goBack()}>
          {'[ X ]'}
        </T>
      </View>
      <ScrollView contentContainerStyle={{ padding: SP.md, paddingTop: 0, paddingBottom: SP.xl }}>
        <Panel title="SUMMARY">
          <T bold>{trunc(alert.signature, 44)}</T>
          <View style={{ flexDirection: 'row', gap: SP.md, marginTop: SP.xs }}>
            <SevChip severity={alert.severity} />
            <SyncChip status={alert.sync} />
          </View>
        </Panel>
        <Line />
        <Panel title="FIELDS">
          <DotRow label="id" value={alert.id} width={30} />
          <DotRow label="source" value={alert.source} width={30} />
          <DotRow label="category" value={alert.category ?? '—'} width={30} />
          <DotRow label="severity" value={alert.severity} width={30} valueColor={C.sev[alert.severity] ?? C.text} />
          <DotRow label="src_ip" value={alert.src_ip ?? '—'} width={30} />
          <DotRow label="dest_ip" value={alert.dest_ip ?? '—'} width={30} />
          <DotRow label="mitre" value={alert.mitre ?? '—'} width={30} />
          <DotRow label="fired" value={`${clock(alert.ts)} (${ago(alert.ts)})`} width={30} />
          <DotRow label="status" value={alert.status} width={30} />
          {alert.ack_at ? <DotRow label="acked" value={`${clock(alert.ack_at)} by ${trunc(alert.ack_by ?? '?', 12)}`} width={30} /> : null}
        </Panel>
        {acked ? (
          <View style={{ marginTop: SP.lg }}>
            <T dim size={FS.sm}>
              {`ACKED · sync=${alert.sync}`}
            </T>
          </View>
        ) : (
          <View style={{ marginTop: SP.lg }}>
            <T dim size={FS.sm}>
              ACK NOTE (optional, ≤500 chars server-side)
            </T>
            <Input value={note} onChangeText={setNote} placeholder="triage note…" maxLength={120} style={{ marginVertical: SP.sm }} />
            <Btn label="ACK ALERT" onPress={doAck} fill />
          </View>
        )}
        {msg ? (
          <T color={C.accent} size={FS.sm} style={{ marginTop: SP.md }}>
            {msg}
          </T>
        ) : null}
        <Line />
        <Panel title="RAW EVE LINE">
          <T size={FS.xs} dim style={{ lineHeight: FS.sm + 8 }}>
            {trunc(alert.raw_json, 600)}
          </T>
        </Panel>
      </ScrollView>
    </View>
  );
}
