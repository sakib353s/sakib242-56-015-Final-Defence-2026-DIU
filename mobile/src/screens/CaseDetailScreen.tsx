/** Case detail — hash-chained timeline + BTRC / Police draft PDF links.
 *  Every open/share is gated behind a fresh biometric re-check (P-04 spec). */
import React, { useCallback, useEffect, useState } from 'react';
import { ScrollView, View } from 'react-native';
import * as FileSystem from 'expo-file-system';
import * as Linking from 'expo-linking';
import * as Sharing from 'expo-sharing';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';

import { absUrl } from '../config/env';
import type { RootStackParamList } from '../navigation/types';
import { Btn, DotRow, Line, Panel, T } from '../components/ui';
import { loadCaseDetail, loadComplaintLinks } from '../lib/actions';
import { promptBiometric } from '../lib/biometrics';
import { isNetworkError } from '../lib/api';
import { clock, trunc } from '../lib/format';
import { C, FS, SP } from '../theme';
import type { CaseDetail, ComplaintLink } from '../types';

type Props = NativeStackScreenProps<RootStackParamList, 'CaseDetail'>;

export default function CaseDetailScreen({ route, navigation }: Props): React.JSX.Element {
  const { id } = route.params;
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [links, setLinks] = useState<ComplaintLink[]>([]);
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');

  const load = useCallback(async (): Promise<void> => {
    setError('');
    try {
      setDetail(await loadCaseDetail(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    try {
      setLinks(await loadComplaintLinks(id));
    } catch (e) {
      setLinks([]);
      if (!isNetworkError(e)) setError(String(e instanceof Error ? e.message : e));
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  const gate = async (action: string): Promise<boolean> => {
    const ok = await promptBiometric(`Re-authenticate to ${action}`);
    if (!ok) setMsg(`ABORTED: biometric re-check failed for "${action}"`);
    else setMsg('');
    return ok;
  };

  const openPdf = async (d: ComplaintLink): Promise<void> => {
    if (!(await gate(`open ${d.agency.toUpperCase()} complaint PDF`))) return;
    try {
      await Linking.openURL(absUrl(d.download));
      setMsg(`opened ${d.agency} draft (signed link, 300 s TTL)`);
    } catch (e) {
      setMsg(`open failed: ${String(e instanceof Error ? e.message : e)}`);
    }
  };

  const sharePdf = async (d: ComplaintLink): Promise<void> => {
    if (!(await gate(`share ${d.agency.toUpperCase()} complaint PDF`))) return;
    try {
      const r = await FileSystem.downloadAsync(absUrl(d.download), `${FileSystem.cacheDirectory}${d.name}`);
      if (r.status === 200 && (await Sharing.isAvailableAsync())) {
        await Sharing.shareAsync(r.uri, { mimeType: 'application/pdf', dialogTitle: `DRAFT — ${d.agency}` });
        setMsg('share sheet presented');
      } else {
        setMsg(`download failed: HTTP ${r.status}`);
      }
    } catch (e) {
      setMsg(`share failed: ${String(e instanceof Error ? e.message : e)}`);
    }
  };

  const regenerate = async (): Promise<void> => {
    // plumbing note: server requires X-TOTP step-up for generation; mobile never
    // holds a live TOTP seed → draft generation is desktop-only by design.
    if (!(await gate('complaint draft regeneration (step-up)'))) return;
    setMsg('GENERATION REFUSED: complaint drafts need a fresh TOTP code — run from desktop console (P-00)');
  };

  return (
    <View style={{ flex: 1, backgroundColor: C.bg }}>
      <View style={{ flexDirection: 'row', justifyContent: 'space-between', padding: SP.md }}>
        <T bold color={C.accent}>
          CASE {trunc(id, 16)}
        </T>
        <T dim onPress={() => navigation.goBack()}>
          {'[ X ]'}
        </T>
      </View>
      <ScrollView contentContainerStyle={{ padding: SP.md, paddingTop: 0, paddingBottom: SP.xl }}>
        {error ? (
          <Panel title="ERROR">
            <T size={FS.sm} color={C.fail}>
              {trunc(error, 120)}
            </T>
          </Panel>
        ) : null}
        {detail ? (
          <>
            <Panel title="CASE">
              <DotRow label="type" value={detail.case.case_type} width={30} />
              <DotRow label="status" value={detail.case.status} width={30} />
              <DotRow label="opened" value={clock(detail.case.created_at)} width={30} />
              <T size={FS.xs} dim style={{ marginTop: SP.sm, lineHeight: FS.sm + 6 }}>
                {trunc(detail.case.narrative, 400)}
              </T>
            </Panel>
            <Line />
            <Panel title={`TIMELINE · ${detail.timeline.length} EVENTS (hash-chained)`}>
              {detail.timeline.map((ev) => (
                <View key={ev.seq} style={{ flexDirection: 'row', gap: SP.sm, paddingVertical: SP.xs }}>
                  <T size={FS.xs} dim>
                    {`${String(ev.seq).padStart(3, '0')}`}
                  </T>
                  <T size={FS.xs} dim>
                    {clock(ev.ts)}
                  </T>
                  <T size={FS.xs} style={{ flex: 1 }} numberOfLines={1}>
                    {ev.action}
                  </T>
                  <T size={FS.xs} color={C.accent}>
                    {ev.hash.slice(0, 8)}
                  </T>
                </View>
              ))}
            </Panel>
            <Line />
            <Panel title="OFFICIAL CHANNEL DRAFTS" right={<T dim size={FS.xs}>biometric-gated</T>}>
              {links.length === 0 ? (
                <T dim size={FS.sm}>
                  no BTRC/Police drafts on gateway yet (generation is desktop + TOTP step-up)
                </T>
              ) : null}
              {links.map((d) => (
                <View key={d.report_id} style={{ marginBottom: SP.md }}>
                  <T size={FS.sm} bold>
                    {`${d.agency.toUpperCase()} · ${trunc(d.name, 26)}`}
                  </T>
                  <View style={{ flexDirection: 'row', gap: SP.md, marginTop: SP.xs }}>
                    <Btn label="open pdf" tone="cyan" onPress={() => void openPdf(d)} />
                    <Btn label="share" onPress={() => void sharePdf(d)} />
                  </View>
                </View>
              ))}
              {links.length > 0 ? (
                <View style={{ marginTop: SP.sm }}>
                  <Btn label="regenerate drafts" tone="warn" onPress={() => void regenerate()} />
                </View>
              ) : null}
            </Panel>
          </>
        ) : !error ? (
          <T dim>loading case…</T>
        ) : null}
        {msg ? (
          <T size={FS.sm} color={C.warn} style={{ marginTop: SP.lg }}>
            {msg}
          </T>
        ) : null}
      </ScrollView>
    </View>
  );
}
