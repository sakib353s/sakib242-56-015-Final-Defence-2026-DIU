/** Case Viewer — victim case list (mirror + GET /api/v1/victim/cases) and a
 *  case-id loader for direct access / deep links. */
import React, { useCallback, useEffect, useState } from 'react';
import { FlatList, Pressable, RefreshControl, View } from 'react-native';

import { TopBar } from '../components/TopBar';
import { Btn, Input, Line, T } from '../components/ui';
import { cachedCases, refreshCases } from '../lib/actions';
import { ago, trunc } from '../lib/format';
import { useNav } from '../navigation/hooks';
import { C, FS, SP } from '../theme';
import type { CaseSummary } from '../types';

export default function CaseScreen(): React.JSX.Element {
  const nav = useNav();
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [caseId, setCaseId] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(async (): Promise<void> => {
    setCases(cachedCases());
    setRefreshing(true);
    try {
      setCases(await refreshCases());
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <View style={{ flex: 1, backgroundColor: C.bg }}>
      <TopBar title="VICTIM CASES" active="Case" />
      <View style={{ flexDirection: 'row', gap: SP.sm, paddingHorizontal: SP.md, alignItems: 'center' }}>
        <Input
          value={caseId}
          onChangeText={setCaseId}
          placeholder="case id (uuid)…"
          style={{ flex: 1 }}
          onSubmitEditing={() => caseId.trim() && nav.navigate('CaseDetail', { id: caseId.trim() })}
        />
        <Btn label="load" disabled={!caseId.trim()} onPress={() => nav.navigate('CaseDetail', { id: caseId.trim() })} />
      </View>
      {error ? (
        <T size={FS.sm} color={C.dim} style={{ paddingHorizontal: SP.md, marginTop: SP.xs }}>
          {`mirror shown · rest: ${trunc(error, 90)}`}
        </T>
      ) : null}
      <Line style={{ marginVertical: SP.sm }} />
      <FlatList
        data={cases}
        keyExtractor={(c) => c.id}
        contentContainerStyle={{ paddingHorizontal: SP.md, paddingBottom: SP.xl }}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => void load()} tintColor={C.accent} />}
        ListEmptyComponent={<T dim size={FS.sm}>{'-- no cached cases · pull to fetch --'}</T>}
        renderItem={({ item }) => (
          <Pressable
            onPress={() => nav.navigate('CaseDetail', { id: item.id })}
            style={({ pressed }) => ({ paddingVertical: SP.sm, borderBottomWidth: 1, borderBottomColor: C.line, backgroundColor: pressed ? C.panelHi : 'transparent' })}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <T size={FS.sm}>
                {item.case_type.toUpperCase()} · {trunc(item.id, 18)}
              </T>
              <T size={FS.sm} color={item.status === 'OPEN' ? C.warn : C.accent}>
                [{item.status}]
              </T>
            </View>
            <T size={FS.xs} dim>
              {`opened ${ago(item.created_at)}`}
            </T>
          </Pressable>
        )}
      />
    </View>
  );
}
