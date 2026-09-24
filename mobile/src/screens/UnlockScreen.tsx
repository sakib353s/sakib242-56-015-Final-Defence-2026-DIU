/** Biometric resume gate: a saved refresh token exists and biometric-resume is
 *  ON — nothing is decrypted/refreshed until the fingerprint passes. */
import React, { useState } from 'react';
import { View } from 'react-native';

import { useAuth } from '../lib/auth';
import { C, FS, SP } from '../theme';
import { Btn, Panel, T } from '../components/ui';

export default function UnlockScreen(): React.JSX.Element {
  const { unlock, abandonSavedSession, principal, biometricAvailable } = useAuth();
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const doUnlock = async (): Promise<void> => {
    setBusy(true);
    const res = await unlock();
    setBusy(false);
    if (res === 'unavailable') setMsg('biometric hardware/enrollment unavailable — use password');
    else if (res === 'failed') setMsg('unlock denied / session refresh failed');
  };

  return (
    <View style={{ flex: 1, backgroundColor: C.bg, justifyContent: 'center', padding: SP.xl }}>
      <Panel title="SESSION LOCKED">
        <T size={FS.sm}>
          {`principal ..... ${principal?.username ?? '?'}`}
        </T>
        <T dim size={FS.sm}>
          {`role .......... ${principal?.role ?? '?'}`}
        </T>
        <View style={{ height: SP.lg }} />
        <Btn label={busy ? 'prompt…' : 'biometric unlock'} onPress={() => void doUnlock()} disabled={busy || !biometricAvailable} fill />
        <View style={{ height: SP.md }} />
        <Btn label="abandon saved session" tone="fail" onPress={() => void abandonSavedSession()} />
        {msg ? (
          <T bold color={C.warn} size={FS.sm} style={{ marginTop: SP.md }}>
            {msg}
          </T>
        ) : null}
      </Panel>
    </View>
  );
}
