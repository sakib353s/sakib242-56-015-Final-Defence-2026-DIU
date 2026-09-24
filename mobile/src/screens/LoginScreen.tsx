/** Login: username + password (+ optional 6-digit TOTP — the server treats login
 *  TOTP as a display hint; step-up gates are enforced per-operation). Terminal
 *  style, no decorative chrome. */
import React, { useState } from 'react';
import { KeyboardAvoidingView, Platform, ScrollView, View } from 'react-native';

import { API_BASE } from '../config/env';
import { useAuth } from '../lib/auth';
import { C, FS, SP } from '../theme';
import { Btn, Input, Panel, T } from '../components/ui';

export default function LoginScreen(): React.JSX.Element {
  const { login, loginError } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (): Promise<void> => {
    if (busy || !username || !password) return;
    setBusy(true);
    await login(username.trim().toLowerCase(), password, totp.trim());
    setBusy(false);
  };

  return (
    <View style={{ flex: 1, backgroundColor: C.bg }}>
      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : undefined} style={{ flex: 1 }}>
        <ScrollView contentContainerStyle={{ padding: SP.xl }} keyboardShouldPersistTaps="handled">
          <T bold color={C.accent} size={FS.xl}>
            CYBERWATCH-BD
          </T>
          <T dim size={FS.sm}>
            {`// cwb-core gateway ${API_BASE.replace(/^\w+:\/\//, '')}`}
          </T>
          <T dim size={FS.sm}>
            {'// BD Edition · CSO-2025 + ICT-2006 enforced'}
          </T>
          <View style={{ height: SP.xl }} />
          <Panel title="IDENTITY CHALLENGE">
            <T dim size={FS.sm}>
              username
            </T>
            <Input
              value={username}
              onChangeText={setUsername}
              placeholder="analyst id"
              autoCapitalize="none"
              returnKeyType="next"
              style={{ marginTop: SP.xs, marginBottom: SP.md }}
            />
            <T dim size={FS.sm}>
              password
            </T>
            <Input
              value={password}
              onChangeText={setPassword}
              placeholder="••••••••"
              secureTextEntry
              returnKeyType="next"
              style={{ marginTop: SP.xs, marginBottom: SP.md }}
            />
            <T dim size={FS.sm}>
              totp (6-digit, optional at login)
            </T>
            <Input
              value={totp}
              onChangeText={(t) => setTotp(t.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              keyboardType="number-pad"
              maxLength={6}
              style={{ marginTop: SP.xs, marginBottom: SP.md }}
            />
            <Btn label={busy ? 'authenticating…' : 'authenticate'} onPress={() => void submit()} disabled={busy} fill />
          </Panel>
          {loginError ? (
            <T bold color={C.fail} size={FS.sm} style={{ marginTop: SP.md }}>
              {`FAIL: ${loginError}`}
            </T>
          ) : null}
        </ScrollView>
      </KeyboardAvoidingView>
    </View>
  );
}
