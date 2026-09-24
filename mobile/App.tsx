/** CYBERWATCH-BD mobile (P-04) root: font bootstrap (JetBrains Mono with
 *  bundled fallback), SQLite mirror + outbox init, auth gate, WS + sync wiring. */
import React, { useEffect, useState } from 'react';
import { View } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import NetInfo from '@react-native-community/netinfo';
import * as Font from 'expo-font';

import RootNavigator from './src/navigation/RootNavigator';
import { AuthProvider } from './src/lib/auth';
import { initDb } from './src/lib/db';
import { alertsSocket } from './src/lib/ws';
import { C, FONT_KEYS, markFontsLoaded, FS } from './src/theme';
import { T } from './src/components/ui';

async function bootstrapFonts(): Promise<void> {
  try {
    await Font.loadAsync({
      [FONT_KEYS.regular]: require('./assets/fonts/JetBrainsMono-Regular.ttf'),
      [FONT_KEYS.bold]: require('./assets/fonts/JetBrainsMono-Bold.ttf'),
    });
    markFontsLoaded();
  } catch {
    // fallback: platform monospace (theme.mono()) — never block startup on fonts
  }
}

export default function App(): React.JSX.Element {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let mounted = true;
    void (async () => {
      await Promise.all([bootstrapFonts(), initDb()]);
      if (mounted) setReady(true);
    })();
    return () => {
      mounted = false;
    };
  }, []);

  // WS follows connectivity (the sync worker has its own NetInfo subscription)
  useEffect(() => {
    if (!ready) return;
    const unsub = NetInfo.addEventListener((st) => {
      if (st.isConnected === true) alertsSocket.connect();
      else alertsSocket.disconnect();
    });
    return unsub;
  }, [ready]);

  if (!ready) {
    return (
      <View style={{ flex: 1, backgroundColor: C.bg, justifyContent: 'center', alignItems: 'center' }}>
        <T bold color={C.accent} size={FS.lg}>
          CYBERWATCH-BD
        </T>
        <T dim size={FS.sm}>
          initializing local mirror…
        </T>
      </View>
    );
  }

  return (
    <SafeAreaProvider>
      <StatusBar style="light" backgroundColor={C.bg} />
      <AuthProvider>
        <RootNavigator />
      </AuthProvider>
    </SafeAreaProvider>
  );
}
