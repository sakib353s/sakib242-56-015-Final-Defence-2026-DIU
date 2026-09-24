/** Root stack + deep links. cyberwatch:// and https://cwb.bd map onto the same
 *  routes the in-app nav uses — the AlertDetail modal is deep-linkable:
 *  cyberwatch://alerts/detail/<id> */
import React from 'react';
import { DefaultTheme, NavigationContainer, type LinkingOptions } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import * as Linking from 'expo-linking';

import { useAuth } from '../lib/auth';
import { alertsSocket } from '../lib/ws';
import { startSync } from '../lib/sync';
import { C } from '../theme';
import type { RootStackParamList } from './types';

import LoginScreen from '../screens/LoginScreen';
import UnlockScreen from '../screens/UnlockScreen';
import DashboardScreen from '../screens/DashboardScreen';
import AlertsScreen from '../screens/AlertsScreen';
import AlertDetailScreen from '../screens/AlertDetailScreen';
import PentestScreen from '../screens/PentestScreen';
import PentestSessionScreen from '../screens/PentestSessionScreen';
import CaseScreen from '../screens/CaseScreen';
import CaseDetailScreen from '../screens/CaseDetailScreen';
import SettingsScreen from '../screens/SettingsScreen';

const Stack = createNativeStackNavigator<RootStackParamList>();

const linking: LinkingOptions<RootStackParamList> = {
  prefixes: [Linking.createURL('/'), 'cyberwatch://', 'https://cwb.bd'],
  config: {
    screens: {
      Login: 'login',
      Unlock: 'unlock',
      Dashboard: 'dashboard',
      Alerts: 'alerts',
      AlertDetail: 'alerts/detail/:id',
      Pentest: 'pentest',
      PentestSession: 'pentest/session/:id',
      Case: 'cases',
      CaseDetail: 'cases/detail/:id',
      Settings: 'settings',
    },
  },
};

const navTheme = {
  ...DefaultTheme,
  colors: {
    ...DefaultTheme.colors,
    primary: C.accent,
    background: C.bg,
    card: C.panel,
    text: C.text,
    border: C.line,
  },
};

export default function RootNavigator(): React.JSX.Element {
  const { status } = useAuth();
  return (
    <NavigationContainer
      theme={navTheme}
      linking={linking}
      onReady={() => {
        alertsSocket.connect();
        startSync();
      }}>
      <Stack.Navigator
        initialRouteName={status === 'authed' ? 'Dashboard' : status === 'locked' ? 'Unlock' : 'Login'}
        screenOptions={{ headerShown: false, contentStyle: { backgroundColor: C.bg } }}>
        {status === 'authed' ? (
          <>
            <Stack.Screen name="Dashboard" component={DashboardScreen} />
            <Stack.Screen name="Alerts" component={AlertsScreen} />
            <Stack.Screen name="AlertDetail" component={AlertDetailScreen} options={{ presentation: 'modal', animation: 'slide_from_bottom' }} />
            <Stack.Screen name="Pentest" component={PentestScreen} />
            <Stack.Screen name="PentestSession" component={PentestSessionScreen} />
            <Stack.Screen name="Case" component={CaseScreen} />
            <Stack.Screen name="CaseDetail" component={CaseDetailScreen} />
            <Stack.Screen name="Settings" component={SettingsScreen} />
          </>
        ) : status === 'locked' ? (
          <Stack.Screen name="Unlock" component={UnlockScreen} />
        ) : (
          <Stack.Screen name="Login" component={LoginScreen} />
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}
