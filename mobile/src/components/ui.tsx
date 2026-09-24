/** Terminal UI kit — JetBrains Mono, [ OK ]/WARN/FAIL chips, dot-leader rows. */
import React, { useEffect, useState } from 'react';
import {
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
  type PressableProps,
  type StyleProp,
  type TextProps,
  type TextInputProps,
  type TextStyle,
  type ViewStyle,
} from 'react-native';

import { C, FS, SP, mono } from '../theme';
import { alertsSocket, type WsState } from '../lib/ws';
import type { OutboxStatus, Severity } from '../types';

export function T({
  bold,
  dim,
  size = FS.md,
  color,
  style,
  children,
  ...rest
}: TextProps & { bold?: boolean; dim?: boolean; size?: number; color?: string }): React.JSX.Element {
  return (
    <Text {...rest} style={[{ fontFamily: mono(bold), fontSize: size, color: color ?? (dim ? C.dim : C.text) }, style]}>
      {children}
    </Text>
  );
}

const STATUS_CHIP: Record<string, { label: string; color: string }> = {
  OK: { label: '[ OK ]', color: C.accent },
  WARN: { label: '[ WARN ]', color: C.warn },
  FAIL: { label: '[ FAIL ]', color: C.fail },
};

export function StatusChip({ status }: { status: string }): React.JSX.Element {
  const chip = STATUS_CHIP[status.toUpperCase()] ?? { label: `[ ${status.slice(0, 6).toUpperCase()} ]`, color: C.dim };
  return (
    <T bold color={chip.color}>
      {chip.label}
    </T>
  );
}

export function SevChip({ severity }: { severity: Severity }): React.JSX.Element {
  const color = C.sev[severity?.toUpperCase()] ?? C.dim;
  const label = severity === 'CRITICAL' ? '[CRIT]' : `[${String(severity).slice(0, 4).toUpperCase()}]`;
  return (
    <T bold color={color}>
      {label}
    </T>
  );
}

const SYNC_CHIP: Record<OutboxStatus, { label: string; color: string }> = {
  pending: { label: '[QUEUED]', color: C.warn },
  synced: { label: '[SYNCED]', color: C.accent },
  failed: { label: '[FAILED]', color: C.fail },
};

export function SyncChip({ status }: { status: OutboxStatus | 'clean' }): React.JSX.Element | null {
  if (status === 'clean') return null;
  const chip = SYNC_CHIP[status];
  return (
    <T bold color={chip.color} size={FS.sm}>
      {chip.label}
    </T>
  );
}

const WS_LABEL: Record<WsState, { label: string; color: string }> = {
  online: { label: '● WS:LIVE', color: C.accent },
  connecting: { label: '◐ WS:OPEN…', color: C.warn },
  backoff: { label: '○ WS:RETRY', color: C.warn },
  off: { label: '○ WS:OFF', color: C.dim },
};

export function WsDot(): React.JSX.Element {
  const [state, setState] = useState<WsState>(alertsSocket.state);
  useEffect(() => alertsSocket.onState(setState), []);
  const l = WS_LABEL[state];
  return (
    <T bold size={FS.sm} color={l.color}>
      {l.label}
    </T>
  );
}

/** dot-leader row: LABEL ········· value (monospace column alignment) */
export function DotRow({
  label,
  value,
  valueColor,
  width = 36,
  style,
}: {
  label: string;
  value: string;
  valueColor?: string;
  width?: number;
  style?: StyleProp<TextStyle>;
}): React.JSX.Element {
  const dots = Math.max(3, width - label.length - value.length - 2);
  return (
    <View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
      <T size={FS.sm} dim>
        {`${label} ${'·'.repeat(dots)} `}
      </T>
      <T size={FS.sm} color={valueColor ?? C.text} style={style}>
        {value}
      </T>
    </View>
  );
}

export function SectionLabel({ children }: { children: string }): React.JSX.Element {
  return (
    <T dim size={FS.sm} style={{ marginTop: SP.lg, marginBottom: SP.sm }}>
      {'// '}
      {children}
    </T>
  );
}

export function Panel({
  title,
  right,
  children,
  style,
}: {
  title?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  style?: StyleProp<ViewStyle>;
}): React.JSX.Element {
  return (
    <View
      style={{
        borderWidth: 1,
        borderColor: C.line,
        backgroundColor: C.panel,
        padding: SP.md,
        ...StyleSheet.flatten(style),
      }}>
      {title ? (
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: SP.sm }}>
          <T dim size={FS.sm} bold>
            {title}
          </T>
          {right}
        </View>
      ) : null}
      {children}
    </View>
  );
}

export function Btn({
  label,
  onPress,
  disabled,
  tone = 'accent',
  fill,
}: {
  label: string;
  onPress?: () => void;
  disabled?: boolean;
  tone?: 'accent' | 'warn' | 'fail' | 'cyan';
  fill?: boolean;
}): React.JSX.Element {
  const color = disabled ? C.dim : tone === 'fail' ? C.fail : tone === 'warn' ? C.warn : tone === 'cyan' ? C.cyan : C.accent;
  return (
    <Pressable
      onPress={onPress}
      disabled={disabled}
      style={({ pressed }) => ({
        paddingVertical: SP.sm,
        paddingHorizontal: SP.md,
        borderWidth: 1,
        borderColor: color,
        backgroundColor: pressed && !disabled ? C.panelHi : fill ? C.panel : 'transparent',
        opacity: disabled ? 0.4 : 1,
      })}>
      <T bold color={color} size={FS.sm}>
        {'[ '}
        {label.toUpperCase()}
        {' ]'}
      </T>
    </Pressable>
  );
}

export function Line({ style }: { style?: StyleProp<ViewStyle> }): React.JSX.Element {
  return <View style={{ height: 1, backgroundColor: C.line, marginVertical: SP.md, ...StyleSheet.flatten(style) }} />;
}

export function Input({ style, ...rest }: TextInputProps): React.JSX.Element {
  return (
    <TextInput
      placeholderTextColor={C.dim}
      autoCapitalize="none"
      autoCorrect={false}
      cursorColor={C.accent}
      spellCheck={false}
      style={{
        fontFamily: mono(),
        fontSize: FS.md,
        color: C.text,
        backgroundColor: C.panelHi,
        borderWidth: 1,
        borderColor: C.line,
        paddingHorizontal: SP.md,
        paddingVertical: SP.sm + 2,
        ...StyleSheet.flatten(style),
      }}
      {...rest}
    />
  );
}

export function ScreenBox({ children }: { children: React.ReactNode }): React.JSX.Element {
  return <View style={{ flex: 1, backgroundColor: C.bg }}>{children}</View>;
}
