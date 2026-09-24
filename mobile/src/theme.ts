/** Terminal identity — CYBERWATCH-BD. bg #0B0F14, JetBrains Mono w/ bundled
 *  fallback to platform monospace if the custom font ever fails to register. */
import { Platform } from 'react-native';

export const C = {
  bg: '#0B0F14',
  panel: '#0F151C',
  panelHi: '#131C25',
  line: '#1B2836',
  text: '#C9D6E3',
  dim: '#5F7488',
  accent: '#39D98A',
  warn: '#F5B942',
  fail: '#FF5C5C',
  cyan: '#4CC9F0',
  sev: {
    CRITICAL: '#FF3B5C',
    HIGH: '#FF8A3D',
    MEDIUM: '#F5B942',
    LOW: '#4CC9F0',
    INFO: '#5F7488',
  } as Record<string, string>,
};

export const FONT_KEYS = {
  regular: 'JetBrainsMono',
  bold: 'JetBrainsMono-Bold',
} as const;

let bundledLoaded = false;
export function markFontsLoaded(): void {
  bundledLoaded = true;
}

export function mono(bold = false): string | undefined {
  if (bundledLoaded) return bold ? FONT_KEYS.bold : FONT_KEYS.regular;
  return Platform.select({ android: 'monospace', default: undefined });
}

export const FS = { xs: 10, sm: 11, md: 13, lg: 15, xl: 19 } as const;
export const SP = { xs: 2, sm: 4, md: 8, lg: 14, xl: 22 } as const;
