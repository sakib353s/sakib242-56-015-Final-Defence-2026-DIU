/** Dense terminal formatting helpers (dot-leader rows, relative time, truncation). */

export const isoNow = (): string => new Date().toISOString();

const SEC = 1000;
const MIN = 60 * SEC;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

export function ago(ts: string | null | undefined): string {
  if (!ts) return '—';
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return '—';
  const d = Date.now() - t;
  if (d < 0) return 'future';
  if (d < MIN) return `${Math.floor(d / SEC)}s ago`;
  if (d < HOUR) return `${Math.floor(d / MIN)}m ago`;
  if (d < DAY) return `${Math.floor(d / HOUR)}h ago`;
  return `${Math.floor(d / DAY)}d ago`;
}

export function clock(ts: string | null | undefined): string {
  if (!ts) return '—';
  const t = new Date(ts);
  if (Number.isNaN(t.getTime())) return '—';
  const p = (n: number): string => `${n}`.padStart(2, '0');
  return `${p(t.getMonth() + 1)}-${p(t.getDate())} ${p(t.getHours())}:${p(t.getMinutes())}:${p(t.getSeconds())}`;
}

export function trunc(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, Math.max(0, n - 1))}…`;
}

/** "LABEL ......... value" — dots fill a fixed column, terminal style. */
export function dotLeader(label: string, value: string, width = 34): string {
  const head = label.length > width - 6 ? `${label.slice(0, width - 7)}~` : label;
  const dots = Math.max(3, width - head.length - value.length);
  return `${head} ${'.'.repeat(dots)} ${value}`;
}

export function pct(v: number | null | undefined): string {
  if (typeof v !== 'number' || Number.isNaN(v)) return '—';
  return `${Math.round(v <= 1 ? v * 100 : v)}%`;
}
