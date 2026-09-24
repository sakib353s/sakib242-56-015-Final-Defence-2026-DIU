"use client";

/** Real charts for real data — recharts primitives wired to the live queries.
 *  Nothing here fabricates a series: every component takes rows the caller read
 *  from the API. Renders only after mount (ResponsiveContainer + SSR don't mix). */

import { useEffect, useMemo, useState } from "react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { THEME_EVENT } from "@/lib/theme";

export const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#e5484d",
  HIGH: "#ef7433",
  MEDIUM: "#d4a72c",
  LOW: "#58a6ff",
  INFO: "#8b949e",
};

export const SERIES = ["#4c8dff", "#3fb950", "#d4a72c", "#e5484d", "#56d3dd", "#8957e5", "#a5a9b3"];

function useTheme(): "dark" | "light" {
  const [t, setT] = useState<"dark" | "light">("dark");
  useEffect(() => {
    const read = () => setT(document.documentElement.dataset.theme === "light" ? "light" : "dark");
    read();
    const on = () => read();
    window.addEventListener(THEME_EVENT, on);
    const mo = new MutationObserver(on);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => {
      window.removeEventListener(THEME_EVENT, on);
      mo.disconnect();
    };
  }, []);
  return t;
}

function usePalette() {
  const theme = useTheme();
  return useMemo(
    () =>
      theme === "dark"
        ? { grid: "rgba(139,148,158,0.14)", axis: "#8b949e", tipBg: "#161d27", tipBorder: "#303642", tipFg: "#e6edf3" }
        : { grid: "rgba(31,35,40,0.1)", axis: "#59636e", tipBg: "#ffffff", tipBorder: "#d0d7de", tipFg: "#1f2328" },
    [theme],
  );
}

const tipStyle = (p: ReturnType<typeof usePalette>) => ({
  contentStyle: {
    background: p.tipBg,
    border: `1px solid ${p.tipBorder}`,
    borderRadius: 12,
    fontFamily: "var(--font)",
    fontSize: 11.5,
    color: p.tipFg,
    boxShadow: "0 12px 32px rgba(0,0,0,0.35)",
  },
  labelStyle: { color: p.axis, letterSpacing: 0.5 },
  itemStyle: { color: p.tipFg },
});

function Frame({ height, children }: { height: number; children: React.ReactElement }) {
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);
  if (!ready) return <div style={{ height }} />;
  return (
    <div className="chart-wrap" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  );
}

export interface Slice {
  name: string;
  value: number;
  color?: string;
}

export function Donut({
  data,
  height = 210,
  centerValue,
  centerLabel,
}: {
  data: Slice[];
  height?: number;
  centerValue?: string | number;
  centerLabel?: string;
}) {
  const p = usePalette();
  const rows = data.filter((d) => d.value > 0);
  const total = rows.reduce((s, d) => s + d.value, 0);
  if (!rows.length) {
    return <div style={{ height, display: "flex", alignItems: "center", justifyContent: "center", color: p.axis, fontSize: 12 }}>No data to display</div>;
  }
  return (
    <div style={{ position: "relative" }}>
      <Frame height={height}>
        <PieChart>
          <Pie
            data={rows}
            dataKey="value"
            nameKey="name"
            innerRadius="72%"
            outerRadius="88%"
            paddingAngle={rows.length > 1 ? 2 : 0}
            cornerRadius={4}
            stroke="none"
            isAnimationActive
          >
            {rows.map((d, i) => (
              <Cell key={d.name} fill={d.color ?? SERIES[i % SERIES.length]} />
            ))}
          </Pie>
          <Tooltip {...tipStyle(p)} formatter={(v: number | string, n: string) => [`${v} · ${((Number(v) / total) * 100).toFixed(0)}%`, n]} />
        </PieChart>
      </Frame>
      <div className="chart-center">
        <span className="big">{centerValue ?? total}</span>
        <span className="sub">{centerLabel ?? "total"}</span>
      </div>
    </div>
  );
}

export function Legend({ items }: { items: Slice[] }) {
  const total = items.reduce((s, d) => s + d.value, 0);
  return (
    <div className="legend">
      {items.map((d, i) => (
        <span key={d.name} className="li">
          <span className="sw" style={{ background: d.color ?? SERIES[i % SERIES.length] }} />
          <span className="name">{d.name}</span>
          <span className="val">{d.value}</span>
          <span className="pct">{total ? `${Math.round((d.value / total) * 100)}%` : "0%"}</span>
        </span>
      ))}
    </div>
  );
}

/** Donut with its breakdown beside it — the ring alone leaves the reader
 *  counting colours, and a stacked legend under it wastes the panel's width. */
export function DonutStat({
  data,
  height = 168,
  centerValue,
  centerLabel,
}: {
  data: Slice[];
  height?: number;
  centerValue?: string | number;
  centerLabel?: string;
}) {
  return (
    <div className="donut-row">
      <Donut data={data} height={height} centerValue={centerValue} centerLabel={centerLabel} />
      <Legend items={data} />
    </div>
  );
}

/** Ranked bars for categories whose names are full sentences — a vertical
 *  axis cannot fit them without the labels colliding. */
export function RankList({
  items,
  color = "#4c8dff",
}: {
  items: { label: string; value: number; color?: string }[];
  color?: string;
}) {
  const max = items.reduce((m, it) => Math.max(m, it.value), 0) || 1;
  return (
    <ol className="ranklist">
      {items.map((it, i) => (
        <li key={`${it.label}-${i}`}>
          <span className="rl-label" title={it.label}>
            {it.label}
          </span>
          <span className="rl-track">
            <span
              className="rl-fill"
              style={{ width: `${Math.max(3, (it.value / max) * 100)}%`, background: it.color ?? color }}
            />
          </span>
          <span className="rl-value">{it.value}</span>
        </li>
      ))}
    </ol>
  );
}

export function Bars({
  data,
  height = 210,
  color = "#4c8dff",
  perCell,
}: {
  data: { label: string; value: number; color?: string }[];
  height?: number;
  color?: string;
  perCell?: boolean;
}) {
  const p = usePalette();
  if (!data.length) {
    return <div style={{ height, display: "flex", alignItems: "center", justifyContent: "center", color: p.axis, fontSize: 12 }}>No data to display</div>;
  }
  return (
    <Frame height={height}>
      <BarChart data={data} margin={{ top: 6, right: 6, left: -18, bottom: 0 }}>
        <CartesianGrid stroke={p.grid} vertical={false} />
        <XAxis dataKey="label" tick={{ fill: p.axis, fontSize: 10 }} axisLine={{ stroke: p.grid }} tickLine={false} interval={0} />
        <YAxis tick={{ fill: p.axis, fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip {...tipStyle(p)} cursor={{ fill: "rgba(148,163,184,0.06)" }} />
        <Bar dataKey="value" fill={color} radius={[6, 6, 0, 0]} maxBarSize={34} isAnimationActive>
          {perCell
            ? data.map((d, i) => <Cell key={d.label} fill={d.color ?? color} />)
            : null}
        </Bar>
      </BarChart>
    </Frame>
  );
}

export function Trend({
  data,
  height = 210,
  color = "#4c8dff",
  xKey = "t",
  yKey = "v",
  unit = "",
  type = "monotone",
}: {
  data: Record<string, number | string>[];
  height?: number;
  color?: string;
  xKey?: string;
  yKey?: string;
  unit?: string;
  type?: "monotone" | "linear" | "step";
}) {
  const p = usePalette();
  const gid = `g-${color.replace("#", "")}-${yKey}`;
  if (data.length < 2) {
    return (
      <div style={{ height, display: "flex", alignItems: "center", justifyContent: "center", color: p.axis, fontSize: 12 }}>
        Collecting data · {data.length} point{data.length === 1 ? "" : "s"} so far
      </div>
    );
  }
  return (
    <Frame height={height}>
      <AreaChart data={data} margin={{ top: 6, right: 6, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.42} />
            <stop offset="100%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={p.grid} vertical={false} />
        <XAxis dataKey={xKey} tick={{ fill: p.axis, fontSize: 10 }} axisLine={{ stroke: p.grid }} tickLine={false} minTickGap={28} />
        <YAxis tick={{ fill: p.axis, fontSize: 10 }} axisLine={false} tickLine={false} width={44} allowDecimals={false} />
        <Tooltip {...tipStyle(p)} formatter={(v: number | string) => [`${v}${unit}`, yKey.toUpperCase()]} />
        <Area type={type} dataKey={yKey} stroke={color} strokeWidth={2} fill={`url(#${gid})`} isAnimationActive={false} />
      </AreaChart>
    </Frame>
  );
}

export function MiniLine({ data, color = "#4c8dff", height = 34, width = "100%" }: {
  data: number[]; color?: string; height?: number; width?: number | string;
}) {
  const rows = data.map((v, i) => ({ i, v }));
  if (rows.length < 2) return null;
  return (
    <div style={{ width, height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={rows} margin={{ top: 2, right: 0, left: 0, bottom: 2 }}>
          <Line type="monotone" dataKey="v" stroke={color} strokeWidth={1.6} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
