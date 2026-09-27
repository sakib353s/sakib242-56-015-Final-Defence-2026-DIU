"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { toProblem } from "@/lib/api";
import { getToken } from "@/lib/auth";
import { getRole } from "@/lib/auth";
import { hasRole, ROLE_TAG } from "@/lib/rbac";
import type { Role, Tone } from "@/lib/types";

const TONES = ["ok", "warn", "fail", "info", "dim", "critical", "high", "medium", "low"];

export function Chip({ tone, label }: { tone: Tone | string; label?: string }) {
  const t = TONES.includes(tone) ? (tone as string) : "dim";
  const txt = label ?? String(tone);
  return <span className={t === "dim" ? "chip dim" : `chip ${t}`}>{txt}</span>;
}

/** Placeholder for a number that has not arrived yet. A bare em dash reads as
 *  "the system measured nothing", which is a different claim. */
export function Skel({ w = 54 }: { w?: number }) {
  return <span className="skel" style={{ width: w }} role="status" aria-label="Loading" />;
}

export function StatCard({
  label,
  value,
  unit,
  foot,
  tone = "",
  spark,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  foot?: ReactNode;
  tone?: "" | "ok" | "warn" | "fail";
  spark?: ReactNode;
}) {
  return (
    <div className={`stat-card${tone ? ` ${tone}` : ""}`}>
      <span className="stat-orb" aria-hidden />
      <div className="stat-label">{label}</div>
      <div className="stat-value">
        {value}
        {unit ? <span className="unit"> {unit}</span> : null}
      </div>
      {spark ? <div className="stat-spark" aria-hidden>{spark}</div> : null}
      {foot ? <div className="stat-foot">{foot}</div> : null}
    </div>
  );
}

export function Segmented({
  options,
  value,
  onChange,
  ariaLabel,
}: {
  options: { id: string; label: string }[];
  value: string;
  onChange: (id: string) => void;
  ariaLabel?: string;
}) {
  return (
    <div className="seg" role="radiogroup" aria-label={ariaLabel}>
      {options.map((o) => (
        <button key={o.id} type="button" role="radio" aria-checked={o.id === value}
                className={o.id === value ? "on" : ""} onClick={() => onChange(o.id)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Panel({
  title,
  actions,
  children,
  tight,
  className,
}: {
  title: string;
  actions?: ReactNode;
  children: ReactNode;
  tight?: boolean;
  className?: string;
}) {
  return (
    <section className={`panel${className ? ` ${className}` : ""}`}>
      <header className="panel-hd">
        <h2 className="panel-title">{title}</h2>
        {actions ? <div className="panel-actions">{actions}</div> : null}
      </header>
      <div className={`panel-body${tight ? " tight" : ""}`}>{children}</div>
    </section>
  );
}

export function TabBar({
  tabs,
  active,
  onChange,
  actions,
}: {
  tabs: { id: string; label: string }[];
  active: string;
  onChange: (id: string) => void;
  actions?: ReactNode;
}) {
  return (
    <div className="tabbar-wrap">
      <div className="tabs" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={t.id === active}
            className={`tab${t.id === active ? " on" : ""}`}
            onClick={() => onChange(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      {actions ? <div className="tabbar-actions">{actions}</div> : null}
    </div>
  );
}

export function Leader({ label, value, tone }: { label: string; value?: ReactNode; tone?: Tone }) {
  return (
    <div className="kv-row">
      <span className="lbl">{label}</span>
      <span className={tone ? `val ${tone}` : "val"}>{value}</span>
    </div>
  );
}

/* TanStack v5 leaves status=pending/fetchStatus=paused while a retry is held by the
   online/focus managers — isFetching is false there, so pages must check both or the
   console goes silent mid-flight. */
export function qBusy(q: { isFetching: boolean; isPaused: boolean }): boolean {
  return q.isFetching || q.isPaused;
}

export function LoaderRows({ lines, paused }: { lines: string[]; paused?: boolean }) {
  return (
    <div className="state-rows" role="status" aria-busy="true">
      {lines.map((l, i) => (
        <div key={i} className={paused ? undefined : "breathe"}>
          {l}
          <span className={paused ? "w" : "b"} style={{ marginLeft: 8 }}>
            {paused ? "Paused" : "Loading…"}
          </span>
        </div>
      ))}
      {paused ? (
        <div>
          <span className="w">Paused</span> — connection is held; it will retry when the network or window focus returns.
        </div>
      ) : null}
    </div>
  );
}

export function EmptyRows({ what = "No records to display" }: { what?: string }) {
  return (
    <div className="state-rows">
      <div>{what}</div>
    </div>
  );
}

export function ErrBanner({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  // Normalise every shape (ApiProblem, transport Error, plain string, foreign
  // bundle) so the banner never collapses into "Request failed · about:blank".
  const p = toProblem(error);
  return (
    <div className="problem" role="alert">
      <div className="pt">
        {p.title} · HTTP {p.status || "—"} · {p.type}
      </div>
      <div className="pd">{p.detail || p.title}</div>
      <div className="pm">
        audit_ref={p.audit_ref ?? "—"} · request_id={p.request_id ?? "—"}
        {onRetry ? (
          <>
            {" · "}
            <button className="btn-link" onClick={onRetry} type="button">
              try again
            </button>
          </>
        ) : null}
      </div>
    </div>
  );
}

const METER_COLOR: Record<string, string> = {
  "": "var(--accent)",
  ok: "var(--ok)",
  warn: "var(--warn)",
  fail: "var(--fail)",
  info: "var(--accent)",
};

export function Meter({
  v,
  max = 10,
  tone = "",
  className,
}: {
  v: number;
  max?: number;
  tone?: string;
  className?: string;
}) {
  const pct = Math.max(0, Math.min(100, (v / max) * 100));
  return (
    <span className={className ? `meter ${className}` : "meter"} role="img" aria-label={`${Math.round(pct)}%`}>
      <span className="meter-fill" style={{ width: `${pct}%`, background: METER_COLOR[tone] ?? "var(--accent)" }} />
    </span>
  );
}

export function KV({ rows }: { rows: Array<[string, ReactNode]> }) {
  return (
    <div className="kv">
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <span className="k">{k}</span>
          <span className="v">{v}</span>
        </div>
      ))}
    </div>
  );
}

export function Lock({ text }: { text: string }) {
  return (
    <div className="lockline">
      Restricted access — {text}. Permissions are enforced on the server, independent of this view.
    </div>
  );
}

export function AuthGuard({ children }: { children: ReactNode }) {
  const router = useRouter();
  useEffect(() => {
    if (!getToken()) router.replace("/boot");
  }, [router]);
  return <>{children}</>;
}

export function RoleGuard({ min, children }: { min: Role; children: ReactNode }) {
  const [ok, setOk] = useState<boolean | null>(null);
  const router = useRouter();
  useEffect(() => {
    if (!getToken()) {
      router.replace("/boot");
      return;
    }
    setOk(hasRole(getRole(), min));
  }, [min, router]);
  if (ok === false) return <Lock text={`${ROLE_TAG[min]} access is required for this section`} />;
  if (ok === null) return <LoaderRows lines={["Checking your access"]} />;
  return <>{children}</>;
}

export function Modal({
  title,
  onClose,
  children,
  footer,
  wide,
  xwide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  xwide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const prev = document.activeElement as HTMLElement | null;
    const focusables = () =>
      Array.from(
        el.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'),
      ).filter((f) => !f.hasAttribute("disabled"));
    focusables()[0]?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key === "Tab") {
        const f = focusables();
        if (!f.length) return;
        const first = f[0];
        const last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        } else if (!el.contains(document.activeElement)) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      prev?.focus?.();
    };
  }, [onClose]);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div ref={ref} className={`modal${wide ? " wide" : ""}${xwide ? " xwide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <header className="modal-hd">
          <span>{title}</span>
          <button type="button" className="x" onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>
        <div className="modal-bd">{children}</div>
        {footer ? <footer className="modal-ft">{footer}</footer> : null}
      </div>
    </div>
  );
}

export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint ? <span className="page-note">{hint}</span> : null}
    </div>
  );
}

export function useTick(ms = 1000): void {
  const [, set] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => set((n) => n + 1), ms);
    return () => window.clearInterval(t);
  }, [ms]);
}

export function useMounted(): boolean {
  const [m, set] = useState(false);
  useEffect(() => set(true), []);
  return m;
}
