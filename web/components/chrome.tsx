"use client";

import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { get, maybeRefresh } from "@/lib/api";
import { clearSession, getRole, getSession, getToken, logout } from "@/lib/auth";
import { findPage, hasRole, ROLE_TAG, visibleGroups } from "@/lib/rbac";
import { useCwbSocket, type WsStatus } from "@/lib/ws";
import { fmtTs, humanAction, trunc } from "@/lib/format";
import { useToast } from "./toast";
import { Meter } from "./ui";
import { StatusActivity } from "./ticker";
import { CommandPalette } from "./palette";
import { ThemeToggle } from "./theme";
import { Icon } from "./icons";
import { useMounted } from "./ui";
import type { Health, LedgerList, WsEnvelope } from "@/lib/types";

/* ---------------------------------- WS hub ---------------------------------- */

export interface JobView {
  job_id: string;
  kind: string;
  progress: number;
  message: string;
  status: string;
}

export interface StreamEvent {
  ts_ms: number;
  actor: string;
  action: string;
  object_ref?: string;
}

export interface LiveAlert {
  id: string;
  ts: string;
  severity: string;
  signature: string;
  src_ip: string;
  dest_ip: string;
  mitre: string;
}

interface WsHub {
  alerts: WsStatus;
  jobs: WsStatus;
  jobList: JobView[];
  events: StreamEvent[];
  liveAlerts: LiveAlert[];
  alertCount: number;
  clearAlerts: () => void;
}

const WsCtx = createContext<WsHub>({ alerts: "down", jobs: "down", jobList: [], events: [], liveAlerts: [], alertCount: 0, clearAlerts: () => {} });
export const useWsHub = () => useContext(WsCtx);

const sevTone = (sev?: unknown) => (sev === "CRITICAL" || sev === "HIGH" ? "fail" : sev === "MEDIUM" ? "warn" : "info");

export function WsProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [jobMap, setJobMap] = useState<Record<string, JobView>>({});
  const [streamEvents, setStreamEvents] = useState<StreamEvent[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<LiveAlert[]>([]);
  const [alertCount, setAlertCount] = useState(0);

  const alertsStatus = useCwbSocket("alerts", (env: WsEnvelope) => {
    const p = (env.payload ?? {}) as Record<string, unknown>;
    switch (env.type) {
      case "audit.event": {
        const ev = p as unknown as StreamEvent;
        if (ev && ev.action) setStreamEvents((prev) => [...prev.slice(-19), ev]);
        break;
      }
      case "alert.new": {
        const a = p as { id?: string; signature?: string; severity?: string; src_ip?: string; dest_ip?: string; mitre?: string; ts?: string };
        qc.invalidateQueries({ queryKey: ["alerts"] });
        setAlertCount((n) => n + 1);
        setLiveAlerts((prev) => [
          {
            id: String(a.id ?? `live-${Date.now()}`),
            ts: a.ts ?? new Date().toISOString(),
            severity: a.severity ?? "INFO",
            signature: a.signature ?? "",
            src_ip: a.src_ip ?? "unknown",
            dest_ip: a.dest_ip ?? "unknown",
            mitre: a.mitre ?? "",
          },
          ...prev.slice(-19),
        ]);
        toast.push({ tone: sevTone(a.severity), title: `Alert ${a.severity ?? ""}`, text: `${a.signature ?? ""} · source ${a.src_ip ?? "unknown"}` });
        break;
      }
      case "pentest.complete":
        qc.invalidateQueries({ queryKey: ["pentest"] });
        toast.push({ tone: "ok", title: "Pentest session finished", text: `${p.findings ?? 0} findings · ${p.session}` });
        break;
      case "vuln.critical":
        qc.invalidateQueries({ queryKey: ["vuln"] });
        toast.push({ tone: "fail", title: "Scanner found critical issues", text: `scan ${p.scan} · ${p.count}` });
        break;
      case "ip.blocked":
        qc.invalidateQueries({ queryKey: ["blocks"] });
        toast.push({ tone: "ok", title: "Address blocked", text: String(p.ip ?? "") });
        break;
      case "hw.anomaly":
        qc.invalidateQueries({ queryKey: ["hardware"] });
        toast.push({ tone: "warn", title: "Hardware anomaly", text: `${p.asset} · ${(p.anomalies as string[] | undefined)?.join(" ") ?? ""}` });
        break;
      default:
        break;
    }
  });

  const jobsStatus = useCwbSocket("jobs", (env: WsEnvelope) => {
    const p = (env.payload ?? {}) as Record<string, unknown>;
    const jid = String(p.job_id ?? "");
    if (!jid) return;
    setJobMap((prev) => {
      const cur: JobView = prev[jid] ?? { job_id: jid, kind: String(p.kind ?? env.type), progress: 0, message: "", status: "running" };
      const next: JobView = {
        ...cur,
        kind: String(p.kind ?? cur.kind),
        progress: typeof p.progress === "number" ? p.progress : cur.progress,
        message: String(p.message ?? cur.message ?? ""),
        status: env.type === "job.finish" ? String(p.status ?? "done") : "running",
      };
      if (env.type === "job.finish") {
        qc.invalidateQueries({ queryKey: ["pentest"] });
        qc.invalidateQueries({ queryKey: ["vuln"] });
        qc.invalidateQueries({ queryKey: ["assessment"] });
        qc.invalidateQueries({ queryKey: ["document"] });
        toast.push({
          tone: next.status === "done" ? "ok" : "fail",
          title: `${humanAction(next.kind)} ${next.status === "done" ? "finished" : "did not finish"}`,
          text: next.message || jid,
        });
        return { ...prev, [jid]: next };
      }
      return { ...prev, [jid]: next };
    });
  });

  const jobList = useMemo(() => Object.values(jobMap).slice(-4), [jobMap]);
  const clearAlerts = () => setAlertCount(0);
  return <WsCtx.Provider value={{ alerts: alertsStatus, jobs: jobsStatus, jobList, events: streamEvents, liveAlerts, alertCount, clearAlerts }}>{children}</WsCtx.Provider>;
}

/* ------------------------------- navigation -------------------------------- */

const NAV_ALL_KEY = "cwb-nav-all";

function readFlag(key: string): boolean {
  try {
    return window.localStorage.getItem(key) === "1";
  } catch {
    return false;
  }
}

function writeFlag(key: string, on: boolean) {
  try {
    window.localStorage.setItem(key, on ? "1" : "0");
  } catch {
    /* private mode — the preference simply won't persist */
  }
}

function fmtUptime(): string {
  const s = getSession();
  if (!s) return "—";
  const t = Math.floor((Date.now() - s.since) / 1000);
  return `${String(Math.floor(t / 3600)).padStart(2, "0")}:${String(Math.floor((t % 3600) / 60)).padStart(2, "0")}:${String(t % 60).padStart(2, "0")}`;
}

/** The rail holds one entry per group; the context column lists that group's pages.
    The active marker is one physical pill that slides between entries — the eye
    should feel the interface move, not repaint. */
function Rail({
  groups,
  activeKey,
  onSelect,
}: {
  groups: ReturnType<typeof visibleGroups>;
  activeKey: string;
  onSelect: (key: string) => void;
}) {
  const { alertCount, alerts, jobs, clearAlerts } = useWsHub();
  const live = alerts === "live" && jobs === "live";
  const activeIndex = Math.max(0, groups.findIndex((g) => g.key === activeKey));
  return (
    <nav className="rail" aria-label="sections">
      <Link href="/dashboard" className="rail-mark" aria-label="CyberWatch-BD">
        <span className="rail-mark-core" aria-hidden>CW</span>
      </Link>
      <div className="rail-items">
        <span className="rail-pill" style={{ transform: `translateY(${activeIndex * 36}px)` }} aria-hidden />
        {groups.map((g, i) => (
          <button
            key={g.key}
            type="button"
            className={`rail-btn${g.key === activeKey ? " on" : ""}`}
            title={g.label}
            aria-label={g.label}
            aria-current={g.key === activeKey ? "true" : undefined}
            onClick={() => { if (g.key === "overview") clearAlerts(); onSelect(g.key); }}
            style={{ zIndex: i + 1 }}
          >
            <span className="rail-ico" aria-hidden><Icon name={g.icon} size={18} /></span>
            {g.key === "overview" && alertCount > 0 ? (
              <span className="rail-badge" aria-hidden>{alertCount > 99 ? "99+" : alertCount}</span>
            ) : null}
          </button>
        ))}
      </div>
      <span className="rail-spacer" />
      <span className={`rail-live ${live ? "on" : ""}`} title={live ? "Live telemetry connected" : "Telemetry offline"} aria-hidden />
      <span className="rail-div" />
      <ThemeToggle className="icon-btn" iconOnly />
    </nav>
  );
}

function Context({
  groups,
  activeKey,
  filter,
  onFilter,
  onNavigate,
}: {
  groups: ReturnType<typeof visibleGroups>;
  activeKey: string;
  filter: string;
  onFilter: (v: string) => void;
  onNavigate: () => void;
}) {
  const pathname = usePathname();
  const mounted = useMounted();
  const { data: health } = useQuery({ queryKey: ["health"], queryFn: () => get<Health>("/health"), staleTime: 30000 });
  const [expandAll, setExpandAll] = useState(false);
  useEffect(() => setExpandAll(readFlag(NAV_ALL_KEY)), []);
  const toggleAll = () => {
    const next = !expandAll;
    setExpandAll(next);
    writeFlag(NAV_ALL_KEY, next);
  };

  const q = filter.trim().toLowerCase();
  const visible = (groups: ReturnType<typeof visibleGroups>) =>
    groups
      .map((g) => ({ ...g, items: g.items.filter((i) => !q || i.label.toLowerCase().includes(q)) }))
      .filter((g) => g.items.length);
  const shownGroups = visible(q ? groups : expandAll ? groups : groups.filter((g) => g.key === activeKey));
  const hitCount = shownGroups.reduce((n, g) => n + g.items.length, 0);
  const active = groups.find((g) => g.key === activeKey);

  return (
    <aside className="context" aria-label={active ? `${active.label} pages` : "pages"}>
      <div className="context-hd">
        {q ? (
          <div className="context-title">
            {hitCount} {hitCount === 1 ? "page" : "pages"} match “{filter}”
          </div>
        ) : (
          <>
            <div className="context-title">{active?.label}</div>
            <div className="context-underline" aria-hidden />
            <div className="context-hint">{active?.hint}</div>
          </>
        )}
      </div>

      <div className="context-search">
        <span className="cs-ico" aria-hidden><Icon name="search" size={13} /></span>
        <input
          className="text"
          value={filter}
          onChange={(e) => onFilter(e.target.value)}
          placeholder="Filter pages"
          aria-label="Filter pages"
        />
      </div>

      <div className="ctx-list" key={`${activeKey}-${expandAll}`}>
        {!q && groups.length > 1 ? (
          <button type="button" className="ctx-item ctx-toggle" onClick={toggleAll}>
            <span className="nav-ico" aria-hidden><Icon name="chevron" size={14} /></span>
            <span className="nav-label">{expandAll ? "Collapse to this section" : "Expand all sections"}</span>
          </button>
        ) : null}

        {shownGroups.map((g) => (
          <div key={g.key}>
            {q || expandAll ? <div className="ctx-head">{g.label}</div> : null}
            {g.items.map((i, n) => (
              <Link
                key={i.href}
                href={i.href}
                className={`ctx-item${pathname === i.href ? " on" : ""}`}
                aria-current={pathname === i.href ? "page" : undefined}
                onClick={onNavigate}
                title={i.desc}
                style={{ animationDelay: `${Math.min(n * 22, 240)}ms` }}
              >
                <span className="nav-ico" aria-hidden><Icon name={i.icon} size={17} /></span>
                <span className="nav-label">{i.label}</span>
                {i.min === "SUPER_ADMIN" ? <span className="nav-meta">admin</span> : null}
              </Link>
            ))}
          </div>
        ))}
        {!hitCount ? <div className="context-empty">Nothing matches that filter.</div> : null}
      </div>

      <div className="context-foot">
        <div className="cf-row"><span>core</span><b>{health?.core ?? "…"}</b></div>
        <div className="cf-row"><span>policy</span><b>{health?.policy_hash ? trunc(health.policy_hash, 12) : "—"}</b></div>
        <div className="cf-row"><span>session</span><b>{mounted ? fmtUptime() : "—"}</b></div>
        <div className="cf-row cf-env"><span>mode</span><b>{health?.env ?? "…"}</b></div>
      </div>
    </aside>
  );
}

/* --------------------------------- topbar ---------------------------------- */

function Authorizations() {
  const mounted = useMounted();
  const role = mounted ? getRole() : null;
  const isSuper = role === "SUPER_ADMIN";
  const { data } = useQuery({
    queryKey: ["ledger"],
    queryFn: () => get<LedgerList>("/admin/ledger"),
    enabled: isSuper,
    staleTime: 15000,
    refetchInterval: 60000,
  });
  const active = (data?.warrants ?? []).filter((w) => !w.revoked_at && new Date(w.valid_until) > new Date());
  const full = active.length
    ? active.map((w) => `${humanAction(w.kind)} · ${w.warrant_ref} · expires ${fmtTs(w.valid_until)}`).join("   |   ")
    : "No active authorizations";
  return (
    <span className="topbar-warrant" title={full} aria-label={`${active.length} active authorizations`}>
      {isSuper ? (
        active.length ? (
          <><b>{active.length}</b> active authorization{active.length === 1 ? "" : "s"}</>
        ) : (
          <>No active authorizations</>
        )
      ) : (
        <>Authorizations managed by administrators</>
      )}
    </span>
  );
}

function AccountMenu() {
  const router = useRouter();
  const mounted = useMounted();
  const session = mounted ? getSession() : null;
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!box.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (!session) return null;
  return (
    <div className="user-menu" ref={box}>
      <button
        type="button"
        className="user-chip"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="avatar" aria-hidden>{session.username.slice(0, 1).toUpperCase()}</span>
        <span className="role">{session.username}</span>
        <span>· {ROLE_TAG[session.role]}</span>
      </button>
      {open ? (
        <div className="user-pop" role="menu">
          <div className="who">
            <b>{session.username}</b>
            <span>{ROLE_TAG[session.role]}</span>
          </div>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              router.push("/settings");
            }}
          >
            <Icon name="settings" size={15} /> Account settings
          </button>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              router.push("/reports");
            }}
          >
            <Icon name="report" size={15} /> Reports
          </button>
          <button
            type="button"
            role="menuitem"
            onClick={async () => {
              setOpen(false);
              await logout().catch(() => undefined);
              clearSession();
              router.replace("/login");
            }}
          >
            <Icon name="logout" size={15} /> Sign out
          </button>
        </div>
      ) : null}
    </div>
  );
}

function Topbar({
  onOpenPalette,
  onToggleCtx,
}: {
  onOpenPalette: () => void;
  onToggleCtx: () => void;
}) {
  const { alerts, jobs, jobList } = useWsHub();
  const pathname = usePathname();
  const mounted = useMounted();
  const groups = visibleGroups(mounted ? getRole() : null);
  const { group, item } = findPage(groups, pathname);
  const ws = alerts === "live" && jobs === "live" ? "live" : alerts === "connecting" || jobs === "connecting" ? "connecting" : "down";
  const job = jobList[jobList.length - 1];

  return (
    <header className="topbar">
      <button type="button" className="icon-btn ctx-toggle" onClick={onToggleCtx} aria-label="Show or hide the page list">
        <Icon name="menu" size={17} />
      </button>
      <nav className="crumbs" aria-label="breadcrumb">
        <span>{group?.label ?? "Console"}</span>
        <span className="sep" aria-hidden>/</span>
        <span className="here" aria-current="page">{item?.label ?? "Overview"}</span>
      </nav>
      <button type="button" className="search-trigger" onClick={onOpenPalette} aria-label="Go to a page">
        <Icon name="search" size={14} />
        <span className="st-label">Go to a page…</span>
        <kbd aria-hidden>⌘K</kbd>
      </button>
      <span className="topbar-spacer" />
      {job ? (
        <span className="topbar-job" title={`${humanAction(job.kind)} ${Math.round(job.progress * 100)}% — ${job.message}`}>
          <Meter v={job.progress} max={1} />
          {humanAction(job.kind)} {Math.round(job.progress * 100)}%
        </span>
      ) : null}
      <Authorizations />
      <span
        className="ws-pill"
        title={`Alert stream: ${alerts}. Job stream: ${jobs}.`}
      >
        <span className={`ws-dot ${ws}`} aria-hidden />
        {ws === "live" ? "Connected" : ws === "connecting" ? "Connecting" : "Offline"}
      </span>
      <AccountMenu />
    </header>
  );
}

/* -------------------------------- page head -------------------------------- */

function PageHeader({ groups }: { groups: ReturnType<typeof visibleGroups> }) {
  const pathname = usePathname();
  const { item } = findPage(groups, pathname);
  if (!item) return null;
  return (
    <div className="page-hd">
      <div>
        <h1>{item.label}</h1>
        <p className="desc">{item.desc}</p>
      </div>
    </div>
  );
}

/* ---------------------------------- shell ----------------------------------- */

export function Chrome({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const mounted = useMounted();
  const groups = visibleGroups(mounted ? getRole() : null);
  const { group } = findPage(groups, pathname);
  const [activeKey, setActiveKey] = useState(group?.key ?? groups[0]?.key ?? "");
  const [filter, setFilter] = useState("");
  const [ctxOpen, setCtxOpen] = useState(false);
  const [palette, setPalette] = useState(false);

  useEffect(() => {
    if (!getToken()) window.location.replace("/boot");
    else void maybeRefresh(); // quiet top-up: a 15-min token should never interrupt work
  }, []);

  useEffect(() => {
    if (group?.key) {
      setActiveKey(group.key);
      setCtxOpen(false);
      setFilter("");
    }
  }, [group?.key]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const selectGroup = (key: string) => {
    setActiveKey(key);
    setCtxOpen(false);
    const first = groups.find((g) => g.key === key)?.items[0];
    if (first && first.href !== pathname) router.push(first.href);
  };

  return (
    <div className={`shell${ctxOpen ? " ctx-open" : ""}`}>
      <Rail groups={groups} activeKey={activeKey} onSelect={selectGroup} />
      <Context
        groups={groups}
        activeKey={activeKey}
        filter={filter}
        onFilter={setFilter}
        onNavigate={() => setCtxOpen(false)}
      />
      <div className="ctx-scrim" aria-hidden onClick={() => setCtxOpen(false)} />
      <div className="main-col">
        <Topbar onOpenPalette={() => setPalette(true)} onToggleCtx={() => setCtxOpen((v) => !v)} />
        <main id="main" className="main">
          <PageHeader groups={groups} />
          {children}
        </main>
        <StatusActivity />
      </div>
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
    </div>
  );
}
