"use client";

/* Intelligence command center. Every number here is read from a live endpoint:
   core health, module checks, Suricata alerts (REST history + WebSocket stream),
   host telemetry and the authorization ledger. Nothing is simulated. */

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { get } from "@/lib/api";
import { getSession } from "@/lib/auth";
import { hasRole } from "@/lib/rbac";
import { bytes, clock, fmtTs, humanAction, humanStatus, sevTone, trunc } from "@/lib/format";
import { useMounted, useTick } from "@/components/ui";
import { useWsHub, type LiveAlert } from "@/components/chrome";
import { DonutStat, MiniLine, RankList, SEV_COLORS, Trend } from "@/components/charts";
import { Chip, EmptyRows, ErrBanner, LoaderRows, Meter, Panel, Skel, StatCard } from "@/components/ui";
import type { Alert, Health, LedgerList, ModulesHealth } from "@/lib/types";

interface Telemetry {
  ts_ms: number;
  host: { hostname: string; os: string; machine: string; boot_ts: number };
  cpu: { percent: number; cores: number; per_core: number[]; load: [number, number, number] };
  mem: { percent: number; used: number; total: number };
  disk: { percent: number; used: number; total: number };
  net: { rates: Record<string, number>; totals: Record<string, number> };
  procs: { count: number; top_rss: { pid: number; name: string; rss: number }[] };
  interfaces: Record<string, string[]>;
  history: { ts_ms: number; cpu: number; mem: number }[];
}

const BUCKETS = 24;

const SEV_VAR: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
  INFO: "var(--sev-info)",
};

function pctTone(v: number): "ok" | "warn" | "fail" {
  return v >= 85 ? "fail" : v >= 65 ? "warn" : "ok";
}

function ago(iso: string): string {
  const t = ts(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function ts(iso: string): number {
  return new Date(iso.endsWith("Z") || iso.includes("+") ? iso : `${iso}Z`).getTime();
}

export default function DashboardPage() {
  useTick(1000);
  const mounted = useMounted();
  const session = mounted ? getSession() : null;
  const isSuper = hasRole(session?.role, "SUPER_ADMIN");
  const canSeeLedger = hasRole(session?.role, "ANALYST");
  const { liveAlerts, alerts: wsState } = useWsHub();

  const health = useQuery({ queryKey: ["health"], queryFn: () => get<Health>("/health"), staleTime: 30000 });
  const tele = useQuery({ queryKey: ["telemetry"], queryFn: () => get<Telemetry>("/system/telemetry"), refetchInterval: 2000 });
  const modules = useQuery({ queryKey: ["modules"], queryFn: () => get<ModulesHealth>("/modules/health") });
  const alertQ = useQuery({ queryKey: ["alerts"], queryFn: () => get<{ alerts: Alert[] }>(`/soc/alerts${qsLimit()}`) });
  const ledger = useQuery({
    queryKey: ["ledger", "available"],
    queryFn: () => get<LedgerList>("/admin/ledger/available"),
    enabled: canSeeLedger,
  });

  const activeWarrants = (ledger.data?.warrants ?? [])
    .filter((w) => !w.revoked_at && new Date(w.valid_until) > new Date())
    .sort((a, b) => new Date(a.valid_until).getTime() - new Date(b.valid_until).getTime());
  const rows = alertQ.data?.alerts ?? [];
  const sevMix = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const)
    .map((s) => ({ name: humanStatus(s), value: rows.filter((a) => a.severity === s).length, color: SEV_COLORS[s] }))
    .filter((d) => d.value > 0);
  const critCount = rows.filter((a) => a.severity === "CRITICAL" || a.severity === "HIGH").length;
  const unacked = rows.filter((a) => a.status !== "acked").length;
  const recent = rows.filter((a) => Date.now() - ts(a.ts) < 3600000).length;
  const density = bucketAlerts(rows);
  const densityData = density.map((v, i) => ({ t: i === BUCKETS - 1 ? "now" : `-${(BUCKETS - 1 - i) * 5}m`, v }));

  const core = health.data;
  const modList = modules.data?.modules ?? [];
  const okModules = modList.filter((m) => m.status === "OK").length;
  const failModules = modList.filter((m) => m.status === "FAIL").length;
  const total = modList.length;
  const t = tele.data;
  const cpuHist = (t?.history ?? []).map((h) => ({ t: clock(new Date(h.ts_ms)), v: Math.round(h.cpu) }));

  const liveCrit = rows.filter((a) => (a.severity === "CRITICAL" || a.severity === "HIGH") && Date.now() - ts(a.ts) < 3600000).length;
  const posture = failModules || liveCrit || !core?.asgi_ready
    ? { label: "THREAT ACTIVE", sev: "var(--sev-critical)" }
    : unacked || activeWarrants.some((w) => new Date(w.valid_until).getTime() - Date.now() < 3 * 86400000)
      ? { label: "GUARDED", sev: "var(--sev-medium)" }
      : { label: "NOMINAL", sev: "var(--ok)" };

  const lastHr = recent;

  // WebSocket deliveries first (newest), then REST history excluding duplicates.
  const rest = rows.filter((a) => !liveAlerts.some((l) => l.id === a.id));
  const feed: (LiveAlert | Alert)[] = [...liveAlerts, ...rest].slice(0, 12);

  return (
    <>
      <div className="posture" style={{ "--sev": posture.sev } as React.CSSProperties}>
        <span className="posture-verdict">{posture.label}</span>
        <span className="posture-detail">
          {!core?.asgi_ready
            ? "Core is still starting — readings below may be incomplete."
            : failModules
              ? `${failModules} service${failModules === 1 ? "" : "s"} reporting failure.`
              : "All services responding · detections come from live Suricata traffic."}
        </span>
        <span className="posture-spacer" />
        <dl className="posture-stats">
          <div><dt>Detections</dt><dd>{alertQ.isPending ? <Skel w={30} /> : rows.length}</dd></div>
          <div><dt>High/Crit</dt><dd className={liveCrit ? "crit" : ""}>{critCount}</dd></div>
          <div><dt>Open</dt><dd>{unacked}</dd></div>
          <div><dt>Services</dt><dd className={total && okModules === total ? "ok" : ""}>{total ? `${okModules}/${total}` : "—"}</dd></div>
          <div><dt>Warrants</dt><dd>{canSeeLedger ? activeWarrants.length : "—"}</dd></div>
        </dl>
      </div>

      <div className="span-12">
        <div className="stat-grid">
          <StatCard
            label="Core version"
            value={core ? core.core : <Skel w={44} />}
            foot={core ? <>Environment {core.env} · policy {trunc(core.policy_hash, 8)} · {core.asgi_ready ? "ready" : "starting"}</> : "Loading…"}
          />
          <StatCard
            label="Detections · last hour"
            tone={lastHr ? "warn" : "ok"}
            value={alertQ.isPending ? <Skel w={38} /> : String(lastHr)}
            foot={`${rows.length} retained · ${wsState === "live" ? "streaming live" : "stream offline"}`}
          />
          <StatCard
            label="Open investigations"
            tone={unacked ? "fail" : "ok"}
            value={alertQ.isPending ? <Skel w={38} /> : String(unacked)}
            foot={`${lastHr} detected in the last hour · ${rows.filter((a) => a.status === "acked").length} acknowledged`}
          />
          <StatCard
            label="Modules online"
            tone={total && okModules === total ? "ok" : "warn"}
            value={modules.isPending ? <Skel w={44} /> : total ? `${okModules}/${total}` : "—"}
            foot="Service health checks"
          />
          <StatCard
            label="CPU usage"
            tone={t ? pctTone(t.cpu.percent) : ""}
            value={t ? t.cpu.percent.toFixed(0) : <Skel w={38} />}
            unit={t ? "%" : undefined}
            spark={<MiniLine data={cpuHist.map((d) => d.v)} height={30} />}
            foot={t ? `${t.cpu.cores} cores · load ${t.cpu.load.map((l) => l.toFixed(1)).join(" ")}` : "—"}
          />
          <StatCard
            label="Memory"
            tone={t ? pctTone(t.mem.percent) : ""}
            value={t ? t.mem.percent.toFixed(0) : <Skel w={38} />}
            unit={t ? "%" : undefined}
            foot={t ? `${bytes(t.mem.used)} of ${bytes(t.mem.total)} in use · disk ${t.disk.percent.toFixed(0)}%` : "—"}
          />
        </div>
      </div>

      <div className="span-4 fill">
        <Panel
          title="Detection stream"
          actions={<span className={`sb-dot ${wsState === "live" ? "live" : "down"}`} aria-hidden title={`WebSocket: ${wsState}`} />}
        >
          {!feed.length ? (
            <div className="feed-empty">
              {alertQ.isPending ? "Loading…" : "No detections recorded yet. New Suricata alerts appear here the moment they fire."}
            </div>
          ) : (
            <div className="feed" aria-live="polite">
              {feed.map((a, i) => (
                <div
                  key={`${a.id}-${i}`}
                  className={`feed-row${liveAlerts.some((l) => l.id === a.id) ? " feed-new" : ""}`}
                  style={{ "--sev": SEV_VAR[a.severity] ?? "var(--line)" } as React.CSSProperties}
                >
                  <span className="feed-time">{clock(new Date(a.ts.endsWith("Z") || a.ts.includes("+") ? a.ts : `${a.ts}Z`))}</span>
                  <span style={{ minWidth: 0 }}>
                    <span className="feed-sig" title={a.signature}>{a.signature || "unsigned alert"}</span>
                    <span className="feed-meta">
                      <Chip tone={sevTone(a.severity)} label={humanStatus(a.severity)} />
                      {a.src_ip ?? "unknown"} → {a.dest_ip ?? "unknown"}
                      {a.mitre ? <Link href={`/soc/mitre/${a.mitre}`} className="chip dim" title="Open technique war-room">{a.mitre}</Link> : null}
                      {ago(a.ts) ? <span>{ago(a.ts)}</span> : null}
                    </span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="span-4 fill">
        <Panel title="Alert severity">
          {alertQ.isPending ? (
            <LoaderRows lines={["Loading alerts"]} />
          ) : alertQ.error ? (
            <ErrBanner error={alertQ.error} onRetry={() => alertQ.refetch()} />
          ) : (
            <DonutStat data={sevMix} centerLabel="alerts" />
          )}
        </Panel>
      </div>

      <div className="span-4 fill">
        <Panel title="Authorizations">
          {!isSuper ? (
            <div className="lockline">
              The authorization ledger is visible to administrators. Ask an administrator if you need an
              authorization for security testing.
            </div>
          ) : ledger.isPending ? (
            <LoaderRows lines={["Loading authorizations"]} />
          ) : ledger.error ? (
            <ErrBanner error={ledger.error} onRetry={() => ledger.refetch()} />
          ) : activeWarrants.length === 0 ? (
            <EmptyRows what="No active authorizations. Security testing stays unavailable until one is issued." />
          ) : (
            <>
              <RankList
                items={activeWarrants.slice(0, 6).map((w) => {
                  const days = Math.max(0, Math.round((new Date(w.valid_until).getTime() - Date.now()) / 86400000));
                  return {
                    label: `${humanAction(w.kind)} · ${trunc(w.subject_name || w.warrant_ref, 18)}`,
                    value: days,
                    color: days <= 3 ? "#f85149" : days <= 7 ? "#d29922" : "#3fb950",
                  };
                })}
              />
              <div className="page-note" style={{ marginTop: 10 }}>
                Days until each authorization lapses. Next expiry {fmtTs(activeWarrants[0].valid_until)}.
              </div>
            </>
          )}
        </Panel>
      </div>

      <div className="span-6 fill">
        <Panel title="Alerts over time">
          {density.every((v) => !v) ? (
            <EmptyRows what={`No detections in the last ${BUCKETS * 5} minutes`} />
          ) : (
            <Trend data={densityData} color="#4c8dff" yKey="v" unit=" alerts" />
          )}
          <div className="page-note" style={{ marginTop: 8 }}>
            Suricata detections grouped by 5-minute buckets · updates as new alerts arrive
          </div>
        </Panel>
      </div>

      <div className="span-6 fill">
        <Panel title="CPU history">
          <Trend data={cpuHist} color="#4c8dff" unit="%" />
          <div className="page-note" style={{ marginTop: 8 }}>
            Live system readings from {t?.host.hostname ?? "this host"}
          </div>
        </Panel>
      </div>

      <div className="span-12">
        <Panel
          title="Module status"
          actions={<span className="cell-id mono-dim">{total ? `${okModules} OK · ${modList.length - okModules} attention` : "Checking services"}</span>}
        >
          {modules.isPending ? (
            <LoaderRows lines={["Checking services"]} />
          ) : modules.error ? (
            <div style={{ padding: 12 }}>
              <ErrBanner error={modules.error} onRetry={() => modules.refetch()} />
            </div>
          ) : (
            <div className="matrix">
              {modList.map((m) => (
                <div className="mx-cell" key={m.module} title={`${m.display} · ${m.detail || m.status}`}>
                  <span className="mx-top">
                    <span className={`mx-dot ${m.status}`} aria-hidden />
                    <span className="mx-name">{m.display}</span>
                  </span>
                  <span className="mx-detail">{m.detail || "—"}</span>
                  <span className="mx-id">{m.module}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {tele.isPending ? (
        <div className="span-12">
          <Panel title="System telemetry" tight>
            <LoaderRows lines={["Loading system readings"]} />
          </Panel>
        </div>
      ) : tele.error ? (
        <div className="span-12">
          <Panel title="System telemetry" tight>
            <div style={{ padding: 12 }}>
              <ErrBanner error={tele.error} onRetry={() => tele.refetch()} />
            </div>
          </Panel>
        </div>
      ) : (
        <div className="span-12">
          <Panel
            title="System telemetry"
            actions={<span className="cell-id mono-dim">Updated {clock()} · {tele.data!.host.hostname}</span>}
          >
            <div className="sensor-grid">
              <div className="sensor-cell">
                <div className="sensor-cap">CPU {tele.data!.cpu.percent.toFixed(0)}% · {tele.data!.cpu.cores} cores · load {tele.data!.cpu.load.join(" / ")}</div>
                <Meter v={tele.data!.cpu.percent} max={100} tone={pctTone(tele.data!.cpu.percent)} />
                <div className="sensor-cores">
                  {tele.data!.cpu.per_core.map((c, i) => (
                    <span
                      key={i}
                      className="sensor-core"
                      title={`Core ${i} · ${c.toFixed(0)}% busy`}
                      style={{ height: `${Math.max(6, Math.min(100, c))}%`, background: c >= 85 ? "var(--fail)" : c >= 65 ? "var(--warn)" : undefined }}
                    />
                  ))}
                </div>
              </div>
              <div className="sensor-cell">
                <div className="sensor-cap">MEM {tele.data!.mem.percent.toFixed(0)}% · {bytes(tele.data!.mem.used)} / {bytes(tele.data!.mem.total)}</div>
                <Meter v={tele.data!.mem.percent} max={100} tone={pctTone(tele.data!.mem.percent)} />
                <div className="sensor-cap">DISK {tele.data!.disk.percent.toFixed(0)}% · {bytes(tele.data!.disk.used)} used</div>
                <Meter v={tele.data!.disk.percent} max={100} tone={pctTone(tele.data!.disk.percent)} />
              </div>
              <div className="sensor-cell">
                <div className="sensor-cap">NET ▼ {bytes(tele.data!.net.rates.bytes_recv)}/s · ▲ {bytes(tele.data!.net.rates.bytes_sent)}/s</div>
                <Meter v={tele.data!.net.rates.bytes_recv ?? 0} max={131072} tone="ok" />
                <div className="sensor-flows cell-id">
                  {Object.entries(tele.data!.interfaces).slice(0, 4).map(([nic, ips]) => (
                    <div key={nic}>{nic} · {ips[0]}</div>
                  ))}
                </div>
              </div>
              <div className="sensor-cell">
                <div className="sensor-cap">TOP RSS · {tele.data!.procs.count} procs</div>
                <div className="sensor-procs">
                  {tele.data!.procs.top_rss.slice(0, 6).map((p) => (
                    <span key={p.pid} className="sensor-proc" title={`pid ${p.pid}`}>
                      {trunc(p.name, 14)} <b>{bytes(p.rss)}</b>
                    </span>
                  ))}
                </div>
              </div>
            </div>
            <div className="page-note" style={{ marginTop: 8 }}>
              Live readings from {tele.data!.host.os} ({tele.data!.host.machine}) · sampled every 2 seconds
            </div>
          </Panel>
        </div>
      )}

      <div className="span-12">
        <Panel
          title="Recent alerts"
          tight
          actions={<Link href="/soc" className="btn small">SOC Center</Link>}
        >
          {alertQ.isPending ? (
            <LoaderRows lines={["Loading alerts"]} />
          ) : alertQ.error ? (
            <div style={{ padding: 12 }}>
              <ErrBanner error={alertQ.error} onRetry={() => alertQ.refetch()} />
            </div>
          ) : !rows.length ? (
            <EmptyRows what="No alerts recorded yet" />
          ) : (
            <table className="dtable">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Signature</th>
                  <th>Source → Destination</th>
                  <th>MITRE</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 10).map((a) => (
                  <tr key={a.id} className="sev-strip" style={{ "--sev": SEV_VAR[a.severity] ?? "var(--line)" } as React.CSSProperties}>
                    <td className="cell-id">{fmtTs(a.ts)}</td>
                    <td>
                      <Chip tone={sevTone(a.severity)} label={humanStatus(a.severity)} />
                    </td>
                    <td>{trunc(a.signature, 52)}</td>
                    <td className="cell-id">
                      {a.src_ip ?? "unknown"} → {a.dest_ip ?? "unknown"}
                    </td>
                    <td className="cell-id">{a.mitre ?? "—"}</td>
                    <td>{a.status === "acked" ? <Chip tone="ok" label="Acknowledged" /> : <Chip tone="dim" label="New" />}</td>
                    <td>
                      <Link href="/soc" className="btn small">Open</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </>
  );
}

function qsLimit() {
  const p = new URLSearchParams({ limit: "100" });
  return `?${p.toString()}`;
}

function bucketAlerts(alerts: Alert[]): number[] {
  if (!alerts.length) return new Array(BUCKETS).fill(0);
  const now = Date.now();
  const out = new Array(BUCKETS).fill(0);
  for (const a of alerts) {
    const ts = new Date(a.ts.endsWith("Z") || a.ts.includes("+") ? a.ts : `${a.ts}Z`).getTime();
    const idx = BUCKETS - 1 - Math.floor((now - ts) / (5 * 60 * 1000));
    if (idx >= 0 && idx < BUCKETS) out[idx] += 1;
  }
  return out;
}
