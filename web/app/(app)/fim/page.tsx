"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "@/lib/api";
import { fmtTs, trunc } from "@/lib/format";
import { useToast } from "@/components/toast";
import { Chip, EmptyRows, ErrBanner, Field, LoaderRows, Panel } from "@/components/ui";

const EV_TONE: Record<string, string> = {
  delete: "fail", permission_change: "fail", ownership_change: "fail",
  modify: "warn", hash_change: "warn", create: "info", rename: "info",
};

export default function FimPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const [showForm, setShowForm] = useState(false);
  const [path, setPath] = useState("");
  const [name, setName] = useState("");
  const [interval, setInterval] = useState("300");
  const [depth, setDepth] = useState("4");
  const [expanded, setExpanded] = useState<string | null>(null);

  const status = useQuery({
    queryKey: ["fim", "status"],
    queryFn: () => get<{ policies: FimPolicy[]; events_24h: number; engine: string; note: string }>("/fim/status"),
    refetchInterval: 15000,
  });
  const events = useQuery({
    queryKey: ["fim", "events"],
    queryFn: () => get<{ events: FimEvent[] }>("/fim/events?limit=80"),
    refetchInterval: 15000,
  });
  const rules = useQuery({
    queryKey: ["soc", "rules"],
    queryFn: () => get<{ rules: DetRule[] }>("/soc/rules?include_disabled=true"),
  });

  const create = useMutation({
    mutationFn: () => post("/fim/policies", {
      path: path.trim(), name: name.trim(), recursive: true,
      max_depth: Number(depth) || 4, interval_s: Number(interval) || 300,
    }),
    onSuccess: (r) => {
      const res = r as { id: string; baseline: { status: string; files?: number } };
      toast.push({ tone: "ok", title: "FIM policy created", text: `baseline: ${res.baseline.status} (${res.baseline.files ?? 0} files)` });
      setShowForm(false); setPath(""); setName("");
      qc.invalidateQueries({ queryKey: ["fim"] });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Policy refused", text: String((e as Error).message) }),
  });

  const scanNow = useMutation({
    mutationFn: (pid: string) => post<{ status: string; events?: number }>(`/fim/policies/${pid}/scan`),
    onSuccess: (r) => {
      const res = r as { status: string; events?: number };
      toast.push({ tone: res.events ? "warn" : "ok", title: `Scan ${res.status}`, text: `${res.events ?? 0} events` });
      qc.invalidateQueries({ queryKey: ["fim"] });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Scan failed", text: String((e as Error).message) }),
  });

  const pols = status.data?.policies ?? [];
  const evs = events.data?.events ?? [];
  const rl = rules.data?.rules ?? [];

  return (
    <>
      <div className="span-12">
        <Panel title="File Integrity Monitoring" actions={
          <span className="page-note cell-id">
            {status.data ? `${pols.filter((x) => x.enabled).length} active · ${status.data.events_24h} events/24h · ${status.data.engine}` : "…"}
          </span>
        }>
          {status.data ? <div className="page-note" style={{ marginBottom: 8 }}><i>{status.data.note}</i></div> : null}
          <button type="button" className="btn small primary" onClick={() => setShowForm((v) => !v)}>
            {showForm ? "Close" : "New monitoring policy"}
          </button>
          {showForm ? (
            <div style={{ border: "1px solid var(--line)", padding: 10, marginTop: 8 }}>
              <div className="form-row">
                <Field label="Directory (absolute path)">
                  <input className="text" placeholder="/etc or /srv/app/config" value={path} onChange={(e) => setPath(e.target.value)} />
                </Field>
                <Field label="Policy name">
                  <input className="text" value={name} maxLength={120} onChange={(e) => setName(e.target.value)} />
                </Field>
                <Field label="Interval (s)">
                  <input className="text" type="number" min={60} value={interval} onChange={(e) => setInterval(e.target.value)} />
                </Field>
                <Field label="Max depth">
                  <input className="text" type="number" min={1} max={10} value={depth} onChange={(e) => setDepth(e.target.value)} />
                </Field>
                <button type="button" className="btn primary" disabled={path.trim().length < 2 || name.trim().length < 2 || create.isPending}
                        onClick={() => create.mutate()}>
                  Create + baseline
                </button>
              </div>
            </div>
          ) : null}

          {status.isPending ? <LoaderRows lines={["Loading policies"]} />
            : !pols.length ? <EmptyRows what="No FIM policies — monitor a protected directory to detect create/modify/delete/permission/ownership changes" />
            : (
              <table className="dtable" style={{ marginTop: 8 }}>
                <thead><tr><th>Policy</th><th>Path</th><th>Baseline</th><th>Last scan</th><th>Status</th><th /></tr></thead>
                <tbody>
                  {pols.map((p) => (
                    <tr key={p.id}>
                      <td>{p.name}</td>
                      <td className="cell-id">{p.path}</td>
                      <td>{p.baseline_ready ? `${p.files_baseline} files` : "not built"}</td>
                      <td className="cell-id">{p.last_scan_at ? fmtTs(p.last_scan_at) : "never"} <span className="cell-id">{p.last_scan_status || ""}</span></td>
                      <td><Chip tone={p.enabled ? "ok" : "dim"} label={p.enabled ? "MONITORING" : "DISABLED"} /></td>
                      <td>
                        <button type="button" className="btn small" disabled={!p.enabled || scanNow.isPending}
                                onClick={() => scanNow.mutate(p.id)}>Scan now</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
        </Panel>
      </div>

      <div className="span-12">
        <Panel title={`Integrity events · ${evs.length}`}>
          {!evs.length ? <EmptyRows what="No integrity events yet — events appear here between baseline scans" /> : (
            <table className="dtable">
              <thead><tr><th>When</th><th>Event</th><th>File</th><th>Detail</th><th>Alert</th></tr></thead>
              <tbody>
                {evs.map((ev) => (
                  <tr key={ev.id} style={{ cursor: "pointer" }} onClick={() => setExpanded(expanded === ev.id ? null : ev.id)}>
                    <td className="cell-id">{fmtTs(ev.detected_at)}</td>
                    <td><Chip tone={EV_TONE[ev.event_type] || "info"} label={ev.event_type} /></td>
                    <td className="cell-id">{ev.file_path}{ev.prev_path ? ` ← ${ev.prev_path}` : ""}</td>
                    <td className="cell-id">{hashHint(ev)}</td>
                    <td className="cell-id">{ev.alert_id ? trunc(ev.alert_id, 10) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>

      <div className="span-12">
        <Panel title={`Detection rules · ${rl.length}`} actions={
          <span className="page-note cell-id">versioned · suppression-aware · correlation → incident</span>
        }>
          {rules.isPending ? <LoaderRows lines={["Loading detection rules"]} /> : (
            <table className="dtable">
              <thead><tr><th>Rule</th><th>Source</th><th>Severity</th><th>Conf</th><th>Correlate</th><th>Version</th><th>State</th><th /></tr></thead>
              <tbody>
                {rl.map((r) => (
                  <tr key={r.id}>
                    <td title={r.description || ""}>{r.name}<div className="cell-id">{r.rule_key}</div></td>
                    <td>{r.source}</td>
                    <td><Chip tone={r.severity === "critical" || r.severity === "high" ? "fail" : r.severity === "medium" ? "warn" : "info"} label={r.severity} /></td>
                    <td>{Math.round(r.confidence * 100)}%</td>
                    <td className="cell-id">{r.correlate_json ? "window" : "—"}</td>
                    <td className="cell-id">v{r.version}</td>
                    <td><Chip tone={r.enabled ? "ok" : "dim"} label={r.enabled ? "ENABLED" : "DISABLED"} /></td>
                    <td>
                      <button type="button" className="btn small" disabled={r.enabled === 1}
                              onClick={() => post(`/soc/rules/${r.id}/enable`).then(() => qc.invalidateQueries({ queryKey: ["soc"] }))}>Enable</button>
                      <button type="button" className="btn small" style={{ marginLeft: 4 }} disabled={!r.enabled}
                              onClick={() => post(`/soc/rules/${r.id}/disable`).then(() => qc.invalidateQueries({ queryKey: ["soc"] }))}>Disable</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {rules.error ? <ErrBanner error={rules.error} /> : null}
        </Panel>
      </div>
    </>
  );
}

function hashHint(ev: FimEvent): string {
  if (ev.old_sha256 && ev.new_sha256) return `${trunc(ev.old_sha256, 8)} → ${trunc(ev.new_sha256, 8)}`;
  if (ev.new_sha256) return `→ ${trunc(ev.new_sha256, 8)}`;
  if (ev.old_sha256) return `${trunc(ev.old_sha256, 8)} →`;
  if (ev.new_uid != null || ev.old_uid != null) return `uid ${ev.old_uid ?? "?"} → ${ev.new_uid ?? "?"}`;
  if (ev.new_mode != null || ev.old_mode != null) return `mode ${ev.old_mode?.toString(8) ?? "?"} → ${ev.new_mode?.toString(8) ?? "?"}`;
  return "—";
}

interface FimPolicy {
  id: string; name: string; path: string; enabled: number; baseline_ready: number;
  files_baseline: number | null; last_scan_at: string | null; last_scan_status: string | null;
  interval_s: number; recursive: number; max_depth: number;
}

interface FimEvent {
  id: string; policy_id: string; event_type: string; file_path: string; prev_path: string | null;
  old_sha256: string | null; new_sha256: string | null; old_size: number | null; new_size: number | null;
  old_mode: number | null; new_mode: number | null; old_uid: number | null; new_uid: number | null;
  alert_id: string | null; detected_at: string;
}

interface DetRule {
  id: string; rule_key: string; version: number; name: string; description: string | null;
  source: string; matcher_json: string; severity: string; confidence: number;
  correlate_json: string | null; suppress_json: string | null; mitre: string | null;
  enabled: number; updated_at: string;
}