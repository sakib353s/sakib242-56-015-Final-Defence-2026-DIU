"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post, qs } from "@/lib/api";
import { getRole } from "@/lib/auth";
import { hasRole } from "@/lib/rbac";
import { clock, elapsedSince, fmtTs, humanAction, humanStatus, statusTone, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { DonutStat, RankList, SEV_COLORS } from "@/components/charts";
import { sevVar } from "@/components/findings";
import { Chip, EmptyRows, ErrBanner, Field, Leader, LoaderRows, Modal, Panel, Segmented, useMounted, useTick } from "@/components/ui";
import type { Alert, BlockResult, HoneypotResult, IpBlock, PlaybookResult } from "@/lib/types";

const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const PLAYBOOKS = ["brute_force", "sqli", "ddos", "malware"] as const;
/* Keys are what the API accepts; the operator should read an outcome, not an identifier. */
const PLAYBOOK_LABEL: Record<string, string> = {
  brute_force: "Brute-force login response",
  sqli: "SQL injection response",
  ddos: "DDoS mitigation",
  malware: "Malware containment",
};

export default function SocPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const { requestTotp } = useStepUp();

  const [sev, setSev] = useState<string>("");
  const [blockTarget, setBlockTarget] = useState<{ ip: string } | null>(null);
  const [blockMin, setBlockMin] = useState(60);
  const [blockTotpBusy, setBlockTotpBusy] = useState(false);
  const [ackTarget, setAckTarget] = useState<Alert | null>(null);
  const [ackNote, setAckNote] = useState("");
  const [pbFor, setPbFor] = useState<Alert | null>(null);
  const [pbName, setPbName] = useState<string>("brute_force");
  const [pbResult, setPbResult] = useState<(PlaybookResult & { ran_at: number }) | null>(null);
  const [lastBlock, setLastBlock] = useState<BlockResult | null>(null);

  useTick(1000);
  const mounted = useMounted();
  const alerts = useQuery({
    queryKey: ["alerts", sev],
    queryFn: () => get<{ alerts: Alert[] }>(`/soc/alerts${qs({ sev: sev || undefined, limit: 100 })}`),
  });
  const blocksQ = useQuery({
    queryKey: ["blocks"],
    queryFn: () => get<{ blocks: IpBlock[] }>("/soc/blocks"),
    refetchInterval: (q) => ((q.state.data?.blocks ?? []).some((b) => b.status === "active") ? 15000 : false),
  });

  const feed = useQuery({
    queryKey: ["alerts", "all"],
    queryFn: () => get<{ alerts: Alert[] }>("/soc/alerts?limit=100"),
  });
  const frows = feed.data?.alerts ?? [];
  const sevMix = (SEVS as readonly string[]).map((s) => ({
    name: humanStatus(s),
    value: frows.filter((a) => a.severity === s).length,
    color: SEV_COLORS[s],
  })).filter((d) => d.value > 0);
  const catCounts: Record<string, number> = {};
  for (const a of frows) {
    const c = (a.category || "uncategorized").toLowerCase();
    catCounts[c] = (catCounts[c] ?? 0) + 1;
  }
  const topCats = Object.entries(catCounts).sort((a, b) => b[1] - a[1]).slice(0, 6)
    .map(([label, value]) => ({ label: label.charAt(0).toUpperCase() + label.slice(1), value }));

  const ack = useMutation({
    mutationFn: async (a: Alert) => post(`/soc/alerts/${a.id}/ack`, { note: ackNote.slice(0, 500) }),
    onSuccess: () => {
      toast.push({ tone: "ok", title: "Alert acknowledged" });
      setAckTarget(null);
      setAckNote("");
      qc.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  const block = useMutation({
    mutationFn: async (totp: string) =>
      post<BlockResult>("/soc/block-ip", { ip: blockTarget!.ip, expires_min: blockMin }, totp),
    onSuccess: (r) => {
      setLastBlock(r);
      setBlockTarget(null);
      setBlockTotpBusy(false);
      qc.invalidateQueries({ queryKey: ["blocks"] });
      toast.push({ tone: "ok", title: `Block deployed for ${r.ip}`, text: `Rule ${trunc(r.block_id, 10)} expires automatically` });
    },
    onError: (e) => {
      setBlockTotpBusy(false);
      toast.push({ tone: "fail", title: "Block deployment failed", text: String((e as Error).message) });
    },
  });

  const unblock = useMutation({
    mutationFn: async (blockId: string) => post("/soc/unblock-ip", { block_id: blockId }),
    onSuccess: () => {
      toast.push({ tone: "ok", title: "Block lifted" });
      qc.invalidateQueries({ queryKey: ["blocks"] });
    },
  });

  const runPb = useMutation({
    mutationFn: async (a: Alert) => {
      const inc = await post<{ incident_id: string }>("/soc/incidents", { alert_id: a.id, playbook: pbName });
      return post<PlaybookResult>(`/soc/incidents/${inc.incident_id}/playbook`, {
        playbook: pbName,
        context: { alert_id: a.id, src_ip: a.src_ip ?? "0.0.0.0" },
      });
    },
    onSuccess: (r) => {
      setPbResult({ ...r, ran_at: Date.now() });
      setPbFor(null);
      toast.push({ tone: "info", title: `Playbook ${r.playbook} planned`, text: `${r.steps.length} steps queued for incident ${trunc(r.incident_id, 10)}` });
    },
  });

  const honeypot = useMutation({
    mutationFn: async (totp: string) => post<HoneypotResult>("/soc/honeypot/deploy", undefined, totp),
    onSuccess: (r) => toast.push({ tone: "warn", title: r.status, text: trunc(r.policy_note, 90) }),
    onError: (e) => toast.push({ tone: "fail", title: "Honeypot deployment failed", text: String((e as Error).message) }),
  });

  return (
    <>
      <div className="span-12">
        <div className="stat-grid">
          <Panel title="Alert severity">
            {feed.isPending ? <LoaderRows lines={["Loading alerts"]} /> : feed.error ? <ErrBanner error={feed.error} /> : (
              <DonutStat data={sevMix} centerLabel="alerts" />
            )}
          </Panel>
          <Panel title="Top categories">
            {feed.isPending ? <LoaderRows lines={["Aggregating categories"]} /> : !topCats.length ? <EmptyRows what="No categories yet" /> : (
              <RankList items={topCats} />
            )}
          </Panel>
        </div>
      </div>

      <div className="span-12">
        <Panel
          title="Alert feed"
          tight
          actions={
            <Segmented
              ariaLabel="severity filter"
              value={sev}
              onChange={setSev}
              options={[{ id: "", label: "All" }, ...SEVS.map((s) => ({ id: s, label: humanStatus(s) }))]}
            />
          }
        >
          {alerts.isPending ? (
            <LoaderRows lines={["Loading alerts", "Correlating MITRE techniques"]} />
          ) : alerts.error ? (
            <div style={{ padding: 12 }}>
              <ErrBanner error={alerts.error} onRetry={() => alerts.refetch()} />
            </div>
          ) : !alerts.data!.alerts.length ? (
            <EmptyRows what="No alerts match this filter" />
          ) : (
            <table className="dtable">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Signature</th>
                  <th>Source → Destination</th>
                  <th>MITRE</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.data!.alerts.map((a) => (
                  <tr key={a.id} className="sev-strip" style={{ "--sev": sevVar(a.severity) } as React.CSSProperties}>
                    <td className="cell-id" title={fmtTs(a.ts)}>{fmtTs(a.ts).slice(11)}</td>
                    <td>
                      <Chip tone={statusTone(a.severity)} label={humanStatus(a.severity)} />
                    </td>
                    <td style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={a.signature}>
                      {a.signature}
                      {a.status === "acked" ? <span className="cell-id"> · acknowledged</span> : null}
                    </td>
                    <td className="cell-id">
                      {a.src_ip ?? "unknown"} → {a.dest_ip ?? "unknown"}
                    </td>
                    <td className="cell-id">
                      {a.mitre ? (
                        <a href={`https://attack.mitre.org/techniques/${a.mitre.replace(/\./g, "/")}/`} target="_blank" rel="noreferrer">
                          {a.mitre}
                        </a>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      <div className="row-actions">
                        <button type="button" className="btn small" disabled={a.status === "acked"} onClick={() => setAckTarget(a)}>
                          Acknowledge
                        </button>
                        <button
                          type="button"
                          className="btn small danger"
                          disabled={!a.src_ip || a.src_ip === "0.0.0.0"}
                          onClick={() => setBlockTarget({ ip: a.src_ip! })}
                        >
                          Block IP
                        </button>
                        <button
                          type="button"
                          className="btn small"
                          onClick={() => {
                            setPbFor(a);
                            setPbName(a.category?.toLowerCase().includes("brute") ? "brute_force" : pbName);
                          }}
                        >
                          Run playbook
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>

      <div className="span-12">
        <Panel
          title="Firewall block ledger"
          tight
          actions={<span className="cell-id mono-dim">{(blocksQ.data?.blocks ?? []).filter((b) => b.status === "active").length} active · watchdog lifts expired rules automatically</span>}
        >
          {blocksQ.isPending ? (
            <LoaderRows lines={["Loading deployed rules"]} />
          ) : blocksQ.error ? (
            <div style={{ padding: 12 }}>
              <ErrBanner error={blocksQ.error} onRetry={() => blocksQ.refetch()} />
            </div>
          ) : !blocksQ.data!.blocks.length ? (
            <EmptyRows what="No addresses have been blocked from this console" />
          ) : (
            <table className="dtable">
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Rule</th>
                  <th>Deployed</th>
                  <th>Via</th>
                  <th>Expires</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {blocksQ.data!.blocks.map((b) => (
                  <tr key={b.id}>
                    <td className="cell-id">{b.ip}</td>
                    <td className="cell-id" title={b.rule ?? undefined}>{trunc(b.rule, 40)}</td>
                    <td className="cell-id">{fmtTs(b.created_at)}</td>
                    <td className="cell-id">{b.deployed_via ?? "—"}</td>
                    <td className="cell-id">
                      {b.status === "active" && b.expires_at ? `in ${elapsedSince(b.expires_at.replace(" ", "T") + "Z")}` : fmtTs(b.expires_at)}
                    </td>
                    <td><Chip tone={b.status === "active" ? "fail" : "dim"} label={humanStatus(b.status)} /></td>
                    <td>
                      {b.status === "active" ? (
                        <div className="row-actions">
                          <button type="button" className="btn small" disabled={unblock.isPending} onClick={() => unblock.mutate(b.id)}>
                            Lift block
                          </button>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {unblock.isError ? <div style={{ padding: 12 }}><ErrBanner error={unblock.error} /></div> : null}
        </Panel>
      </div>

      <div className="span-12">
        <div className="panel-grid">
          <Panel title="IP blocking">
            <div className="page-note" style={{ marginBottom: 8 }}>
              Blocking requires a verification code. Every rule expires automatically and is removed by
              the watchdog.
            </div>
            <Field label="Block an address manually">
              <button type="button" className="btn" onClick={() => setBlockTarget({ ip: "" })}>
                Add block
              </button>
            </Field>
            {lastBlock ? (
              <Leader label={`Blocking ${lastBlock.ip}`} value={`rule ${trunc(lastBlock.block_id, 12)} · active`} tone="ok" />
            ) : null}
          </Panel>

          <Panel title="Honeypot activity">
            {mounted && hasRole(getRole(), "SUPER_ADMIN") ? (
              <>
                <div className="page-note" style={{ marginBottom: 8 }}>
                  Deploys a monitored honeypot segment. This requires segment authorization, and every request is recorded in the audit log.
                </div>
                <button
                  type="button"
                  className="btn warn"
                  disabled={honeypot.isPending}
                  onClick={async () => {
                    const code = await requestTotp("soc: honeypot deploy request");
                    if (code) honeypot.mutate(code);
                  }}
                >
                  Request deployment
                </button>
                {honeypot.data ? (
                  <div className="lockline" style={{ marginTop: 10 }}>
                    {honeypot.data.status} {honeypot.data.policy_note}
                  </div>
                ) : null}
              </>
            ) : (
              <div className="lockline">Honeypot deployment is managed by an administrator.</div>
            )}
          </Panel>

          <Panel title="Incident response plan">
            {!pbResult ? (
              <EmptyRows what="No playbook has run in this session" />
            ) : (
              <>
                <div className="page-note" style={{ marginBottom: 6 }}>
                  Incident {trunc(pbResult.incident_id, 14)} · playbook {humanStatus(pbResult.playbook)} · planned {clock(new Date(pbResult.ran_at))}
                </div>
                <ol className="stepper-flow">
                  {pbResult.steps.map((s, i) => (
                    <li key={i}>
                      <div className="sf-step">
                        <span className={`sf-badge${s.auto ? "" : " manual"}`}>{String(i + 1).padStart(2, "0")}</span>
                        <span style={{ minWidth: 0 }}>
                          <span className="sf-title">{humanAction(s.step)}</span>
                          {s.detail ? <span className="sf-detail">{s.detail}</span> : null}
                          <span className="chip dim" style={{ marginTop: 4, display: "inline-flex" }}>{s.auto ? "Automatic" : "Manual action"}</span>
                        </span>
                      </div>
                    </li>
                  ))}
                </ol>
              </>
            )}
          </Panel>
        </div>
      </div>

      {blockTarget ? (
        <Modal
          title="Confirm block deployment"
          onClose={() => setBlockTarget(null)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setBlockTarget(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn danger"
                disabled={!blockTarget.ip || blockTotpBusy}
                onClick={async () => {
                  setBlockTotpBusy(true);
                  const code = await requestTotp(`soc: block ${blockTarget.ip} for ${blockMin} min`);
                  if (code) block.mutate(code);
                  else setBlockTotpBusy(false);
                }}
              >
                Deploy block
              </button>
            </>
          }
        >
          <Field label="source IP">
            <input className="text" value={blockTarget.ip} onChange={(e) => setBlockTarget({ ip: e.target.value.trim() })} placeholder="103.x.y.z" />
          </Field>
          <Field label="expiry in minutes" hint="Between 5 and 1440. The rule is lifted automatically at expiry.">
            <input
              className="text"
              inputMode="numeric"
              value={String(blockMin)}
              onChange={(e) => setBlockMin(Math.max(5, Math.min(1440, Number(e.target.value.replace(/\D/g, "")) || 5)))}
            />
          </Field>
          {block.isError ? <ErrBanner error={block.error} /> : null}
        </Modal>
      ) : null}

      {ackTarget ? (
        <Modal
          title={`Acknowledge alert: ${trunc(ackTarget.signature, 40)}`}
          onClose={() => setAckTarget(null)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setAckTarget(null)}>
                Cancel
              </button>
              <button type="button" className="btn primary" disabled={ack.isPending} onClick={() => ack.mutate(ackTarget)}>
                Acknowledge
              </button>
            </>
          }
        >
          <Field label="triage note (optional, audited)">
            <textarea value={ackNote} onChange={(e) => setAckNote(e.target.value)} maxLength={500} placeholder="Assigned to the on-call analyst. Possible false positive…" />
          </Field>
          {ack.isError ? <ErrBanner error={ack.error} /> : null}
        </Modal>
      ) : null}

      {pbFor ? (
        <Modal
          title={`Run playbook: ${trunc(pbFor.signature, 36)}`}
          onClose={() => setPbFor(null)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setPbFor(null)}>
                Cancel
              </button>
              <button type="button" className="btn warn" disabled={runPb.isPending} onClick={() => runPb.mutate(pbFor)}>
                Create incident and plan
              </button>
            </>
          }
        >
          <Field label="playbook" hint="The planner returns ordered steps. An incident record is created and audited.">
            <select value={pbName} onChange={(e) => setPbName(e.target.value)}>
              {PLAYBOOKS.map((p) => (
                <option key={p} value={p}>
                  {PLAYBOOK_LABEL[p] ?? p}
                </option>
              ))}
            </select>
          </Field>
          <div className="page-note">
            Source {pbFor.src_ip ?? "not recorded"} · severity {humanStatus(pbFor.severity)} · MITRE {pbFor.mitre ?? "—"}
          </div>
          {runPb.isError ? <ErrBanner error={runPb.error} /> : null}
        </Modal>
      ) : null}
    </>
  );
}
