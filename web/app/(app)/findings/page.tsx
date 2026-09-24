"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "@/lib/api";
import { fmtTs, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { Chip, EmptyRows, ErrBanner, LoaderRows, Modal, Panel } from "@/components/ui";
import type { AssessmentFinding, BrainDecision, Evidence } from "@/lib/types";

type Lifecycle = AssessmentFinding["lifecycle"];

const SEV_TONE: Record<string, string> = {
  critical: "fail", high: "fail", medium: "warn", low: "info", informational: "dim",
};

const LC_LABEL: Record<Lifecycle, string> = {
  detected: "Detected", triaged: "Triaged", validating: "Validating", confirmed: "Confirmed",
  remediation_recommended: "Remediation Recommended", remediated: "Remediated",
  verified_fixed: "Verified Fixed", false_positive: "False Positive",
  not_reproducible: "Not Reproducible", unconfirmed: "Unconfirmed",
  actioned_but_not_verified: "Actioned But Not Verified",
};

const LC_TONE: Record<Lifecycle, string> = {
  detected: "info", triaged: "info", validating: "warn", confirmed: "warn",
  remediation_recommended: "warn", remediated: "ok", verified_fixed: "ok",
  false_positive: "dim", not_reproducible: "dim", unconfirmed: "dim",
  actioned_but_not_verified: "fail",
};

const NEXT_EDGES: Record<Lifecycle, Lifecycle[]> = {
  detected: ["triaged", "false_positive", "unconfirmed"],
  triaged: ["validating", "confirmed", "false_positive", "not_reproducible", "unconfirmed"],
  validating: ["confirmed", "false_positive", "not_reproducible", "unconfirmed"],
  confirmed: ["remediation_recommended", "false_positive", "unconfirmed"],
  remediation_recommended: ["remediated", "actioned_but_not_verified", "unconfirmed"],
  remediated: ["verified_fixed", "actioned_but_not_verified", "not_reproducible", "unconfirmed"],
  verified_fixed: [],
  false_positive: [],
  not_reproducible: [],
  unconfirmed: ["detected", "triaged"],
  actioned_but_not_verified: ["remediated", "verified_fixed", "unconfirmed"],
};

const RETESTABLE: Lifecycle[] = ["confirmed", "remediation_recommended", "remediated", "actioned_but_not_verified"];

export default function FindingsPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const { requestTotp } = useStepUp();
  const [minSev, setMinSev] = useState("informational");
  const [selected, setSelected] = useState<string | null>(null);
  const [transitionOpen, setTransitionOpen] = useState(false);
  const [targetState, setTargetState] = useState<Lifecycle | null>(null);
  const [reason, setReason] = useState("");

  const queue = useQuery({
    queryKey: ["findings", "queue", minSev],
    queryFn: () => get<{ queue: AssessmentFinding[] }>(`/findings/queue?min_severity=${minSev}&limit=200`),
    refetchInterval: (q) => ((q.state.data?.queue ?? []).length ? 30000 : false),
  });

  const detail = useQuery({
    queryKey: ["findings", "one", selected],
    queryFn: () => get<{ finding: AssessmentFinding; history: TransitionRow[]; warrant_id: string | null }>(
      `/findings/${selected}`),
    enabled: !!selected,
  });

  const rows = queue.data?.queue ?? [];
  useEffect(() => {
    if (!selected && rows.length) setSelected(rows[0].id);
  }, [selected, rows]);

  const doTransition = useMutation({
    mutationFn: async ({ fid, to }: { fid: string; to: Lifecycle }) =>
      post(`/findings/${fid}/transition`, { to_state: to, reason: reason || undefined }),
    onSuccess: (_, vars) => {
      toast.push({ tone: "ok", title: `Moved to ${LC_LABEL[vars.to]}`, text: trunc(vars.fid, 12) });
      setTransitionOpen(false);
      setReason("");
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Transition refused", text: String((e as Error).message) }),
  });

  const doRetest = useMutation({
    mutationFn: async (fid: string) => {
      const code = await requestTotp(`finding: retest ${trunc(fid, 10)}`);
      if (!code) throw new Error("cancelled");
      return post(`/findings/${fid}/retest`, {}, code);
    },
    onSuccess: () => {
      toast.push({ tone: "info", title: "Retest dispatched", text: "Real adapter check running" });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["findings"] }), 6000);
    },
    onError: (e) => {
      if ((e as Error).message !== "cancelled")
        toast.push({ tone: "fail", title: "Retest failed", text: String((e as Error).message) });
    },
  });

  function armTransition(to: Lifecycle) {
    setTargetState(to);
    setTransitionOpen(true);
  }

  return (
    <>
      <div className="span-12">
        <Panel title="Finding Engine · open queue" actions={
          <select className="text" value={minSev} onChange={(e) => setMinSev(e.target.value)} style={{ width: 140 }}>
            {["critical", "high", "medium", "low", "informational"].map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}+</option>
            ))}
          </select>
        }>
          {queue.isPending ? (
            <LoaderRows lines={["Loading finding queue"]} />
          ) : queue.error ? (
            <ErrBanner error={queue.error} onRetry={() => queue.refetch()} />
          ) : !rows.length ? (
            <EmptyRows what="No open findings at this severity — run an assessment to populate the engine" />
          ) : (
            <table className="dtable">
              <thead>
                <tr><th>Title</th><th>Severity</th><th>Lifecycle</th><th>Confidence</th><th>Host / Endpoint</th><th>Updated</th></tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <tr key={f.id} onClick={() => setSelected(f.id)}
                      style={{ cursor: "pointer", background: selected === f.id ? "var(--sel)" : undefined }}>
                    <td>{f.title}</td>
                    <td><Chip tone={SEV_TONE[f.severity] || "dim"} label={f.severity.toUpperCase()} /></td>
                    <td><Chip tone={LC_TONE[f.lifecycle]} label={LC_LABEL[f.lifecycle]} /></td>
                    <td>{Math.round((f.confidence ?? 0) * 100)}%</td>
                    <td className="cell-id">{trunc(f.host || f.endpoint || "—", 28)}</td>
                    <td className="cell-id">{fmtTs(f.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>

      <div className="span-12">
        <Panel title="Inspector" tight>
          {!selected ? (
            <div style={{ padding: 12 }}><EmptyRows what="Select a finding to inspect its evidence and lifecycle" /></div>
          ) : detail.isPending ? (
            <div style={{ padding: 12 }}><LoaderRows lines={["Loading finding record", "Ordering transition history"]} /></div>
          ) : detail.error ? (
            <div style={{ padding: 12 }}><ErrBanner error={detail.error} onRetry={() => detail.refetch()} /></div>
          ) : (() => {
            const f = detail.data!.finding;
            const hist = detail.data!.history;
            const nextEdges = NEXT_EDGES[f.lifecycle] ?? [];
            const canRetest = RETESTABLE.includes(f.lifecycle);
            return (
              <div style={{ padding: 12 }}>
                <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
                  <span className="panel-title">{f.title}</span>
                  <Chip tone={SEV_TONE[f.severity] || "dim"} label={f.severity.toUpperCase()} />
                  <Chip tone={LC_TONE[f.lifecycle]} label={LC_LABEL[f.lifecycle]} />
                  <span className="cell-id">ID {trunc(f.id, 18)} · source {f.source_engine} v{f.source_version || "?"}</span>
                </div>
                <p style={{ fontSize: 13, margin: "4px 0 10px" }}>{f.description || "no description recorded"}</p>
                {f.impact ? <p className="page-note" style={{ marginTop: 0 }}>Impact: {f.impact}</p> : null}
                {f.remediation_hint ? <p className="page-note">Recommended fix: {f.remediation_hint}</p> : null}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(180px,1fr))", gap: 6, margin: "8px 0" }}>
                  <Meta k="Detection state" v={f.detection_state} />
                  <Meta k="CVE / CWE" v={[f.cve, f.cwe].filter(Boolean).join(" · ") || "—"} />
                  <Meta k="MITRE" v={f.mitre || "—"} />
                  <Meta k="Endpoint" v={f.endpoint || "—"} />
                  <Meta k="Parameter" v={f.parameter || "—"} />
                  <Meta k="Technology" v={f.technology || "—"} />
                  <Meta k="Confidence" v={`${Math.round((f.confidence ?? 0) * 100)}%`} />
                  <Meta k="Verify result" v={f.verify_result || "not yet verified"} />
                  <Meta k="Retests" v={String(f.retest_count ?? 0)} />
                </div>

                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "10px 0" }}>
                  {nextEdges.map((to) => (
                    <button key={to} type="button"
                            className={`btn small${to === "false_positive" || to === "not_reproducible" ? "" : " primary"}`}
                            disabled={doTransition.isPending}
                            onClick={() => armTransition(to)}>
                      → {LC_LABEL[to]}
                    </button>
                  ))}
                  {canRetest ? (
                    <button type="button" className="btn small" disabled={doRetest.isPending}
                            onClick={() => doRetest.mutate(f.id)}>
                      {doRetest.isPending ? "Dispatching…" : "Retest now"}
                    </button>
                  ) : null}
                  {!nextEdges.length && !canRetest ? (
                    <span className="page-note" style={{ alignSelf: "center" }}>Terminal state — no further transitions or retests</span>
                  ) : null}
                </div>

                {hist.length ? (
                  <>
                    <div className="panel-title" style={{ marginTop: 10, marginBottom: 4 }}>Transition history</div>
                    <table className="dtable">
                      <thead><tr><th>From</th><th>To</th><th>Actor</th><th>Reason</th><th>When</th></tr></thead>
                      <tbody>
                        {hist.map((h) => (
                          <tr key={h.id}>
                            <td><Chip tone={LC_TONE[h.from_lifecycle as Lifecycle]} label={LC_LABEL[h.from_lifecycle as Lifecycle]} /></td>
                            <td><Chip tone={LC_TONE[h.to_lifecycle as Lifecycle]} label={LC_LABEL[h.to_lifecycle as Lifecycle]} /></td>
                            <td className="cell-id">{trunc(h.actor, 12)}</td>
                            <td>{h.reason || "—"}</td>
                            <td className="cell-id">{fmtTs(h.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                ) : null}
              </div>
            );
          })()}
        </Panel>
      </div>

      {transitionOpen && targetState && selected ? (
        <Modal title={`Move to ${LC_LABEL[targetState]}`} onClose={() => setTransitionOpen(false)}
               footer={<>
                 <button type="button" className="btn" onClick={() => setTransitionOpen(false)}>Cancel</button>
                 <button type="button" className="btn primary" disabled={doTransition.isPending}
                         onClick={() => doTransition.mutate({ fid: selected, to: targetState })}>
                   Confirm transition
                 </button>
               </>}>
          <label className="checkline" style={{ flexDirection: "column", alignItems: "stretch", gap: 6 }}>
            Reason (optional, audit-recorded)
            <textarea className="text" rows={3} value={reason} maxLength={500}
                      onChange={(e) => setReason(e.target.value)}
                      placeholder="Why is this finding moving to this state?" />
          </label>
        </Modal>
      ) : null}
    </>
  );
}

interface TransitionRow {
  id: string;
  from_lifecycle: string;
  to_lifecycle: string;
  actor: string;
  reason: string | null;
  created_at: string;
}

function Meta({ k, v }: { k: string; v: string | number | null | undefined }) {
  return (
    <div style={{ fontSize: 12 }}>
      <span style={{ color: "var(--muted)" }}>{k}: </span>
      <b>{v ?? "—"}</b>
    </div>
  );
}