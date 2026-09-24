"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "@/lib/api";
import { fmtTs, humanStatus, statusTone, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { WarrantPicker } from "@/components/warrant";
import { Chip, EmptyRows, ErrBanner, Field, LoaderRows, Meter, Modal, Panel } from "@/components/ui";
import { RiskGauge, RiskValue } from "@/components/risk";
import { Icon } from "@/components/icons";
import type {
  Assessment,
  AssessmentDetail,
  AssessmentFinding,
  AssessmentStage,
  BrainDecision,
  Evidence,
  FindingDetail,
} from "@/lib/types";

const ACTIVE = new Set(["CREATED", "AUTHORIZED", "PLANNED", "QUEUED", "DISPATCHED", "RUNNING", "PARSING", "VERIFYING"]);
const PROFILES: Array<{ id: "quick" | "standard" | "deep"; label: string; hint: string }> = [
  { id: "quick", label: "Quick", hint: "DNS + TLS + HTTP surface only" },
  { id: "standard", label: "Standard", hint: "Discovery, technology identification and configuration analysis" },
  { id: "deep", label: "Deep", hint: "Full pipeline including endpoint discovery and correlation" },
];

export default function AssessmentPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const { requestTotp } = useStepUp();

  const [warrantId, setWarrantId] = useState("");
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<"quick" | "standard" | "deep">("standard");
  const [attestOpen, setAttestOpen] = useState(false);
  const [attested, setAttested] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [openFinding, setOpenFinding] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["assessment", "list"],
    queryFn: () => get<{ assessments: Assessment[] }>("/assessment"),
    refetchInterval: (q) => ((q.state.data?.assessments ?? []).some((a) => ACTIVE.has(a.status)) ? 3000 : false),
  });
  const detail = useQuery({
    queryKey: ["assessment", "detail", selected],
    queryFn: () => get<AssessmentDetail>(`/assessment/${selected}`),
    enabled: !!selected,
    refetchInterval: (q) => (ACTIVE.has(q.state.data?.assessment.status ?? "") ? 2500 : false),
  });

  const rows = list.data?.assessments ?? [];
  useEffect(() => {
    if (!selected && rows.length) setSelected(rows[0].id);
  }, [selected, rows]);

  const create = useMutation({
    mutationFn: async (totp: string) => {
      const a = await post<Assessment>(
        "/assessment",
        { target: target.trim(), warrant_id: warrantId, profile, authorization_confirmed: true },
        totp,
      );
      await post(`/assessment/${a.id}/start`, {}, totp);
      return a;
    },
    onSuccess: (a) => {
      toast.push({ tone: "ok", title: "Assessment dispatched", text: `${a.target_canonical} · ${trunc(a.id, 10)}` });
      setSelected(a.id);
      setAttestOpen(false);
      setAttested(false);
      qc.invalidateQueries({ queryKey: ["assessment"] });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Could not start assessment", text: String((e as Error).message) }),
  });

  const cancelMut = useMutation({
    mutationFn: (id: string) => post(`/assessment/${id}/cancel`),
    onSuccess: () => {
      toast.push({ tone: "warn", title: "Cancellation requested", text: "Already-collected evidence is preserved." });
      qc.invalidateQueries({ queryKey: ["assessment"] });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Cancel failed", text: String((e as Error).message) }),
  });

  async function arm() {
    const code = await requestTotp(`assessment: analyze ${target} (${profile})`);
    if (code) create.mutate(code);
  }

  return (
    <>
      <div className="span-12">
        <Panel title="New authorized assessment" actions={<Chip tone={rows.some((r) => ACTIVE.has(r.status)) ? "warn" : "dim"} label={rows.some((r) => ACTIVE.has(r.status)) ? "An assessment is running" : "Engines idle"} />}>
          <div className="form-row">
            <Field label="Authorization">
              <WarrantPicker kind="pentest" value={warrantId} onChange={setWarrantId} />
            </Field>
            <Field label="Target (IP / domain / URL)" hint="Canonicalized and re-checked against scope on every privileged stage.">
              <input className="text" placeholder="https://authorized-example.com or 10.0.0.5" value={target} onChange={(e) => setTarget(e.target.value)} maxLength={500} />
            </Field>
            <Field label="Profile">
              <select className="text" value={profile} onChange={(e) => setProfile(e.target.value as typeof profile)}>
                {PROFILES.map((p) => (<option key={p.id} value={p.id}>{p.label} — {p.hint}</option>))}
              </select>
            </Field>
            <button type="button" className="btn primary" disabled={!warrantId || target.trim().length < 4} onClick={() => setAttestOpen(true)}>
              Analyze
            </button>
          </div>
          <div className="page-note" style={{ marginTop: 8 }}>
            Passive observation plus single benign requests only — no exploit payloads. Every stage, finding, decision and action is persisted with provenance and audit references.
          </div>
        </Panel>
      </div>

      <div className="span-12">
        <div className="wb">
          <div>
            <div className="panel-title" style={{ marginBottom: 8 }}>Assessments · {rows.length}</div>
            {list.isPending ? (
              <LoaderRows lines={["Loading assessments"]} />
            ) : list.error ? (
              <ErrBanner error={list.error} onRetry={() => list.refetch()} />
            ) : !rows.length ? (
              <EmptyRows what="No assessments recorded yet" />
            ) : (
              <div className="wb-list" role="listbox" aria-label="Assessments">
                {rows.map((a) => (
                  <button key={a.id} type="button" role="option" aria-selected={selected === a.id}
                    className={`wb-item${selected === a.id ? " on" : ""}`}
                    onClick={() => { setSelected(a.id); setOpenFinding(null); }}>
                    <span className={`wb-dot ${ACTIVE.has(a.status) ? "run" : a.status === "COMPLETED" ? "ok" : a.status === "PARTIAL" ? "" : "bad"}`} aria-hidden />
                    <span className="wb-main">
                      <span className="wb-target">{a.target_canonical}</span>
                      <span className="wb-meta">{fmtTs(a.created_at)} · {a.profile} · {a.current_stage ? humanStatus(a.current_stage) : humanStatus(a.status)}</span>
                    </span>
                    <span className="wb-side">
                      <RiskValue score={a.risk_score} />
                      <span className="wb-meta">{a.findings_count} findings</span>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <Panel title="Live assessment workspace" tight>
            {!selected ? (
              <div style={{ padding: 12 }}><EmptyRows what="Select an assessment to open its live workspace" /></div>
            ) : detail.isPending ? (
              <LoaderRows lines={["Loading assessment record", "Ordering stages and findings"]} />
            ) : detail.error ? (
              <div style={{ padding: 12 }}><ErrBanner error={detail.error} onRetry={() => detail.refetch()} /></div>
            ) : (
              <Workspace data={detail.data!} onCancel={(id) => cancelMut.mutate(id)} cancelling={cancelMut.isPending} openFinding={openFinding} onOpenFinding={setOpenFinding} />
            )}
          </Panel>
        </div>
      </div>

      {attestOpen ? (
        <Modal title="Confirm authorization" onClose={() => setAttestOpen(false)} footer={<>
          <button type="button" className="btn" onClick={() => setAttestOpen(false)}>Cancel</button>
          <button type="button" className="btn primary" disabled={!attested} onClick={() => { setAttestOpen(false); void arm(); }}>Confirm and analyze</button>
        </>}>
          <div className="problem" style={{ marginTop: 0 }}>
            <div className="pt">Warning: this operation touches systems outside your own</div>
            <div className="pd">You are about to run a security assessment against <b style={{ color: "var(--hdr)" }}>{target}</b> under the <b>{profile}</b> profile. The server re-checks authorization type, validity window, scope and revocation before dispatch and again inside each privileged worker stage. Scope drift aborts the run and preserves collected evidence.</div>
          </div>
          <label className="checkline">
            <input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} />
            I confirm written authorization is in force for this target, scope and time window.
          </label>
        </Modal>
      ) : null}

      {create.isError ? <ErrBanner error={create.error} /> : null}
    </>
  );
}

function Workspace({ data, onCancel, cancelling, openFinding, onOpenFinding }: {
  data: AssessmentDetail;
  onCancel: (id: string) => void;
  cancelling: boolean;
  openFinding: string | null;
  onOpenFinding: (id: string | null) => void;
}) {
  const { assessment: a, stages, findings, brain_decisions } = data;
  const canCancel = ACTIVE.has(a.status);
  return (
    <div style={{ padding: 12 }}>
      <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
        <span className="panel-title">{a.target_canonical.toUpperCase()}</span>
        <Chip tone={statusTone(a.status)} label={humanStatus(a.status)} />
        <span className="cell-id">ID {trunc(a.id, 18)} · authz {trunc(a.warrant_id, 18)} · profile {a.profile}</span>
        {canCancel ? <button type="button" className="btn small danger" disabled={cancelling} onClick={() => onCancel(a.id)}>Cancel run</button> : null}
      </div>
      <div style={{ margin: "6px 0 10px" }}>
        <RiskGauge score={a.risk_score} />
        <div className="page-note" style={{ marginTop: 6 }}>
          {a.observations_count} observations · {findings.length} normalized findings · {brain_decisions.length} Brain decisions
          {a.risk_version ? ` · risk model ${a.risk_version}` : ""}
        </div>
      </div>
      {a.error_message ? <Leader label="Failure" value={trunc(a.error_message, 120)} tone="fail" /> : null}
      {a.status === "WORKER_LOST" || a.status === "UNKNOWN_RESULT" ? (
        <div className="problem" style={{ marginTop: 8 }}>
          <div className="pt">{a.status === "WORKER_LOST" ? "Worker lost" : "Unknown result"}</div>
          <div className="pd">The execution state cannot be confirmed. Collected evidence has been preserved and nothing has been marked successful.</div>
        </div>
      ) : null}

      <StageRail stages={stages} progress={a.progress} active={ACTIVE.has(a.status)} />

      <div className="panel-title" style={{ margin: "12px 0 6px" }}>Findings · {findings.length}</div>
      {!findings.length ? (
        <EmptyRows what={ACTIVE.has(a.status) ? "Findings appear here as stages complete" : "No findings produced by this assessment"} />
      ) : (
        <table className="dtable">
          <thead><tr><th>Severity</th><th>Title</th><th>Asset / Endpoint</th><th>Validation</th><th>Confidence</th><th>Source</th></tr></thead>
          <tbody>
            {findings.map((f) => (
              <FindingRow key={f.id} f={f} open={openFinding === f.id} onToggle={() => onOpenFinding(openFinding === f.id ? null : f.id)} />
            ))}
          </tbody>
        </table>
      )}

      {openFinding ? <FindingInspector fid={openFinding} /> : null}

      <div className="panel-title" style={{ margin: "12px 0 6px" }}>Brain recommendations</div>
      {!brain_decisions.length ? (
        <EmptyRows what="Brain analysis appears once findings are correlated" />
      ) : (
        <div style={{ display: "grid", gap: 8 }}>
          {brain_decisions.slice(0, 8).map((d) => <DecisionCard key={d.id} d={d} />)}
        </div>
      )}
    </div>
  );
}

function StageRail({ stages, progress, active }: { stages: AssessmentStage[]; progress: number; active: boolean }) {
  return (
    <div className="stepper" style={{ margin: "10px 0 14px", flexWrap: "wrap" }} role="group" aria-label="Assessment stages">
      {stages.map((s) => (
        <span key={s.id} title={s.detail ?? s.label}
          className={`step${s.status === "DONE" ? " done" : s.status === "FAILED" ? " fail" : s.status === "RUNNING" ? " cur" : ""}`}
          style={s.status === "DEGRADED" || s.status === "SKIPPED" ? { opacity: 0.55 } : undefined}>
          {s.label}{s.status === "DEGRADED" ? " ⚠" : s.status === "SKIPPED" ? " –" : ""}
        </span>
      ))}
      <span className="step" style={{ borderRight: "none", borderLeft: "none", background: "transparent", display: "flex", alignItems: "center", gap: 8, minWidth: 132 }}>
        <Meter className="meter-inline" v={progress} max={1} tone={active ? "info" : progress >= 1 ? "ok" : "fail"} />
        {Math.round(progress * 100)}%
      </span>
    </div>
  );
}

function Leader({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="page-note" style={{ marginTop: 6 }}>
      <b style={{ color: `var(--${tone === "fail" ? "err" : "warn"})` }}>{label}:</b> {value}
    </div>
  );
}

function FindingRow({ f, open, onToggle }: { f: AssessmentFinding; open: boolean; onToggle: () => void }) {
  const sev = f.severity.toLowerCase();
  return (
    <>
      <tr onClick={onToggle} style={{ cursor: "pointer" }} aria-expanded={open}>
        <td><Chip tone={sev === "critical" || sev === "high" ? "fail" : sev === "medium" ? "warn" : "info"} label={f.severity} /></td>
        <td>{f.title}</td>
        <td className="cell-id">{f.affected_asset}{f.affected_endpoint ? ` · ${trunc(f.affected_endpoint, 40)}` : ""}</td>
        <td>{validationLabel(f.validation_state)}</td>
        <td>{Math.round(f.confidence * 100)}%</td>
        <td className="cell-id">{f.scanner} {f.scanner_version}</td>
      </tr>
      {open ? (
        <tr><td colSpan={6} style={{ paddingTop: 0 }}>
          <div className="page-note">{f.description}</div>
          {f.cve || f.cwe || f.mitre ? <div className="page-note cell-id">{[f.cve, f.cwe, f.mitre].filter(Boolean).join(" · ")}</div> : null}
          {f.rationale ? <div className="page-note"><b>Why flagged:</b> {f.rationale}</div> : null}
          {f.missing_evidence ? <div className="page-note" style={{ color: "var(--warn)" }}><b>Missing evidence:</b> {f.missing_evidence}</div> : null}
        </td></tr>
      ) : null}
    </>
  );
}

function validationLabel(v: AssessmentFinding["validation_state"]) {
  switch (v) {
    case "confirmed": return "Confirmed";
    case "probable": return "Probable";
    case "requires_validation": return "Needs validation";
    case "false_positive": return "False positive";
    case "unconfirmed": return "Unconfirmed";
    default: return "Detected";
  }
}

function FindingInspector({ fid }: { fid: string }) {
  const q = useQuery({ queryKey: ["assessment", "finding", fid], queryFn: () => get<FindingDetail>(`/assessment/findings/${fid}`) });
  return (
    <Panel title="Finding inspector" tight>
      <div style={{ padding: 12 }}>
        {q.isPending ? <LoaderRows lines={["Loading finding, evidence and decision"]} />
          : q.error ? <ErrBanner error={q.error} onRetry={() => q.refetch()} />
          : (() => {
              const fd = q.data!;
              return (
                <>
                  <div className="panel-title" style={{ fontSize: 13 }}>{fd.finding.title}</div>
                  <EvidenceBlock evs={fd.evidence} />
                  {fd.decision ? <div style={{ marginTop: 10 }}><DecisionCard d={fd.decision} /></div> : (
                    <div className="page-note" style={{ marginTop: 10 }}>No Brain decision linked to this finding yet.</div>
                  )}
                </>
              );
            })()}
      </div>
    </Panel>
  );
}

function EvidenceBlock({ evs }: { evs: Evidence[] }) {
  if (!evs.length) return <div className="page-note">No evidence artifacts captured for this finding.</div>;
  return (
    <div style={{ display: "grid", gap: 6 }}>
      {evs.map((e) => (
        <details key={e.id}>
          <summary style={{ cursor: "pointer" }}>
            <Icon name="file" size={13} /> {e.kind} · {e.summary} <span className="cell-id">sha256 {trunc(e.content_sha256, 12)} · {e.source_engine} {e.source_version}</span>
          </summary>
          <pre style={{ whiteSpace: "pre-wrap", fontSize: 12, margin: "6px 0 0", maxHeight: 240, overflow: "auto" }}>{e.redacted_content ?? "[content stored as hash only]"}</pre>
        </details>
      ))}
    </div>
  );
}

function DecisionCard({ d }: { d: BrainDecision }) {
  let recs: string[] = [];
  try { recs = JSON.parse(d.recommendations_json || "[]"); } catch { recs = []; }
  return (
    <div className="panel" style={{ padding: 10 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <Chip tone="info" label={d.autonomy_level.replace(/_/g, " ")} />
        <span className="cell-id">{d.decision_type} · risk {d.risk.toFixed(1)} · sec-conf {Math.round(d.security_confidence * 100)}%</span>
      </div>
      <div className="page-note" style={{ marginTop: 6 }}><b>Rationale:</b> {d.rationale}</div>
      {recs.length ? (
        <ul style={{ margin: "6px 0 0 18px", fontSize: 12 }}>
          {recs.map((r, i) => (<li key={i}>{r}</li>))}
        </ul>
      ) : null}
      <div className="page-note cell-id" style={{ marginTop: 6 }}>
        policy: {d.policy_result} · authz: {d.authorization_result} · verification: {d.verification_state} · runtime: {d.model_runtime} ({d.rule_pack_version})
      </div>
    </div>
  );
}