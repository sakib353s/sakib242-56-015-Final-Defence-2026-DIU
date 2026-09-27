"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "@/lib/api";
import { fmtTs, humanStatus, statusTone, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { WarrantPicker, useWarrantEnforced, type Verdict } from "@/components/warrant";
import { Chip, EmptyRows, ErrBanner, Field, LoaderRows, Meter, Modal, Panel, Segmented } from "@/components/ui";
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
  { id: "quick", label: "Quick", hint: "DNS, TLS and HTTP surface" },
  { id: "standard", label: "Standard", hint: "Discovery, technology and configuration analysis" },
  { id: "deep", label: "Deep", hint: "Everything, plus endpoint discovery and correlation" },
];

export default function AssessmentPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const { requestTotp } = useStepUp();

  const [warrantId, setWarrantId] = useState("");
  const enf = useWarrantEnforced();
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<"quick" | "standard" | "deep">("standard");
  const [attestOpen, setAttestOpen] = useState(false);
  const [attested, setAttested] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [openFinding, setOpenFinding] = useState<string | null>(null);
  const [verdict, setVerdict] = useState<Verdict>({ state: "empty" });

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
      // POST /assessment returns the small kickoff shape {id,target,...} — NOT a
      // full Assessment row; typing it as Assessment printed "undefined" in the toast.
      const a = await post<{ id: string; target: string }>(
        "/assessment",
        { target: target.trim(), warrant_id: warrantId, profile, authorization_confirmed: true },
        totp,
      );
      await post(`/assessment/${a.id}/start`, {}, totp);
      return a;
    },
    onSuccess: (a) => {
      toast.push({ tone: "ok", title: "Assessment running", text: `${a.target} · ${trunc(a.id, 10)}` });
      setSelected(a.id);
      setAttestOpen(false);
      setAttested(false);
      qc.invalidateQueries({ queryKey: ["assessment"] });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Run refused", text: String((e as Error).message) }),
  });

  const cancelMut = useMutation({
    mutationFn: (id: string) => post(`/assessment/${id}/cancel`),
    onSuccess: () => {
      toast.push({ tone: "warn", title: "Cancellation requested", text: "Evidence collected so far is preserved." });
      qc.invalidateQueries({ queryKey: ["assessment"] });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Cancel failed", text: String((e as Error).message) }),
  });

  async function arm() {
    const code = await requestTotp(`assessment: analyze ${target} (${profile})`);
    if (code) create.mutate(code);
  }

  const running = rows.some((r) => ACTIVE.has(r.status));

  return (
    <>
      <div className="span-12">
        <Panel
          title="Launch an assessment"
          actions={<Chip tone={running ? "warn" : "dim"} label={running ? "Run in progress" : "Engines idle"} />}
        >
          <div className="launch-grid">
            <Field label="Authorization">
              <WarrantPicker kind="pentest" value={warrantId} onChange={setWarrantId} target={target} onVerdict={setVerdict} />
            </Field>
            <Field label="Target" hint="IP, domain or URL — the host is checked against the scope live.">
              <input className="text" placeholder="10.0.0.5 · internal.example.com" value={target} onChange={(e) => setTarget(e.target.value)} maxLength={500} />
            </Field>
            <Field label="Depth">
              <Segmented
                ariaLabel="Assessment depth"
                options={PROFILES.map((p) => ({ id: p.id, label: p.label }))}
                value={profile}
                onChange={(id) => setProfile(id as typeof profile)}
              />
              <span className="field-note">{PROFILES.find((p) => p.id === profile)?.hint}</span>
            </Field>
            <div className="launch-cta">
              <span className="label-twin" aria-hidden>&nbsp;</span>
              <button
                type="button"
                className={`btn go ${verdict.state === "outside" ? "warn" : "primary"}`}
                disabled={(enf && !warrantId) || target.trim().length < 4}
                onClick={() => setAttestOpen(true)}
                title={verdict.state === "outside" ? "The server will refuse this target — see the scope verdict" : undefined}
              >
                Run assessment
              </button>
              <span className="field-note">Passive observation plus single benign requests — no exploit payloads.</span>
            </div>
          </div>
        </Panel>
      </div>

      <div className="span-12">
        <div className="wb">
          <div>
            <div className="panel-title" style={{ marginBottom: 8 }}>Runs · {rows.length}</div>
            {list.isPending ? (
              <LoaderRows lines={["Loading assessments"]} />
            ) : list.error ? (
              <ErrBanner error={list.error} onRetry={() => list.refetch()} />
            ) : !rows.length ? (
              <EmptyRows what="No assessments yet — the first run will appear here" />
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

          <Panel title="Live workspace" tight>
            {!selected ? (
              <div style={{ padding: 12 }}><EmptyRows what="Select a run to open its live workspace" /></div>
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
          <button type="button" className="btn primary" disabled={!attested} onClick={() => { setAttestOpen(false); void arm(); }}>Confirm and run</button>
        </>}>
          <div className="problem" style={{ marginTop: 0 }}>
            <div className="pt">This operation touches systems outside your own</div>
            <div className="pd">You are about to assess <b style={{ color: "var(--hdr)" }}>{target}</b> at <b>{profile}</b> depth. The server re-checks authorization type, validity window, scope and revocation before dispatch and inside every privileged stage. Scope drift aborts the run and preserves collected evidence.</div>
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
      <div className="ws-head">
        <span className="ws-target">{a.target_canonical}</span>
        <Chip tone={statusTone(a.status)} label={humanStatus(a.status)} />
        <span className="cell-id">{trunc(a.id, 18)} · {a.profile}</span>
        <span className="ws-actions">
          {canCancel ? <button type="button" className="btn small danger" disabled={cancelling} onClick={() => onCancel(a.id)}>Cancel</button> : null}
          <ExportStixButton aid={a.id} />
        </span>
      </div>
      <div style={{ margin: "6px 0 10px" }}>
        <RiskGauge score={a.risk_score} />
        <div className="page-note" style={{ marginTop: 6 }}>
          {a.observations_count} observations · {findings.length} findings · {brain_decisions.length} Brain decisions
          {a.risk_version ? ` · risk model ${a.risk_version}` : ""}
        </div>
      </div>
      {a.aborted_reason ? (
        <div className="problem" style={{ marginTop: 8 }}>
          <div className="pt">Run halted</div>
          <div className="pd">{a.aborted_reason}</div>
        </div>
      ) : null}
      {a.status === "WORKER_LOST" || a.status === "UNKNOWN_RESULT" ? (
        <div className="problem" style={{ marginTop: 8 }}>
          <div className="pt">{a.status === "WORKER_LOST" ? "Worker lost" : "Unknown result"}</div>
          <div className="pd">The execution state cannot be confirmed. Collected evidence is preserved and nothing has been marked successful.</div>
        </div>
      ) : null}

      <StageRail stages={stages} progress={a.progress} active={ACTIVE.has(a.status)} />

      <div className="panel-title" style={{ margin: "12px 0 6px" }}>Findings · {findings.length}</div>
      {!findings.length ? (
        <EmptyRows what={ACTIVE.has(a.status) ? "Findings appear here as stages complete" : "No findings produced by this run"} />
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
        <span key={s.id} title={s.message ?? s.label}
          className={`step${s.status === "completed" ? " done" : s.status === "failed" ? " fail" : s.status === "running" ? " cur" : ""}`}
          style={s.status === "degraded" || s.status === "skipped" ? { opacity: 0.55 } : undefined}>
          {s.label}{s.status === "degraded" ? " ⚠" : s.status === "skipped" ? " –" : ""}
        </span>
      ))}
      <span className="step step-progress">
        <Meter className="meter-inline" v={progress} max={1} tone={active ? "info" : progress >= 1 ? "ok" : "fail"} />
        {Math.round(progress * 100)}%
      </span>
    </div>
  );
}

function ExportStixButton({ aid }: { aid: string }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  return (
    <button type="button" className="btn small" disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const bundle = await get<Record<string, unknown>>(`/ti/export/${aid}`);
                const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const link = document.createElement("a");
                link.href = url;
                link.download = `cwb-${aid.slice(0, 8)}.stix2.json`;
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);
                toast.push({ tone: "ok", title: "STIX 2.1 bundle exported", text: "Evidence-backed intelligence bundle" });
              } catch (e) {
                toast.push({ tone: "fail", title: "Export failed", text: String((e as Error).message) });
              } finally {
                setBusy(false);
              }
            }}>
      {busy ? "Exporting…" : "Export STIX"}
    </button>
  );
}

function FindingRow({ f, open, onToggle }: { f: AssessmentFinding; open: boolean; onToggle: () => void }) {
  const sev = f.severity.toLowerCase();
  return (
    <>
      <tr onClick={onToggle} style={{ cursor: "pointer" }}>
        <td><Chip tone={sev === "critical" || sev === "high" ? "fail" : sev === "medium" ? "warn" : "info"} label={f.severity} /></td>
        <td>{f.title}</td>
        <td className="cell-id">{f.host}{f.endpoint ? ` · ${trunc(f.endpoint, 40)}` : ""}</td>
        <td>{detectionLabel(f.detection_state)} · {LC_SHORT[f.lifecycle]}</td>
        <td>{Math.round((f.confidence ?? 0) * 100)}%</td>
        <td className="cell-id">{f.source_engine} {f.source_version || ""}</td>
      </tr>
      {open ? (
        <tr><td colSpan={6} style={{ paddingTop: 0 }}>
          <div className="page-note">{f.description}</div>
          {f.impact ? <div className="page-note"><b>Impact:</b> {f.impact}</div> : null}
          {f.remediation_hint ? <div className="page-note"><b>Recommended:</b> {f.remediation_hint}</div> : null}
          {f.cve || f.cwe || f.mitre ? <div className="page-note cell-id">{[f.cve, f.cwe, f.mitre].filter(Boolean).join(" · ")}</div> : null}
        </td></tr>
      ) : null}
    </>
  );
}

const LC_SHORT: Record<string, string> = {
  detected: "new", triaged: "triaged", validating: "validating", confirmed: "confirmed",
  remediation_recommended: "fix proposed", remediated: "remediated", verified_fixed: "verified",
  false_positive: "FP", not_reproducible: "n/r", unconfirmed: "unconfirmed",
  actioned_but_not_verified: "unverified",
};

function detectionLabel(v: string) {
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
                  <div className="page-note" style={{ margin: "4px 0 8px" }}>
                    {fd.finding.description}
                  </div>
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
            <Icon name="file" size={13} /> {e.kind} · {e.description || e.ref}{" "}
            <span className="cell-id">sha256 {trunc(e.sha256 || "", 12)} · {e.produced_by} {e.produced_version || ""}{e.redacted ? " · redacted" : ""}</span>
          </summary>
          <div className="page-note cell-id" style={{ margin: "6px 0 0" }}>
            source: {e.produced_by} {e.produced_version || ""} · ref {trunc(e.ref, 60)} · captured {fmtTs(e.captured_at)}
            · integrity: SHA-256 {e.sha256 || "not recorded"}
          </div>
        </details>
      ))}
    </div>
  );
}

interface Rationale {
  why_flagged?: string;
  why_recommendation?: string;
  why_autonomy?: string;
  evidence_supporting?: string[];
  evidence_missing?: string[];
  posture?: number;
  material_findings?: number;
  next_best_step?: string;
}

function DecisionCard({ d }: { d: BrainDecision }) {
  let recs: string[] = [];
  try { recs = JSON.parse(d.recommendations_json || "[]"); } catch { recs = []; }
  let rat: Rationale = {};
  try { rat = JSON.parse(d.rationale_json || "{}"); } catch { rat = {}; }
  return (
    <div className="panel" style={{ padding: 10 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <Chip tone="info" label={d.autonomy_level.replace(/_/g, " ")} />
        <span className="cell-id">
          {d.classification || "decision"} · risk {(d.risk ?? 0).toFixed(1)} · confidence {Math.round((d.security_confidence ?? 0) * 100)}%
        </span>
      </div>
      {rat.why_flagged ? <div className="page-note" style={{ marginTop: 6 }}><b>Why flagged:</b> {rat.why_flagged}</div> : null}
      {rat.why_recommendation ? <div className="page-note"><b>Why this recommendation:</b> {rat.why_recommendation}</div> : null}
      {rat.why_autonomy ? <div className="page-note"><b>Autonomy:</b> {rat.why_autonomy}</div> : null}
      {rat.next_best_step ? <div className="page-note"><b>Next best step:</b> {rat.next_best_step}</div> : null}
      {rat.evidence_missing && rat.evidence_missing.length ? (
        <div className="page-note" style={{ color: "var(--warn)" }}><b>Missing evidence:</b> {rat.evidence_missing.join(" · ")}</div>
      ) : null}
      {recs.length ? (
        <ul style={{ margin: "6px 0 0 18px", fontSize: 12 }}>
          {recs.map((r, i) => (<li key={i}>{r}</li>))}
        </ul>
      ) : null}
      <div className="page-note cell-id" style={{ marginTop: 6 }}>
        policy: {d.policy_result || "—"} · authz: {d.authorization_result || "—"} · verification: {d.verification_state} · runtime: {d.model_runtime || "—"} ({d.rule_pack_version || "?"})
      </div>
    </div>
  );
}
