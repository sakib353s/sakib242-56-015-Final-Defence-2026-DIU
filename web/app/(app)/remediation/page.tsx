"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "@/lib/api";
import { fmtTs, humanStatus, statusTone, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { WarrantPicker } from "@/components/warrant";
import { sevVar } from "@/components/findings";
import { Chip, EmptyRows, ErrBanner, Field, LoaderRows, Modal, Panel } from "@/components/ui";
import type { Finding, HwAsset, RemediationDiff, RemediationJob } from "@/lib/types";

/* The saga states are wire values. A chip should say what happened, not echo the column. */
const STATE_LABEL: Record<string, string> = {
  DRAFT: "Draft",
  CONSENTED: "Consent recorded",
  APPLIED: "Applied",
  APPLIED_UNVERIFIED: "Applied, unverified",
  ROLLED_BACK: "Rolled back",
  ABORTED: "Aborted",
};

function stateLabel(s: string | null | undefined): string {
  if (!s) return "—";
  return STATE_LABEL[s] ?? humanStatus(s);
}

export default function RemediationPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const { requestTotp } = useStepUp();

  const [findingId, setFindingId] = useState("");
  const [host, setHost] = useState("");
  const [warrantId, setWarrantId] = useState("");
  const [assetId, setAssetId] = useState("");
  const [attested, setAttested] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [consentOpen, setConsentOpen] = useState(false);
  const [consentCode, setConsentCode] = useState("");

  const jobs = useQuery({ queryKey: ["remediation", "jobs"], queryFn: () => get<{ jobs: RemediationJob[] }>("/remediation/jobs") });
  const diff = useQuery({
    queryKey: ["remediation", "diff", selected],
    queryFn: () => get<RemediationDiff>(`/remediation/jobs/${selected}/diff`),
    enabled: !!selected,
  });
  const assets = useQuery({ queryKey: ["hardware", "assets"], queryFn: () => get<{ assets: HwAsset[] }>("/hardware/assets") });
  const findingsQ = useQuery({
    queryKey: ["remediation", "findings"],
    queryFn: () => get<{ findings: (Finding & { job_count: number })[] }>("/remediation/findings"),
  });
  const selFinding = (findingsQ.data?.findings ?? []).find((f) => f.id === findingId);

  useEffect(() => {
    // Default the picker to the most severe open finding so the launch form is usable at rest.
    if (!findingId && findingsQ.data?.findings?.length) {
      const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      const best = [...findingsQ.data.findings].sort((a, b) => (rank[(a.severity || "").toUpperCase()] ?? 4) - (rank[(b.severity || "").toUpperCase()] ?? 4))[0];
      setFindingId(best.id);
      setHost(best.host);
    }
  }, [findingId, findingsQ.data]);

  useEffect(() => {
    if (!selected && (jobs.data?.jobs ?? []).length) setSelected(jobs.data!.jobs[0].id);  }, [selected, jobs.data]);

  const create = useMutation({
    mutationFn: async (totp: string) =>
      post<{ job_id: string; state: string }>(
        "/remediation/jobs",
        {
          finding_id: findingId,
          host: host.trim().toLowerCase(),
          warrant_id: warrantId,
          asset_id: assetId || null,
          authorization_confirmed: true,
        },
        totp,
      ),
    onSuccess: (r) => {
      toast.push({ tone: "ok", title: "Draft job created", text: `${stateLabel(r.state)} · ${trunc(r.job_id, 10)}` });
      setSelected(r.job_id);
      setFindingId("");
      setAttested(false);
      qc.invalidateQueries({ queryKey: ["remediation"] });
    },
  });

  const consent = useMutation({
    mutationFn: () => post<{ state: string }>(`/remediation/jobs/${selected}/consent`, undefined, consentCode),
    onSuccess: () => {
      toast.push({ tone: "ok", title: "Consent recorded", text: "The job is ready to apply." });
      setConsentOpen(false);
      setConsentCode("");
      qc.invalidateQueries({ queryKey: ["remediation"] });
    },
  });

  const apply = useMutation({
    mutationFn: async (totp: string) => post<{ state: string; log: string[] }>(`/remediation/jobs/${selected}/apply`, undefined, totp),
    onSuccess: (r) => {
      toast.push({ tone: "ok", title: `Job ${stateLabel(r.state)}`, text: r.log.join(" · ").slice(0, 140) });
      qc.invalidateQueries({ queryKey: ["remediation"] });
    },
  });

  const rollback = useMutation({
    mutationFn: async (totp: string) => post<{ state: string }>(`/remediation/jobs/${selected}/rollback`, undefined, totp),
    onSuccess: (r) => {
      toast.push({ tone: "warn", title: `Job ${stateLabel(r.state)}`, text: "Snapshot restored" });
      qc.invalidateQueries({ queryKey: ["remediation"] });
    },
  });

  const state = diff.data?.state;

  return (
    <>
      <div className="span-4">
        <Panel title="New remediation">
          <div className="page-note" style={{ marginBottom: 10 }}>
            Two approvals are required: an active remediation authorization and confirmation from an
            administrator with a fresh verification code. Every change is written to the audit log.
          </div>
          <Field label="Finding" hint="Recorded by a penetration test or vulnerability scan under its own authorization.">
            {findingsQ.isPending ? (
              <LoaderRows lines={["Loading findings"]} />
            ) : findingsQ.error ? (
              <ErrBanner error={findingsQ.error} onRetry={() => findingsQ.refetch()} />
            ) : !(findingsQ.data?.findings ?? []).length ? (
              <div className="lockline">No findings are recorded yet. Run an authorized scan first.</div>
            ) : (
              <>
                <select
                  className="text"
                  value={findingId}
                  onChange={(e) => {
                    const f = (findingsQ.data?.findings ?? []).find((x) => x.id === e.target.value);
                    setFindingId(f ? f.id : "");
                    if (f) setHost(f.host);
                  }}
                >
                  <option value="">— select a finding —</option>
                  {(findingsQ.data!.findings ?? []).map((f) => (
                    <option key={f.id} value={f.id}>
                      {f.severity} · {f.host}{f.port ? `:${f.port}` : ""} · {f.cve || f.service || trunc(f.description, 24)}
                      {f.job_count ? ` · ${f.job_count} job${f.job_count === 1 ? "" : "s"}` : ""}
                    </option>
                  ))}
                </select>
                {selFinding ? (
                  <div className="page-note" style={{ marginTop: 6, display: "flex", gap: 8, alignItems: "center" }}>
                    <Chip tone={(selFinding.severity || "").toLowerCase()} label={humanStatus(selFinding.severity)} />
                    <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{trunc(selFinding.description, 70)}</span>
                  </div>
                ) : null}
              </>
            )}
          </Field>
          <Field label="Host">
            <input className="text" value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.7" />
          </Field>
          <Field label="Authorization (remediation)">
            <WarrantPicker kind="remediation" value={warrantId} onChange={setWarrantId} />
          </Field>
          <Field label="Linked asset (optional)">
            <select value={assetId} onChange={(e) => setAssetId(e.target.value)}>
              <option value="">— none —</option>
              {(assets.data?.assets ?? []).map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} · {a.host}
                </option>
              ))}
            </select>
          </Field>
          <label className="checkline" style={{ marginBottom: 10 }}>
            <input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} />
            I confirm asset ownership and that written authorization is in force.
          </label>
          <button
            type="button"
            className="btn primary"
            disabled={!attested || !findingId || !host || !warrantId}
            onClick={async () => {
              const code = await requestTotp(`remediation: draft job for ${host}`);
              if (code) create.mutate(code);
            }}
          >
            Generate diff
          </button>
          {create.isError ? <ErrBanner error={create.error} /> : null}
        </Panel>
      </div>

      <div className="span-8">
        <Panel title="Jobs" tight>
          {jobs.isPending ? (
            <LoaderRows lines={["Loading change jobs"]} />
          ) : jobs.error ? (
            <div style={{ padding: 12 }}>
              <ErrBanner error={jobs.error} onRetry={() => jobs.refetch()} />
            </div>
          ) : !jobs.data!.jobs.length ? (
            <EmptyRows what="No remediation jobs" />
          ) : (
            <table className="dtable">
              <thead>
                <tr>
                  <th>Created</th>
                  <th>Host</th>
                  <th>Finding</th>
                  <th>Updated</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {jobs.data!.jobs.map((j) => {
                  const f = (findingsQ.data?.findings ?? []).find((x) => x.id === j.finding_id);
                  return (
                    <tr
                      key={j.id}
                      className={`click sev-strip${selected === j.id ? " sel" : ""}`}
                      style={{ "--sev": sevVar(f?.severity), whiteSpace: "nowrap" } as React.CSSProperties}
                      onClick={() => setSelected(j.id)}
                      tabIndex={0}
                      onKeyDown={(e) => e.key === "Enter" && setSelected(j.id)}
                    >
                      <td className="cell-id">{fmtTs(j.created_at)}</td>
                      <td>{j.host}</td>
                      <td className="cell-id">
                        {f ? (
                          <Chip tone={(f.severity || "").toLowerCase()} label={f.cve || humanStatus(f.severity)} />
                        ) : (
                          trunc(j.finding_id, 14)
                        )}
                      </td>
                      <td className="cell-id">{fmtTs(j.updated_at)}</td>
                      <td>
                        <Chip tone={statusTone(j.state)} label={stateLabel(j.state)} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Panel>
      </div>

      <div className="span-12">
        <Panel title="Change preview" tight>
          {!selected ? (
            <div style={{ padding: 12 }}>
              <EmptyRows what="Select a job to preview its diff" />
            </div>
          ) : diff.isPending ? (
            <LoaderRows lines={["Building the change preview", "Comparing the proposed state against the host"]} />
          ) : diff.error ? (
            <div style={{ padding: 12 }}>
              <ErrBanner error={diff.error} onRetry={() => diff.refetch()} />
            </div>
          ) : (
            <div style={{ padding: 12 }}>
              <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
                <Chip tone={statusTone(diff.data!.state)} label={stateLabel(diff.data!.state)} />
                <code className="diff-script" title={diff.data!.script}>{diff.data!.script}</code>
                <span style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
                  <button type="button" className="btn primary" disabled={state !== "DRAFT"} onClick={() => setConsentOpen(true)}>
                    Record consent
                  </button>
                  <button
                    type="button"
                    className="btn danger"
                    disabled={state !== "CONSENTED"}
                    onClick={async () => {
                      const code = await requestTotp(`remediation: APPLY job on ${diff.data ? diff.data.job_id.slice(0, 8) : ""}`);
                      if (code) apply.mutate(code);
                    }}
                  >
                    Apply change
                  </button>
                  <button
                    type="button"
                    className="btn warn"
                    disabled={state !== "APPLIED" && state !== "APPLIED_UNVERIFIED"}
                    onClick={async () => {
                      const code = await requestTotp(`remediation: ROLLBACK from snapshot`);
                      if (code) rollback.mutate(code);
                    }}
                  >
                    Roll back
                  </button>
                </span>
              </div>
              {apply.isError ? <ErrBanner error={apply.error} /> : null}
              {rollback.isError ? <ErrBanner error={rollback.error} /> : null}
              <pre className="diff">
                {diff.data!.diff.map((l, i) => (
                  <span key={i} className={l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : l.startsWith("@@") ? "hunk" : "ctx"}>
                    {l}
                    {"\n"}
                  </span>
                ))}
              </pre>
            </div>
          )}
        </Panel>
      </div>

      {consentOpen ? (
        <Modal
          title="Record consent"
          onClose={() => setConsentOpen(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setConsentOpen(false)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn primary"
                disabled={consentCode.length !== 6 || consent.isPending}
                onClick={() => consent.mutate()}
              >
                Sign and consent
              </button>
            </>
          }
        >
          <div className="page-note" style={{ marginBottom: 10 }}>
            Consent is recorded against the exact change previewed above, together with your current
            verification code. It authorizes the remediation script to run on the linked asset.
          </div>
          <Field label="Current verification code" hint="Valid for about 30 seconds and for this action only.">
            <input
              className="text"
              inputMode="numeric"
              maxLength={6}
              value={consentCode}
              onChange={(e) => setConsentCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="6-digit code"
            />
          </Field>
          {consent.isError ? <ErrBanner error={consent.error} /> : null}
        </Modal>
      ) : null}
    </>
  );
}
