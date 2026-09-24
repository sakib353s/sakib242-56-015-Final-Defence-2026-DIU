"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiFetch, get, post } from "@/lib/api";
import { fmtTs, humanStatus, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { Chip, EmptyRows, ErrBanner, Field, KV, Leader, LoaderRows, Panel } from "@/components/ui";
import type { ChainVerify, ComplaintDrafts, VictimCaseDetail, VictimCaseRow } from "@/lib/types";

const TYPES = ["fraud", "harassment", "leak", "other"] as const;
const TYPE_LABEL: Record<string, string> = { fraud: "Fraud", harassment: "Harassment", leak: "Data leak", other: "Other" };
const STEPS = ["Case type", "Complainant", "Statement"];

function human(s: string): string {
  return s.replace(/[._]/g, " ");
}

export default function VictimPage() {
  const toast = useToast();
  const { requestTotp } = useStepUp();

  const [step, setStep] = useState(0);
  const [caseType, setCaseType] = useState<string>("fraud");
  const [cName, setCName] = useState("");
  const [cPhone, setCPhone] = useState("");
  const [cEmail, setCEmail] = useState("");
  const [narrative, setNarrative] = useState("");
  const [consent, setConsent] = useState(false);
  const [consentDoc, setConsentDoc] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [evAction, setEvAction] = useState("");
  const [evRef, setEvRef] = useState("");

  const cases = useQuery({ queryKey: ["victim", "cases"], queryFn: () => get<{ cases: VictimCaseRow[] }>("/victim/cases") });
  const detail = useQuery({
    queryKey: ["victim", "detail", selected],
    queryFn: () => get<VictimCaseDetail>(`/victim/cases/${selected}`),
    enabled: !!selected,
  });
  const chain = useQuery({
    queryKey: ["victim", "chain", selected],
    queryFn: () => get<ChainVerify>(`/victim/cases/${selected}/timeline`),
    enabled: !!selected,
  });

  useEffect(() => {
    if (!selected && (cases.data?.cases ?? []).length) setSelected(cases.data!.cases[0].id);
  }, [selected, cases.data]);

  const create = useMutation({
    mutationFn: () =>
      post<{ case_id: string; status: string }>("/victim/cases", {
        case_type: caseType,
        complainant: Object.fromEntries(
          Object.entries({ name: cName, phone: cPhone, email: cEmail }).filter(([, v]) => v.trim()),
        ),
        narrative,
        consent_attested: consent,
        consent_doc_id: consentDoc || null,
      }),
    onSuccess: (r) => {
      toast.push({ tone: "ok", title: "Case opened", text: `${r.status} · ${trunc(r.case_id, 10)}` });
      setStep(0);
      setNarrative("");
      setConsent(false);
      cases.refetch();
      setSelected(r.case_id);
    },
  });

  const addEvent = useMutation({
    mutationFn: () => apiFetch<{ event_id: string; seq: number; hash: string }>(`/victim/cases/${selected}/timeline`, {
      method: "POST",
      body: { action: evAction.trim(), evidence_ref: evRef.trim() || null },
    }),
    onSuccess: (r) => {
      toast.push({ tone: "ok", title: `Timeline entry ${r.seq}`, text: trunc(r.hash, 16) });
      setEvAction("");
      setEvRef("");
      detail.refetch();
      chain.refetch();
    },
  });

  const complaint = useMutation({
    mutationFn: async (totp: string) =>
      apiFetch<ComplaintDrafts>(`/victim/cases/${selected}/complaints`, { method: "POST", totp }),
    onSuccess: () => {
      toast.push({ tone: "warn", title: "Drafts generated", text: "Human review is required before filing" });
      detail.refetch();
    },
  });

  return (
    <>
      <div className="span-12">
        <Panel title="Report intake">
          <div className="stepper" style={{ marginBottom: 12 }}>
            {STEPS.map((s, i) => (
              <span key={s} className={`step${i === step ? " cur" : i < step ? " done" : ""}`}>
                {i + 1}. {s}
              </span>
            ))}
          </div>
          {step === 0 ? (
            <>
              <Field label="Case type" hint="Choose the category that best fits what was reported.">
                <select value={caseType} onChange={(e) => setCaseType(e.target.value)}>
                  {TYPES.map((t) => (
                    <option key={t} value={t}>
                      {TYPE_LABEL[t] ?? t}
                    </option>
                  ))}
                </select>
              </Field>
              <button type="button" className="btn primary" onClick={() => setStep(1)}>
                Next: complainant details
              </button>
            </>
          ) : step === 1 ? (
            <>
              <div className="form-row">
                <Field label="Name">
                  <input className="text" value={cName} onChange={(e) => setCName(e.target.value)} maxLength={120} />
                </Field>
                <Field label="Phone">
                  <input className="text" value={cPhone} onChange={(e) => setCPhone(e.target.value)} maxLength={32} placeholder="+8801XXXXXXXXX" />
                </Field>
                <Field label="Email">
                  <input className="text" value={cEmail} onChange={(e) => setCEmail(e.target.value)} maxLength={120} />
                </Field>
              </div>
              <div className="page-note" style={{ margin: "4px 0 10px" }}>
                Complainant details are encrypted at rest and are never sent to third parties
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button type="button" className="btn" onClick={() => setStep(0)}>
                  Back
                </button>
                <button type="button" className="btn primary" disabled={!cName && !cPhone && !cEmail} onClick={() => setStep(2)}>
                  Next: incident narrative
                </button>
              </div>
            </>
          ) : (
            <>
              <Field label={`Incident narrative (${narrative.length}/4000)`} hint="At least 20 characters. Include dates, platforms, amounts, and URLs.">
                <textarea style={{ minHeight: 140 }} value={narrative} onChange={(e) => setNarrative(e.target.value.slice(0, 4000))} />
              </Field>
              <label className="checkline" style={{ marginBottom: 6 }}>
                <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
                Victim consent has been obtained and confirmed. This is required by the server.
              </label>
              <Field label="Consent document ID (optional)">
                <input className="text" value={consentDoc} onChange={(e) => setConsentDoc(e.target.value)} placeholder="Document ID from the document module" />
              </Field>
              {create.isError ? <ErrBanner error={create.error} /> : null}
              <div style={{ display: "flex", gap: 8 }}>
                <button type="button" className="btn" onClick={() => setStep(1)}>
                  Back
                </button>
                <button
                  type="button"
                  className="btn primary"
                  disabled={!consent || narrative.trim().length < 20 || create.isPending}
                  onClick={() => create.mutate()}
                >
                  File case
                </button>
              </div>
            </>
          )}
        </Panel>
      </div>

      <div className="span-12">
        <div className="wb">
          <div>
            <div className="panel-title" style={{ marginBottom: 8 }}>Cases · {(cases.data?.cases ?? []).length}</div>
            {cases.isPending ? (
              <LoaderRows lines={["Loading cases"]} />
            ) : cases.error ? (
              <ErrBanner error={cases.error} onRetry={() => cases.refetch()} />
            ) : !cases.data!.cases.length ? (
              <EmptyRows what="No victim cases recorded yet" />
            ) : (
              <div className="wb-list" role="listbox" aria-label="Victim cases">
                {cases.data!.cases.map((c) => (
                  <button
                    key={c.id}
                    type="button"
                    role="option"
                    aria-selected={selected === c.id}
                    className={`wb-item${selected === c.id ? " on" : ""}`}
                    onClick={() => setSelected(c.id)}
                  >
                    <span className={`wb-dot ${c.status === "OPEN" ? "run" : "ok"}`} aria-hidden />
                    <span className="wb-main">
                      <span className="wb-target">{TYPE_LABEL[c.case_type] ?? c.case_type}</span>
                      <span className="wb-meta">{fmtTs(c.created_at)} · {trunc(c.id, 10)}</span>
                    </span>
                    <span className="wb-side">
                      <Chip tone={c.status === "OPEN" ? "info" : "ok"} label={humanStatus(c.status)} />
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <Panel
            title="Case record and evidence timeline"
            tight
            actions={
              selected ? (
                <button
                  type="button"
                  className="btn small warn"
                  disabled={complaint.isPending}
                  onClick={async () => {
                    const code = await requestTotp("victim: generate draft complaints for BTRC and Cyber Police");
                    if (code) complaint.mutate(code);
                  }}
                >
                  Generate draft complaints
                </button>
              ) : null
            }
          >
            {!selected ? (
              <div style={{ padding: 12 }}>
                <EmptyRows what="Select a case to view its evidence timeline" />
              </div>
            ) : detail.isPending ? (
              <LoaderRows lines={["Loading the case", "Decrypting complainant details and ordering the timeline"]} />
            ) : detail.error ? (
              <div style={{ padding: 12 }}>
                <ErrBanner error={detail.error} onRetry={() => detail.refetch()} />
              </div>
            ) : (
              <div style={{ padding: 12, display: "grid", gridTemplateColumns: "minmax(0,7fr) minmax(0,5fr)", gap: 16 }}>
                <div>
                  <KV
                    rows={[
                      ["Case", `${detail.data.case.id}`],
                      ["Type and status", `${TYPE_LABEL[detail.data.case.case_type] ?? detail.data.case.case_type} · ${detail.data.case.status}`],
                      ["Opened", fmtTs(detail.data.case.created_at)],
                      [
                        "Complainant",
                        Object.entries(detail.data.complainant)
                          .map(([k, v]) => `${human(k)}: ${v}`)
                          .join(" · ") || "—",
                      ],
                      ["Narrative", detail.data.case.narrative],
                    ]}
                  />
                  <div style={{ marginTop: 10 }}>
                    {chain.data ? (
                      chain.data.ok ? (
                        <Leader label="Timeline integrity" value={`Verified intact · ${chain.data.events} events`} tone="ok" />
                      ) : (
                        <div className="problem">
                          <div className="pt">Timeline integrity check failed at entry {chain.data.broken_at_seq}</div>
                          <div className="pd">The HMAC chain over this evidence log is broken. Treat every entry from that sequence onward as unverified and escalate.</div>
                        </div>
                      )
                    ) : (
                      <LoaderRows lines={["Verifying the HMAC chain"]} />
                    )}
                  </div>
                  {complaint.data ? (
                    <div className="lockline" style={{ marginTop: 10 }}>
                      Draft: {complaint.data.note}
                      <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                        {Object.entries(complaint.data.drafts).map(([agency, d]) => (
                          <li key={agency}>
                            <a className="btn small" href={d.download} target="_blank" rel="noreferrer" style={{ textDecoration: "none" }}>
                              {agency === "btrc" ? "BTRC" : "Cyber Police"} complaint PDF
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                  {complaint.isError ? <ErrBanner error={complaint.error} /> : null}
                </div>
                <div>
                  <div className="page-note" style={{ marginBottom: 6 }}>Append an entry (hash-chained)</div>
                  <Field label="Action">
                    <input className="text" value={evAction} onChange={(e) => setEvAction(e.target.value)} placeholder="Evidence received" maxLength={120} />
                  </Field>
                  <Field label="Evidence reference (optional)">
                    <input className="text" value={evRef} onChange={(e) => setEvRef(e.target.value)} placeholder="Document ID or exhibit reference" />
                  </Field>
                  <button type="button" className="btn primary small" disabled={evAction.trim().length < 3 || addEvent.isPending} onClick={() => addEvent.mutate()}>
                    Append entry
                  </button>
                  {addEvent.isError ? <ErrBanner error={addEvent.error} /> : null}
                  <ol className="stepper-flow" style={{ marginTop: 14 }}>
                    {detail.data.timeline.map((t) => (
                      <li key={t.seq}>
                        <span className="sf-badge">{t.seq}</span>
                        <div className="sf-step">
                          <span className="sf-title">
                            {human(t.action)} <span className="cell-id">{fmtTs(t.ts)}</span>
                          </span>
                          <span className="sf-detail">
                            {t.evidence_ref ? trunc(t.evidence_ref, 44) : "No exhibit"} · {trunc(t.hash, 16)}
                          </span>
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}
