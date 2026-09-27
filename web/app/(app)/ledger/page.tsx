"use client";
/* Authorization ledger — issue, list and revoke written-authorization warrants.
   Active security-testing tools refuse any target not covered by a live
   vuln_scan warrant; this page is where those warrants come from. The server
   (SUPER_ADMIN only) re-validates every field — nothing here is authoritative. */
import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "@/lib/api";
import { isCidr, isDomain, isIp, isIp6 } from "@/lib/scopes";
import { fmtTs } from "@/lib/format";
import { Chip, ErrBanner, Field, LoaderRows, Panel } from "@/components/ui";
import { useToast } from "@/components/toast";
import { KIND_LABEL } from "@/components/warrant";
import type { LedgerList, Warrant } from "@/lib/types";

const KINDS = Object.keys(KIND_LABEL) as Warrant["kind"][];

function scopeEntryOk(e: string): boolean {
  return isIp(e) || isIp6(e) || isCidr(e) || isDomain(e);
}

function defaultUntil(): string {
  const d = new Date(Date.now() + 7 * 86400_000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export default function LedgerPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const [kind, setKind] = useState<Warrant["kind"]>("vuln_scan");
  const [scope, setScope] = useState("");
  const [purpose, setPurpose] = useState("");
  const [ref, setRef] = useState("");
  const [subject, setSubject] = useState("");
  const [until, setUntil] = useState(defaultUntil);
  const [err, setErr] = useState<unknown>(null);

  const list = useQuery({ queryKey: ["ledger", "full"], queryFn: () => get<LedgerList>("/admin/ledger") });
  const refresh = () => qc.invalidateQueries({ queryKey: ["ledger"] });

  const entries = useMemo(
    () => scope.split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean),
    [scope],
  );
  const badEntries = entries.filter((e) => !scopeEntryOk(e));

  const issue = useMutation({
    mutationFn: () =>
      post<Warrant>("/admin/ledger", {
        kind,
        scope: entries,
        purpose: purpose.trim(),
        warrant_ref: ref.trim(),
        subject_name: subject.trim(),
        valid_from: new Date().toISOString(),
        valid_until: new Date(until).toISOString(),
      }),
    onSuccess: (w) => {
      setErr(null);
      setScope(""); setPurpose(""); setRef(""); setSubject("");
      toast.push({ tone: "ok", title: "Warrant issued", text: `${KIND_LABEL[w.kind]} · ${w.warrant_ref} · until ${fmtTs(w.valid_until)}` });
      refresh();
    },
    onError: (e) => setErr(e),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => post<{ ok: boolean }>(`/admin/ledger/${id}/revoke`),
    onSuccess: () => {
      toast.push({ tone: "warn", title: "Warrant revoked", text: "Live sessions bound to it are being terminated." });
      refresh();
    },
    onError: (e) => setErr(e),
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    issue.mutate();
  };

  const now = Date.now();
  const rows = [...(list.data?.warrants ?? [])].sort((a, b) =>
    String(b.valid_until).localeCompare(String(a.valid_until)));
  const formOk = entries.length > 0 && badEntries.length === 0 && entries.length <= 32 &&
    purpose.trim().length >= 12 && ref.trim().length >= 6 && !!until && new Date(until).getTime() > now;

  return (
    <>
      <div className="span-6">
        <Panel title="Issue authorization warrant" tight>
          <form onSubmit={submit} style={{ display: "grid", gap: 10, padding: 12 }}>
            <Field label="Action type" hint="What the written authorization covers">
              <select value={kind} onChange={(e) => setKind(e.target.value as Warrant["kind"])}>
                {KINDS.map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
              </select>
            </Field>
            <Field label="Scope" hint="IPs, CIDR ranges or domains, space/comma separated. Domains cover all subdomains.">
              <textarea className="text" rows={3} value={scope}
                onChange={(e) => setScope(e.target.value)}
                placeholder="10.0.0.0/8 example.com scanme.nmap.org" maxLength={2048} />
            </Field>
            {entries.length ? (
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                {entries.map((e) => (
                  <Chip key={e} tone={scopeEntryOk(e) ? "ok" : "fail"} label={e} />
                ))}
              </div>
            ) : null}
            <Field label="Purpose" hint="Why this work is authorized (min 12 characters)">
              <input className="text" value={purpose} onChange={(e) => setPurpose(e.target.value)}
                minLength={12} maxLength={500} placeholder="Sanctioned vulnerability assessment of owned assets" />
            </Field>
            <Field label="Authorization document ref" hint="Number of the signed authorization (min 6 characters)">
              <input className="text" value={ref} onChange={(e) => setRef(e.target.value)}
                minLength={6} maxLength={120} placeholder="MSME/PENTEST/2026-014" />
            </Field>
            <Field label="Subject / asset owner" hint="Optional — who granted it">
              <input className="text" value={subject} onChange={(e) => setSubject(e.target.value)} maxLength={120} />
            </Field>
            <Field label="Valid until" hint="Capped at 90 days by the server">
              <input className="text" type="datetime-local" value={until}
                onChange={(e) => setUntil(e.target.value)} />
            </Field>
            {err ? <ErrBanner error={err} /> : null}
            <button type="submit" className="btn primary" disabled={!formOk || issue.isPending}>
              {issue.isPending ? "Issuing…" : "Issue warrant"}
            </button>
            <p className="page-note">
              Every issue and revoke is written to the tamper-evident audit chain.
            </p>
          </form>
        </Panel>
      </div>

      <div className="span-6">
        <Panel title={`Ledger (${rows.length})`}>
          {list.isPending ? (
            <LoaderRows lines={["loading authorization ledger"]} />
          ) : (
            <table className="dtable">
              <thead>
                <tr><th>action</th><th>ref</th><th>scope</th><th>valid until</th><th>status</th><th /></tr>
              </thead>
              <tbody>
                {rows.map((w) => {
                  let scopeList: string[] = w.scope ?? [];
                  if (!scopeList.length && w.scope_json) {
                    try { scopeList = JSON.parse(w.scope_json) as string[]; } catch { scopeList = []; }
                  }
                  const state = w.revoked_at ? "revoked"
                    : new Date(w.valid_until).getTime() < now ? "expired"
                    : "active";
                  return (
                    <tr key={w.id}>
                      <td>{KIND_LABEL[w.kind]}</td>
                      <td title={w.purpose}>{w.warrant_ref}</td>
                      <td className="mono-dim">{scopeList.join(", ")}</td>
                      <td>{fmtTs(w.valid_until)}</td>
                      <td><Chip tone={state === "active" ? "ok" : state === "expired" ? "warn" : "fail"} label={state} /></td>
                      <td>
                        {state === "active" ? (
                          <button type="button" className="btn small danger"
                            disabled={revoke.isPending}
                            onClick={() => revoke.mutate(w.id)}>
                            Revoke
                          </button>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </>
  );
}
