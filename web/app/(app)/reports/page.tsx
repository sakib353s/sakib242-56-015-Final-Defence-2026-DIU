"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch, get, qs } from "@/lib/api";
import { fmtTs, humanStatus, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { DonutStat, SERIES, Trend } from "@/components/charts";
import { Chip, EmptyRows, ErrBanner, LoaderRows, Panel, Segmented } from "@/components/ui";
import type { ReportRow } from "@/lib/types";

const KIND_LABEL: Record<string, string> = {
  pentest: "Penetration test",
  diag: "Hardware diagnostics",
  evidence: "Evidence pack",
  complaint_btrc: "BTRC complaint",
  complaint_cyber_police: "Cyber Police complaint",
};

function kindLabel(k: string): string {
  return KIND_LABEL[k] ?? humanStatus(k);
}

export default function ReportsPage() {
  const toast = useToast();
  const { requestTotp } = useStepUp();
  const [kind, setKind] = useState("");
  const [mintErr, setMintErr] = useState<unknown>(null);

  const reports = useQuery({
    queryKey: ["reports", kind],
    queryFn: () => get<{ reports: ReportRow[] }>(`/reports${qs({ kind: kind || undefined })}`),
  });
  const all = useQuery({
    queryKey: ["reports", "all"],
    queryFn: () => get<{ reports: ReportRow[] }>("/reports"),
  });

  const kinds = useMemo(() => Array.from(new Set((all.data?.reports ?? []).map((r) => r.kind))).sort(), [all.data]);
  const byKind = useMemo(() => {
    const m: Record<string, number> = {};
    for (const r of all.data?.reports ?? []) m[r.kind] = (m[r.kind] ?? 0) + 1;
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [all.data]);
  const slices = byKind.map(([k, v], i) => ({ name: kindLabel(k), value: v, color: SERIES[i % SERIES.length] }));
  const daily = useMemo(() => {
    const rows = all.data?.reports ?? [];
    const now = new Date();
    const out: { t: string; v: number }[] = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
      const key = d.toISOString().slice(0, 10);
      out.push({ t: key.slice(5), v: rows.filter((r) => (r.created_at ?? "").slice(0, 10) === key).length });
    }
    return out;
  }, [all.data]);

  async function mint(r: ReportRow) {
    setMintErr(null);
    const ref = r.ref_id ?? "";
    if (r.kind === "diag" && ref) {
      const code = await requestTotp(`Re-sign diagnostic report ${trunc(r.name, 20)}`);
      if (!code) return;
      try {
        const res = await apiFetch<{ download: string }>(`/hardware/assets/${ref}/diag.pdf`, { totp: code });
        window.open(res.download, "_blank");
      } catch (e) {
        setMintErr(e);
      }
    } else if (r.kind === "evidence" && ref) {
      const code = await requestTotp(`Re-issue evidence pack`);
      if (!code) return;
      try {
        const res = await apiFetch<{ download: string }>(`/document/${ref}/evidence`, { method: "POST", totp: code });
        window.open(res.download, "_blank");
      } catch (e) {
        setMintErr(e);
      }
    } else {
      try {
        const res = await apiFetch<{ download: string }>(`/reports/${r.id}/link`, { method: "POST" });
        window.open(res.download, "_blank");
        toast.push({ tone: "ok", title: "Download link created", text: `${kindLabel(r.kind)} link is valid for 300 seconds` });
      } catch (e) {
        setMintErr(e);
      }
    }
  }

  return (
    <>
      <div className="span-12">
        <div className="stat-grid">
          <Panel title="Reports by type">
            {all.isPending ? <LoaderRows lines={["Loading report summary"]} /> : !slices.length ? <EmptyRows what="No reports have been generated yet" /> : (
              <DonutStat data={slices} height={180} centerLabel="reports" />
            )}
          </Panel>
          <Panel title="Reports issued · last 14 days">
            {all.isPending ? <LoaderRows lines={["Calculating totals"]} /> : !daily.some((d) => d.v) ? <EmptyRows what="No reports in this window" /> : (
              <>
                <Trend data={daily} yKey="v" unit=" reports" type="linear" />
                <div className="page-note" style={{ marginTop: 8 }}>
                  {daily.reduce((s, d) => s + d.v, 0)} generated in the last 14 days
                </div>
              </>
            )}
          </Panel>
        </div>
      </div>

      <div className="span-12">
        <Panel
          title="Report history"
          tight
          actions={
            <>
              <Segmented
                ariaLabel="Filter by report type"
                value={kind}
                onChange={setKind}
                options={[{ id: "", label: "All" }, ...kinds.map((k) => ({ id: k, label: kindLabel(k) }))]}
              />
              <button type="button" className="btn small" onClick={() => { reports.refetch(); all.refetch(); }}>
                Refresh
              </button>
            </>
          }
        >
          {reports.isPending ? (
            <LoaderRows lines={["Loading reports", "Building the report index"]} />
          ) : reports.error ? (
            <div style={{ padding: 12 }}>
              <ErrBanner error={reports.error} onRetry={() => reports.refetch()} />
            </div>
          ) : !reports.data!.reports.length ? (
            <div style={{ padding: 12 }}>
              <EmptyRows what={`No ${kind ? kindLabel(kind).toLowerCase() + "s" : "reports"} have been generated yet`} />
            </div>
          ) : (
            <table className="dtable">
              <thead>
                <tr>
                  <th>Created</th>
                  <th>Type</th>
                  <th>Report</th>
                  <th>Reference</th>
                  <th>Checksum</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {reports.data!.reports.map((r) => (
                  <tr key={r.id}>
                    <td className="cell-id">{fmtTs(r.created_at)}</td>
                    <td>
                      <Chip tone="info" label={kindLabel(r.kind)} />
                    </td>
                    <td>{r.name}</td>
                    <td className="cell-id">{trunc(r.ref_id, 14)}</td>
                    <td className="cell-id">{trunc(r.sha256, 16)}</td>
                    <td>
                      <div className="row-actions">
                        <button type="button" className="btn small" onClick={() => mint(r)} title="Open a temporary download link (a verification code may be required)">
                          Download
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {mintErr ? <div style={{ padding: 12 }}><ErrBanner error={mintErr} /></div> : null}
        </Panel>
      </div>
    </>
  );
}
