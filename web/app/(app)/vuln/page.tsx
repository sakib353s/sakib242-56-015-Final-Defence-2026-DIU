"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "@/lib/api";
import { fmtTs, humanStatus, statusTone, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { WarrantPicker, useWarrantEnforced } from "@/components/warrant";
import { Bars, DonutStat, SEV_COLORS } from "@/components/charts";
import { FindingRow, SevBar } from "@/components/findings";
import { Chip, EmptyRows, ErrBanner, Field, LoaderRows, Modal, Panel } from "@/components/ui";
import { RiskGauge, RiskValue } from "@/components/risk";
import type { VulnDetail, VulnScan } from "@/lib/types";

export default function VulnPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const { requestTotp } = useStepUp();

  const [warrantId, setWarrantId] = useState("");
  const enf = useWarrantEnforced();
  const [target, setTarget] = useState("");
  const [attestOpen, setAttestOpen] = useState(false);
  const [attested, setAttested] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const scans = useQuery({
    queryKey: ["vuln", "scans"],
    queryFn: () => get<{ scans: VulnScan[] }>("/vuln/scans"),
    refetchInterval: (q) => ((q.state.data?.scans ?? []).some((s) => s.status === "RUNNING" || s.status === "PENDING") ? 4000 : false),
  });
  const detail = useQuery({
    queryKey: ["vuln", "detail", selected],
    queryFn: () => get<VulnDetail>(`/vuln/scans/${selected}`),
    enabled: !!selected,
  });

  useEffect(() => {
    if (!selected && (scans.data?.scans ?? []).length) setSelected(scans.data!.scans[0].id);
  }, [selected, scans.data]);

  const scan = useMutation({
    mutationFn: async (totp: string) =>      post<{ scan_id: string; status: string }>(
        "/vuln/scan",
        { target: target.trim().toLowerCase(), warrant_id: warrantId, authorization_confirmed: true },
        totp,
      ),
    onSuccess: (r) => {
      toast.push({ tone: "ok", title: "Scan queued", text: `${r.status} · ${trunc(r.scan_id, 10)}` });
      setSelected(r.scan_id);
      setAttestOpen(false);
      setAttested(false);
      qc.invalidateQueries({ queryKey: ["vuln"] });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Scan request rejected", text: String((e as Error).message) }),
  });

  async function arm() {
    const code = await requestTotp(`vuln_scan: authenticated CVE scan of ${target}`);
    if (code) scan.mutate(code);
  }

  const findings = detail.data?.findings ?? [];
  const sevMix = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => ({
    name: s.toLowerCase(),
    value: findings.filter((f) => (f.severity || "").toUpperCase() === s).length,
    color: SEV_COLORS[s],
  })).filter((d) => d.value > 0);
  const topCvss = [...findings]
    .filter((f) => f.cvss != null)
    .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
    .slice(0, 8)
    .map((f) => ({
      label: (f.cve || (f.port ? `${f.host}:${f.port}` : f.host)).replace("CVE-", "").slice(0, 12),
      value: Number((f.cvss ?? 0).toFixed(1)),
      color: (f.cvss ?? 0) >= 7 ? SEV_COLORS.CRITICAL : (f.cvss ?? 0) >= 4 ? SEV_COLORS.MEDIUM : SEV_COLORS.LOW,
    }));

  return (
    <>
      <div className="span-12">
        <Panel title="New authorized scan">
          <div className="form-row">
            <Field label="Authorization (vulnerability scan)">
              <WarrantPicker kind="vuln_scan" value={warrantId} onChange={setWarrantId} />
            </Field>
            <Field label="Target" hint="Service fingerprinting, correlation with public NVD data, and an aggregate risk score from 0 to 100.">
              <input className="text" placeholder="10.0.0.5 or host.example.com" value={target} onChange={(e) => setTarget(e.target.value)} maxLength={253} />
            </Field>
            <button type="button" className="btn primary" disabled={(enf && !warrantId) || target.trim().length < 4} onClick={() => setAttestOpen(true)}>
              Start scan
            </button>
          </div>
        </Panel>
      </div>

      <div className="span-12">
        <div className="wb">
          <div>
            <div className="panel-title" style={{ marginBottom: 8 }}>Scans · {(scans.data?.scans ?? []).length}</div>
            {scans.isPending ? (
              <LoaderRows lines={["Loading scans"]} />
            ) : scans.error ? (
              <ErrBanner error={scans.error} onRetry={() => scans.refetch()} />
            ) : !scans.data!.scans.length ? (
              <EmptyRows what="No scans recorded" />
            ) : (
              <div className="wb-list" role="listbox" aria-label="Vulnerability scans">
                {scans.data!.scans.map((s) => (
                  <button
                    key={s.id}
                    type="button"
                    role="option"
                    aria-selected={selected === s.id}
                    className={`wb-item${selected === s.id ? " on" : ""}`}
                    onClick={() => { setSelected(s.id); setExpanded(null); }}
                  >
                    <span className={`wb-dot ${s.status === "RUNNING" || s.status === "PENDING" ? "run" : s.status === "DONE" ? "ok" : s.status === "CREATED" ? "" : "bad"}`} aria-hidden />
                    <span className="wb-main">
                      <span className="wb-target">{s.target}</span>
                      <span className="wb-meta">{fmtTs(s.created_at)} · {s.findings_count} findings</span>
                    </span>
                    <span className="wb-side">
                      <RiskValue score={s.risk_score} />
                      <Chip tone={statusTone(s.status)} label={humanStatus(s.status)} />
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <Panel title="Scan detail" tight>
            {!selected ? (
              <div style={{ padding: 12 }}>
                <EmptyRows what="Select a scan to view its findings" />
              </div>
            ) : detail.isPending ? (
              <LoaderRows lines={["Loading the scan record", "Ordering findings by CVSS"]} />
            ) : detail.error ? (
              <div style={{ padding: 12 }}>
                <ErrBanner error={detail.error} onRetry={() => detail.refetch()} />
              </div>
            ) : (
              <div style={{ padding: 12 }}>
                {detail.data!.scan ? (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ display: "flex", gap: 16, alignItems: "center", marginBottom: 6, flexWrap: "wrap" }}>
                      <span className="panel-title">{detail.data!.scan.target.toUpperCase()}</span>
                      <Chip tone={statusTone(detail.data!.scan.status)} label={humanStatus(detail.data!.scan.status)} />
                      <span className="cell-id">Finished {fmtTs(detail.data!.scan.finished_at)}</span>
                      {detail.data!.scan.report_path ? (
                        <button
                          type="button"
                          className="btn small primary"
                          onClick={async () => {
                            try {
                              const r = await get<{ download: string }>(`/vuln/scans/${detail.data!.scan!.id}/report`);
                              window.open(r.download, "_blank");
                            } catch (e) {
                              toast.push({ tone: "fail", title: "Report link failed", text: String((e as Error).message) });
                            }
                          }}
                        >
                          Download PDF report
                        </button>
                      ) : (
                        <span className="cell-id">report pending</span>
                      )}
                    </div>
                    <RiskGauge score={detail.data!.scan.risk_score} />
                  </div>
                ) : null}
                {!detail.data!.findings.length ? (
                  <EmptyRows what="No CVEs mapped to the discovered services yet" />
                ) : (
                  <>
                    <SevBar findings={detail.data!.findings} />
                    <table className="dtable">
                      <thead>
                        <tr>
                          <th>Host / Port</th>
                          <th>Service</th>
                          <th>CVE</th>
                          <th>CVSS</th>
                          <th>Severity</th>
                          <th>MITRE</th>
                          <th>Description</th>
                          <th />
                        </tr>
                      </thead>
                      <tbody>
                        {detail.data!.findings.map((f) => (
                          <FindingRow key={f.id} f={f} open={expanded === f.id} onToggle={() => setExpanded(expanded === f.id ? null : f.id)} />
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </div>
            )}
          </Panel>
        </div>
      </div>

      {selected && findings.length ? (
        <div className="span-12">
          <div className="stat-grid">
            <Panel title="Findings by severity">
              <DonutStat data={sevMix} height={180} centerValue={findings.length} centerLabel="cves" />
            </Panel>
            <Panel title="Highest CVSS scores">
              <Bars data={topCvss} height={220} perCell />
            </Panel>
          </div>
        </div>
      ) : null}

      {attestOpen ? (
        <Modal
          title="Confirm authorization"
          onClose={() => setAttestOpen(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setAttestOpen(false)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn primary"
                disabled={!attested}
                onClick={() => {
                  setAttestOpen(false);
                  void arm();
                }}
              >
                Confirm and run scan
              </button>
            </>
          }
        >
          <div className="problem" style={{ marginTop: 0 }}>
            <div className="pt">Warning: this scan performs active service fingerprinting</div>
            <div className="pd">
              Service version detection against <b style={{ color: "var(--hdr)" }}>{target}</b>, followed by correlation with
              public NVD data. The authorization scope, validity period and type are re-checked on the server
              when you submit.
            </div>
          </div>
          <label className="checkline">
            <input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} />
            I confirm written authorization is in force for this target.
          </label>
        </Modal>
      ) : null}
      {scan.isError ? <ErrBanner error={scan.error} /> : null}
    </>
  );
}
