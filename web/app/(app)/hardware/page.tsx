"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, get } from "@/lib/api";
import { fmtTs, trunc } from "@/lib/format";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { Chip, EmptyRows, ErrBanner, Field, KV, Leader, LoaderRows, Modal, Panel } from "@/components/ui";
import type { HwAsset, HwAssetDetail, HwCheckResult } from "@/lib/types";

const KINDS = ["server", "workstation", "network", "iot"] as const;
const KIND_LABEL: Record<string, string> = {
  server: "Server",
  workstation: "Workstation",
  network: "Network device",
  iot: "IoT device",
};
const READING_LABEL: Record<string, string> = {
  disk: "Disk usage",
  mem: "Memory usage",
  load: "Load average",
  temp: "Temperature",
  os: "Operating system",
  up: "Uptime",
  uptime: "Uptime",
  sysdescr: "System description",
  sysuptime: "System uptime",
  error: "Error",
};

export default function HardwarePage() {
  const qc = useQueryClient();
  const toast = useToast();
  const { requestTotp } = useStepUp();

  const [selected, setSelected] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [f, setF] = useState({ name: "", kind: "server", host: "", ssh_port: "22", ssh_user: "", ssh_password: "", snmp_community: "" });
  const [attested, setAttested] = useState(false);

  const assets = useQuery({ queryKey: ["hardware", "assets"], queryFn: () => get<{ assets: HwAsset[] }>("/hardware/assets") });
  const detail = useQuery({
    queryKey: ["hardware", "asset", selected],
    queryFn: () => get<HwAssetDetail>(`/hardware/assets/${selected}`),
    enabled: !!selected,
  });

  const list = assets.data?.assets ?? [];
  useEffect(() => {
    if (!selected && list.length) setSelected(list[0].id);
  }, [selected, list]);

  const add = useMutation({
    mutationFn: () =>
      apiFetch<HwAsset>("/hardware/assets", {
        method: "POST",
        body: {
          name: f.name.trim(),
          kind: f.kind,
          host: f.host.trim().toLowerCase(),
          ssh_port: Number(f.ssh_port) || 22,
          ssh_user: f.ssh_user.trim(),
          ssh_password: f.ssh_password,
          snmp_community: f.snmp_community,
          ownership_attested: attested,
        },
      }),
    onSuccess: (a) => {
      toast.push({ tone: "ok", title: "Asset added", text: `${a.name} · ${a.host}` });
      setAddOpen(false);
      setAttested(false);
      setF({ name: "", kind: "server", host: "", ssh_port: "22", ssh_user: "", ssh_password: "", snmp_community: "" });
      setSelected(a.id);
      qc.invalidateQueries({ queryKey: ["hardware"] });
    },
  });

  const check = useMutation({
    mutationFn: async (id: string) => {
      const code = await requestTotp(`hardware: run an SSH/SNMP health check of ${id.slice(0, 8)}`);
      if (!code) throw new Error("Verification was cancelled, so the check did not run.");
      return apiFetch<HwCheckResult>(`/hardware/assets/${id}/check`, { method: "POST", totp: code });
    },
    onSuccess: (r) => {
      toast.push({
        tone: r.anomalies.length ? "warn" : "ok",
        title: r.anomalies.length ? `Anomalies: ${r.anomalies.join(" ")}` : "Check complete",
        text: r.checked_at ?? "",
      });
      qc.invalidateQueries({ queryKey: ["hardware"] });
      detail.refetch();
    },
    onError: (e) => {
      if (!/cancelled/.test(String((e as Error).message)))
        toast.push({ tone: "fail", title: "Check failed", text: trunc(String((e as Error).message), 90) });
    },
  });

  async function diag(id: string) {
    const code = await requestTotp("hardware: download the diagnostics PDF");
    if (!code) return;
    try {
      const r = await apiFetch<{ download: string }>(`/hardware/assets/${id}/diag.pdf`, { totp: code });
      window.open(r.download, "_blank");
    } catch (e) {
      toast.push({ tone: "fail", title: "Diagnostics download failed", text: String((e as Error).message) });
    }
  }

  const last = parseCheck(detail.data?.last_check_json);
  const noAssets = !assets.isPending && !assets.error && !list.length;

  return (
    <>
      <div className="span-12">
        <div className="wb">
          <div>
            <div className="panel-title" style={{ marginBottom: 8 }}>
              Inventory · {list.length}
            </div>
            {assets.isPending ? (
              <LoaderRows lines={["Loading assets"]} />
            ) : assets.error ? (
              <ErrBanner error={assets.error} onRetry={() => assets.refetch()} />
            ) : noAssets ? (
              <>
                <EmptyRows what="No assets registered. Credentials encrypt at rest; an asset locks after three failed SSH sign-ins. A machine hosted by this very gateway can be monitored locally — no SSH credentials needed." />
                <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
                  <button type="button" className="btn small primary" onClick={() => setAddOpen(true)}>
                    Register the first asset
                  </button>
                  <button
                    type="button"
                    className="btn small"
                    onClick={() => {
                      setF({ name: "This machine (local probe)", kind: "workstation", host: "localhost", ssh_port: "22", ssh_user: "", ssh_password: "", snmp_community: "" });
                      setAddOpen(true);
                    }}
                  >
                    Monitor this machine
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="wb-list" role="listbox" aria-label="Hardware assets">
                  {list.map((a) => (
                    <button
                      key={a.id}
                      type="button"
                      role="option"
                      aria-selected={selected === a.id}
                      className={`wb-item${selected === a.id ? " on" : ""}`}
                      onClick={() => setSelected(a.id)}
                    >
                      <span className={`wb-dot ${a.disabled ? "bad" : "ok"}`} aria-hidden />
                      <span className="wb-main">
                        <span className="wb-target">{a.name}</span>
                        <span className="wb-meta">
                          {a.host}
                          {a.ssh_port && a.ssh_port !== 22 ? `:${a.ssh_port}` : ""} · {KIND_LABEL[a.kind] ?? a.kind}
                        </span>
                      </span>
                      <span className="wb-side">
                        <Chip tone={a.disabled ? "fail" : "ok"} label={a.disabled ? "Locked" : "Active"} />
                      </span>
                    </button>
                  ))}
                </div>
                <button type="button" className="btn small primary" style={{ marginTop: 8 }} onClick={() => setAddOpen(true)}>
                  Add asset
                </button>
              </>
            )}
          </div>

          <Panel
            title={detail.data ? `${detail.data.name} · health` : "Asset health"}
            tight
            actions={
              selected ? (
                <div style={{ display: "flex", gap: 6 }}>
                  <button type="button" className="btn small warn" disabled={check.isPending || !!detail.data?.disabled} onClick={() => check.mutate(selected)}>
                    Run check
                  </button>
                  <button type="button" className="btn small primary" disabled={!last} onClick={() => diag(selected)}>
                    Diagnostics PDF
                  </button>
                </div>
              ) : null
            }
          >
            {!selected ? (
              <div style={{ padding: 12 }}>
                <EmptyRows what={noAssets ? "Health readings appear once an asset has been registered and checked." : "Select an asset to see its health."} />
              </div>
            ) : detail.isPending ? (
              <LoaderRows lines={["Loading asset details"]} />
            ) : detail.error ? (
              <div style={{ padding: 12 }}>
                <ErrBanner error={detail.error} onRetry={() => detail.refetch()} />
              </div>
            ) : (
              <div style={{ padding: 12 }}>
                <KV
                  rows={[
                    ["Host", `${detail.data!.host}${detail.data!.ssh_port && detail.data!.ssh_port !== 22 ? `:${detail.data!.ssh_port}` : ""}`],
                    ["SSH user", detail.data!.ssh_user || "—"],
                    ["Last check", fmtTs(detail.data!.last_check_at)],
                  ]}
                />
                <div style={{ height: 10 }} />
                {last ? (
                  <>
                    {Object.entries(last.checks ?? {}).map(([via, vals]) => (
                      <div key={via} style={{ marginBottom: 10 }}>
                        <div className="page-note">{via.toUpperCase()} readings</div>
                        {Object.entries(vals ?? {}).map(([k, v]) => (
                          <Leader key={k} label={READING_LABEL[k.toLowerCase()] ?? k} value={String(v)} tone={k.toLowerCase() === "error" ? "fail" : "ok"} />
                        ))}
                      </div>
                    ))}
                    {last.anomalies.length ? (
                      <div style={{ marginTop: 6 }}>
                        <div className="page-note" style={{ marginBottom: 4 }}>Anomalies · each one is audited and pushed as a live alert</div>
                        {last.anomalies.map((a, i) => (
                          <div key={i} className="problem" style={{ margin: "0 0 8px" }}>
                            <div className="pt">Warning: {a}</div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <Leader label="Thresholds" value="Disk ≤ 85% · memory ≤ 90% · load ≤ 2 per core — all within limits" tone="ok" />
                    )}
                  </>
                ) : (
                  <EmptyRows what="No checks recorded yet. Run a check to collect SSH/SNMP readings." />
                )}
              </div>
            )}
          </Panel>
        </div>
      </div>

      {addOpen ? (
        <Modal
          title="Add an asset"
          onClose={() => setAddOpen(false)}
          wide
          footer={
            <>
              <button type="button" className="btn" onClick={() => setAddOpen(false)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn primary"
                disabled={!attested || !f.name.trim() || !f.host.trim() || add.isPending}
                onClick={() => add.mutate()}
              >
                Register asset
              </button>
            </>
          }
        >
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Field label="Name">
              <input className="text" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} maxLength={80} />
            </Field>
            <Field label="Type">
              <select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
                {KINDS.map((k) => (
                  <option key={k} value={k}>
                    {KIND_LABEL[k]}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Host (IP or domain)">
              <input className="text" value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} maxLength={253} />
            </Field>
            <Field label="SSH port">
              <input className="text" inputMode="numeric" value={f.ssh_port} onChange={(e) => setF({ ...f, ssh_port: e.target.value.replace(/\D/g, "").slice(0, 5) })} />
            </Field>
            <Field label="SSH user (optional)">
              <input className="text" value={f.ssh_user} onChange={(e) => setF({ ...f, ssh_user: e.target.value })} maxLength={64} />
            </Field>
            <Field label="SSH password (optional, encrypted at rest)">
              <input className="text" type="password" value={f.ssh_password} onChange={(e) => setF({ ...f, ssh_password: e.target.value })} maxLength={128} />
            </Field>
            <Field label="SNMP v2c community (optional)">
              <input className="text" type="password" value={f.snmp_community} onChange={(e) => setF({ ...f, snmp_community: e.target.value })} maxLength={64} />
            </Field>
          </div>
          <label className="checkline" style={{ marginTop: 6 }}>
            <input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} />
            I own or administer this asset and authorize active diagnostics. This confirmation is required by the server.
          </label>
          {add.isError ? <ErrBanner error={add.error} /> : null}
        </Modal>
      ) : null}
    </>
  );
}

function parseCheck(json: string | null | undefined): HwCheckResult | null {
  if (!json) return null;
  try {
    const v = JSON.parse(json) as { checks?: Record<string, Record<string, string>>; anomalies?: string[] };
    return { checks: v.checks ?? {}, anomalies: v.anomalies ?? [] };
  } catch {
    return null;
  }
}
