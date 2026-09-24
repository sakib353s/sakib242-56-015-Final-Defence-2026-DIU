"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiFetch, get, post } from "@/lib/api";
import { elapsedSince, fmtTs, humanStatus, statusTone, trunc } from "@/lib/format";
import { useTick } from "@/components/ui";
import { useStepUp } from "@/components/stepup";
import { useToast } from "@/components/toast";
import { WarrantPicker } from "@/components/warrant";
import { Chip, EmptyRows, ErrBanner, Field, KV, LoaderRows, Panel } from "@/components/ui";
import type { Circuit } from "@/lib/types";

export default function IpPage() {
  useTick(1000);
  const toast = useToast();
  const { requestTotp } = useStepUp();
  const [warrantId, setWarrantId] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const circuits = useQuery({
    queryKey: ["ip", "status"],
    queryFn: () => get<{ circuits: Circuit[] }>("/ip/status"),
    refetchInterval: (q) => ((q.state.data?.circuits ?? []).some((c) => c.status === "active" || c.status === "building") ? 5000 : false),
  });

  const list = circuits.data?.circuits ?? [];
  const live = list.find((c) => c.status === "active") ?? null;

  useEffect(() => {
    if (!selected && list.length) setSelected(list[0].id);
  }, [selected, list]);

  const start = useMutation({
    mutationFn: async (totp: string) =>
      post<{ circuit_id: string; status: string; masked_ip: string | null; tor: string }>("/ip/start", { warrant_id: warrantId }, totp),
    onSuccess: (r) => {
      toast.push({ tone: "ok", title: `Circuit ${r.status}`, text: `Masked IP: ${r.masked_ip ?? "—"}` });
      setSelected(r.circuit_id);
      circuits.refetch();
    },
    onError: (e) => toast.push({ tone: "fail", title: "Circuit could not be started", text: String((e as Error).message) }),
  });

  const stop = useMutation({
    mutationFn: async (cid: string) => apiFetch<{ ok: boolean }>(`/ip/stop?circuit_id=${encodeURIComponent(cid)}`, { method: "POST" }),
    onSuccess: () => {
      toast.push({ tone: "warn", title: "Circuit stopped" });
      circuits.refetch();
    },
  });

  const sel = list.find((c) => c.id === selected) ?? null;

  return (
    <>
      <div className="span-12">
        <Panel title="Anonymized routing">
          <div className="form-row">
            <Field label="Authorization (anonymized routing)">
              <WarrantPicker kind="ipanon" value={warrantId} onChange={setWarrantId} />
            </Field>
            <div style={{ flex: "1 1 300px", paddingTop: 22 }}>
              {live ? (
                <KV
                  rows={[
                    ["Now exit", <span key="m" style={{ color: "var(--ok)" }}>{live.masked_ip ?? "Awaiting heartbeat"}</span>],
                    ["Online for", elapsedSince(live.started_at)],
                  ]}
                />
              ) : (
                <div className="page-note">No active circuit. Exit traffic is not being anonymized right now.</div>
              )}
            </div>
            <button
              type="button"
              className="btn primary"
              disabled={!warrantId || start.isPending || !!live}
              onClick={async () => {
                const code = await requestTotp("Build a new anonymization circuit");
                if (code) start.mutate(code);
              }}
            >
              {live ? "Circuit already active" : "Build new circuit"}
            </button>
          </div>
          <div className="page-note" style={{ marginTop: 4 }}>
            Circuits exist only for the lifetime of an authorized session. The status refreshes on a five-minute
            heartbeat, and a circuit closes automatically when its authorization expires. This is not a
            general-purpose traffic proxy.
          </div>
          {start.isError ? <ErrBanner error={start.error} /> : null}
          {stop.isError ? <ErrBanner error={stop.error} /> : null}
        </Panel>
      </div>

      <div className="span-12">
        <div className="wb">
          <div>
            <div className="panel-title" style={{ marginBottom: 8 }}>Circuits · {list.length}</div>
            {circuits.isPending ? (
              <LoaderRows lines={["Loading circuits"]} />
            ) : circuits.error ? (
              <ErrBanner error={circuits.error} onRetry={() => circuits.refetch()} />
            ) : !list.length ? (
              <EmptyRows what="No circuits have been built recently" />
            ) : (
              <div className="wb-list" role="listbox" aria-label="Anonymization circuits">
                {list.map((c) => (
                  <button
                    key={c.id}
                    type="button"
                    role="option"
                    aria-selected={selected === c.id}
                    className={`wb-item${selected === c.id ? " on" : ""}`}
                    onClick={() => setSelected(c.id)}
                  >
                    <span className={`wb-dot ${c.status === "active" ? "run" : c.status === "building" ? "run" : c.status === "failed" ? "bad" : "ok"}`} aria-hidden />
                    <span className="wb-main">
                      <span className="wb-target">{c.masked_ip ?? "no exit yet"}</span>
                      <span className="wb-meta">{fmtTs(c.started_at)} · {trunc(c.id, 10)}</span>
                    </span>
                    <span className="wb-side">
                      <Chip tone={statusTone(c.status)} label={humanStatus(c.status)} />
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <Panel title="Circuit detail" tight>
            {!sel ? (
              <div style={{ padding: 12 }}>
                <EmptyRows what="Select a circuit to inspect its heartbeat and exit address" />
              </div>
            ) : (
              <div style={{ padding: 12 }}>
                <KV
                  rows={[
                    ["Circuit", sel.id],
                    ["Status", <Chip key="s" tone={statusTone(sel.status)} label={humanStatus(sel.status)} />],
                    ["Started", fmtTs(sel.started_at)],
                    ["Time online", sel.status === "active" ? elapsedSince(sel.started_at) : "—"],
                    ["Masked exit IP", <span key="i" style={{ color: "var(--ok)" }}>{sel.masked_ip ?? "Not available"}</span>],
                    ["Last heartbeat", sel.last_heartbeat ? `${fmtTs(sel.last_heartbeat)} · ${elapsedSince(sel.last_heartbeat)} ago` : "Awaiting first heartbeat"],
                  ]}
                />
                {(sel.status === "active" || sel.status === "building") ? (
                  <button type="button" className="btn small danger" style={{ marginTop: 10 }} disabled={stop.isPending} onClick={() => stop.mutate(sel.id)}>
                    Tear down circuit
                  </button>
                ) : null}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}
