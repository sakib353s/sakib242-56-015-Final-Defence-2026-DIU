"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "@/lib/api";
import { fmtTs, trunc } from "@/lib/format";
import { useToast } from "@/components/toast";
import { Chip, EmptyRows, ErrBanner, Field, LoaderRows, Panel } from "@/components/ui";
import type { TiObject, TiObjectDetail, TiStats } from "@/lib/types";

const TI_TYPES = [
  "indicator", "malware", "threat-actor", "campaign", "tool", "attack-pattern",
  "infrastructure", "vulnerability", "report", "intrusion-set", "observed-data",
] as const;

const TLP_TONE: Record<string, string> = { RED: "fail", AMBER: "warn", GREEN: "ok", CLEAR: "dim" };

export default function ThreatIntelPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [matchValue, setMatchValue] = useState("");
  const [showCreate, setShowCreate] = useState(false);

  const stats = useQuery({ queryKey: ["ti", "stats"], queryFn: () => get<TiStats>("/ti/stats") });

  const objects = useQuery({
    queryKey: ["ti", "objects", typeFilter, search],
    queryFn: () => get<{ objects: TiObject[] }>(
      `/ti/objects?limit=150${typeFilter ? `&type=${typeFilter}` : ""}${search ? `&q=${encodeURIComponent(search)}` : ""}`),
  });

  const detail = useQuery({
    queryKey: ["ti", "detail", selected],
    queryFn: () => get<TiObjectDetail>(`/ti/objects/${selected}`),
    enabled: !!selected,
  });

  const rows = objects.data?.objects ?? [];
  useEffect(() => {
    if (!selected && rows.length) setSelected(rows[0].id);
  }, [selected, rows]);

  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => post("/ti/objects", body),
    onSuccess: (o) => {
      toast.push({ tone: "ok", title: "Indicator stored", text: trunc((o as { id: string }).id, 12) });
      setShowCreate(false);
      qc.invalidateQueries({ queryKey: ["ti"] });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Rejected", text: String((e as Error).message) }),
  });

  const archive = useMutation({
    mutationFn: (oid: string) => post(`/ti/objects/${oid}/archive`),
    onSuccess: () => {
      toast.push({ tone: "warn", title: "TI object archived", text: "Removed from matching" });
      qc.invalidateQueries({ queryKey: ["ti"] });
    },
  });

  return (
    <>
      <div className="span-12">
        <Panel title="Threat intelligence store" actions={
          <span className="page-note cell-id">
            {stats.data ? `${stats.data.total} objects · ${stats.data.untrusted} untrusted · ${stats.data.links} links · last ingest ${stats.data.last_ingest ? fmtTs(stats.data.last_ingest) : "never"}` : "…"}
          </span>
        }>
          {stats.data ? (
            <div className="page-note" style={{ marginBottom: 8 }}>
              {stats.data.by_type.map((b) => `${b.stix_type} ${b.n}`).join(" · ") || "empty store — add indicators or ingest a STIX bundle"}
              {"  ·  "}
              <i>external intelligence is inert data: it can flag and advise, never instruct, authorize or execute.</i>
            </div>
          ) : null}
          <div className="form-row">
            <Field label="Observable match">
              <div style={{ display: "flex", gap: 6 }}>
                <input className="text" placeholder="IP / domain / URL / hash / email"
                       value={matchValue} onChange={(e) => setMatchValue(e.target.value)} />
                <MatchButton value={matchValue} />
              </div>
            </Field>
            <Field label="Filter type">
              <select className="text" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
                <option value="">All types</option>
                {TI_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </Field>
            <Field label="Search">
              <input className="text" placeholder="name, description, pattern…"
                     value={search} onChange={(e) => setSearch(e.target.value)} />
            </Field>
            <button type="button" className="btn primary" onClick={() => setShowCreate((v) => !v)}>
              {showCreate ? "Close form" : "New object"}
            </button>
          </div>
          {showCreate ? <CreateForm form={create} /> : null}
          <BundleIngest onDone={() => qc.invalidateQueries({ queryKey: ["ti"] })} />
        </Panel>
      </div>

      <div className="span-12">
        <div className="wb">
          <div>
            <div className="panel-title" style={{ marginBottom: 8 }}>Objects · {rows.length}</div>
            {objects.isPending ? (
              <LoaderRows lines={["Loading intelligence"]} />
            ) : objects.error ? (
              <ErrBanner error={objects.error} onRetry={() => objects.refetch()} />
            ) : !rows.length ? (
              <EmptyRows what="No intelligence stored yet — ingest a STIX 2.1 bundle or add indicators manually" />
            ) : (
              <div className="wb-list" role="listbox" aria-label="Threat intel objects">
                {rows.map((o) => (
                  <button key={o.id} type="button" role="option" aria-selected={selected === o.id}
                          className={`wb-item${selected === o.id ? " on" : ""}`}
                          onClick={() => setSelected(o.id)}>
                    <span className={`wb-dot ${o.trust === "untrusted" ? "bad" : "ok"}`} aria-hidden />
                    <span className="wb-main">
                      <span className="wb-target">{o.name}</span>
                      <span className="wb-meta">{o.stix_type} · {o.source} · {fmtTs(o.created_at)}</span>
                    </span>
                    <span className="wb-side">
                      {o.tlp ? <Chip tone={TLP_TONE[o.tlp]} label={`TLP:${o.tlp}`} /> : null}
                      <span className="wb-meta">{o.confidence != null ? `${o.confidence}%` : "—"}</span>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <Panel title="Object detail" tight>
            {!selected ? (
              <div style={{ padding: 12 }}><EmptyRows what="Select an object" /></div>
            ) : detail.isPending ? (
              <div style={{ padding: 12 }}><LoaderRows lines={["Loading object, relationships, observables"]} /></div>
            ) : detail.error ? (
              <div style={{ padding: 12 }}><ErrBanner error={detail.error} onRetry={() => detail.refetch()} /></div>
            ) : (() => {
              const o = detail.data!.object;
              return (
                <div style={{ padding: 12 }}>
                  <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                    <span className="panel-title">{o.name}</span>
                    <Chip tone="info" label={o.stix_type} />
                    <Chip tone={o.trust === "untrusted" ? "fail" : "ok"}
                          label={o.trust === "untrusted" ? "UNTRUSTED FEED" : "INTERNAL"} />
                    {o.tlp ? <Chip tone={TLP_TONE[o.tlp]} label={`TLP:${o.tlp}`} /> : null}
                    <span className="cell-id">confidence {o.confidence ?? "—"}/100 · source {o.source}</span>
                  </div>
                  {o.description ? <p className="page-note" style={{ margin: "6px 0" }}>{o.description}</p> : null}
                  {o.pattern ? (
                    <pre className="cell-id" style={{ fontSize: 12, margin: "4px 0", whiteSpace: "pre-wrap" }}>{o.pattern}</pre>
                  ) : null}
                  {detail.data!.observables.length ? (
                    <>
                      <div className="panel-title" style={{ fontSize: 12, margin: "8px 0 4px" }}>Observables ({detail.data!.observables.length})</div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {detail.data!.observables.map((ob, i) => (
                          <span key={i} className="cell-id" style={{ border: "1px solid var(--line)", padding: "2px 6px", borderRadius: 4 }}>
                            {ob.observable_type}: {ob.value}
                          </span>
                        ))}
                      </div>
                    </>
                  ) : null}
                  {detail.data!.relationships.length ? (
                    <>
                      <div className="panel-title" style={{ fontSize: 12, margin: "10px 0 4px" }}>Relationships</div>
                      <table className="dtable">
                        <thead><tr><th>From</th><th>Type</th><th>To</th><th>State</th></tr></thead>
                        <tbody>
                          {detail.data!.relationships.slice(0, 25).map((r) => (
                            <tr key={r.id}>
                              <td className="cell-id">{r.source_name || `${r.source_kind}:${trunc(r.source_id, 8)}`}</td>
                              <td>{r.relationship_type}</td>
                              <td className="cell-id">{r.target_name || `${r.target_kind}:${trunc(r.target_id, 8)}`}</td>
                              <td>{r.state}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </>
                  ) : null}
                  <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
                    {!o.revoked ? (
                      <button type="button" className="btn small danger" disabled={archive.isPending}
                              onClick={() => archive.mutate(o.id)}>Archive (stop matching)</button>
                    ) : <Chip tone="dim" label="ARCHIVED" />}

                  </div>
                  <div className="page-note cell-id" style={{ marginTop: 8 }}>
                    {detail.data!.decisions.length ? `${detail.data!.decisions.length} Brain decisions referenced this object` : "No Brain decisions reference this object yet"}
                  </div>
                </div>
              );
            })()}
          </Panel>
        </div>
      </div>
    </>
  );
}

function MatchButton({ value }: { value: string }) {
  const [res, setRes] = useState<{ type: string | null; matches: { name: string; stix_type: string; source: string; trust: string; tlp: string | null }[]; normalized: string | null } | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <>
      <button type="button" className="btn" disabled={busy || value.trim().length < 3}
              onClick={async () => {
                setBusy(true);
                try {
                  const r = await get<{ type: string | null; normalized: string | null; matches: { name: string; stix_type: string; source: string; trust: string; tlp: string | null }[] }>(
                    `/ti/match?value=${encodeURIComponent(value.trim())}`);
                  setRes(r);
                } finally { setBusy(false); }
              }}>
                {busy ? "…" : "Match"}
      </button>
      {res ? (
        <span className="page-note cell-id">
          {res.type ? `${res.type} ${trunc(res.normalized || "", 30)} → ` : "unrecognized: "}
          {res.matches.length ? res.matches.map((m) => `${m.name} (${m.stix_type}, ${m.trust})`).join(" · ") : "no matches"}
        </span>
      ) : null}
    </>
  );
}

function CreateForm({ form }: { form: { mutate: (b: Record<string, unknown>) => void; isPending: boolean } }) {
  const [st, setSt] = useState<string>("indicator");
  const [name, setName] = useState("");
  const [pattern, setPattern] = useState("");
  const [tlp, setTlp] = useState("");
  const [conf, setConf] = useState("75");
  return (
    <div style={{ border: "1px solid var(--line)", padding: 10, marginTop: 8 }}>
      <div className="form-row">
        <Field label="Type">
          <select className="text" value={st} onChange={(e) => setSt(e.target.value)}>
            {TI_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </Field>
        <Field label="Name">
          <input className="text" value={name} maxLength={400} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="TLP">
          <select className="text" value={tlp} onChange={(e) => setTlp(e.target.value)}>
            <option value="">—</option><option>CLEAR</option><option>GREEN</option><option>AMBER</option><option>RED</option>
          </select>
        </Field>
        <Field label="Confidence (0-100)">
          <input className="text" type="number" min={0} max={100} value={conf} onChange={(e) => setConf(e.target.value)} />
        </Field>
      </div>
      <Field label="STIX pattern (indicators only)" hint="e.g. [ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'evil.example']">
        <input className="text" value={pattern} maxLength={4000} onChange={(e) => setPattern(e.target.value)} />
      </Field>
      <div style={{ marginTop: 6 }}>
        <button type="button" className="btn primary"
                disabled={name.trim().length < 2 || form.isPending}
                onClick={() => form.mutate({
                  stix_type: st, name: name.trim(),
                  pattern: pattern.trim(), tlp: tlp || null,
                  confidence: Number(conf) || null,
                })}>
          Store object
        </button>
      </div>
    </div>
  );
}

function BundleIngest({ onDone }: { onDone: () => void }) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [label, setLabel] = useState("");
  const mut = useMutation({
    mutationFn: () => {
      let parsed: unknown;
      try { parsed = JSON.parse(text); }
      catch { throw new Error("not valid JSON"); }
      return post("/ti/bundles", { bundle: parsed, source_label: label.trim() || "pasted-bundle" });
    },
    onSuccess: (r) => {
      const res = r as { objects_ingested: number; relationships_linked: number; skipped: string[] };
      toast.push({
        tone: "ok", title: "Bundle ingested (untrusted)",
        text: `${res.objects_ingested} objects · ${res.relationships_linked} links · ${res.skipped.length} skipped`,
      });
      setText(""); setOpen(false); onDone();
    },
    onError: (e) => toast.push({ tone: "fail", title: "Bundle rejected", text: String((e as Error).message) }),
  });
  return (
    <div style={{ marginTop: 8 }}>
      <button type="button" className="btn small" onClick={() => setOpen((v) => !v)}>
        {open ? "Close ingest" : "Ingest STIX 2.1 bundle"}
      </button>
      {open ? (
        <div style={{ marginTop: 6 }}>
          <Field label="Source label" hint="Stored as provenance — feed contents are treated as inert, untrusted data.">
            <input className="text" value={label} maxLength={120} placeholder="e.g. partner-feed-2026-09"
                   onChange={(e) => setLabel(e.target.value)} />
          </Field>
          <textarea className="text" rows={5} style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
                    placeholder='{"type":"bundle","spec_version":"2.1","objects":[…]}'
                    value={text} onChange={(e) => setText(e.target.value)} />
          <div style={{ marginTop: 6 }}>
            <button type="button" className="btn primary" disabled={text.trim().length < 20 || mut.isPending}
                    onClick={() => mut.mutate()}>
              {mut.isPending ? "Parsing…" : "Ingest bundle"}
            </button>
          </div>
          {mut.isError ? <ErrBanner error={mut.error} /> : null}
        </div>
      ) : null}
    </div>
  );
}