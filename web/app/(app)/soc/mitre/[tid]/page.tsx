"use client";
/* Technique war-room — opens inside the console (no more external redirect).
   Left: live force graph of THIS system's observed activity for the technique.
   Right: official MITRE metadata parsed live from attack.mitre.org + who /
   what / when / where panels built from real alerts, refreshing every 10 s. */
import { useMemo } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useQuery } from "@tanstack/react-query";
import { get } from "@/lib/api";
import { fmtTs } from "@/lib/format";
import { Chip, ErrBanner, LoaderRows, Panel } from "@/components/ui";
import { MitreGraph, type GLink, type GNode } from "@/components/mitre-graph";

interface Profile {
  technique: {
    id: string; name: string; matrix: string; url: string; description: string;
    tactics: { id: string; name: string }[]; platforms: string[];
    subtechniques: { id: string; name: string }[];
    mitigations: { id: string; name: string; description: string }[];
    source: string; parent?: { id: string; name: string; url: string };
  };
  observed: {
    events: number; first: string | null; last: string | null;
    subtechniques_seen: Record<string, number>;
    hosts: { ip: string; events: number; sources: number; destinations: number; first: string | null; last: string | null }[];
    signatures: { signature: string; events: number; max_severity: string }[];
    timeline: { hour: string; count: number }[];
    recent: { id: string; ts: string; severity: string; signature: string; src_ip: string; dest_ip: string }[];
  };
  graph: { nodes: GNode[]; links: GLink[] };
  parent_activity?: { id: string; events: number } | null;
  as_of: string;
}

export default function MitreTechniquePage() {
  const params = useParams<{ tid: string }>();
  const tid = String(params?.tid ?? "").toUpperCase();
  const q = useQuery({
    queryKey: ["mitre", tid],
    queryFn: () => get<Profile>(`/soc/mitre-profile/${encodeURIComponent(tid)}`),
    refetchInterval: 10_000,
    enabled: /^T\d{4}(\.\d{3})?$/.test(tid),
  });

  // sub-technique with no events of its own → show the PARENT's real observations
  // in the graph panel (clearly labelled) instead of a dead-end empty state
  const hint = q.data?.parent_activity;
  const showParentGraph = !!hint && hint.events > 0 && !q.data?.observed.events;
  const parentQ = useQuery({
    queryKey: ["mitre", hint?.id ?? "none"],
    queryFn: () => get<Profile>(`/soc/mitre-profile/${encodeURIComponent(hint!.id)}`),
    refetchInterval: 10_000,
    enabled: !!showParentGraph,
  });
  const graphPerMin = useMemo(() => {
    const src = showParentGraph ? parentQ.data : q.data;
    const tl = src?.observed.timeline ?? [];
    return tl.length ? tl[tl.length - 1].count : 0;
  }, [showParentGraph, parentQ.data, q.data]);

  if (!/^T\d{4}(\.\d{3})?$/.test(tid)) {
    return <div className="span-12"><ErrBanner error={`'${tid}' is not a technique id (expected T1070 or T1070.001)`} /></div>;
  }
  if (q.isPending) return <div className="span-12"><LoaderRows lines={["fetching official technique record", "joining local alert history"]} /></div>;
  if (q.error) return <div className="span-12"><ErrBanner error={q.error} /></div>;

  const d = q.data!;
  const t = d.technique;
  const o = d.observed;
  const live = o.last && Date.now() - new Date(o.last + (o.last.endsWith("Z") ? "" : "Z")).getTime() < 15 * 60_000;
  const pd = showParentGraph ? parentQ.data : undefined;
  const graphD = pd && pd.observed.events ? pd : d;

  return (
    <>
      <div className="span-12">
        <Panel
          title={`${t.id} · ${t.name}`}
          actions={
            <span style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
              <Chip tone={o.events ? (live ? "ok" : "info") : "dim"} label={o.events ? `${o.events} observed event${o.events === 1 ? "" : "s"}` : "no local activity yet"} />
              <Chip tone={t.source.startsWith("unavailable") ? "fail" : "dim"} label={`metadata: ${t.source}`} />
              <span className="watermark-note">refreshes every 10 s · move the cursor to part the net · drag nodes</span>
              <a className="btn small" href={t.url} target="_blank" rel="noreferrer">attack.mitre.org ↗</a>
            </span>
          }
        >
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
            {t.tactics.map((x) => <Chip key={x.id} tone="warn" label={`tactic · ${x.name}`} />)}
            <Chip tone="info" label={`${t.matrix} matrix`} />
            {t.platforms.map((x) => <Chip key={x} tone="dim" label={x} />)}
          </div>
          {t.description ? <p className="page-note" style={{ margin: 0 }}>{t.description}</p> : (
            <p className="page-note" style={{ color: "var(--fail)" }}>Official record unavailable ({t.source}) — local observations below are still real.</p>
          )}
          {t.parent ? <p className="page-note cell-id">sub-technique of <Link href={`/soc/mitre/${t.parent.id}`}>{t.parent.id} · {t.parent.name}</Link></p> : null}
        </Panel>
      </div>

      <div className="span-8">
        <Panel
          title="Activity graph — technique · sub-techniques · hosts · signatures"
          actions={<span className="watermark-note">live: {d.as_of.slice(11, 19)}Z</span>}
        >
          {graphD.observed.events ? (
            <>
              {graphD !== d && (
                <div className="page-note" style={{ margin: "0 0 8px", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <Chip tone="info" label={`showing ${graphD.technique.id} — ${t.id} has no events tagged to it yet`} />
                  <Link href={`/soc/mitre/${graphD.technique.id}`}>open parent profile ↗</Link>
                </div>
              )}
              <MitreGraph nodes={graphD.graph.nodes} links={graphD.graph.links} recentPerMin={graphPerMin} />
            </>
          ) : (
            <div style={{ height: 320, display: "grid", placeItems: "center", textAlign: "center" }}>
              <div>
                <div style={{ fontSize: 34, marginBottom: 6 }}>⬡</div>
                <b>{t.name}</b> has no observed events on this platform yet.<br />
                <span className="dim">The graph builds itself from real alerts the moment detection fires — nothing is simulated.</span>
                <div style={{ marginTop: 10 }}>
                  <MitreGraph nodes={[{ id: t.id, label: `${t.id}`, kind: "technique", weight: 0 }]} links={[]} recentPerMin={0} height={140} />
                </div>
              </div>
            </div>
          )}
        </Panel>
      </div>

      <div className="span-4">
        <Panel title="When — events per hour" tight>
          <div style={{ padding: 10 }}>
            {o.timeline.length ? (
              <ResponsiveContainer width="100%" height={150}>
                <AreaChart data={o.timeline}>
                  <defs>
                    <linearGradient id="gmitre" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#2563eb" stopOpacity={0.45} />
                      <stop offset="100%" stopColor="#2563eb" stopOpacity={0.04} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="hour" hide />
                  <YAxis hide allowDecimals={false} />
                  <Tooltip
                    formatter={(v: number) => [`${v} event${v === 1 ? "" : "s"}`, "count"]}
                    labelFormatter={(l: string) => `${l}Z`}
                    contentStyle={{ fontFamily: "var(--font-mono)", fontSize: 11, borderRadius: 8, border: "1px solid var(--line)" }}
                  />
                  <Area type="monotone" dataKey="count" stroke="#2563eb" strokeWidth={2} fill="url(#gmitre)" animationDuration={600} />
                </AreaChart>
              </ResponsiveContainer>
            ) : <p className="page-note">No timeline yet — first alert will draw it.</p>}
            {o.first ? <p className="page-note cell-id" style={{ margin: "6px 0 2px" }}>first {fmtTs(o.first)} · last {fmtTs(o.last)}Z</p> : null}
          </div>
        </Panel>
        <Panel title="Who & where — hosts" tight>
          <div style={{ padding: o.hosts.length ? 0 : 12 }}>
            {o.hosts.length ? (
              <table className="dtable">
                <thead><tr><th>ip</th><th className="r">ev</th><th className="r">src</th><th className="r">dst</th><th>seen</th></tr></thead>
                <tbody>
                  {o.hosts.slice(0, 10).map((h) => (
                    <tr key={h.ip}>
                      <td className="cell-id">{h.ip}</td>
                      <td className="r">{h.events}</td><td className="r">{h.sources}</td><td className="r">{h.destinations}</td>
                      <td className="cell-id">{fmtTs(h.last ?? "")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <p className="page-note">No host activity recorded for this technique yet.</p>}
          </div>
        </Panel>
      </div>

      <div className="span-6">
        <Panel title="What & how — detection signatures" tight>
          <div style={{ padding: o.signatures.length ? 0 : 12 }}>
            {o.signatures.length ? (
              <table className="dtable">
                <thead><tr><th>signature</th><th>severity</th><th className="r">events</th></tr></thead>
                <tbody>
                  {o.signatures.slice(0, 12).map((s) => (
                    <tr key={s.signature}>
                      <td style={{ maxWidth: 340, overflow: "hidden", textOverflow: "ellipsis" }}>{s.signature}</td>
                      <td><Chip tone={s.max_severity === "CRITICAL" || s.max_severity === "HIGH" ? "fail" : s.max_severity === "MEDIUM" ? "warn" : "dim"} label={s.max_severity} /></td>
                      <td className="r">{s.events}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <p className="page-note">No signatures have fired for this technique on this platform.</p>}
          </div>
        </Panel>
      </div>

      <div className="span-6">
        <Panel title="Sub-techniques (official) & observed" tight>
          <div style={{ padding: 12, display: "flex", gap: 6, flexWrap: "wrap" }}>
            {t.subtechniques.map((s) => (
              <Link key={s.id} href={`/soc/mitre/${s.id}`} className={`btn small${o.subtechniques_seen[s.id] ? " primary" : ""}`}
                title={o.subtechniques_seen[s.id] ? `${o.subtechniques_seen[s.id]} observed events` : "official sub-technique"}>
                {s.id} · {s.name}{o.subtechniques_seen[s.id] ? ` (${o.subtechniques_seen[s.id]})` : ""}
              </Link>
            ))}
            {!t.subtechniques.length ? <span className="page-note">No sub-techniques recorded.</span> : null}
          </div>
        </Panel>
        <Panel title="How to stop it — official mitigations" tight>
          <div style={{ padding: t.mitigations.length ? 0 : 12 }}>
            {t.mitigations.length ? (
              <table className="dtable">
                <thead><tr><th>id</th><th>mitigation</th><th>what it does</th></tr></thead>
                <tbody>
                  {t.mitigations.map((m) => (
                    <tr key={m.id}>
                      <td className="cell-id">{m.id}</td>
                      <td style={{ whiteSpace: "nowrap" }}>{m.name}</td>
                      <td className="dim" style={{ maxWidth: 420 }}>{m.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <p className="page-note">No mitigation records returned.</p>}
          </div>
        </Panel>
      </div>
    </>
  );
}
