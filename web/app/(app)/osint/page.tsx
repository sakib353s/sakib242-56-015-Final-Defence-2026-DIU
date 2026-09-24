"use client";

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { get, post, qs } from "@/lib/api";
import { fmtTs, trunc } from "@/lib/format";
import { useToast } from "@/components/toast";
import { Chip, EmptyRows, ErrBanner, Field, KV, Leader, LoaderRows, Panel, TabBar, qBusy } from "@/components/ui";
import type { LeakResults, OsintDomainResult, OsintEmailResult, OsintPasswordResult, OsintProfileResult, OsintUrlResult } from "@/lib/types";

type Tab = "email" | "password" | "domain" | "url" | "profile";
const TABS: { id: Tab; label: string }[] = [
  { id: "email", label: "Email" },
  { id: "password", label: "Password" },
  { id: "domain", label: "Domain" },
  { id: "url", label: "URL" },
  { id: "profile", label: "Profile" },
];
const FIELD_LABEL: Record<Tab, string> = {
  email: "Email address",
  password: "Password to check",
  domain: "Domain name",
  url: "Web address",
  profile: "Username or email",
};
const PLACEHOLDER: Record<Tab, string> = {
  email: "someone@example.com",
  password: "Enter a password to test against breach records",
  domain: "example.com",
  url: "https://example.com/path",
  profile: "jdoe or jdoe@example.com",
};
const SCOPENOTE: Record<Tab, string> = {
  email: "Uses the Have I Been Pwned breach registry without an API key, so results are reported at domain level. Audit records store hashed identifiers only.",
  password: "Checks the password against the Pwned Passwords corpus using k-anonymity. Only a five-character SHA-1 prefix is sent; the password itself never leaves this server.",
  domain: "Uses DNS, domain registration data, the TLS certificate and certificate transparency logs, plus Shodan host data where the server has access to it. Public records only — nothing is probed or scanned.",
  url: "Sends a single GET request and reports the redirect chain and security headers. No scanning is performed.",
  profile: "Estimates username exposure from public breach data, scored from 0 to 100.",
};
const SIGNAL_LABEL: Record<string, string> = {
  email_breached: "Found in a public breach",
  breach_count: "Breach count",
  note: "Note",
};
const RUBRIC_LABEL: Record<string, string> = {
  email_exposed: "Email found in a breach",
  breach_count_gt_3: "More than three breaches",
  open_ports_gt_2: "More than two open ports",
  cert_expired: "Expired TLS certificate",
  subdomains_gt_20: "More than 20 subdomains",
};

function signalValue(v: unknown): string {
  if (typeof v === "boolean") return v ? "Yes" : "No";
  return String(v);
}

/** HTTP header names come back lowercased from the wire; they read as Content-Type. */
function headerName(k: string): string {
  return k.split("-").map((p) => (p ? p[0].toUpperCase() + p.slice(1).toLowerCase() : p)).join("-");
}

export default function OsintPage() {
  const toast = useToast();
  const [tab, setTab] = useState<Tab>("email");
  const [draft, setDraft] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [watch, setWatch] = useState("");

  const email = useQuery({
    queryKey: ["osint", "email", submitted],
    queryFn: () => get<OsintEmailResult>(`/osint/email${qs({ e: submitted })}`),
    enabled: tab === "email" && !!submitted,
  });
  const domain = useQuery({
    queryKey: ["osint", "domain", submitted],
    queryFn: () => get<OsintDomainResult>(`/osint/domain${qs({ d: submitted })}`),
    enabled: tab === "domain" && !!submitted,
  });
  const url = useQuery({
    queryKey: ["osint", "url", submitted],
    queryFn: () => get<OsintUrlResult>(`/osint/url${qs({ u: submitted })}`),
    enabled: tab === "url" && !!submitted,
  });
  const profile = useQuery({
    queryKey: ["osint", "profile", submitted],
    queryFn: () => get<OsintProfileResult>(`/osint/profile${qs({ u: submitted })}`),
    enabled: tab === "profile" && !!submitted,
  });
  const leaks = useQuery({ queryKey: ["osint", "leaks"], queryFn: () => get<LeakResults>("/osint/leaks") });
  const pwCheck = useMutation({
    mutationFn: (v: string) => post<OsintPasswordResult>("/osint/password", { password: v }),
  });
  const addWatch = useMutation({
    mutationFn: () => post<{ watch_id: string }>("/osint/leaks/watch", { query: watch }),
    onSuccess: (r) => {
      toast.push({ tone: "ok", title: "Watch registered", text: trunc(r.watch_id, 12) });
      setWatch("");
      leaks.refetch();
    },
  });

  const active = tab === "password" ? null : { email, domain, url, profile }[tab];
  const runQuery = () => {
    if (!draft.trim()) return;
    if (tab === "password") pwCheck.mutate(draft);
    else setSubmitted(draft.trim());
  };

  return (
    <>
      <div className="span-12">
        <Panel title="Open-source intelligence" actions={<span className="watermark-note">Public sources only</span>}>
          <TabBar tabs={TABS} active={tab} onChange={(t) => { setTab(t as Tab); setSubmitted(""); }} />
          <div className="runrow" style={{ marginTop: 4 }}>
            <div style={{ flex: 1 }}>
              <Field label={FIELD_LABEL[tab]}>
                <input
                  className="text"
                  type={tab === "password" ? "text" : undefined}
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && runQuery()}
                  placeholder={PLACEHOLDER[tab]}
                  maxLength={2048}
                />
              </Field>
            </div>
            <button type="button" className="btn primary" disabled={!draft.trim()} onClick={runQuery}>
              {tab === "password" && pwCheck.isPending ? "Checking…" : "Search"}
            </button>
            {active && submitted ? (
              <button type="button" className="btn" onClick={() => active.refetch()}>
                ↻
              </button>
            ) : null}
          </div>
          <div className="page-note">{SCOPENOTE[tab]}</div>
        </Panel>
      </div>

      {active && qBusy(active) ? (
        <div className="span-12">
          <LoaderRows paused={(active as { isPaused?: boolean }).isPaused} lines={["Loading results", tab === "domain" ? "Reading DNS, registration, and certificate records" : "Correlating public sources"]} />
        </div>
      ) : null}
      {tab === "password" && pwCheck.isPending ? (
        <div className="span-12">
          <LoaderRows lines={["Checking the password", "Comparing it against known breach records"]} />
        </div>
      ) : null}
      {active && active.error && submitted ? (
        <div className="span-12">
          <ErrBanner error={active.error} onRetry={() => active.refetch()} />
        </div>
      ) : null}
      {tab === "password" && pwCheck.error ? (
        <div className="span-12">
          <ErrBanner error={pwCheck.error} />
        </div>
      ) : null}

      {pwCheck.data ? (
        <div className="span-12">
          <Panel title="Password exposure" tight>
            <div style={{ padding: 14 }}>
              <Leader
                label="Breach check"
                value={pwCheck.data.pwned ? "Found in known breaches" : "Not found in known breaches"}
                tone={pwCheck.data.pwned ? "fail" : "ok"}
              />
              <div className="page-note" style={{ marginTop: 8 }}>
                <b style={{ color: pwCheck.data.pwned ? "var(--fail)" : "var(--ok)" }}>
                  {pwCheck.data.approximate_exposures.toLocaleString()}
                </b>{" "}
                {pwCheck.data.approximate_exposures === 1 ? "appearance" : "appearances"} of this password in breached
                data sets. {pwCheck.data.pwned
                  ? "Rotate it wherever it is still in use."
                  : "It has not appeared in the corpus we can reach."}{" "}
                Logged as case {trunc(pwCheck.data.case_id, 10)}.
              </div>
            </div>
          </Panel>
        </div>
      ) : null}

      {active && !qBusy(active) && submitted && tab === "email" && email.data ? (
        <div className="span-12">
          <Panel
            title={`Breaches found (${email.data.breach_count})`}
            tight
            actions={
              <Chip
                tone={email.data.mode?.startsWith("exact") ? "ok" : "info"}
                label={email.data.mode?.startsWith("exact") ? "Exact address" : "Whole domain"}
              />
            }
          >
            <div style={{ padding: 12 }}>
              {!email.data.breaches.length ? (
                <EmptyRows what={email.data.mode?.startsWith("exact") ? "No breaches found for this address" : `No breaches recorded for ${email.data.domain ?? "this domain"}. Without a registry account the search covers the whole domain rather than this single address.`} />
              ) : (
                <>
                  <div className="page-note" style={{ marginBottom: 8 }}>
                    Case {trunc(email.data.case_id, 14)}
                    {email.data.registry_total ? ` · ${email.data.registry_total.toLocaleString()} breaches indexed in the free registry` : ""}
                  </div>
                  <div className="tiles">
                    {email.data.breaches.map((b, i) => (
                      <div className="breach-card" key={i}>
                        <div className="bn">{b.Title ?? b.Name ?? "Unknown"}</div>
                        <div className="bd2">{b.Name} · {b.Domain ?? "Unknown"} · Breached {b.BreachDate ?? "unknown"} · Verified {b.Verified ? "yes" : "unknown"}</div>
                        <div className="dc" style={{ marginTop: 4 }}>
                          {(b.DataClasses ?? []).map((d) => (
                            <span className="chip warn" key={d} style={{ marginRight: 4, marginBottom: 4 }}>
                              {d}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </Panel>
        </div>
      ) : null}

      {active && !qBusy(active) && submitted && tab === "domain" && domain.data ? (
        <>
          <div className="span-6">
            <Panel title="Domain registration and TLS">
              {Object.entries(domain.data.dns ?? {}).length === 0 ? <EmptyRows what="No DNS records returned" /> : null}
              {Object.entries(domain.data.dns ?? {}).map(([t, recs]) => (
                <div key={t}>
                  <Leader label={`${t} records`} value={String(recs.length)} tone="info" />
                  <ul style={{ margin: "2px 0 8px", paddingLeft: 18, color: "var(--dim)", fontSize: 11 }}>
                    {recs.slice(0, 6).map((r) => (
                      <li key={r}>{trunc(r, 70)}</li>
                    ))}
                  </ul>
                </div>
              ))}
              {domain.data.rdap && !domain.data.rdap.error ? (
                <KV
                  rows={[
                    ["RDAP handle", domain.data.rdap.handle ?? "—"],
                    [
                      "Events",
                      (domain.data.rdap.events ?? []).map((e) => `${e.eventAction}: ${trunc(e.date ?? "", 20)}`).join(" · ") || "—",
                    ],
                  ]}
                />
              ) : (
                <div className="page-note">
                  {domain.data.rdap?.error === "unreachable"
                    ? "The RDAP registry could not be reached from this server."
                    : "This domain has no public RDAP record."}
                </div>
              )}
              {domain.data.tls && !domain.data.tls.error ? (
                <KV
                  rows={[
                    ["TLS valid until", domain.data.tls.not_after ?? "—"],
                    ["Expiring soon", domain.data.tls.expire_warning ? <span key="y" style={{ color: "var(--fail)" }}>Yes</span> : "No"],
                    ["Issuer", Object.values(domain.data.tls.issuer ?? {}).join(" ") || "—"],
                  ]}
                />
              ) : null}
            </Panel>
          </div>
          <div className="span-6">
            <Panel title="Attack surface" tight>
              {domain.data.shodan && !domain.data.shodan.error ? (
                <div style={{ padding: 12 }}>
                  <Leader label="Shodan hosts" value={String((domain.data.shodan.hosts ?? []).length)} tone="info" />
                  <div className="cell-id">{(domain.data.shodan.hosts ?? []).join(", ") || "—"}</div>
                  <div style={{ marginTop: 6 }}>
                    {(domain.data.shodan.data ?? []).map((d) => (
                      <span className="chip dim" key={d} style={{ marginRight: 4 }}>
                        {d}
                      </span>
                    ))}
                  </div>
                </div>
              ) : (
                <div style={{ padding: 12 }}>
                  <EmptyRows what="Shodan is not configured on the server, so exposed hosts are unavailable" />
                </div>
              )}
            </Panel>
            <div style={{ height: 16 }} />
            <Panel title="Subdomains (certificate transparency)" tight>
              {!domain.data.subdomains?.length ? (
                <div style={{ padding: 12 }}>
                  <EmptyRows what="No subdomains found" />
                </div>
              ) : (
                <div style={{ padding: 12, maxHeight: 220, overflow: "auto", columns: 2, fontSize: 11.5 }}>
                  {domain.data.subdomains.map((s) => (
                    <div key={s}>{s}</div>
                  ))}
                </div>
              )}
            </Panel>
          </div>
        </>
      ) : null}

      {active && !qBusy(active) && submitted && tab === "url" && url.data ? (
        <div className="span-8">
          <Panel title="URL analysis">
            <KV
              rows={[
                ["Final status", <Chip key="s" tone={url.data.status < 400 ? "ok" : "warn"} label={String(url.data.status)} />],
                ["Resolved", url.data.final_url],
                ["Redirect chain", url.data.redirects.length ? url.data.redirects.join("  →  ") : "Direct"],
                ...Object.entries(url.data.headers).map(([k, v]) => [headerName(k), v] as [string, string]),
                ["Case", trunc(url.data.case_id, 14)],
              ]}
            />
          </Panel>
        </div>
      ) : null}

      {active && !qBusy(active) && submitted && tab === "profile" && profile.data ? (
        <div className="span-8">
          <Panel title="Username exposure">
            <div className="gauge" style={{ marginBottom: 12 }}>
              <span className="gv" style={{ color: profile.data.exposure_score > 50 ? "var(--fail)" : "var(--warn)" }}>
                {profile.data.exposure_score}
              </span>
              <div className="dial-track">
                <div
                  className="dial-fill"
                  style={{ width: `${profile.data.exposure_score}%`, color: profile.data.exposure_score > 50 ? "var(--fail)" : "var(--warn)" }}
                />
              </div>
              <span className="cell-id">/100</span>
            </div>
            <KV
              rows={[
                ["Subject hash", profile.data.username_hash],
                ...Object.entries(profile.data.signals).map(([k, v]) => [SIGNAL_LABEL[k] ?? k, signalValue(v)] as [string, string]),
              ]}
            />
            {Object.keys(profile.data.rubric).length ? (
              <div style={{ marginTop: 10 }}>
                <div className="page-note">Scoring weights</div>
                {Object.entries(profile.data.rubric).map(([k, v]) => (
                  <Leader key={k} label={RUBRIC_LABEL[k] ?? k} value={`+${v}`} tone="dim" />
                ))}
              </div>
            ) : null}
          </Panel>
        </div>
      ) : null}

      <div className="span-12">
        <Panel
          title="Leak monitor (public repositories)"
          tight
          actions={
            <div style={{ display: "flex", gap: 6 }}>
              <input
                className="text"
                style={{ width: 268 }}
                placeholder="Token, domain or brand to watch for"
                value={watch}
                onChange={(e) => setWatch(e.target.value)}
                maxLength={64}
              />
              <button type="button" className="btn small primary" disabled={!watch.trim() || addWatch.isPending} onClick={() => addWatch.mutate()}>
                Add watch
              </button>
              <button type="button" className="btn small" onClick={() => leaks.refetch()}>
                ↻ Rescan
              </button>
            </div>
          }
        >
          {leaks.isPending ? (
            <LoaderRows lines={["Loading leak monitors", "Searching public code for each watch"]} />
          ) : leaks.error ? (
            <div style={{ padding: 12 }}>
              <ErrBanner error={leaks.error} onRetry={() => leaks.refetch()} />
            </div>
          ) : !leaks.data!.results.length ? (
            <div style={{ padding: 12 }}>
              <EmptyRows what="No watches registered yet. Add one above." />
            </div>
          ) : (
            <table className="dtable">
              <thead>
                <tr>
                  <th>Watch</th>
                  <th>Matched repositories</th>
                  <th>Last checked</th>
                </tr>
              </thead>
              <tbody>
                {leaks.data!.results.map((r) => (
                  <tr key={r.watch_id}>
                    <td title={`Query hash ${r.query_hash}`}>{r.query}</td>
                    <td>
                      {r.public_repos_matched < 0 ? (
                        <Chip tone="warn" label="Rate limited" />
                      ) : r.public_repos_matched > 0 ? (
                        <Chip tone="fail" label={`${r.public_repos_matched} matches`} />
                      ) : (
                        <Chip tone="ok" label="No matches" />
                      )}
                    </td>
                    <td className="cell-id">{fmtTs(r.checked_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {addWatch.isError ? <div style={{ padding: 12 }}><ErrBanner error={addWatch.error} /></div> : null}
        </Panel>
      </div>
    </>
  );
}
