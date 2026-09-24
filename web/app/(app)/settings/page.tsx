"use client";

import { useState } from "react";
import { apiFetch, get, post, qs } from "@/lib/api";
import { getRole } from "@/lib/auth";
import { hasRole, ROLE_TAG } from "@/lib/rbac";
import { fmtMs, trunc } from "@/lib/format";
import { useToast } from "@/components/toast";
import { Chip, EmptyRows, ErrBanner, Field, KV, Leader, LoaderRows, Lock, Panel, TabBar, useMounted } from "@/components/ui";
import { ThemeSelect } from "@/components/theme";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { AuditChainVerify, AuditEntry, Me, PolicyResult } from "@/lib/types";

interface EnrollStart {
  secret: string;
  uri: string;
  expires_at?: string;
  audit_ref: string;
}

const TABS = [
  { id: "appearance", label: "Appearance" },
  { id: "operator", label: "Profile" },
  { id: "totp", label: "Two-factor" },
  { id: "compliance", label: "Compliance" },
  { id: "audit", label: "Audit chain" },
];

export default function SettingsPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const mounted = useMounted();
  const [tab, setTab] = useState("appearance");
  const me = useQuery({ queryKey: ["me"], queryFn: () => get<Me>("/auth/me") });
  const policy = useQuery({
    queryKey: ["policy"],
    queryFn: () => get<PolicyResult>("/settings/policy"),
    enabled: mounted && hasRole(getRole(), "ANALYST"),
  });

  const [enroll, setEnroll] = useState<EnrollStart | null>(null);
  const [code, setCode] = useState("");

  const startEnroll = useMutation({
    mutationFn: () => post<EnrollStart>("/auth/totp/enroll"),
    onSuccess: (r) => {
      setEnroll(r);
      setCode("");
      toast.push({ tone: "info", title: "Enrollment started", text: "Enter a current code within 10 minutes to finish setup" });
    },
  });

  const verifyEnroll = useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; enrolled: boolean }>("/auth/totp/enroll", {
        method: "POST",
        body: { code },
      }),
    onSuccess: () => {
      toast.push({ tone: "ok", title: "Two-factor authentication enabled", text: "A verification code is now required for privileged actions" });
      setEnroll(null);
      setCode("");
      qc.invalidateQueries({ queryKey: ["me"] });
    },
  });

  const isSuper = mounted && hasRole(getRole(), "SUPER_ADMIN");
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const audit = useQuery({
    queryKey: ["audit", actor, action],
    queryFn: () => get<{ entries: AuditEntry[] }>(`/admin/audit${qs({ limit: 200, actor: actor || undefined, action: action || undefined })}`),
    enabled: isSuper,
  });
  const [chainVerdict, setChainVerdict] = useState<AuditChainVerify | null>(null);
  const verify = useMutation({
    mutationFn: () => post<AuditChainVerify>("/admin/audit/verify", { trigger_source: "api" }),
    onSuccess: (r) => {
      setChainVerdict(r);
      toast.push({ tone: r.ok ? "ok" : "fail", title: r.ok ? "Audit chain verified" : "Audit chain does not match", text: r.ok ? `${r.verified} entries checked` : `Mismatch found at entry ${r.broken_at}` });
    },
    onError: (e) => toast.push({ tone: "fail", title: "Verification failed", text: String((e as Error).message) }),
  });

  return (
    <div className="span-12">
      <TabBar
        tabs={TABS}
        active={tab}
        onChange={setTab}
        actions={
          tab === "audit" && isSuper ? (
            <button type="button" className="btn small primary" disabled={verify.isPending} onClick={() => verify.mutate()}>
              Verify full chain
            </button>
          ) : tab === "totp" && !enroll ? (
            <button type="button" className="btn small primary" disabled={startEnroll.isPending} onClick={() => startEnroll.mutate()}>
              Start enrollment
            </button>
          ) : null
        }
      />

      {tab === "appearance" ? (
        <div className="tab-body">
          <div className="span-6">
            <Panel title="Appearance">
              <ThemeSelect />
              <div className="page-note" style={{ marginTop: 10 }}>
                Dark is the default theme. Light uses the same contrast values and meets WCAG AA. The
                change applies across the console as soon as you pick it.
              </div>
            </Panel>
          </div>
          <div className="span-6">
            <Panel title="About these settings">
              <KV
                rows={[
                  ["Profile", "Account details and session information"],
                  ["Two-factor", "Authentication setup and enrollment"],
                  ["Compliance", "Policy details and the signed policy checksum"],
                  ["Audit", "Signed audit trail, visible to administrators"],
                ]}
              />
              <div className="page-note" style={{ marginTop: 10 }}>
                Nothing here changes what an action requires: the server still checks authorization,
                role and step-up verification on every request.
              </div>
            </Panel>
          </div>
        </div>
      ) : null}

      {tab === "operator" ? (
        <div className="tab-body">
          <div className="span-6">
            <Panel title="Your profile">
              {me.isPending ? (
                <LoaderRows lines={["Loading your profile"]} />
              ) : me.error ? (
                <ErrBanner error={me.error} onRetry={() => me.refetch()} />
              ) : (
                <KV
                  rows={[
                    ["Username", me.data!.username],
                    ["Role", <Chip key="r" tone="info" label={ROLE_TAG[me.data!.role]} />],
                    ["Two-factor", <Chip key="t" tone={me.data!.totp_ok ? "ok" : "warn"} label={me.data!.totp_ok ? "Verified at sign-in" : "Not verified"} />],
                    ["Session", <span key="s" className="cell-id">{me.data!.session_id}</span>],
                    ["User ID", <span key="i" className="cell-id">{me.data!.id}</span>],
                  ]}
                />
              )}
            </Panel>
          </div>
        </div>
      ) : null}

      {tab === "totp" ? (
        <div className="tab-body">
          <div className="span-7">
            <Panel title="Two-factor authentication">
              {!enroll ? (
                <>
                  <div className="page-note" style={{ marginBottom: 10 }}>
                    This generates a setup key and a configuration link. Enter one current code to activate
                    the factor. Two-factor authentication is required for privileged actions.
                  </div>
                  <button type="button" className="btn primary" disabled={startEnroll.isPending} onClick={() => startEnroll.mutate()}>
                    Start enrollment
                  </button>
                </>
              ) : (
                <>
                  <KV
                    rows={[
                      ["Setup key", <code key="s" style={{ color: "var(--warn)" }}>{enroll.secret}</code>],
                      ["Configuration", <span key="u" className="cell-id" style={{ wordBreak: "break-all" }}>{enroll.uri}</span>],
                      ["Audit reference", <span key="a" className="cell-id">{enroll.audit_ref}</span>],
                    ]}
                  />
                  <Field label="Enter a current 6-digit code" hint="The setup key is stored encrypted on the server and never returns to the browser. The request expires after 10 minutes.">
                    <input
                      className="text"
                      inputMode="numeric"
                      maxLength={6}
                      value={code}
                      onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      placeholder="123456"
                    />
                  </Field>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button type="button" className="btn" onClick={() => setEnroll(null)}>
                      Cancel
                    </button>
                    <button type="button" className="btn primary" disabled={code.length !== 6 || verifyEnroll.isPending} onClick={() => verifyEnroll.mutate()}>
                      Activate
                    </button>
                  </div>
                </>
              )}
              {startEnroll.isError ? <ErrBanner error={startEnroll.error} /> : null}
              {verifyEnroll.isError ? <ErrBanner error={verifyEnroll.error} /> : null}
            </Panel>
          </div>
        </div>
      ) : null}

      {tab === "compliance" ? (
        <div className="tab-body">
          <div className="span-7">
            <Panel title="Policy integrity">
              {!mounted || !hasRole(getRole(), "ANALYST") ? (
                <Lock text="Policy settings require the Analyst role" />
              ) : policy.isPending ? (
                <LoaderRows lines={["Loading policy details"]} />
              ) : policy.error ? (
                <ErrBanner error={policy.error} onRetry={() => policy.refetch()} />
              ) : (
                <>
                  <Leader label="Policy file checksum (SHA-256)" value={policy.data!.sha256.slice(0, 32)} tone="ok" />
                  <Leader label="Active policy sets" value={String(policy.data!.ledger_active.length)} tone={policy.data!.ledger_active.length ? "warn" : "dim"} />
                  <details style={{ marginTop: 10 }}>
                    <summary className="page-note" style={{ cursor: "pointer" }}>
                      View the policy file as stored on disk, verified at startup
                    </summary>
                    <pre className="diff" style={{ maxHeight: 280 }}>{JSON.stringify(policy.data!.rulepack, null, 2)}</pre>
                  </details>
                </>
              )}
            </Panel>
          </div>
        </div>
      ) : null}

      {tab === "audit" ? (
        <div className="tab-body">
          <div className="span-12">
            <Panel title="Audit chain" tight>
              {!isSuper ? (
                <div style={{ padding: 12 }}>
                  <Lock text="The audit trail is visible to administrators" />
                </div>
              ) : (
                <>
                  {chainVerdict ? (
                    chainVerdict.ok ? (
                      <div style={{ padding: "10px 12px", color: "var(--ok)" }}>
                        Audit chain re-computed successfully. {String(chainVerdict.verified)} entries verified.
                      </div>
                    ) : (
                      <div className="problem" style={{ margin: 12 }}>
                        <div className="pt">Audit chain verification failed at entry {String(chainVerdict.broken_at)}</div>
                        <div className="pd">Restore the audit database from a known-good backup before any privileged operation. The console does not treat a chain that fails verification as reliable.</div>
                      </div>
                    )
                  ) : null}
                  <div style={{ display: "flex", gap: 6, padding: 12, borderBottom: "1px solid var(--line)" }}>
                    <input className="text" placeholder="Filter by actor" value={actor} onChange={(e) => setActor(e.target.value)} style={{ maxWidth: 180 }} />
                    <input className="text" placeholder="Filter by action" value={action} onChange={(e) => setAction(e.target.value)} style={{ maxWidth: 180 }} />
                    <button type="button" className="btn small" onClick={() => audit.refetch()}>
                      Search
                    </button>
                  </div>
                  {audit.isPending ? (
                    <LoaderRows lines={["Loading recent audit entries"]} />
                  ) : audit.error ? (
                    <div style={{ padding: 12 }}>
                      <ErrBanner error={audit.error} onRetry={() => audit.refetch()} />
                    </div>
                  ) : !audit.data!.entries.length ? (
                    <div style={{ padding: 12 }}>
                      <EmptyRows what="No entries match the current filters" />
                    </div>
                  ) : (
                    <div className="scroll-x">
                      <table className="dtable">
                        <thead>
                          <tr>
                            <th>Sequence</th>
                            <th>Time</th>
                            <th>Actor</th>
                            <th>Action</th>
                            <th>Object</th>
                            <th>Signature</th>
                          </tr>
                        </thead>
                        <tbody>
                          {audit.data!.entries.slice(0, 100).map((e) => (
                            <tr key={e.seq}>
                              <td className="cell-id">{e.seq}</td>
                              <td className="cell-id">{fmtMs(e.ts_ms)}</td>
                              <td>{trunc(e.actor, 18)}</td>
                              <td style={{ color: "var(--hdr)" }}>{e.action}</td>
                              <td className="cell-id">{trunc(e.object_ref, 22)}</td>
                              <td className="cell-id">{trunc(e.hmac, 10)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </>
              )}
            </Panel>
          </div>
        </div>
      ) : null}
    </div>
  );
}
