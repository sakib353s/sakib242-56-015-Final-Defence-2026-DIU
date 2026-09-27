"use client";

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { get } from "@/lib/api";
import Link from "next/link";
import { getRole } from "@/lib/auth";
import { hasRole } from "@/lib/rbac";
import { fmtTs, trunc } from "@/lib/format";
import { hostOf, scopeMatches } from "@/lib/scopes";
import { Chip, LoaderRows, useMounted } from "./ui";
import type { LedgerList, Warrant } from "@/lib/types";

/** true = server enforces warrants; false = lab skip (CWB_WARRANT_ENFORCE=auto/off).
    Defaults to enforced until the config resolves — advice mirrors the server, never gates it. */
export function useWarrantEnforced(): boolean {
  const q = useQuery({
    queryKey: ["config"],
    queryFn: () => get<{ warrant_required: boolean }>("/config"),
    staleTime: 3e5,
  });
  return q.data?.warrant_required ?? true;
}

export const KIND_LABEL: Record<Warrant["kind"], string> = {
  pentest: "penetration test",
  vuln_scan: "vulnerability scan",
  remediation: "remediation",
  ipanon: "anonymized routing",
};

export function warrantScope(w: Warrant | undefined | null): string[] {
  if (!w) return [];
  if (w.scope?.length) return w.scope;
  if (w.scope_json) {
    try {
      return JSON.parse(w.scope_json) as string[];
    } catch {
      return [];
    }
  }
  return [];
}

export function activeWarrants(list: Warrant[] | undefined, kind: Warrant["kind"]): Warrant[] {
  const now = Date.now();
  return (list ?? []).filter(
    (w) => w.kind === kind && !w.revoked_at &&
      (!w.valid_from || new Date(w.valid_from) <= new Date(now)) && new Date(w.valid_until) > new Date(now),
  );
}

/* ------------------------- live scope verdict ------------------------- */

export type Verdict = { state: "empty" | "idle" | "covered" | "outside" | "unrecognized"; by?: string };

/** Advisory pre-check mirroring the server's scope logic, so a refusal is
    explained before dispatch instead of arriving as a dead-end toast. */
export function scopeVerdict(target: string, warrant?: Warrant | null): Verdict {
  const host = hostOf(target);
  if (!host) return { state: "empty" };
  const scope = warrantScope(warrant);
  if (!scope.length) return { state: "idle" };
  if (!isTargetShaped(host)) return { state: "unrecognized" };
  if (scopeMatches(scope, host)) {
    const by = scope.find((e) => e.trim().toLowerCase() === host || e.includes("/") || host.endsWith("." + e.trim().toLowerCase()));
    return { state: "covered", by };
  }
  return { state: "outside" };
}

function isTargetShaped(host: string): boolean {
  return host !== "" && !host.includes(" ") && (host.includes(".") || host.includes(":"));
}

export function ScopeVerdict({ target, warrant }: { target: string; warrant?: Warrant | null }) {
  const v = scopeVerdict(target, warrant);
  const enforced = useWarrantEnforced();
  if (v.state === "empty" || v.state === "idle") return null;
  if (v.state === "outside" && !enforced) {
    return (
      <div className="verdict wait" role="status">
        <span className="v-dot" aria-hidden />
        <b>{hostOf(target)}</b> is outside the selected authorization’s scope — lab mode: the server skips
        the scope check for this run and records the skip in the audit log. Production enforces it.
      </div>
    );
  }

  if (v.state === "unrecognized") {
    return (
      <div className="verdict wait" role="status">
        <span className="v-dot" aria-hidden />
        Enter an IP address, domain or URL — the host part is checked against scope.
      </div>
    );
  }

  if (v.state === "covered") {
    return (
      <div className="verdict ok" role="status">
        <span className="v-dot" aria-hidden />
        <b>{hostOf(target)}</b> is inside this authorization’s scope{v.by ? ` (${v.by})` : ""}. The server re-checks this at dispatch and inside every stage.
      </div>
    );
  }

  return (
    <div className="verdict fail" role="alert">
      <span className="v-dot" aria-hidden />
      <b>{hostOf(target)}</b> is outside this authorization’s scope. Covered: {warrantScope(warrant).join(", ") || "—"}. Extend the authorization first, or pick a target inside it.
    </div>
  );
}

/* --------------------------- warrant picker --------------------------- */

export function WarrantPicker({
  kind,
  value,
  onChange,
  target,
  onVerdict,
}: {
  kind: Warrant["kind"];
  value: string;
  onChange: (id: string) => void;
  target?: string;
  onVerdict?: (v: Verdict) => void;
}) {
  const mounted = useMounted();
  const enforced = useWarrantEnforced();
  const role = mounted ? getRole() : null;
  const canList = mounted && hasRole(role, "ANALYST"); // remediation-only ops stay manual-entry below ANALYST
  const isSuper = mounted && hasRole(role, "SUPER_ADMIN");
  const ledger = useQuery({
    // remediation warrants never surface in the analyst subset (fail-closed design);
    // the remediation page is SUPER_ADMIN-only, so it reads the full active ledger.
    queryKey: ["ledger", "available", kind === "remediation" && isSuper ? "active" : "subset"],
    queryFn: () =>
      get<LedgerList>(kind === "remediation" && isSuper ? "/admin/ledger/active" : "/admin/ledger/available"),
    enabled: !!canList && (kind !== "remediation" || !!isSuper),
  });
  const opts = activeWarrants(ledger.data?.warrants, kind);
  const selected = opts.find((w) => w.id === value);
  const v = scopeVerdict(target ?? "", selected);
  useEffect(() => {
    onVerdict?.(v);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [v.state, v.by]);

  // bind the select and state together so the CTA is never silently disabled
  useEffect(() => {
    if (canList && opts.length && !opts.some((w) => w.id === value)) onChange(opts[0].id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canList, value, opts[0]?.id]);

  if (!canList) {
    return (
      <div>
        <div className="lockline" style={{ marginBottom: 8 }}>
          The authorization list requires the Analyst role. If an administrator gave you an authorization ID directly, enter it here.
        </div>
        <input className="text" placeholder="Authorization ID" value={value} onChange={(e) => onChange(e.target.value.trim())} />
      </div>
    );
  }
  if (ledger.isPending) return <LoaderRows paused={ledger.isPaused} lines={["Loading authorizations"]} />;
  if (ledger.error) return <div className="lockline">Could not reach the authorization service — {trunc(String((ledger.error as Error)?.message ?? ledger.error), 60)}</div>;

  if (!opts.length) {
    if (!enforced) {
      return (
        <div className="warrant-empty">
          <div className="we-t">Lab mode — authorization not required</div>
          <div className="we-d">
            Warrant enforcement is relaxed in this lab (CWB_WARRANT_ENFORCE=auto/off); the run proceeds
            without a warrant and the skip is audited. An administrator can issue one on the{" "}
            <Link href="/ledger">Authorization Ledger</Link> page anyway.
          </div>
        </div>
      );
    }
    return (
      <div className="warrant-empty">
        <div className="we-t">No active {KIND_LABEL[kind]} authorization</div>
        <div className="we-d">
          An administrator must issue one before any run can start. The server refuses everything without it — that gate never opens client-side.
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="selectwrap">
        <select className="text" value={value} onChange={(e) => onChange(e.target.value)} aria-label="Authorization">
          {opts.map((w) => (
            <option key={w.id} value={w.id}>
              {w.warrant_ref} · {w.purpose} · until {fmtTs(w.valid_until)}
            </option>
          ))}
        </select>
        <span className="select-carat" aria-hidden />
      </div>
      {selected ? <WarrantMeta warrant={selected} /> : null}
      {target !== undefined ? <ScopeVerdict target={target} warrant={selected} /> : null}
    </div>
  );
}

export function WarrantMeta({ warrant }: { warrant?: Warrant }) {
  if (!warrant) return null;
  const scope = warrantScope(warrant);
  return (
    <div className="warrant-meta">
      <div className="wm-row">
        <span className="wm-k">Scope</span>
        <span className="wm-scope">
          {scope.length ? (
            scope.map((s) => <span key={s} className="scope-chip">{s}</span>)
          ) : (
            <span className="scope-chip">not disclosed by this listing</span>
          )}
        </span>
      </div>
      <div className="wm-row">
        <span className="wm-k">Purpose</span>
        <span className="wm-v">{warrant.purpose}</span>
      </div>
      <div className="wm-row">
        <span className="wm-k">Valid until</span>
        <span className="wm-v">{fmtTs(warrant.valid_until)}</span>
      </div>
    </div>
  );
}

export function WarrantStatusChip({ warrant }: { warrant?: Warrant }) {
  const now = Date.now();
  if (!warrant) return <Chip tone="dim" label="no authorization" />;
  const left = new Date(warrant.valid_until).getTime() - now;
  const days = Math.floor(left / 86400000);
  return (
    <Chip
      tone={warrant.revoked_at ? "fail" : days < 0 ? "fail" : days <= 7 ? "warn" : "ok"}
      label={warrant.revoked_at ? "revoked" : days < 0 ? "expired" : days <= 7 ? `${days}d left` : `${warrant.warrant_ref}`}
    />
  );
}
