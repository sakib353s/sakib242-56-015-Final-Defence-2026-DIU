"use client";

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { get } from "@/lib/api";
import { getRole } from "@/lib/auth";
import { hasRole } from "@/lib/rbac";
import { fmtTs, trunc } from "@/lib/format";
import { Leader, LoaderRows, useMounted } from "./ui";
import type { LedgerList, Warrant } from "@/lib/types";

export const KIND_LABEL: Record<Warrant["kind"], string> = {
  pentest: "penetration test",
  vuln_scan: "vulnerability scan",
  remediation: "remediation",
  ipanon: "anonymized routing",
};

export function activeWarrants(list: Warrant[] | undefined, kind: Warrant["kind"]): Warrant[] {
  const now = Date.now();
  return (list ?? []).filter(
    (w) => w.kind === kind && !w.revoked_at &&
      (!w.valid_from || new Date(w.valid_from) <= new Date(now)) && new Date(w.valid_until) > new Date(now),
  );
}

export function WarrantPicker({
  kind,
  value,
  onChange,
}: {
  kind: Warrant["kind"];
  value: string;
  onChange: (id: string) => void;
}) {
  const mounted = useMounted();
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

  useEffect(() => {
    // the select would otherwise render option 1 as chosen while state is still empty,
    // leaving the CTA disabled with no visible cause — bind them together
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
  if (!opts.length)
    return (
      <div className="lockline">
        No active {KIND_LABEL[kind]} authorization. An administrator must issue one before this can run.
      </div>
    );
  return (
    <div>
      <select className="text" value={value} onChange={(e) => onChange(e.target.value)}>
        {opts.map((w) => (
          <option key={w.id} value={w.id}>
            {w.warrant_ref} · {w.purpose}
          </option>
        ))}
      </select>
      {value ? <WarrantMeta warrant={opts.find((w) => w.id === value)} /> : null}
    </div>
  );
}

export function WarrantMeta({ warrant }: { warrant?: Warrant }) {
  if (!warrant) return null;
  let scope: string[] = warrant.scope ?? [];
  if (!scope.length && warrant.scope_json) {
    try {
      scope = JSON.parse(warrant.scope_json) as string[];
    } catch {
      scope = [];
    }
  }
  return (
    <div style={{ marginTop: 6 }}>
      <Leader label="Valid until" value={fmtTs(warrant.valid_until)} tone="warn" />
      <Leader label="Scope" value={scope.join(", ") || "—"} />
      <Leader label="Purpose" value={warrant.purpose} />
    </div>
  );
}
