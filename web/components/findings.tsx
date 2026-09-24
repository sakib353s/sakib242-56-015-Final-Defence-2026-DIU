"use client";

/* Shared finding presentation for pentest, vuln and remediation pages.
   Recommendations are derived only from fields the scanner actually returned —
   nothing here invents a finding or a score. */

import Link from "next/link";
import { humanStatus, trunc } from "@/lib/format";
import { Chip, Meter } from "./ui";
import type { Finding } from "@/lib/types";

export function sevVar(sev: string | null | undefined): string {
  const s = (sev ?? "").toUpperCase();
  return s === "CRITICAL" ? "var(--sev-critical)"
    : s === "HIGH" ? "var(--sev-high)"
    : s === "MEDIUM" ? "var(--sev-medium)"
    : s === "LOW" ? "var(--sev-low)"
    : "var(--sev-info)";
}

/** Actionable guidance derived only from fields the scanner actually returned. */
export function recommendation(f: Finding): { fix: string; why: string } {
  const svc = (f.service ?? "").toLowerCase();
  const where = f.port ? `${svc || "the service"} on port ${f.port}` : svc || "this service";
  const fix = f.cve
    ? `Upgrade or patch ${where} to a release that resolves ${f.cve}, then re-run this scan to confirm the finding clears.`
    : `Harden or reconfigure ${where}, or remove it from the network if it is not required.`;
  const why = [
    f.cvss != null ? `CVSS ${f.cvss.toFixed(1)}` : null,
    f.mitre ? `mapped to ${f.mitre}` : null,
    f.description ? trunc(f.description, 160) : null,
  ].filter(Boolean).join(" · ");
  return { fix, why: why || "Recorded by reconnaissance against the authorized target." };
}

export function SevBar({ findings }: { findings: Finding[] }) {
  const counts = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => ({
    s, n: findings.filter((f) => (f.severity || "").toUpperCase() === s).length,
  }));
  const total = findings.length;
  if (!total) return null;
  return (
    <div className="sev-bar" role="img" aria-label={counts.map((c) => `${c.n} ${c.s.toLowerCase()}`).join(", ")}>
      {counts.map((c) => (
        <span key={c.s} style={{ width: `${(c.n / total) * 100}%`, background: sevVar(c.s) }} title={`${c.n} ${c.s}`} />
      ))}
    </div>
  );
}

export function CveCell({ f }: { f: Finding }) {
  if (!f.cve) return <td className="cell-id">—</td>;
  return (
    <td className="cell-id">
      <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve)}`} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>
        {f.cve}
      </a>
    </td>
  );
}

export function CvssCell({ f }: { f: Finding }) {
  if (f.cvss === null || f.cvss === undefined) return <td>—</td>;
  return (
    <td>
      <span className="meter-td">
        {f.cvss.toFixed(1)}
        <Meter v={f.cvss} max={10} tone={f.cvss >= 7 ? "fail" : f.cvss >= 4 ? "warn" : "info"} />
      </span>
    </td>
  );
}

/** Table row + expandable remediation detail row. */
export function FindingRow({ f, open, onToggle }: { f: Finding; open: boolean; onToggle: () => void }) {
  const rec = recommendation(f);
  return (
    <>
      <tr className={`click sev-strip${open ? " sel" : ""}`} style={{ "--sev": sevVar(f.severity), whiteSpace: "nowrap" } as React.CSSProperties} onClick={onToggle}>
        <td>
          {f.host}
          {f.port ? `:${f.port}` : ""}
        </td>
        <td className="cell-id">{f.service ?? "—"}</td>
        <CveCell f={f} />
        <CvssCell f={f} />
        <td>
          <Chip tone={(f.severity || "").toLowerCase()} label={humanStatus(f.severity)} />
        </td>
        <td className="cell-id">{f.mitre ?? "—"}</td>
        <td className="cell-id" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={f.description}>
          {f.description}
        </td>
        <td>
          <button type="button" className="btn small" aria-expanded={open} onClick={(e) => { e.stopPropagation(); onToggle(); }}>
            {open ? "Hide" : "Remediation"}
          </button>
        </td>
      </tr>
      {open ? (
        <tr className="finding-detail">
          <td colSpan={8}>
            <div className="rec" style={{ "--sev": sevVar(f.severity) } as React.CSSProperties}>
              <span className="rec-line"><b>Impact</b><span>{rec.why}</span></span>
              <span className="rec-line"><b>Remediation</b><span className="rec-desc">{rec.fix}</span></span>
              <span className="rec-line">
                <b>Next step</b>
                <span>
                  {f.cve ? <Link href="/vuln" className="btn-link">correlate with NVD in the scanner</Link> : "no CVE mapped to this service version"}
                  {" · "}
                  <Link href="/remediation" className="btn-link">raise a remediation job against this finding</Link>
                </span>
              </span>
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}
