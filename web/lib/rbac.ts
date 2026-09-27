import type { Role } from "./types";

export const ROLE_RANK: Record<Role, number> = { READ_ONLY: 0, ANALYST: 1, SUPER_ADMIN: 2 };

export function hasRole(have: Role | null | undefined, min: Role): boolean {
  return have !== null && have !== undefined && ROLE_RANK[have] >= ROLE_RANK[min];
}

export interface NavItem {
  href: string;
  label: string;
  icon: string;
  min: Role;
  desc: string;
}

export interface NavGroup {
  key: string;
  label: string;
  hint: string;
  icon: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    key: "overview",
    label: "Overview",
    hint: "Current posture across every monitored system",
    icon: "activity",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: "dashboard", min: "ANALYST", desc: "Alert volume, sensor readings, active work and authorizations in one view." },
      { href: "/soc", label: "SOC Center", icon: "shield", min: "ANALYST", desc: "Suricata detections, blocking actions and incident response." },
    ],
  },
  {
    // Offensive group — hidden for READ_ONLY; server still enforces.
    key: "offensive",
    label: "Security Testing",
    hint: "Authorized reconnaissance, scanning and remediation",
    icon: "target",
    items: [
      { href: "/assessment", label: "Assessment Studio", icon: "radar", min: "ANALYST", desc: "Full-pipeline security assessment: discovery, analysis, findings, Brain recommendations, and controlled actions." },
      { href: "/findings", label: "Finding Engine", icon: "bug", min: "ANALYST", desc: "Normalized finding lifecycle: triage, validation, confirmation, remediation tracking, retest, and verification." },
      { href: "/pentest", label: "Pentest Engine", icon: "target", min: "ANALYST", desc: "Reconnaissance sessions run against targets inside an authorized scope." },
      { href: "/tools", label: "Tool Library", icon: "grid", min: "ANALYST", desc: "Command-line security tools installed on this server and their versions." },
      { href: "/vuln", label: "Vulnerability Scanner", icon: "bug", min: "ANALYST", desc: "Service fingerprinting correlated with published vulnerability data." },
      { href: "/ledger", label: "Authorization Ledger", icon: "shield", min: "SUPER_ADMIN", desc: "Issue, review and revoke the written-authorization warrants that unlock active security-testing tools." },
      { href: "/remediation", label: "Remediation", icon: "wrench", min: "SUPER_ADMIN", desc: "Approved change jobs that apply fixes to affected hosts." },
    ],
  },
  {
    key: "tools",
    label: "Command Tools",
    hint: "Each tool runs on this server and is recorded in the audit log",
    icon: "grid",
    items: [
      { href: "/tools/subfinder", label: "subfinder", icon: "search", min: "ANALYST", desc: "Subdomain discovery through public sources." },
      { href: "/tools/httpx", label: "httpx", icon: "globe", min: "ANALYST", desc: "Probe hosts and record live web responses." },
      { href: "/tools/naabu", label: "naabu", icon: "activity", min: "ANALYST", desc: "Port scan a host to find open services." },
      { href: "/tools/nuclei", label: "nuclei", icon: "zap", min: "ANALYST", desc: "Template-based checks for known findings." },
      { href: "/tools/ffuf", label: "ffuf", icon: "layers", min: "ANALYST", desc: "Directory and parameter fuzzing against a web target." },
      { href: "/tools/katana", label: "katana", icon: "link", min: "ANALYST", desc: "Crawl a site and collect the URLs it exposes." },
      { href: "/tools/dalfox", label: "dalfox", icon: "shield", min: "ANALYST", desc: "Cross-site scripting checks on supplied parameters." },
      { href: "/tools/sqlmap", label: "sqlmap", icon: "database", min: "ANALYST", desc: "Detect and confirm SQL injection in authorized targets." },
    ],
  },
  {
    key: "defensive",
    label: "Defense & Support",
    hint: "Privacy, hardware integrity and case assistance",
    icon: "shield",
    items: [
      { href: "/ip", label: "IP Anonymizer", icon: "eye-off", min: "ANALYST", desc: "Route a session through a Tor circuit for an authorized investigation." },
      { href: "/fim", label: "Integrity & Detection", icon: "shield", min: "ANALYST", desc: "File integrity monitoring policies, integrity events and the versioned detection-rule engine." },
      { href: "/hardware", label: "Hardware Monitor", icon: "cpu", min: "ANALYST", desc: "Temperatures, loads, storage and physical integrity on this machine." },
      { href: "/victim", label: "Victim Support", icon: "heart", min: "ANALYST", desc: "Complaint intake and case records for affected individuals." },
    ],
  },
  {
    key: "intel",
    label: "Intelligence",
    hint: "Open-source research and evidence examination",
    icon: "radar",
    items: [
      { href: "/threat-intel", label: "Threat Intelligence", icon: "radar", min: "ANALYST", desc: "STIX 2.1 intelligence store: indicators, actors, malware and reports linked to findings and assets." },
      { href: "/osint", label: "OSINT & Breach", icon: "globe", min: "ANALYST", desc: "Public-source research, exposure lookups and attack surface discovery." },
      { href: "/document", label: "Document Forensics", icon: "file", min: "ANALYST", desc: "Metadata and authenticity analysis of submitted files." },
    ],
  },
  {
    key: "system",
    label: "Workspace",
    hint: "Reports and account preferences",
    icon: "settings",
    items: [
      { href: "/reports", label: "Reports", icon: "report", min: "READ_ONLY", desc: "Generate and download formal reports for a case or assessment." },
      { href: "/settings", label: "Settings", icon: "settings", min: "READ_ONLY", desc: "Appearance, account, verification and policy information." },
    ],
  },
];

export function visibleGroups(role: Role | null | undefined): NavGroup[] {
  return NAV_GROUPS.map((g) => ({ ...g, items: g.items.filter((i) => hasRole(role, i.min)) })).filter(
    (g) => g.items.length > 0,
  );
}

export const ROLE_TAG: Record<Role, string> = {
  SUPER_ADMIN: "Administrator",
  ANALYST: "Analyst",
  READ_ONLY: "Observer",
};

/** Resolve the navigation entry for a route, matching the longest href so
    /tools/nuclei belongs to the tool page and not to the tool library. */
export function findPage(groups: NavGroup[], pathname: string): { group?: NavGroup; item?: NavItem } {
  let best: { group: NavGroup; item: NavItem } | null = null;
  for (const g of groups) {
    for (const i of g.items) {
      const hit = pathname === i.href || pathname.startsWith(`${i.href}/`);
      if (hit && (!best || i.href.length > best.item.href.length)) best = { group: g, item: i };
    }
  }
  return best ?? {};
}
