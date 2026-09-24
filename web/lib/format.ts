export function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

export function clock(d: Date = new Date()): string {
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

export function fmtTs(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : `${iso}Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(
    d.getMinutes(),
  )}:${pad2(d.getSeconds())}`;
}

export function fmtMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  return fmtTs(new Date(ms).toISOString());
}

export function elapsedSince(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "00:00:00";
  const t = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : `${iso}Z`).getTime();
  if (Number.isNaN(t)) return "—";
  let s = Math.max(0, Math.floor((now - t) / 1000));
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  return `${pad2(h)}:${pad2(m)}:${pad2(s)}`;
}

export function trunc(s: string | null | undefined, n = 24): string {
  if (!s) return "—";
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

const KEEP_UPPER = new Set(["ok", "na"]);

/** Backend enums arrive as ACTIVE / DONE_NO_REPORT / open. A chip should read like
 *  English, not like a column dump. */
export function humanStatus(s: string | null | undefined): string {
  if (!s) return "—";
  return s
    .replace(/[_\-.]+/g, " ")
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .map((w) => (KEEP_UPPER.has(w) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(" ");
}

const ACRONYM = new Set([
  "osint", "totp", "cve", "mitre", "http", "https", "sha", "md5", "api", "pdf",
  "soc", "rbac", "cwb", "btrc", "tcp", "udp", "dns", "tls", "ip", "id", "url",
]);

/* Internal identifiers are shorter than the words an operator should read. */
const TOKEN = new Set(["pentest", "vuln", "docfp", "ipanon"]);
const TOKEN_WORD: Record<string, string> = {
  pentest: "penetration test",
  vuln: "vulnerability",
  docfp: "document",
  ipanon: "anonymized routing",
};

/** Audit actions, job kinds and warrant scopes arrive dotted or snake_cased
 *  ("osint.leak_scan", "ipanon"). Render them as a sentence fragment. */
export function humanAction(s: string | null | undefined): string {
  if (!s) return "—";
  const words = s
    .replace(/[_.]+/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .flatMap((w) => (TOKEN.has(w) ? TOKEN_WORD[w].split(" ") : [w]));
  return words
    .map((w, i) => {
      if (ACRONYM.has(w)) return w.toUpperCase();
      return i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w;
    })
    .join(" ");
}

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} b`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
}

export function sevTone(sev: string | null | undefined): "ok" | "warn" | "fail" | "info" {
  switch ((sev ?? "").toUpperCase()) {
    case "CRITICAL":
      return "fail";
    case "HIGH":
      return "fail";
    case "MEDIUM":
      return "warn";
    case "LOW":
      return "info";
    default:
      return "info";
  }
}

export function statusTone(s: string | null | undefined): "ok" | "warn" | "fail" | "info" {
  switch ((s ?? "").toUpperCase()) {
    case "OK":
    case "DONE":
    case "ACTIVE":
    case "APPLIED":
    case "TRUE":
      return "ok";
    case "WARN":
    case "PENDING":
    case "BUILDING":
    case "DRAFT":
    case "CREATED":
    case "DONE_NO_REPORT":
      return "warn";
    case "FAIL":
    case "FAILED":
    case "ABORTED":
    case "BROKEN":
    case "EXPIRED":
      return "fail";
    default:
      return "info";
  }
}
