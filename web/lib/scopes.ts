/* Client-side mirror of backend/app/core/scopes.py — advisory only.
   The server re-validates scope on every request and inside every worker;
   this copy exists purely to explain a refusal before dispatch, never to
   authorize anything. */

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

export function isIp(t: string): boolean {
  if (!t) return false;
  const parts = t.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && (p.length === 1 || p[0] !== "0"));
}

export function isIp6(t: string): boolean {
  if (!t || !t.includes(":")) return false;
  return /^([0-9a-f]{0,4}:){2,7}([0-9a-f]{0,4})?$/i.test(t) || /^([0-9a-f]{0,4}:)*:([0-9a-f]{0,4}:)*[0-9a-f]{0,4}$/i.test(t);
}

function ip4ToLong(t: string): number {
  return t.split(".").reduce((n, p) => (n << 8) + Number(p), 0) >>> 0;
}

export function isCidr(t: string): boolean {
  if (!t.includes("/")) return false;
  const [base, bits] = t.split("/");
  if (!isIp(base)) return false;
  const n = Number(bits);
  return Number.isInteger(n) && n >= 0 && n <= 32;
}

function cidrContains(cidr: string, ip: string): boolean {
  const [base, bits] = cidr.split("/");
  const n = Number(bits);
  const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
  return (ip4ToLong(base) & mask) === (ip4ToLong(ip) & mask);
}

export function isDomain(t: string): boolean {
  return DOMAIN_RE.test(t.toLowerCase());
}

/** Backend semantics: exact IP/domain match, CIDR containment, subdomain-inclusive domains. */
export function scopeMatches(scope: string[], target: string): boolean {
  const t = target.trim().toLowerCase().replace(/\.$/, "");
  if (!t) return false;
  for (const raw of scope) {
    const e = raw.trim().toLowerCase();
    if (!e) continue;
    if (e.includes("/")) {
      if (isIp(t) && isCidr(e) && cidrContains(e, t)) return true;
      continue;
    }
    if (e === t) return true;
    if (isDomain(e) && t.endsWith("." + e)) return true;
  }
  return false;
}

/** Extract the host a user meant, accepting bare IPs, domains or URLs.
    Mirrors the spirit of the server's canonicalizer closely enough for advice. */
export function hostOf(input: string): string {
  const t = input.trim();
  if (!t) return "";
  const noScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "") : t;
  const host = noScheme.split(/[/?#]/)[0] ?? "";
  const bare = host.split("@").pop() ?? "";
  // drop an explicit :port only when what remains is an IP or a domain (not [IPv6] literal yet)
  const noPort = isIp6(bare.replace(/^\[|\]$/g, "")) ? bare.replace(/^\[|\]$/g, "") : bare.replace(/:\d{1,5}$/, "");
  return noPort.toLowerCase();
}

export function isTargetLike(input: string): boolean {
  const t = input.trim();
  return isIp(t) || isIp6(t) || isDomain(t) || /^https?:\/\//i.test(t);
}
