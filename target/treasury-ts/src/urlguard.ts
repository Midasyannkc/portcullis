// Outbound URL policy shared by every feature that fetches a user supplied URL.
import { isIP } from "node:net";

function privateV4(h: string): boolean {
  const p = h.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
}

export function assertPublicHttps(raw: string): URL {
  let u: URL;
  try { u = new URL(raw); } catch { throw new Error("bad url"); }
  if (u.protocol !== "https:") throw new Error("https only");
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal") || host.endsWith(".local")) throw new Error("internal host");
  const kind = isIP(host);
  if (kind === 6) throw new Error("ipv6 literals not allowed");
  if (kind === 4 && privateV4(host)) throw new Error("private address");
  if (kind === 0 && /^(0x[0-9a-f]+|\d+)$/i.test(host)) throw new Error("numeric host");
  return u;
}
