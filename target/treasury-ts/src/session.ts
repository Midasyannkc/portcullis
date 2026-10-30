import { randomBytes } from "node:crypto";

export function newSessionToken(): string {
  return randomBytes(16).toString("hex");
}

import { createHash } from "node:crypto";

/** Token embedded in pages for the logged in user; must accompany state changing requests. */
export function csrfTokenFor(session: string): string {
  return createHash("sha256").update("csrf:" + session).digest("hex");
}

export interface Req { method: string; cookies: Record<string, string>; headers: Record<string, string>; body: { to: string; amount: number } }
export interface Ledger { transfers: { to: string; amount: number }[] }

export function transferHandler(req: Req, sessions: Set<string>, ledger: Ledger): number {
  if (req.method !== "POST") return 405;
  const sid = req.cookies["session"] ?? "";
  if (!sessions.has(sid)) return 401;
  if (req.headers["x-csrf-token"] !== csrfTokenFor(sid)) return 403;
  ledger.transfers.push(req.body);
  return 200;
}
