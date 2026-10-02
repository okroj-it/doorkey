import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { config } from "../config.ts";

/**
 * A valid tap on an action tag issues a session for that one action. Signed
 * with its own purpose prefix, so neither a keypad nor an admin session can be
 * replayed here, and bound to the action's slug, so one tag cannot open
 * another action.
 *
 * One run per tap: the nonce is consumed when the action runs. Consumed
 * nonces live in memory until the session would have expired anyway - like
 * the WebAuthn challenges, a restart just means tapping again.
 */
const PURPOSE = "action";
export const COOKIE = "dk_act";

export interface ActionSession {
  slug: string;
  via: "sun" | "token";
  tagId: number | null;
  nonce: string;
  exp: number;
}

function sign(payload: string): string {
  return createHmac("sha256", config.sessionSecret)
    .update(`${PURPOSE}|${payload}`)
    .digest("base64url");
}

export function issue(
  slug: string,
  via: "sun" | "token",
  tagId: number | null,
): string {
  const exp = Date.now() + config.actions.sessionTtlS * 1000;
  const nonce = randomBytes(12).toString("base64url");
  const payload = [exp, slug, via, tagId ?? "", nonce].join("|");
  return `${payload}.${sign(payload)}`;
}

export function verify(token: string | undefined): ActionSession | null {
  if (!token) return null;
  const dot = token.lastIndexOf(".");
  if (dot < 1) return null;

  const payload = token.slice(0, dot);
  const mac = Buffer.from(token.slice(dot + 1), "base64url");
  const want = Buffer.from(sign(payload), "base64url");
  if (mac.length !== want.length || !timingSafeEqual(mac, want)) return null;

  const [expRaw, slug, via, tagRaw, nonce] = payload.split("|");
  const exp = Number(expRaw);
  if (!Number.isFinite(exp) || exp <= Date.now()) return null;
  if (!slug || !nonce || (via !== "sun" && via !== "token")) return null;
  if (consumed.has(nonce)) return null;
  return { slug, via, tagId: tagRaw ? Number(tagRaw) : null, nonce, exp };
}

const consumed = new Map<string, number>();

/** True for the first caller only. */
export function consume(s: ActionSession): boolean {
  if (consumed.has(s.nonce)) return false;
  consumed.set(s.nonce, s.exp);
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [n, exp] of consumed) if (exp < now) consumed.delete(n);
}, 60_000).unref();

export function cookieHeader(token: string): string {
  return [
    `${COOKIE}=${token}`,
    "HttpOnly",
    "Secure",
    // Set by the tap's own navigation and only read by same-origin fetches.
    "SameSite=Strict",
    "Path=/a",
    `Max-Age=${config.actions.sessionTtlS}`,
  ].join("; ");
}

export function clearCookie(): string {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/a; Max-Age=0`;
}
