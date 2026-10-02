import { createHmac, timingSafeEqual } from "node:crypto";
import { config } from "./config.ts";

/**
 * A tap grants a short-lived session; the keypad and the unlock endpoint both
 * require it. Stateless and signed, so there is no session store to reap.
 */

export const COOKIE = "dk_sess";

function sign(payload: string): string {
  return createHmac("sha256", config.sessionSecret).update(payload).digest("base64url");
}

export function issue(): string {
  const exp = String(Date.now() + config.tap.sessionTtlS * 1000);
  return `${exp}.${sign(exp)}`;
}

export function verify(token: string | undefined): boolean {
  if (!token) return false;
  const dot = token.lastIndexOf(".");
  if (dot < 1) return false;

  const exp = token.slice(0, dot);
  const mac = Buffer.from(token.slice(dot + 1), "base64url");
  const want = Buffer.from(sign(exp), "base64url");
  if (mac.length !== want.length || !timingSafeEqual(mac, want)) return false;

  const expMs = Number(exp);
  return Number.isFinite(expMs) && expMs > Date.now();
}

export function cookieHeader(token: string): string {
  return [
    `${COOKIE}=${token}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${config.tap.sessionTtlS}`,
  ].join("; ");
}
