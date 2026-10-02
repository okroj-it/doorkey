import { createHmac, timingSafeEqual } from "node:crypto";
import { config } from "../config.ts";

/**
 * Admin sessions are signed with a different purpose prefix from the keypad's,
 * so a session handed out at the door can never be replayed against /admin.
 */
const PURPOSE = "admin";
export const COOKIE = "dk_admin";

function sign(payload: string): string {
  return createHmac("sha256", config.sessionSecret)
    .update(`${PURPOSE}|${payload}`)
    .digest("base64url");
}

export function issue(label: string): string {
  const exp = Date.now() + config.admin.sessionTtlS * 1000;
  const payload = `${exp}|${encodeURIComponent(label)}`;
  return `${payload}.${sign(payload)}`;
}

/** Returns the admin label, or null if the cookie is missing, forged or stale. */
export function verify(token: string | undefined): string | null {
  if (!token) return null;
  const dot = token.lastIndexOf(".");
  if (dot < 1) return null;

  const payload = token.slice(0, dot);
  const mac = Buffer.from(token.slice(dot + 1), "base64url");
  const want = Buffer.from(sign(payload), "base64url");
  if (mac.length !== want.length || !timingSafeEqual(mac, want)) return null;

  const [expRaw, labelRaw] = payload.split("|");
  const exp = Number(expRaw);
  if (!Number.isFinite(exp) || exp <= Date.now()) return null;
  return decodeURIComponent(labelRaw ?? "");
}

export function cookieHeader(token: string): string {
  return [
    `${COOKIE}=${token}`,
    "HttpOnly",
    "Secure",
    // Strict, not Lax: nothing should ever navigate into the admin surface
    // from another site.
    "SameSite=Strict",
    "Path=/admin",
    `Max-Age=${config.admin.sessionTtlS}`,
  ].join("; ");
}

export function clearCookie(): string {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=0`;
}
