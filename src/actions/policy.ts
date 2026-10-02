import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Pure decisions for tap-gated actions: which taps open an action page, and
 * whether a client counts as "at home". No config or database imports, so
 * the rules are unit-testable on their own.
 */

export interface TapAction {
  id: number;
  require_sun: boolean;
  token_hash: Uint8Array | null;
  active: boolean;
}

/** A SUN tap that already passed verifySunTag (MAC good, counter advanced). */
export interface VerifiedTag {
  id: number;
  action_id: number | null;
}

export type TapOutcome =
  { via: "sun"; tagId: number } | { via: "token"; tagId: null };

/** 128 bits, base64url: the ?t= written to a plain NFC tag. */
export function newToken(): string {
  return randomBytes(16).toString("base64url");
}

/** Domain-separated from guest-code hashes, which use the same pepper. */
export function hashToken(token: string, pepper: string): Buffer {
  return createHmac("sha256", pepper).update(`action-token|${token}`).digest();
}

export function tokenMatches(
  token: string | null,
  hash: Uint8Array | null,
  pepper: string,
): boolean {
  if (!token || !hash) return false;
  const got = hashToken(token, pepper);
  return got.length === hash.length && timingSafeEqual(got, hash);
}

/**
 * A tap opens an action when:
 *   - a verified DNA tag is linked to exactly this action, or
 *   - the action accepts plain tags and the token matches.
 * A DNA tag linked to the door or to another action never opens it, and a
 * presented-but-wrong DNA tap is not rescued by a token.
 */
export function decideTap(
  action: TapAction,
  sunPresented: boolean,
  sunTag: VerifiedTag | null,
  tokenOk: boolean,
): TapOutcome | null {
  if (!action.active) return null;
  if (sunPresented) {
    return sunTag && sunTag.action_id === action.id
      ? { via: "sun", tagId: sunTag.id }
      : null;
  }
  if (action.require_sun) return null;
  return tokenOk ? { via: "token", tagId: null } : null;
}

// --- home CIDRs ------------------------------------------------------------

export interface Cidr {
  v6: boolean;
  net: bigint;
  bits: number;
}

function parseV4(ip: string): bigint | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = (n << 8n) | BigInt(v);
  }
  return n;
}

function parseV6(ip: string): bigint | null {
  if (!/^[0-9a-f:.]+$/i.test(ip)) return null;
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const words = (s: string): number[] | null => {
    if (s === "") return [];
    const out: number[] = [];
    for (const w of s.split(":")) {
      if (!/^[0-9a-f]{1,4}$/i.test(w)) return null;
      out.push(parseInt(w, 16));
    }
    return out;
  };
  const head = words(halves[0]!);
  const tail = halves.length === 2 ? words(halves[1]!) : [];
  if (!head || !tail) return null;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 1 ? fill !== 0 : fill < 1) return null;
  let n = 0n;
  for (const w of [
    ...head,
    ...new Array(halves.length === 2 ? fill : 0).fill(0),
    ...tail,
  ]) {
    n = (n << 16n) | BigInt(w);
  }
  return n;
}

function parseIp(ip: string): { v6: boolean; n: bigint } | null {
  const s = ip
    .trim()
    .toLowerCase()
    .replace(/^::ffff:(?=\d+\.)/, "");
  const v4 = parseV4(s);
  if (v4 !== null) return { v6: false, n: v4 };
  const v6 = parseV6(s);
  return v6 === null ? null : { v6: true, n: v6 };
}

/** "203.0.113.7/32, 192.168.1.0/24, 2001:db8::/48". Throws on garbage. */
export function parseCidrs(spec: string): Cidr[] {
  return spec
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const [addr, bitsRaw] = s.split("/");
      const ip = parseIp(addr ?? "");
      if (!ip) throw new Error(`bad CIDR "${s}"`);
      const max = ip.v6 ? 128 : 32;
      const bits = bitsRaw === undefined ? max : Number(bitsRaw);
      if (!Number.isInteger(bits) || bits < 0 || bits > max)
        throw new Error(`bad CIDR "${s}"`);
      return { v6: ip.v6, net: ip.n >> BigInt(max - bits), bits };
    });
}

export function ipInCidrs(ip: string | null, cidrs: Cidr[]): boolean {
  if (!ip) return false;
  const parsed = parseIp(ip);
  if (!parsed) return false;
  const max = parsed.v6 ? 128 : 32;
  return cidrs.some(
    (c) => c.v6 === parsed.v6 && parsed.n >> BigInt(max - c.bits) === c.net,
  );
}
