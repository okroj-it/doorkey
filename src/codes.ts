import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import { config } from "./config.ts";
import type { CodeRow, ScheduleWindow } from "./db.ts";

/**
 * Codes are stored as HMAC-SHA256(pepper, code) with the pepper held in the
 * environment, never in the database. That buys an O(1) indexed lookup, so
 * identifying a code takes the same time whether or not it exists — argon2
 * would mean verifying against every row in turn.
 *
 * The trade: an attacker holding both the database and the pepper can brute
 * force six digits instantly. The pepper lives outside the database, and the
 * lockout ladder is the real defence.
 */
export function hashCode(code: string): Buffer {
  return createHmac("sha256", config.pepper).update(code.trim()).digest();
}

export function hashesEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Cryptographically random, so nobody picks 1234 or a birth year. */
export function generateCode(digits = 6): string {
  let out = "";
  for (let i = 0; i < digits; i++) out += String(randomInt(0, 10));
  return out;
}

/** Local wall-clock day-of-week and minute-of-day in the configured timezone. */
function localParts(at: Date): { dow: number; minutes: number } {
  const fmt = new Intl.DateTimeFormat("en-GB", {
    timeZone: config.timezone,
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  const parts = Object.fromEntries(fmt.formatToParts(at).map((p) => [p.type, p.value]));
  const dows = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const dow = dows.indexOf(parts.weekday ?? "");
  const minutes = Number(parts.hour) * 60 + Number(parts.minute);
  return { dow, minutes };
}

function parseHHMM(s: string): number {
  const [h, m] = s.split(":");
  return Number(h) * 60 + Number(m);
}

export function withinSchedule(raw: ScheduleWindow[] | string | null, at: Date): boolean {
  // jsonb comes back parsed from some drivers and as text from others.
  const windows: ScheduleWindow[] | null =
    typeof raw === "string" ? (JSON.parse(raw) as ScheduleWindow[]) : raw;
  if (!windows || windows.length === 0) return true;
  const { dow, minutes } = localParts(at);
  return windows.some((w) => {
    if (w.dow.length > 0 && !w.dow.includes(dow)) return false;
    const from = parseHHMM(w.from);
    const to = parseHHMM(w.to);
    // A window that wraps midnight (22:00-02:00) is two ranges.
    return from <= to ? minutes >= from && minutes < to : minutes >= from || minutes < to;
  });
}

export type Rejection = "inactive" | "expired" | "out_of_schedule" | "exhausted" | "code_locked";

/** Policy check for a code we have already identified. */
export function evaluate(code: CodeRow, at: Date): Rejection | null {
  if (code.locked_until && code.locked_until > at) return "code_locked";
  if (!code.active) return "inactive";
  if (code.valid_from && at < code.valid_from) return "expired";
  if (code.valid_until && at > code.valid_until) return "expired";
  if (code.max_uses !== null && code.use_count >= code.max_uses) return "exhausted";
  if (!withinSchedule(code.schedule, at)) return "out_of_schedule";
  return null;
}
