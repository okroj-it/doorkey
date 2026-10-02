import { config } from "./config.ts";
import { getState, setState } from "./db.ts";

/**
 * Global lockout. Counters are keyed on nothing the caller controls — not IP,
 * not session, not MAC — because a phone outside the door can rotate all three
 * by toggling Wi-Fi. Only the global streak actually bounds an attacker.
 *
 * Roughly 15-20 attempts per day get through the ladder, so a random six-digit
 * code survives for tens of thousands of years. The limiter is worth far more
 * than the code length.
 */

const KEY_STREAK = "failed_streak";
const KEY_UNTIL = "locked_until";
const KEY_GRANTED = "last_granted_at";

export async function lockedUntil(): Promise<Date | null> {
  const raw = await getState(KEY_UNTIL);
  if (!raw) return null;
  const until = new Date(raw);
  return until > new Date() ? until : null;
}

export async function currentStreak(): Promise<number> {
  return Number((await getState(KEY_STREAK)) ?? "0");
}

/**
 * Records a failure and applies the ladder.
 * Returns the new streak and the lockout it triggered, if any.
 */
export async function recordFailure(): Promise<{ streak: number; lockedFor: number | null }> {
  const streak = (await currentStreak()) + 1;
  await setState(KEY_STREAK, String(streak));

  let lockedFor: number | null = null;
  if (streak >= config.lockout.hardAfter) lockedFor = config.lockout.hardSeconds;
  else if (streak >= config.lockout.softAfter) lockedFor = config.lockout.softSeconds;

  if (lockedFor !== null) {
    const until = new Date(Date.now() + lockedFor * 1000);
    await setState(KEY_UNTIL, until.toISOString());
  }
  return { streak, lockedFor };
}

export async function recordSuccess(): Promise<void> {
  await setState(KEY_STREAK, "0");
  await setState(KEY_UNTIL, new Date(0).toISOString());
  await setState(KEY_GRANTED, new Date().toISOString());
}
