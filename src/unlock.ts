import { config } from "./config.ts";
import { evaluate, hashCode } from "./codes.ts";
import * as db from "./db.ts";
import * as ha from "./ha.ts";
import * as lockout from "./lockout.ts";
import * as mqttState from "./mqtt.ts";

export type Outcome =
  | { result: "granted"; action: "locked" | "unlocked" }
  | { result: "denied" }
  | { result: "unavailable" };

export interface AttemptContext {
  srcIp: string | null;
  userAgent: string | null;
}

/**
 * Every denial returns the same Outcome regardless of cause. The real reason
 * is kept server-side in attempts.result — telling the caller "expired" rather
 * than "wrong" is a free oracle, and it tells an honest guest nothing they can
 * act on anyway.
 */
export async function attemptUnlock(code: string, ctx: AttemptContext): Promise<Outcome> {
  const now = new Date();

  const until = await lockout.lockedUntil();
  if (until) {
    // Hammering during a lockout must not extend it — that just floods the log.
    await db.logAttempt("system_locked", null, ctx.srcIp, ctx.userAgent);
    await publish();
    return { result: "denied" };
  }

  const row = await db.findByHash(hashCode(code));

  if (!row) {
    await db.logAttempt("bad_code", null, ctx.srcIp, ctx.userAgent);
    await afterFailure();
    return { result: "denied" };
  }

  const rejection = evaluate(row, now);
  if (rejection) {
    await db.logAttempt(rejection, row.id, ctx.srcIp, ctx.userAgent);
    const streak = await db.recordCodeFailure(row.id);
    if (streak >= config.lockout.codeFailuresBeforeLock) {
      await db.lockCode(row.id, new Date(Date.now() + config.lockout.codeLockSeconds * 1000));
    }
    await afterFailure();
    return { result: "denied" };
  }

  let action: "locked" | "unlocked";
  try {
    action = await ha.toggle();
  } catch (err) {
    // The code was correct; the lock is unreachable. Not an auth failure, and
    // not something the guest should be told to retype a code over.
    console.error("lock toggle failed:", err);
    return { result: "unavailable" };
  }

  await db.recordGrant(row.id);
  await lockout.recordSuccess();
  await db.logAttempt("granted", row.id, ctx.srcIp, ctx.userAgent);
  await ha.notify(
    "Front door",
    action === "unlocked" ? `${row.label} unlocked the door` : `${row.label} locked the door`,
  );
  await publish();
  return { result: "granted", action };
}

async function afterFailure(): Promise<void> {
  const { streak, lockedFor } = await lockout.recordFailure();

  if (lockedFor === config.lockout.hardSeconds) {
    await ha.notify(
      "Front door",
      `Keypad locked for ${Math.round(lockedFor / 3600)}h after ${streak} failed attempts`,
    );
  } else if (streak === config.lockout.softAfter) {
    await ha.notify("Front door", `${streak} failed keypad attempts`);
  }
  await publish();
}

/** Push current counters to Home Assistant over MQTT. */
async function publish(): Promise<void> {
  try {
    const midnight = new Date();
    midnight.setHours(0, 0, 0, 0);
    const [failedToday, until, last] = await Promise.all([
      db.failuresSince(midnight),
      lockout.lockedUntil(),
      db.lastGrant(),
    ]);
    mqttState.publishState({
      locked_out: until !== null,
      failed_today: failedToday,
      last_entry: last?.label ?? "never",
      last_entry_at: last?.ts.toISOString() ?? null,
    });
  } catch (err) {
    console.error("state publish failed:", err);
  }
}

export { publish as publishState };
