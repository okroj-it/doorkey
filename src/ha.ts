import { config } from "./config.ts";

/**
 * Home Assistant REST client. The long-lived token is powerful — HA tokens
 * cannot be scoped — so it stays server-side and never reaches the browser.
 */

async function callService(domain: string, service: string, body: unknown): Promise<void> {
  const res = await fetch(`${config.ha.url}/api/services/${domain}/${service}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.ha.token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) {
    throw new Error(`HA ${domain}.${service} failed: ${res.status} ${await res.text()}`);
  }
}

export type LockState = "locked" | "unlocked" | "unknown";

export async function lockState(): Promise<LockState> {
  const res = await fetch(`${config.ha.url}/api/states/${config.ha.lockEntity}`, {
    headers: { Authorization: `Bearer ${config.ha.token}` },
    signal: AbortSignal.timeout(8_000),
  });
  if (!res.ok) return "unknown";
  const body = (await res.json()) as { state?: string };
  return body.state === "locked" ? "locked" : body.state === "unlocked" ? "unlocked" : "unknown";
}

export async function unlock(): Promise<void> {
  await callService("lock", "unlock", { entity_id: config.ha.lockEntity });
}

export async function lock(): Promise<void> {
  await callService("lock", "lock", { entity_id: config.ha.lockEntity });
}

/**
 * One code, both directions: a valid entry does whatever the door is not
 * currently doing. If the state cannot be read we unlock, because being shut
 * out by a flaky sensor read is worse than an extra unlock on a door someone
 * is already standing at.
 */
export async function toggle(): Promise<"locked" | "unlocked"> {
  if ((await lockState()) === "unlocked") {
    await lock();
    return "locked";
  }
  await unlock();
  return "unlocked";
}

export async function notify(title: string, message: string): Promise<void> {
  if (!config.ha.notifyService) return;
  try {
    await callService("notify", config.ha.notifyService, { title, message });
  } catch (err) {
    // A failed notification must never fail an unlock.
    console.error("notify failed:", err);
  }
}

/**
 * Start an allowlisted script. script.turn_on returns as soon as the script is
 * started, so a long script never holds the tap page open. The variables let
 * a script know who ran it and how.
 */
export async function runScript(
  entityId: string,
  variables: Record<string, string>,
): Promise<void> {
  if (!/^script\.[a-z0-9_]+$/.test(entityId)) throw new Error(`not a script: ${entityId}`);
  await callService("script", "turn_on", { entity_id: entityId, variables });
}

/** Scripts an action may point at, for the admin picker. */
export async function listScripts(): Promise<{ entity_id: string; name: string }[]> {
  const res = await fetch(`${config.ha.url}/api/states`, {
    headers: { Authorization: `Bearer ${config.ha.token}` },
    signal: AbortSignal.timeout(8_000),
  });
  if (!res.ok) throw new Error(`HA states failed: ${res.status}`);
  const states = (await res.json()) as { entity_id: string; attributes?: { friendly_name?: string } }[];
  return states
    .filter((s) => /^script\.[a-z0-9_]+$/.test(s.entity_id))
    .map((s) => ({ entity_id: s.entity_id, name: s.attributes?.friendly_name ?? s.entity_id }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
