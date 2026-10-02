import { config } from "../config.ts";

/**
 * Who may use the admin page when doorkey runs as a Home Assistant app.
 *
 * The Supervisor's Ingress gateway tells us which HA user is asking
 * (X-Remote-User-Id) but not whether they are an administrator, and the
 * panel_admin flag only hides the sidebar entry. So the user is looked up in
 * HA itself: Core's WebSocket API, config/auth/list, reached through the
 * Supervisor with SUPERVISOR_TOKEN. The list is cached for a few minutes and
 * refreshed once for a user it does not know yet.
 *
 * Fallback: if that lookup is not possible, DOORKEY_ADMIN_USERS (the app's
 * admin_users option) lists the HA usernames allowed in. Without either,
 * nobody gets in - and the log says why.
 */

interface HaUser {
  id: string;
  username: string | null;
  is_owner: boolean;
  is_active: boolean;
  group_ids: string[];
}

const TTL_MS = 5 * 60_000;
let cache: { users: HaUser[]; at: number } | null = null;

/** One request on HA's WebSocket API: authenticate, send, wait for the result. */
async function wsCommand<T>(type: string): Promise<T> {
  const url = `${config.ha.url.replace(/^http/, "ws")}/websocket`;
  return new Promise<T>((resolve, reject) => {
    const ws = new WebSocket(url);
    const timer = setTimeout(() => {
      ws.close();
      reject(new Error("HA websocket timed out"));
    }, 10_000);
    const done = (fn: () => void) => {
      clearTimeout(timer);
      ws.close();
      fn();
    };
    ws.onerror = () => done(() => reject(new Error("HA websocket error")));
    ws.onmessage = (ev) => {
      const msg = JSON.parse(String(ev.data)) as {
        type: string;
        id?: number;
        success?: boolean;
        result?: T;
        error?: { message: string };
      };
      if (msg.type === "auth_required")
        ws.send(
          JSON.stringify({ type: "auth", access_token: config.ha.token }),
        );
      else if (msg.type === "auth_ok") ws.send(JSON.stringify({ id: 1, type }));
      else if (msg.type === "auth_invalid")
        done(() => reject(new Error("HA refused the token")));
      else if (msg.type === "result" && msg.id === 1) {
        done(() =>
          msg.success
            ? resolve(msg.result as T)
            : reject(new Error(msg.error?.message ?? `${type} failed`)),
        );
      }
    };
  });
}

async function users(refresh: boolean): Promise<HaUser[]> {
  if (!refresh && cache && Date.now() - cache.at < TTL_MS) return cache.users;
  cache = {
    users: await wsCommand<HaUser[]>("config/auth/list"),
    at: Date.now(),
  };
  return cache.users;
}

const isAdmin = (u: HaUser) =>
  u.is_active && (u.is_owner || u.group_ids.includes("system-admin"));

export type Verdict = { ok: true } | { ok: false; reason: string };

export async function haAdmin(
  userId: string,
  userName: string | undefined,
): Promise<Verdict> {
  try {
    let user = (await users(false)).find((u) => u.id === userId);
    if (!user) user = (await users(true)).find((u) => u.id === userId);
    if (!user) return { ok: false, reason: "unknown Home Assistant user" };
    return isAdmin(user)
      ? { ok: true }
      : { ok: false, reason: "not a Home Assistant administrator" };
  } catch (err) {
    const allowed = (process.env.DOORKEY_ADMIN_USERS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (allowed.length) {
      return userName && allowed.includes(userName)
        ? { ok: true }
        : { ok: false, reason: "not in admin_users" };
    }
    console.error(
      `admin: cannot check HA users (${(err as Error).message}) and admin_users is empty - refusing`,
    );
    return {
      ok: false,
      reason: "cannot verify Home Assistant administrators - set admin_users",
    };
  }
}

/** For tests: forget the cached user list. */
export function resetHaUserCache(): void {
  cache = null;
}
