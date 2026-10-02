import { Hono, type Context } from "hono";
import { randomBytes } from "node:crypto";
import { config } from "../config.ts";
import { generateCode, hashCode } from "../codes.ts";
import { hashToken, newToken } from "../actions/policy.ts";
import * as db from "../db.ts";
import { enrolTag, setTagActiveByUid } from "../tags.ts";
import { constraintKind } from "../db-values.ts";
import * as ha from "../ha.ts";
import * as lockout from "../lockout.ts";
import { publishState } from "../unlock.ts";
import * as session from "./session.ts";
import * as webauthn from "./webauthn.ts";

const ADMIN_HTML = new URL("../../web/dist-admin/admin.html", import.meta.url);

export const admin = new Hono();

function ip(c: Context): string | null {
  return c.req.header("CF-Connecting-IP") ?? null;
}

function cookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}

/** Modest cap, purely so a failing client cannot flood the event log. */
let authAttempts = { count: 0, window: 0 };
function tooManyAuthAttempts(): boolean {
  const now = Math.floor(Date.now() / 60_000);
  if (now !== authAttempts.window) authAttempts = { count: 0, window: now };
  return ++authAttempts.count > 30;
}

// --- the page --------------------------------------------------------------

async function page(c: Context) {
  c.header("Cache-Control", "no-store");
  c.header("Referrer-Policy", "no-referrer");
  return c.html(await Bun.file(ADMIN_HTML).text());
}

// The shell carries no data. Everything it shows comes from /admin/api/*,
// which requires the passkey session.
admin.get("/", page);
admin.get("/enroll/:token", page);

// --- enrolment -------------------------------------------------------------
//
// The only way an admin passkey is added. Tokens are minted by the CLI, so
// shell access to the container is the root of trust; there is no
// self-service path in.

async function validEnrollment(token: string) {
  const e = await db.findEnrollment(token);
  if (!e || e.used_at || e.expires_at < new Date()) return null;
  return e;
}

admin.post("/api/enroll/:token/options", async (c) => {
  const token = c.req.param("token");
  const e = await validEnrollment(token);
  if (!e) return c.json({ error: "invalid or expired" }, 404);
  return c.json(await webauthn.registrationOptions(token, e.label));
});

admin.post("/api/enroll/:token/verify", async (c) => {
  const token = c.req.param("token");
  const e = await validEnrollment(token);
  if (!e) return c.json({ error: "invalid or expired" }, 404);

  const ok = await webauthn.verifyRegistration(token, e.label, await c.req.json());
  if (!ok) {
    await db.logAdminEvent("enroll_failed", e.label, ip(c));
    return c.json({ error: "verification failed" }, 400);
  }

  await db.consumeEnrollment(token);
  await db.logAdminEvent("enroll", e.label, ip(c));
  c.header("Set-Cookie", session.cookieHeader(session.issue(e.label)));
  return c.json({ ok: true, label: e.label });
});

// --- sign in ---------------------------------------------------------------

admin.post("/api/auth/options", async (c) => {
  if (tooManyAuthAttempts()) return c.json({ error: "slow down" }, 429);
  if ((await db.listCredentials()).length === 0) {
    return c.json({ error: "no passkeys enrolled" }, 409);
  }
  const key = randomBytes(16).toString("base64url");
  const options = await webauthn.authenticationOptions(key);
  return c.json({ key, options });
});

admin.post("/api/auth/verify", async (c) => {
  if (tooManyAuthAttempts()) return c.json({ error: "slow down" }, 429);
  const body = (await c.req.json()) as { key?: string; response?: unknown };
  if (!body.key || !body.response) return c.json({ error: "bad request" }, 400);

  const label = await webauthn.verifyAuthentication(body.key, body.response);
  if (!label) {
    await db.logAdminEvent("signin_failed", null, ip(c));
    return c.json({ error: "verification failed" }, 401);
  }

  await db.logAdminEvent("signin", label, ip(c));
  c.header("Set-Cookie", session.cookieHeader(session.issue(label)));
  return c.json({ ok: true, label });
});

admin.post("/api/logout", (c) => {
  c.header("Set-Cookie", session.clearCookie());
  return c.json({ ok: true });
});

// --- everything below requires a passkey session ---------------------------

admin.use("/api/*", async (c, next) => {
  const path = c.req.path;
  if (path.startsWith("/admin/api/auth/") || path.startsWith("/admin/api/enroll/")) {
    return next();
  }
  const label = session.verify(cookie(c.req.header("Cookie"), session.COOKIE));
  if (!label) return c.json({ error: "unauthenticated" }, 401);
  c.set("adminLabel" as never, label as never);
  return next();
});

admin.get("/api/session", (c) => {
  const label = session.verify(cookie(c.req.header("Cookie"), session.COOKIE));
  return label ? c.json({ label }) : c.json({ error: "unauthenticated" }, 401);
});

// --- codes -----------------------------------------------------------------

admin.get("/api/codes", async (c) => c.json(await db.listCodes()));

admin.post("/api/codes", async (c) => {
  const body = (await c.req.json()) as {
    label?: string;
    validUntil?: string | null;
    validFrom?: string | null;
    maxUses?: number | null;
    schedule?: unknown | null;
    digits?: number;
  };
  const label = (body.label ?? "").trim();
  if (!label) return c.json({ error: "label required" }, 400);

  const digits = Math.min(Math.max(body.digits ?? 6, 4), 12);
  const code = generateCode(digits);
  const id = await db.insertCode(
    label,
    hashCode(code),
    body.schedule ?? null,
    body.validFrom ?? null,
    body.validUntil ?? null,
    body.maxUses ?? null,
  );

  await db.logAdminEvent("code_created", `${label} (id ${id})`, ip(c));
  // The only time the plaintext exists outside the authenticator's head.
  return c.json({ id, label, code });
});

admin.post("/api/codes/:id/regenerate", async (c) => {
  const id = Number(c.req.param("id"));
  const code = generateCode(6);
  const label = await db.regenerateCode(id, hashCode(code));
  if (!label) return c.json({ error: "not found" }, 404);
  await db.logAdminEvent("code_regenerated", `${label} (id ${id})`, ip(c));
  return c.json({ id, label, code });
});

admin.patch("/api/codes/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = (await c.req.json()) as { active?: boolean; validUntil?: string | null };

  if (typeof body.active === "boolean") {
    await db.setCodeActive(id, body.active);
    await db.logAdminEvent(body.active ? "code_enabled" : "code_revoked", `id ${id}`, ip(c));
  }
  if (body.validUntil !== undefined) {
    await db.setCodeExpiry(id, body.validUntil);
    await db.logAdminEvent("code_expiry_set", `id ${id} -> ${body.validUntil ?? "never"}`, ip(c));
  }
  return c.json({ ok: true });
});

admin.delete("/api/codes/:id", async (c) => {
  const id = Number(c.req.param("id"));
  // Attempts keep referencing it via ON DELETE SET NULL, so the audit trail
  // survives the code being removed.
  await db.deleteCode(id);
  await db.logAdminEvent("code_deleted", `id ${id}`, ip(c));
  return c.json({ ok: true });
});

// --- status ----------------------------------------------------------------

admin.get("/api/status", async (c) => {
  const midnight = new Date();
  midnight.setHours(0, 0, 0, 0);
  const [until, streak, failedToday, last, door] = await Promise.all([
    lockout.lockedUntil(),
    lockout.currentStreak(),
    db.failuresSince(midnight),
    db.lastGrant(),
    ha.lockState().catch(() => "unknown" as const),
  ]);
  return c.json({
    door,
    lockedUntil: until?.toISOString() ?? null,
    streak,
    failedToday,
    lastEntry: last ? { label: last.label, ts: last.ts.toISOString() } : null,
    softAfter: config.lockout.softAfter,
    hardAfter: config.lockout.hardAfter,
  });
});

admin.post("/api/lockout/clear", async (c) => {
  await lockout.recordSuccess();
  await db.logAdminEvent("lockout_cleared", null, ip(c));
  await publishState();
  return c.json({ ok: true });
});

admin.get("/api/log", async (c) => {
  const n = Math.min(Number(c.req.query("limit") ?? 50), 200);
  const [attempts, events] = await Promise.all([
    db.recentAttempts(n),
    db.recentAdminEvents(n),
  ]);
  return c.json({ attempts, events });
});

// --- passkeys --------------------------------------------------------------

admin.get("/api/credentials", async (c) => {
  const creds = await db.listCredentials();
  return c.json(
    creds.map((x) => ({
      id: x.id,
      label: x.label,
      created_at: x.created_at,
      last_used_at: x.last_used_at,
    })),
  );
});

admin.delete("/api/credentials/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const creds = await db.listCredentials();
  // Removing the last passkey would lock you out of the admin surface with no
  // way back except the CLI. Refuse rather than let that happen by accident.
  if (creds.length <= 1) return c.json({ error: "cannot remove the last passkey" }, 409);
  await db.deleteCredential(id);
  await db.logAdminEvent("passkey_removed", `id ${id}`, ip(c));
  return c.json({ ok: true });
});

// --- tap-gated actions ----------------------------------------------------
//
// The same operations as the CLI. Minting action enrolment links here means an
// admin passkey can add action passkeys; it can already create door codes, so
// that is no wider than what admin already is.

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const SCRIPT = /^script\.[a-z0-9_]+$/;
const ROLE = /^[a-z0-9][a-z0-9_-]{0,31}$/;


async function body<T>(c: Context): Promise<Partial<T>> {
  return ((await c.req.json().catch(() => ({}))) ?? {}) as Partial<T>;
}

function role(c: Context): string | null {
  const name = c.req.param("role") ?? "";
  return ROLE.test(name) ? name : null;
}

admin.get("/api/actions", async (c) => {
  const [actions, users, credentials, roles, tags, events] = await Promise.all([
    db.listActions(),
    db.listActionUsers(),
    db.listAllActionCredentials(),
    db.listRoles(),
    db.listTags(),
    db.recentActionEvents(Math.min(Number(c.req.query("limit") ?? 40), 200)),
  ]);
  return c.json({
    actions,
    users: users.map((u) => ({ ...u, credentials: credentials.filter((k) => k.user_id === u.id) })),
    roles,
    tags,
    events,
  });
});

admin.get("/api/ha/scripts", async (c) => {
  try {
    return c.json(await ha.listScripts());
  } catch {
    return c.json({ error: "home assistant unavailable" }, 502);
  }
});

admin.post("/api/actions", async (c) => {
  const b = await body<{ slug: string; label: string; script: string; requireSun: boolean; homeOnly: boolean }>(c);
  const slug = (b.slug ?? "").trim();
  const script = (b.script ?? "").trim();
  if (!SLUG.test(slug)) return c.json({ error: "slug: lowercase letters, digits and -" }, 400);
  if (!SCRIPT.test(script)) return c.json({ error: "the entity must be a script.*" }, 400);
  const label = (b.label ?? "").trim() || slug;
  try {
    const id = await db.insertAction(slug, label, script, b.requireSun === true, b.homeOnly === true);
    await db.logAdminEvent("action_created", `${slug} -> ${script}`, ip(c));
    return c.json({ id });
  } catch (err) {
    if (constraintKind(err) === "unique") return c.json({ error: `action ${slug} already exists` }, 409);
    throw err;
  }
});

admin.patch("/api/actions/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const b = await body<{ label: string; requireSun: boolean; homeOnly: boolean; active: boolean }>(c);
  const bool = (v: unknown) => (typeof v === "boolean" ? v : undefined);
  const patch = {
    label: typeof b.label === "string" && b.label.trim() ? b.label.trim() : undefined,
    requireSun: bool(b.requireSun),
    homeOnly: bool(b.homeOnly),
    active: bool(b.active),
  };
  if (!(await db.updateAction(id, patch))) return c.json({ error: "not found" }, 404);
  const changed = Object.entries(patch).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${v}`);
  await db.logAdminEvent("action_updated", `id ${id}: ${changed.join(", ")}`, ip(c));
  return c.json({ ok: true });
});

admin.delete("/api/actions/:id", async (c) => {
  const id = Number(c.req.param("id"));
  try {
    await db.deleteAction(id);
  } catch (err) {
    if (constraintKind(err) === "foreign_key") return c.json({ error: "unlink its DNA tag first" }, 409);
    throw err;
  }
  await db.logAdminEvent("action_deleted", `id ${id}`, ip(c));
  return c.json({ ok: true });
});

admin.post("/api/actions/:id/token", async (c) => {
  const action = await db.findActionById(Number(c.req.param("id")));
  if (!action) return c.json({ error: "not found" }, 404);
  if (action.require_sun) return c.json({ error: "this action requires a DNA tag" }, 409);
  const token = newToken();
  await db.setActionToken(action.id, hashToken(token, config.pepper));
  await db.logAdminEvent("action_token_issued", action.slug, ip(c));
  // The only time the URL exists outside the tag.
  return c.json({ url: `${config.admin.origin}/a/${action.slug}?t=${token}` });
});

admin.delete("/api/actions/:id/token", async (c) => {
  const action = await db.findActionById(Number(c.req.param("id")));
  if (!action) return c.json({ error: "not found" }, 404);
  await db.setActionToken(action.id, null);
  await db.logAdminEvent("action_token_removed", action.slug, ip(c));
  return c.json({ ok: true });
});

admin.put("/api/actions/:id/roles/:role", async (c) => {
  const name = role(c);
  if (!name) return c.json({ error: "role: lowercase letters, digits, _ and -" }, 400);
  const action = await db.findActionById(Number(c.req.param("id")));
  if (!action) return c.json({ error: "not found" }, 404);
  await db.allowActionRole(action.id, await db.ensureRole(name));
  await db.logAdminEvent("action_role_allowed", `${action.slug} <- ${name}`, ip(c));
  return c.json({ ok: true });
});

admin.delete("/api/actions/:id/roles/:role", async (c) => {
  const name = role(c);
  const roleId = name ? await db.findRole(name) : null;
  const action = await db.findActionById(Number(c.req.param("id")));
  if (!action || roleId === null) return c.json({ error: "not found" }, 404);
  await db.disallowActionRole(action.id, roleId);
  await db.logAdminEvent("action_role_denied", `${action.slug} -/- ${name}`, ip(c));
  return c.json({ ok: true });
});

admin.get("/api/tags", async (c) => c.json(await db.listTags()));

admin.post("/api/tags", async (c) => {
  const b = await body<{ code: string; label: string }>(c);
  if (typeof b.code !== "string" || !b.code.trim()) return c.json({ error: "paste the tag code" }, 400);
  let t;
  try {
    t = await enrolTag(b.code, typeof b.label === "string" ? b.label : undefined);
  } catch (err) {
    // Decoding and KEK problems: worded for the person who pasted the code.
    return c.json({ error: (err as Error).message }, 400);
  }
  await db.logAdminEvent(t.replaced ? "tag_reenrolled" : "tag_enrolled", `${t.label} (${t.uid})`, ip(c));
  return c.json(t);
});

admin.patch("/api/tags/:uid", async (c) => {
  const uid = c.req.param("uid").toLowerCase();
  const b = await body<{ active: boolean }>(c);
  if (typeof b.active !== "boolean") return c.json({ error: "active required" }, 400);
  if (!/^[0-9a-f]{14}$/.test(uid)) return c.json({ error: "bad uid" }, 400);
  if (!(await setTagActiveByUid(uid, b.active))) return c.json({ error: "no such tag" }, 404);
  await db.logAdminEvent(b.active ? "tag_enabled" : "tag_disabled", uid, ip(c));
  return c.json({ ok: true });
});

admin.put("/api/tags/:uid/action", async (c) => {
  const uid = c.req.param("uid").toLowerCase();
  if (!/^[0-9a-f]{14}$/.test(uid)) return c.json({ error: "bad uid" }, 400);
  const b = await body<{ actionId: number | null }>(c);
  const actionId = typeof b.actionId === "number" ? b.actionId : null;
  if (actionId !== null && !(await db.findActionById(actionId))) return c.json({ error: "no such action" }, 404);
  if (!(await db.linkTagToAction(uid, actionId))) return c.json({ error: "no such tag" }, 404);
  await db.logAdminEvent(
    actionId === null ? "tag_to_door" : "tag_to_action",
    actionId === null ? uid : `${uid} -> action ${actionId}`,
    ip(c),
  );
  return c.json({ ok: true });
});

admin.post("/api/action-users", async (c) => {
  const name = ((await body<{ name: string }>(c)).name ?? "").trim();
  if (!name || name.length > 64) return c.json({ error: "name required (max 64)" }, 400);
  try {
    const id = await db.insertActionUser(name);
    await db.logAdminEvent("action_user_created", name, ip(c));
    return c.json({ id });
  } catch (err) {
    if (constraintKind(err) === "unique") return c.json({ error: `user ${name} already exists` }, 409);
    throw err;
  }
});

admin.patch("/api/action-users/:id", async (c) => {
  const user = await db.findActionUser(Number(c.req.param("id")));
  if (!user) return c.json({ error: "not found" }, 404);
  const b = await body<{ active: boolean }>(c);
  if (typeof b.active !== "boolean") return c.json({ error: "active required" }, 400);
  await db.setActionUserActive(user.id, b.active);
  await db.logAdminEvent(b.active ? "action_user_enabled" : "action_user_disabled", user.name, ip(c));
  return c.json({ ok: true });
});

admin.put("/api/action-users/:id/roles/:role", async (c) => {
  const name = role(c);
  if (!name) return c.json({ error: "role: lowercase letters, digits, _ and -" }, 400);
  const user = await db.findActionUser(Number(c.req.param("id")));
  if (!user) return c.json({ error: "not found" }, 404);
  await db.grantUserRole(user.id, await db.ensureRole(name));
  await db.logAdminEvent("action_user_granted", `${user.name} + ${name}`, ip(c));
  return c.json({ ok: true });
});

admin.delete("/api/action-users/:id/roles/:role", async (c) => {
  const name = role(c);
  const roleId = name ? await db.findRole(name) : null;
  const user = await db.findActionUser(Number(c.req.param("id")));
  if (!user || roleId === null) return c.json({ error: "not found" }, 404);
  await db.revokeUserRole(user.id, roleId);
  await db.logAdminEvent("action_user_ungranted", `${user.name} - ${name}`, ip(c));
  return c.json({ ok: true });
});

admin.post("/api/action-users/:id/enroll", async (c) => {
  const user = await db.findActionUser(Number(c.req.param("id")));
  if (!user) return c.json({ error: "not found" }, 404);
  if (!user.active) return c.json({ error: "enable the user first" }, 409);
  const device = ((await body<{ device: string }>(c)).device ?? "").trim() || "phone";
  const token = randomBytes(24).toString("base64url");
  const expiresAt = new Date(Date.now() + 15 * 60_000);
  await db.createActionEnrollment(token, user.id, device.slice(0, 64), expiresAt);
  await db.logAdminEvent("action_enroll_link", `${user.name} / ${device}`, ip(c));
  return c.json({ url: `${config.admin.origin}/a/enroll/${token}`, expiresAt });
});

admin.delete("/api/action-credentials/:id", async (c) => {
  const id = Number(c.req.param("id"));
  if (!(await db.deleteActionCredential(id))) return c.json({ error: "not found" }, 404);
  await db.logAdminEvent("action_passkey_removed", `id ${id}`, ip(c));
  return c.json({ ok: true });
});

admin.delete("/api/roles/:role", async (c) => {
  const name = role(c);
  if (!name) return c.json({ error: "not found" }, 404);
  if (!(await db.deleteUnusedRole(name))) return c.json({ error: "role is still in use" }, 409);
  await db.logAdminEvent("role_deleted", name, ip(c));
  return c.json({ ok: true });
});
