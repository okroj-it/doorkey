import { Hono, type Context } from "hono";
import { config } from "../config.ts";
import * as db from "../db.ts";
import * as ha from "../ha.ts";
import { verifySunTag } from "../auth/ntag424.ts";
import { decideTap, ipInCidrs, tokenMatches, type TapOutcome, type VerifiedTag } from "./policy.ts";
import * as session from "./session.ts";
import * as webauthn from "./webauthn.ts";

/**
 * Tap-gated Home Assistant actions.
 *
 *   GET  /k/sun?picc=&cmac=      DNA tag linked to an action -> /a/<slug>
 *   GET  /a/<slug>?picc=&cmac=   the same, for a tag provisioned with this URL
 *   GET  /a/<slug>?t=<token>     plain tag, unless the action requires DNA
 *   POST /a/api/begin            passkey options for the tapped action
 *   POST /a/api/run              passkey assertion -> RBAC -> run the script
 *
 * The tap proves the phone was at the tag (DNA) or knows the tag's URL
 * (plain); the passkey with user verification proves who is holding it.
 * Neither alone runs anything.
 */

const PAGE = new URL("../../web/dist-action/action.html", import.meta.url);

export const actions = new Hono();

/**
 * Cloudflare's view of the client for public requests, else the first hop
 * Traefik recorded. Both are spoofable by anyone who can reach the origin
 * directly, i.e. from the LAN - which is home anyway.
 */
function clientIp(c: Context): string | null {
  return (
    c.req.header("CF-Connecting-IP") ??
    c.req.header("X-Forwarded-For")?.split(",")[0]?.trim() ??
    null
  );
}

function atHome(c: Context): boolean {
  return ipInCidrs(clientIp(c), config.actions.homeCidrs);
}

/** The one message rendered server-side; the pages translate their own. */
function notHomeText(c: Context): string {
  const first = (c.req.header("Accept-Language") ?? "").split(",")[0]?.trim().slice(0, 2).toLowerCase();
  return first === "pl" ? "Dostępne tylko z sieci domowej." : "Only available from the home network.";
}

function userAgent(c: Context): string | null {
  return c.req.header("User-Agent")?.slice(0, 256) ?? null;
}

function cookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === name)
      return part.slice(eq + 1).trim();
  }
  return undefined;
}

/** Same modest cap as admin sign-in: keeps a broken client out of the log. */
let attempts = { count: 0, window: 0 };
function tooManyAttempts(): boolean {
  const now = Math.floor(Date.now() / 60_000);
  if (now !== attempts.window) attempts = { count: 0, window: now };
  return ++attempts.count > 30;
}

async function page(c: Context) {
  c.header("Cache-Control", "no-store");
  c.header("Referrer-Policy", "no-referrer");
  return c.html(await Bun.file(PAGE).text());
}

// --- enrolment -------------------------------------------------------------
//
// Links are minted by `cli/doorkey.ts user:enroll`; there is no self-service
// way in, same as for admin passkeys.

async function validEnrollment(token: string) {
  const e = await db.findActionEnrollment(token);
  if (!e || e.used_at || e.expires_at < new Date()) return null;
  const user = await db.findActionUser(e.user_id);
  if (!user || !user.active) return null;
  return { e, user };
}

actions.get("/enroll/:token", page);

actions.post("/api/enroll/:token/options", async (c) => {
  if (tooManyAttempts()) return c.json({ error: "slow down" }, 429);
  const token = c.req.param("token");
  const found = await validEnrollment(token);
  if (!found) return c.json({ error: "invalid or expired" }, 404);
  return c.json({
    user: found.user.name,
    device: found.e.label,
    options: await webauthn.registrationOptions(token, found.user),
  });
});

actions.post("/api/enroll/:token/verify", async (c) => {
  if (tooManyAttempts()) return c.json({ error: "slow down" }, 429);
  const token = c.req.param("token");
  const found = await validEnrollment(token);
  if (!found) return c.json({ error: "invalid or expired" }, 404);

  const response = await c.req.json().catch(() => null);
  // Consume first: of two racing verifies, only one may save a passkey.
  if (!(await db.consumeActionEnrollment(token))) {
    return c.json({ error: "invalid or expired" }, 404);
  }
  const ok = await webauthn.verifyRegistration(
    token,
    found.user.id,
    found.e.label,
    response,
  );
  await db.logAdminEvent(
    ok ? "action_enroll" : "action_enroll_failed",
    `${found.user.name} / ${found.e.label}`,
    clientIp(c),
  );
  if (!ok) return c.json({ error: "verification failed" }, 400);
  return c.json({ ok: true, user: found.user.name });
});

// --- running an action -----------------------------------------------------

function current(c: Context): session.ActionSession | null {
  return session.verify(cookie(c.req.header("Cookie"), session.COOKIE));
}

actions.post("/api/begin", async (c) => {
  if (tooManyAttempts()) return c.json({ error: "slow down" }, 429);
  const s = current(c);
  if (!s) return c.json({ error: "expired" }, 401);

  const action = await db.findActionBySlug(s.slug);
  if (!action || !action.active) return c.json({ error: "expired" }, 401);

  const options = await webauthn.authenticationOptions(s.nonce, action.id);
  if (!options)
    return c.json({ label: action.label, error: "nobody allowed" }, 403);
  return c.json({ label: action.label, options });
});

actions.post("/api/run", async (c) => {
  if (tooManyAttempts()) return c.json({ error: "slow down" }, 429);
  const s = current(c);
  if (!s) return c.json({ error: "expired" }, 401);

  const action = await db.findActionBySlug(s.slug);
  const base = {
    actionId: action?.id ?? null,
    via: s.via,
    tagId: s.tagId,
    srcIp: clientIp(c),
    userAgent: userAgent(c),
  };

  if (!action || !action.active) {
    await db.logActionEvent({ ...base, result: "inactive", userId: null });
    return c.json({ error: "expired" }, 401);
  }
  if (action.home_only && !atHome(c)) {
    await db.logActionEvent({ ...base, result: "not_home", userId: null });
    return c.json({ error: "not home" }, 403);
  }

  const body = (await c.req.json().catch(() => null)) as {
    response?: unknown;
  } | null;
  const credential = await webauthn.verifyAuthentication(
    s.nonce,
    body?.response,
  );
  if (!credential) {
    await db.logActionEvent({ ...base, result: "bad_passkey", userId: null });
    return c.json({ error: "verification failed" }, 401);
  }

  const user = await db.findActionUser(credential.user_id);
  if (!user || !user.active || !(await db.userMayRun(user.id, action.id))) {
    await db.logActionEvent({
      ...base,
      result: "not_allowed",
      userId: credential.user_id,
    });
    return c.json({ error: "not allowed" }, 403);
  }

  // One run per tap, decided before HA is called so a double submit cannot
  // run the script twice.
  if (!session.consume(s)) return c.json({ error: "expired" }, 401);
  c.header("Set-Cookie", session.clearCookie());

  try {
    await ha.runScript(action.script_entity, {
      tapgate_action: action.slug,
      tapgate_user: user.name,
      tapgate_via: s.via,
    });
  } catch (err) {
    console.error(`action ${action.slug} failed:`, err);
    await db.logActionEvent({ ...base, result: "ha_error", userId: user.id });
    return c.json({ error: "home assistant unavailable" }, 502);
  }

  await db.markActionRun(action.id);
  await db.logActionEvent({ ...base, result: "ran", userId: user.id });
  void ha.notify(
    action.label,
    `${user.name} (${s.via === "sun" ? "DNA tag" : "tag"})`,
  );
  return c.json({ ok: true, label: action.label });
});

// --- the tap ---------------------------------------------------------------

/**
 * Past decideTap the caller holds a valid tag, so saying why it is refused is
 * no leak. Issues the session for this one action.
 */
async function openSession(
  c: Context,
  action: db.ActionRow,
  tap: TapOutcome,
): Promise<Response | null> {
  if (action.home_only && !atHome(c)) {
    await db.logActionEvent({
      result: "not_home",
      actionId: action.id,
      userId: null,
      via: tap.via,
      tagId: tap.tagId,
      srcIp: clientIp(c),
      userAgent: userAgent(c),
    });
    return c.text(notHomeText(c), 403);
  }
  c.header("Set-Cookie", session.cookieHeader(session.issue(action.slug, tap.via, tap.tagId)));
  return null;
}

/**
 * A DNA tag tapped at the door URL (/k/sun?...) that is linked to an action.
 * Tags keep the URL they were provisioned with; linking one in the database
 * is all it takes to turn it from a door tag into an action tag.
 */
export async function openFromDoorTag(c: Context, tag: VerifiedTag): Promise<Response> {
  const action = tag.action_id === null ? null : await db.findActionById(tag.action_id);
  const tap = action ? decideTap(action, true, tag, false) : null;
  if (!action || !tap) return c.notFound();
  const refused = await openSession(c, action, tap);
  return refused ?? c.redirect(`/a/${action.slug}`, 303);
}

actions.get("/:slug", async (c) => {
  const action = await db.findActionBySlug(c.req.param("slug"));
  if (!action) return c.notFound();

  const query = new URL(c.req.url).searchParams;
  const sunPresented = query.has("picc") || query.has("cmac");

  // Arriving from openFromDoorTag's redirect: the session is already issued.
  if (!sunPresented && !query.has("t")) {
    const s = current(c);
    return s && s.slug === action.slug && action.active ? page(c) : c.notFound();
  }

  const sunTag = sunPresented ? await verifySunTag(query) : null;
  const tokenOk = tokenMatches(query.get("t"), action.token_hash, config.pepper);
  const tap = decideTap(action, sunPresented, sunTag, tokenOk);
  if (!tap) return c.notFound();

  return (await openSession(c, action, tap)) ?? page(c);
});
