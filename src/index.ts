import { Hono } from "hono";
import { actions, openFromDoorTag } from "./actions/routes.ts";
import { admin } from "./admin/routes.ts";
import { config } from "./config.ts";
import { verifyTap } from "./auth/index.ts";
import { verifySunTag } from "./auth/ntag424.ts";
import * as db from "./db.ts";
import * as mqttClient from "./mqtt.ts";
import * as session from "./session.ts";
import { attemptUnlock, publishState } from "./unlock.ts";

const app = new Hono();

const KEYPAD = new URL("../web/dist/index.html", import.meta.url);

/** Nothing else exists. No index, no directory listing, no hints. */
app.notFound((c) => c.text("Not found", 404));

app.onError((err, c) => {
  console.error("unhandled:", err);
  return c.json({ ok: false }, 500);
});

app.get("/healthz", (c) => c.text("ok"));

/**
 * When DOORKEY_ADMIN_HOST is set, the admin surface exists only for requests
 * carrying that Host. Point a LAN-only name at the same Service and /admin
 * stops being publicly reachable — provided the public edge only forwards
 * your own hostnames, so a forged Host header never reaches the service.
 */
if (config.admin.host) {
  app.use("/admin/*", async (c, next) => {
    const host = (c.req.header("Host") ?? "").split(":")[0];
    if (host !== config.admin.host) return c.notFound();
    return next();
  });
}
app.route("/admin", admin);

/** Tap-gated Home Assistant actions; see src/actions/routes.ts. */
app.route("/a", actions);

/**
 * The tag URL. A valid tap issues a short-lived session and serves the keypad;
 * anything else is indistinguishable from a path that was never routed.
 */
app.get("/k/:token", async (c) => {
  const query = new URL(c.req.url).searchParams;
  if (config.tap.mode === "sun") {
    // Verified here rather than through verifyTap, because a tag linked to an
    // action opens that action instead of the keypad.
    const tag = await verifySunTag(query);
    if (!tag) return c.notFound();
    if (tag.action_id !== null) return openFromDoorTag(c, tag);
  } else if (!(await verifyTap({ token: c.req.param("token"), query }))) {
    return c.notFound();
  }

  const html = await Bun.file(KEYPAD).text();
  c.header("Set-Cookie", session.cookieHeader(session.issue()));
  c.header("Cache-Control", "no-store");
  return c.html(html);
});

app.post("/api/unlock", async (c) => {
  const started = Date.now();

  /** Hold every response to the same floor, whatever happened. */
  const settle = async <T>(value: T): Promise<T> => {
    const wait = config.minResponseMs - (Date.now() - started);
    if (wait > 0) await Bun.sleep(wait);
    return value;
  };

  if (!session.verify(getCookie(c.req.header("Cookie"), session.COOKIE))) {
    return settle(c.json({ ok: false }, 401));
  }

  let code = "";
  try {
    const body = (await c.req.json()) as { code?: unknown };
    if (typeof body.code === "string") code = body.code;
  } catch {
    // fall through with an empty code; it fails the same way as a wrong one
  }

  const outcome = await attemptUnlock(code, {
    // Spoofable by anyone reaching the origin directly. Audit trail only.
    srcIp: c.req.header("CF-Connecting-IP") ?? null,
    userAgent: c.req.header("User-Agent")?.slice(0, 256) ?? null,
  });

  if (outcome.result === "granted") return settle(c.json({ ok: true, action: outcome.action }));
  if (outcome.result === "unavailable") {
    return settle(c.json({ ok: false, lock: "unavailable" }, 503));
  }
  return settle(c.json({ ok: false }, 401));
});

function getCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}

await db.migrate();
// Re-publish state on every broker reconnect, not just at boot.
mqttClient.setReconnectHook(() => void publishState());
mqttClient.start();
await publishState();

console.log(`doorkey listening on :${config.port} (tap mode: ${config.tap.mode})`);

export default { port: config.port, fetch: app.fetch };
