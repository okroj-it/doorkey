/** Environment configuration. Every secret arrives here and nowhere else. */
import { parseCidrs } from "./actions/policy.ts";

function req(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env var ${name}`);
  return v;
}

function num(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined) return fallback;
  const n = Number(v);
  if (!Number.isFinite(n))
    throw new Error(`env var ${name} is not a number: ${v}`);
  return n;
}

export type TapMode = "static" | "sun" | "dev";

function tapMode(): TapMode {
  const v = (process.env.DOORKEY_TAP_MODE ?? "static") as TapMode;
  if (v !== "static" && v !== "sun" && v !== "dev") {
    throw new Error(`DOORKEY_TAP_MODE must be static|sun|dev, got ${v}`);
  }
  return v;
}

/**
 * DOORKEY_ORIGIN: scheme + host (+ port), nothing else. WebAuthn compares it
 * byte for byte, so a trailing slash or path would make every passkey fail.
 */
function publicOrigin(): string {
  const raw = req("DOORKEY_ORIGIN");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`DOORKEY_ORIGIN is not a URL: ${raw}`);
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
    throw new Error(
      "DOORKEY_ORIGIN must be https:// (http:// only for localhost)",
    );
  }
  if (url.pathname !== "/" || url.search || url.hash) {
    throw new Error(
      `DOORKEY_ORIGIN must be just scheme and host, e.g. https://door.example.com — got ${raw}`,
    );
  }
  return url.origin;
}

const ORIGIN = publicOrigin();

export const config = {
  port: num("PORT", 8080),
  databaseUrl: req("DATABASE_URL"),

  /** Pepper for HMAC-SHA256(code). Never stored in the database. */
  pepper: req("DOORKEY_PEPPER"),
  /** Signs the short-lived session cookie issued after a valid tap. */
  sessionSecret: req("DOORKEY_SESSION_SECRET"),

  tap: {
    mode: tapMode(),
    /** Capability path segment for mode=static, e.g. the /k/<this> in the tag URL. */
    staticPath: process.env.DOORKEY_STATIC_PATH ?? "",
    /** How long the keypad stays usable after a tap. */
    sessionTtlS: num("DOORKEY_SESSION_TTL_S", 300),
    /**
     * Wraps tag key material at rest (mode=sun). 32 bytes, hex. Distinct from
     * the offline master (kept in a password manager), which this service never holds.
     */
    kek: process.env.DOORKEY_TAG_KEK ?? "",
    /**
     * Shared SDMMetaRead key (K2), 16 bytes hex. Decrypts the PICC blob so the
     * UID can be looked up directly. Shared on purpose; see ntag424.ts.
     */
    metaKey: process.env.DOORKEY_TAG_META_KEY ?? "",
  },

  /**
   * Lockout ladder. A guest fat-fingering one digit hits the soft tier and
   * waits a minute; a real attack hits the hard tier and waits a day.
   * There is no clear-lockout path on purpose: the Companion app and the
   * physical key both bypass this service entirely.
   */
  lockout: {
    softAfter: num("DOORKEY_LOCKOUT_SOFT_AFTER", 3),
    softSeconds: num("DOORKEY_LOCKOUT_SOFT_SECONDS", 60),
    hardAfter: num("DOORKEY_LOCKOUT_HARD_AFTER", 4),
    hardSeconds: num("DOORKEY_LOCKOUT_HARD_SECONDS", 86400),
    /** Per-code lockout for a recognised code that keeps being rejected. */
    codeFailuresBeforeLock: num("DOORKEY_CODE_FAILURES_BEFORE_LOCK", 5),
    codeLockSeconds: num("DOORKEY_CODE_LOCK_SECONDS", 86400),
  },

  /** Every unlock attempt takes at least this long, whatever the outcome. */
  minResponseMs: num("DOORKEY_MIN_RESPONSE_MS", 1000),

  ha: {
    url: req("HA_URL").replace(/\/+$/, ""),
    token: req("HA_TOKEN"),
    /** The lock the keypad toggles, e.g. lock.front_door. */
    lockEntity: req("HA_LOCK_ENTITY"),
    /** e.g. mobile_app_pixel. Empty disables push notifications. */
    notifyService: process.env.HA_NOTIFY_SERVICE ?? "",
  },

  mqtt: {
    url: process.env.MQTT_URL ?? "",
    username: process.env.MQTT_USERNAME ?? "",
    password: process.env.MQTT_PASSWORD ?? "",
    discoveryPrefix: process.env.MQTT_DISCOVERY_PREFIX ?? "homeassistant",
    nodeId: process.env.MQTT_NODE_ID ?? "doorkey",
  },

  admin: {
    /**
     * The public origin the tags point at, e.g. https://door.example.com.
     * Passkeys are bound to it, and every link the CLI and admin mint use it.
     */
    origin: ORIGIN,
    /**
     * WebAuthn relying-party id — the hostname passkeys are bound to. A
     * passkey registered here will not work on any other hostname, which is
     * what makes it unphishable. Defaults to the origin's hostname.
     */
    rpId: process.env.DOORKEY_RP_ID ?? new URL(ORIGIN).hostname,
    rpName: process.env.DOORKEY_RP_NAME ?? "Front door",
    /** Admin session lifetime. */
    sessionTtlS: num("DOORKEY_ADMIN_SESSION_TTL_S", 3600),
    /**
     * When set, /admin is served only to requests carrying this Host. Point a
     * LAN-only hostname at the same service and the admin surface stops being
     * publicly reachable — provided the public edge only forwards your own
     * hostnames, so a forged Host header never reaches the service.
     */
    host: process.env.DOORKEY_ADMIN_HOST ?? "",
  },

  actions: {
    /**
     * How long the action page stays usable after a tap. One run per tap:
     * running again means tapping again.
     */
    sessionTtlS: num("DOORKEY_ACTION_SESSION_TTL_S", 120),
    /**
     * Client IPs that count as home, for actions with home_only. Usually the
     * WAN address (what a proxy like Cloudflare reports for LAN clients) plus
     * the LAN range. Empty means home_only actions refuse everyone.
     */
    homeCidrs: parseCidrs(process.env.DOORKEY_HOME_CIDRS ?? ""),
  },

  /** Schedules and log timestamps are interpreted here. */
  timezone: process.env.TZ ?? "UTC",
} as const;

if (config.tap.mode === "sun") {
  if (config.tap.kek.length !== 64) {
    throw new Error(
      "DOORKEY_TAP_MODE=sun requires DOORKEY_TAG_KEK (64 hex chars)",
    );
  }
  if (config.tap.metaKey.length !== 32) {
    throw new Error(
      "DOORKEY_TAP_MODE=sun requires DOORKEY_TAG_META_KEY (32 hex chars)",
    );
  }
}
if (config.tap.mode === "static" && !config.tap.staticPath) {
  throw new Error("DOORKEY_TAP_MODE=static requires DOORKEY_STATIC_PATH");
}
