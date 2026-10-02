import { randomBytes } from "node:crypto";

/**
 * Running as a Home Assistant app (add-on): the Supervisor starts the
 * container with SUPERVISOR_TOKEN set. DOORKEY_MODE=app forces app mode,
 * DOORKEY_MODE=standalone forces it off.
 *
 * In app mode the settings come from the app's options (/data/options.json)
 * and the Supervisor, and are turned into the same environment variables a
 * standalone install sets by hand - config.ts validates both the same way.
 */
export function isAppMode(): boolean {
  const mode = process.env.DOORKEY_MODE;
  if (mode === "app") return true;
  if (mode === "standalone") return false;
  return Boolean(process.env.SUPERVISOR_TOKEN);
}

/** What the app's options schema lets the user set. */
export interface AppOptions {
  origin: string;
  lock_entity: string;
  notify_service?: string;
  tap_mode?: "sun" | "static";
  static_path?: string;
  tag_kek?: string;
  tag_meta_key?: string;
  home_cidrs?: string[];
  timezone?: string;
}

export interface AppSecrets {
  pepper: string;
  session_secret: string;
}

export interface AppContext {
  supervisorUrl: string;
  supervisorToken: string;
  dataDir: string;
}

/** The environment for config.ts, from the options and the Supervisor. */
export function appEnv(
  o: AppOptions,
  s: AppSecrets,
  ctx: AppContext,
): Record<string, string> {
  const env: Record<string, string> = {
    DOORKEY_ORIGIN: o.origin,
    HA_URL: `${ctx.supervisorUrl}/core`,
    HA_TOKEN: ctx.supervisorToken,
    HA_LOCK_ENTITY: o.lock_entity,
    HA_NOTIFY_SERVICE: o.notify_service ?? "",
    DOORKEY_TAP_MODE: o.tap_mode ?? "sun",
    DOORKEY_HOME_CIDRS: (o.home_cidrs ?? []).join(","),
    DATABASE_URL: `sqlite://${ctx.dataDir}/doorkey.db`,
    DOORKEY_PEPPER: s.pepper,
    DOORKEY_SESSION_SECRET: s.session_secret,
    PORT: "8080",
  };
  if (o.tag_kek) env.DOORKEY_TAG_KEK = o.tag_kek;
  if (o.tag_meta_key) env.DOORKEY_TAG_META_KEY = o.tag_meta_key;
  if (o.static_path) env.DOORKEY_STATIC_PATH = o.static_path;
  if (o.timezone) env.TZ = o.timezone;
  return env;
}

/**
 * The pepper and session secret, generated on first start and kept in
 * /data, which app backups include. Losing the pepper would invalidate
 * every guest code, so they are never regenerated once written.
 */
export async function appSecrets(dataDir: string): Promise<AppSecrets> {
  const file = Bun.file(`${dataDir}/secrets.json`);
  if (await file.exists()) return (await file.json()) as AppSecrets;
  const secrets: AppSecrets = {
    pepper: randomBytes(32).toString("hex"),
    session_secret: randomBytes(32).toString("hex"),
  };
  await Bun.write(file, JSON.stringify(secrets, null, 2));
  const { chmod } = await import("node:fs/promises");
  await chmod(`${dataDir}/secrets.json`, 0o600);
  return secrets;
}

/** The Supervisor's MQTT service, as MQTT_* settings. */
export function mqttEnv(d: {
  host: string;
  port: string | number;
  ssl?: boolean;
  username?: string;
  password?: string;
}): Record<string, string> {
  return {
    MQTT_URL: `${d.ssl ? "mqtts" : "mqtt"}://${d.host}:${d.port}`,
    MQTT_USERNAME: d.username ?? "",
    MQTT_PASSWORD: d.password ?? "",
  };
}

/** Put the app's settings into process.env, before config.ts loads. */
export async function prepareAppEnv(): Promise<void> {
  const ctx: AppContext = {
    supervisorUrl: (process.env.SUPERVISOR_URL ?? "http://supervisor").replace(
      /\/+$/,
      "",
    ),
    supervisorToken: process.env.SUPERVISOR_TOKEN ?? "",
    dataDir: process.env.DOORKEY_DATA_DIR ?? "/data",
  };
  const options = (await Bun.file(
    `${ctx.dataDir}/options.json`,
  ).json()) as AppOptions;
  Object.assign(
    process.env,
    appEnv(options, await appSecrets(ctx.dataDir), ctx),
  );

  // MQTT is optional: without a broker app the keypad entities are skipped.
  try {
    const res = await fetch(`${ctx.supervisorUrl}/services/mqtt`, {
      headers: { Authorization: `Bearer ${ctx.supervisorToken}` },
      signal: AbortSignal.timeout(5_000),
    });
    if (res.ok)
      Object.assign(
        process.env,
        mqttEnv(((await res.json()) as { data: never }).data),
      );
    else
      console.log("doorkey: no MQTT service in Home Assistant - discovery off");
  } catch (err) {
    console.log(
      `doorkey: MQTT service lookup failed (${(err as Error).message}) - discovery off`,
    );
  }
}
