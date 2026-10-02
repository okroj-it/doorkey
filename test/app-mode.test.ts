import { describe, expect, test } from "bun:test";
import { mkdtemp, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appEnv, appSecrets, isAppMode, mqttEnv } from "../src/app-mode.ts";

const ctx = {
  supervisorUrl: "http://supervisor",
  supervisorToken: "sv-token",
  dataDir: "/data",
};
const secrets = { pepper: "p".repeat(64), session_secret: "s".repeat(64) };

describe("app mode", () => {
  test("detected from SUPERVISOR_TOKEN, overridable", () => {
    const saved = { ...process.env };
    try {
      delete process.env.DOORKEY_MODE;
      delete process.env.SUPERVISOR_TOKEN;
      expect(isAppMode()).toBe(false);
      process.env.SUPERVISOR_TOKEN = "x";
      expect(isAppMode()).toBe(true);
      process.env.DOORKEY_MODE = "standalone";
      expect(isAppMode()).toBe(false);
      delete process.env.SUPERVISOR_TOKEN;
      process.env.DOORKEY_MODE = "app";
      expect(isAppMode()).toBe(true);
    } finally {
      process.env = saved;
    }
  });

  test("options become the environment config.ts expects", () => {
    const env = appEnv(
      {
        origin: "https://door.example.com",
        lock_entity: "lock.front_door",
        notify_service: "mobile_app_pixel",
        tag_kek: "k".repeat(64),
        tag_meta_key: "m".repeat(32),
        home_cidrs: ["203.0.113.7/32", "192.168.1.0/24"],
        admin_users: ["alice", "owner"],
        timezone: "Europe/Warsaw",
      },
      secrets,
      ctx,
    );
    expect(env).toMatchObject({
      DOORKEY_ORIGIN: "https://door.example.com",
      HA_URL: "http://supervisor/core",
      HA_TOKEN: "sv-token",
      HA_LOCK_ENTITY: "lock.front_door",
      HA_NOTIFY_SERVICE: "mobile_app_pixel",
      DOORKEY_TAP_MODE: "sun",
      DOORKEY_TAG_KEK: "k".repeat(64),
      DOORKEY_TAG_META_KEY: "m".repeat(32),
      DOORKEY_HOME_CIDRS: "203.0.113.7/32,192.168.1.0/24",
      DOORKEY_ADMIN_USERS: "alice,owner",
      DATABASE_URL: "sqlite:///data/doorkey.db",
      DOORKEY_PEPPER: secrets.pepper,
      DOORKEY_SESSION_SECRET: secrets.session_secret,
      TZ: "Europe/Warsaw",
      PORT: "8080",
    });
  });

  test("optional settings are left out, not set empty", () => {
    const env = appEnv(
      { origin: "https://d.example", lock_entity: "lock.x" },
      secrets,
      ctx,
    );
    expect(env.DOORKEY_TAG_KEK).toBeUndefined();
    expect(env.TZ).toBeUndefined();
    expect(env.DOORKEY_ADMIN_USERS).toBeUndefined();
    expect(env.DOORKEY_HOME_CIDRS).toBe("");
    expect(env.HA_NOTIFY_SERVICE).toBe("");
  });

  test("secrets are generated once, private, and kept", async () => {
    const dir = await mkdtemp(join(tmpdir(), "doorkey-app-"));
    const first = await appSecrets(dir);
    expect(first.pepper).toMatch(/^[0-9a-f]{64}$/);
    expect(first.session_secret).toMatch(/^[0-9a-f]{64}$/);
    expect(first.pepper).not.toBe(first.session_secret);
    expect((await stat(join(dir, "secrets.json"))).mode & 0o777).toBe(0o600);
    expect(await appSecrets(dir)).toEqual(first);
  });

  test("the Supervisor's MQTT service becomes MQTT_*", () => {
    expect(
      mqttEnv({
        host: "core-mosquitto",
        port: "1883",
        ssl: false,
        username: "addons",
        password: "pw",
      }),
    ).toEqual({
      MQTT_URL: "mqtt://core-mosquitto:1883",
      MQTT_USERNAME: "addons",
      MQTT_PASSWORD: "pw",
    });
    expect(mqttEnv({ host: "broker", port: 8883, ssl: true }).MQTT_URL).toBe(
      "mqtts://broker:8883",
    );
  });
});
