import mqtt from "mqtt";
import { config } from "./config.ts";

/**
 * Home Assistant MQTT discovery, same shape the ESP32 nodes publish, so the
 * keypad shows up as a device with history rather than as REST sensors HA has
 * to be told about.
 */

const BASE = config.mqtt.nodeId;
const STATE_TOPIC = `${BASE}/state`;
const AVAIL_TOPIC = `${BASE}/status`;

const DEVICE = {
  identifiers: [BASE],
  name: "Door Keypad",
  manufacturer: "doorkey",
  model: "doorkey",
} as const;

interface Entity {
  component: "binary_sensor" | "sensor";
  key: string;
  name: string;
  valueTemplate: string;
  deviceClass?: string;
  icon?: string;
}

const ENTITIES: Entity[] = [
  {
    component: "binary_sensor",
    key: "locked_out",
    name: "Locked out",
    valueTemplate: "{{ 'ON' if value_json.locked_out else 'OFF' }}",
    deviceClass: "problem",
  },
  {
    component: "sensor",
    key: "failed_today",
    name: "Failed attempts today",
    valueTemplate: "{{ value_json.failed_today }}",
    icon: "mdi:alert-circle-outline",
  },
  {
    component: "sensor",
    key: "last_entry",
    name: "Last entry",
    valueTemplate: "{{ value_json.last_entry }}",
    icon: "mdi:account-check-outline",
  },
  {
    component: "sensor",
    key: "last_entry_at",
    name: "Last entry at",
    valueTemplate: "{{ value_json.last_entry_at }}",
    deviceClass: "timestamp",
  },
];

export interface DoorkeyState {
  locked_out: boolean;
  failed_today: number;
  last_entry: string;
  last_entry_at: string | null;
}

let client: mqtt.MqttClient | null = null;
/**
 * Called on every (re)connect. State is a retained message, but a broker
 * restart loses it — and doorkey has no other reason to publish until someone
 * uses the keypad, so Home Assistant would sit at "unknown" until then.
 */
let onReconnect: (() => void) | null = null;

export function setReconnectHook(fn: () => void): void {
  onReconnect = fn;
}

export function start(): void {
  if (!config.mqtt.url) {
    console.warn("MQTT_URL not set — skipping Home Assistant discovery");
    return;
  }

  client = mqtt.connect(config.mqtt.url, {
    username: config.mqtt.username || undefined,
    password: config.mqtt.password || undefined,
    will: { topic: AVAIL_TOPIC, payload: Buffer.from("offline"), qos: 1, retain: true },
    reconnectPeriod: 5000,
  });

  client.on("connect", () => {
    console.log("mqtt connected");
    client?.publish(AVAIL_TOPIC, "online", { qos: 1, retain: true });
    publishDiscovery();
    onReconnect?.();
  });

  client.on("error", (err) => console.error("mqtt error:", err.message));
}

function publishDiscovery(): void {
  for (const e of ENTITIES) {
    const topic = `${config.mqtt.discoveryPrefix}/${e.component}/${BASE}/${e.key}/config`;
    const payload = {
      name: e.name,
      unique_id: `${BASE}_${e.key}`,
      state_topic: STATE_TOPIC,
      value_template: e.valueTemplate,
      availability_topic: AVAIL_TOPIC,
      device: DEVICE,
      ...(e.deviceClass ? { device_class: e.deviceClass } : {}),
      ...(e.icon ? { icon: e.icon } : {}),
    };
    client?.publish(topic, JSON.stringify(payload), { qos: 1, retain: true });
  }
}

export function publishState(state: DoorkeyState): void {
  client?.publish(STATE_TOPIC, JSON.stringify(state), { qos: 1, retain: true });
}
