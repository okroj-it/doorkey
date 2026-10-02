/**
 * A stand-in Home Assistant Supervisor for the app-mode tests: the MQTT
 * service, /core/* proxied to test/fake-ha.ts, and Core's websocket API with
 * a small user list. FAKE_WS_REFUSE=1 makes the websocket refuse the token,
 * as if SUPERVISOR_TOKEN could not read the users.
 *
 *   bun test/fake-ha.ts & bun test/fake-supervisor.ts      # :18124
 */
const refuse = process.env.FAKE_WS_REFUSE === "1";
const HA = process.env.FAKE_HA_URL ?? "http://127.0.0.1:18123";

export const USERS = [
  { id: "u-owner", username: "owner", name: "Owner", is_owner: true, is_active: true, group_ids: ["system-admin"] },
  { id: "u-admin", username: "alice", name: "Alice", is_owner: false, is_active: true, group_ids: ["system-admin"] },
  { id: "u-user", username: "bob", name: "Bob", is_owner: false, is_active: true, group_ids: ["system-users"] },
  { id: "u-gone", username: "carol", name: "Carol", is_owner: false, is_active: false, group_ids: ["system-admin"] },
];

Bun.serve({
  port: Number(process.env.FAKE_SUPERVISOR_PORT ?? 18124),
  async fetch(req, server) {
    const u = new URL(req.url);
    if (u.pathname === "/core/websocket" && server.upgrade(req)) return;
    if (u.pathname === "/services/mqtt") {
      return Response.json({ result: "ok", data: { host: "127.0.0.1", port: "1883", ssl: false, username: "addons", password: "pw" } });
    }
    if (u.pathname.startsWith("/core/")) {
      const body = req.method === "GET" ? undefined : await req.text();
      return fetch(HA + u.pathname.slice("/core".length) + u.search, { method: req.method, headers: req.headers, body });
    }
    return new Response("not found", { status: 404 });
  },
  websocket: {
    open(ws) {
      ws.send(JSON.stringify({ type: "auth_required", ha_version: "2026.10.0" }));
    },
    message(ws, raw) {
      const m = JSON.parse(String(raw));
      if (m.type === "auth") ws.send(JSON.stringify(refuse ? { type: "auth_invalid", message: "refused" } : { type: "auth_ok" }));
      else if (m.type === "config/auth/list") ws.send(JSON.stringify({ id: m.id, type: "result", success: true, result: USERS }));
    },
  },
});
console.log("fake supervisor listening");
