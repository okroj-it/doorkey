/**
 * A stand-in Home Assistant for the browser tests: records every service call,
 * reports the lock as locked and offers two scripts in /api/states. GET /calls
 * returns what was recorded.
 *
 *   bun test/fake-ha.ts            # then HA_URL=http://127.0.0.1:18123
 */
const calls: { path: string; body: unknown }[] = [];

Bun.serve({
  port: Number(process.env.FAKE_HA_PORT ?? 18123),
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/calls") return Response.json(calls);
    if (url.pathname === "/api/states") {
      return Response.json([
        { entity_id: "script.tapgate_test", state: "off", attributes: { friendly_name: "Tapgate test" } },
        { entity_id: "script.garage_open", state: "off", attributes: { friendly_name: "Open the garage" } },
        { entity_id: "lock.front_door", state: "locked", attributes: {} },
      ]);
    }
    if (req.method === "POST") {
      calls.push({ path: url.pathname, body: await req.json().catch(() => null) });
      return Response.json([]);
    }
    return Response.json({ state: "locked" });
  },
});
console.log("fake HA listening");
