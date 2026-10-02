/**
 * A stand-in for Home Assistant's Ingress gateway: serves the app's ingress
 * port under /api/hassio_ingress/tok and adds the user headers the
 * Supervisor would. FAKE_USER picks the user (default u-admin).
 *
 *   bun test/fake-ingress.ts      # :18125 -> :8099
 */
const PREFIX = "/api/hassio_ingress/tok";
const NAMES: Record<string, [string, string]> = {
  "u-admin": ["alice", "Alice"],
  "u-owner": ["owner", "Owner"],
  "u-user": ["bob", "Bob"],
};
const user = process.env.FAKE_USER ?? "u-admin";
const target = process.env.FAKE_INGRESS_TARGET ?? "http://127.0.0.1:8099";

Bun.serve({
  port: Number(process.env.FAKE_INGRESS_PORT ?? 18125),
  async fetch(req) {
    const u = new URL(req.url);
    if (!u.pathname.startsWith(PREFIX)) return new Response("not ingress", { status: 404 });
    const h = new Headers(req.headers);
    const [name, display] = NAMES[user] ?? [user, user];
    h.set("X-Remote-User-Id", user);
    h.set("X-Remote-User-Name", name);
    h.set("X-Remote-User-Display-Name", display);
    h.set("X-Ingress-Path", PREFIX);
    const body = req.method === "GET" ? undefined : await req.arrayBuffer();
    return fetch(target + u.pathname.slice(PREFIX.length) + u.search, { method: req.method, headers: h, body });
  },
});
console.log("fake ingress listening");
