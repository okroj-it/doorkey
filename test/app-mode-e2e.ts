/**
 * doorkey as a Home Assistant app, end to end, against the stand-ins in
 * test/fake-supervisor.ts and test/fake-ingress.ts. Run by
 * scripts/e2e-app.sh, which starts everything:
 *
 *   bun test/app-mode-e2e.ts lookup     # HA's user list is readable
 *   bun test/app-mode-e2e.ts fallback   # it is not; admin_users=alice
 */
import { stat } from "node:fs/promises";
import puppeteer from "puppeteer-core";

const mode = process.argv[2] ?? "lookup";
const PUBLIC = "http://127.0.0.1:8080";
const INGRESS = "http://127.0.0.1:8099";
const VIA_INGRESS = "http://127.0.0.1:18125/api/hassio_ingress/tok";

const fail: string[] = [];
const check = (name: string, ok: boolean) => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) fail.push(name);
};

/** Status and JSON (or text) of a request to the ingress listener as a user. */
async function asUser(
  path: string,
  user?: [string, string],
  init: RequestInit = {},
) {
  const headers = new Headers(init.headers);
  if (user) {
    headers.set("X-Remote-User-Id", user[0]);
    headers.set("X-Remote-User-Name", user[1]);
  }
  const res = await fetch(INGRESS + path, { ...init, headers });
  const text = await res.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {}
  return {
    status: res.status,
    body: body as { error?: string; label?: string; via?: string },
  };
}
const status = async (url: string) => (await fetch(url)).status;

const alice: [string, string] = ["u-admin", "alice"];
const bob: [string, string] = ["u-user", "bob"];

if (mode === "lookup") {
  // --- the two listeners -----------------------------------------------------
  check("public listener is up", (await status(`${PUBLIC}/healthz`)) === 200);
  check(
    "public listener has no /admin",
    (await status(`${PUBLIC}/admin`)) === 404,
  );
  check(
    "public listener has no admin API",
    (await status(`${PUBLIC}/admin/api/codes`)) === 404,
  );
  // The allowed peer is 127.0.0.1 here; ::1 stands in for anyone else.
  check(
    "ingress port refuses other peers, /healthz included",
    (await status("http://[::1]:8099/healthz")) === 403,
  );
  check(
    "ingress port refuses other peers on /admin",
    (await status("http://[::1]:8099/admin")) === 403,
  );
  // --- framing -----------------------------------------------------------------
  const framing = async (url: string) =>
    (await fetch(url)).headers.get("Content-Security-Policy");
  check(
    "public pages may not be framed",
    (await framing(`${PUBLIC}/healthz`)) === "frame-ancestors 'none'" &&
      (await framing(`${PUBLIC}/admin`)) === "frame-ancestors 'none'",
  );
  check(
    "ingress admin may be framed by Home Assistant only (same origin)",
    (await framing(`${VIA_INGRESS}/admin`)) === "frame-ancestors 'self'",
  );
  check(
    "a refused ingress request carries it too",
    (await framing("http://[::1]:8099/admin")) === "frame-ancestors 'self'",
  );

  // --- who gets in -------------------------------------------------------------
  check(
    "no user header: 401",
    (await asUser("/admin/api/session")).status === 401,
  );
  const s = await asUser("/admin/api/session", alice);
  check(
    "an HA admin gets a session from Home Assistant",
    s.status === 200 && s.body.via === "home-assistant",
  );
  check(
    "the owner gets in",
    (await asUser("/admin/api/codes", ["u-owner", "owner"])).status === 200,
  );
  const b = await asUser("/admin/api/codes", bob);
  check(
    "a non-admin HA user is refused",
    b.status === 403 && b.body.error === "not a Home Assistant administrator",
  );
  check(
    "an inactive admin is refused",
    (await asUser("/admin/api/codes", ["u-gone", "carol"])).status === 403,
  );
  check(
    "an unknown user is refused",
    (await asUser("/admin/api/codes", ["u-nobody", "x"])).status === 403,
  );
  check(
    "passkey sign-in does not exist",
    (await asUser("/admin/api/auth/options", alice, { method: "POST" }))
      .status === 404,
  );
  check(
    "passkey enrolment does not exist",
    (await asUser("/admin/enroll/abc", alice)).status === 404,
  );

  // --- secrets ------------------------------------------------------------------
  const dataDir = process.env.DOORKEY_DATA_DIR ?? "";
  check(
    "secrets are generated, owner-only",
    ((await stat(`${dataDir}/secrets.json`)).mode & 0o777) === 0o600,
  );

  // --- the admin page in a browser, under the Ingress prefix -----------------------
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome-stable",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    const page = await browser.newPage();
    await page.goto(`${VIA_INGRESS}/admin`, { waitUntil: "networkidle0" });
    const has = (t: string) =>
      page
        .waitForFunction(
          (x) => document.body.textContent?.includes(x),
          { timeout: 10000 },
          t,
        )
        .then(
          () => true,
          () => false,
        );
    check(
      "the admin page opens straight into the dashboard",
      await has("New code"),
    );
    check("signed in as the HA user", await has("Alice"));
    check(
      "no sign-out button",
      !(await page.evaluate(() =>
        document.body.textContent?.includes("sign out"),
      )),
    );
    await page.type('input[placeholder="Cleaner"]', "Ingress test");
    await page.click("form button.primary");
    check(
      "creating a code works through the prefixed API",
      await has("shown once"),
    );
    await page.click("nav.tabs button:nth-child(2)");
    check("the Actions tab loads", await has("No actions yet."));
  } finally {
    await browser.close();
  }
} else {
  // HA's user list cannot be read; admin_users=alice decides.
  check(
    "admin_users lets alice in",
    (await asUser("/admin/api/codes", alice)).status === 200,
  );
  const b = await asUser("/admin/api/codes", bob);
  check(
    "and nobody else",
    b.status === 403 && b.body.error === "not in admin_users",
  );
}

console.log(`\n  ${fail.length ? `${fail.length} failed` : "all passed"}`);
process.exit(fail.length ? 1 : 0);
