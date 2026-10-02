/**
 * Regenerates the README screenshots in docs/screenshots/.
 *
 *   bun test/fake-ha.ts &
 *   DOORKEY_TAP_MODE=static DOORKEY_STATIC_PATH=demo ... bun src/index.ts &
 *   bun scripts/screenshots.ts <admin-enroll-token>
 *
 * Run it against a throwaway instance: it seeds demo data (codes, actions,
 * users, passkeys, a few runs) through the same API the admin page uses.
 * Expects DOORKEY_RP_ID=localhost, the fake HA as HA_URL, and an empty
 * database apart from the admin enrolment. Any provisioned DNA tags already in
 * the database get linked to the demo action, so the tag chip shows up.
 */
import puppeteer, { type Page } from "puppeteer-core";

const ORIGIN = process.env.TEST_ORIGIN ?? "http://localhost:18080";
const STATIC_PATH = process.env.DOORKEY_STATIC_PATH ?? "demo";
const OUT = new URL("../docs/screenshots/", import.meta.url).pathname;
const ADMIN_TOKEN = process.argv[2];
if (!ADMIN_TOKEN)
  throw new Error("usage: bun scripts/screenshots.ts <admin-enroll-token>");

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome-stable",
  headless: true,
  protocolTimeout: 30_000,
  args: [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--lang=en-US",
    "--hide-scrollbars",
  ],
});

const PHONE = {
  width: 390,
  height: 780,
  deviceScaleFactor: 2,
  isMobile: true,
  hasTouch: true,
};
const DESKTOP = { width: 1240, height: 900, deviceScaleFactor: 1.5 };

async function tab(viewport: typeof PHONE | typeof DESKTOP): Promise<Page> {
  const page = await browser.newPage();
  await page.setViewport(viewport);
  await page.emulateMediaFeatures([
    { name: "prefers-reduced-motion", value: "reduce" },
  ]);
  page.on(
    "dialog",
    (d) => void d.accept(d.type() === "prompt" ? "pixel" : undefined),
  );
  const cdp = await page.createCDPSession();
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return page;
}

const wait = (page: Page, text: string) =>
  page.waitForFunction(
    (t) => document.body.textContent?.includes(t),
    { timeout: 15000 },
    text,
  );

/** fetch() from inside the page, so it carries the page's cookies. */
const call = <T = any>(
  page: Page,
  path: string,
  method = "GET",
  body?: unknown,
) =>
  page.evaluate(
    async (o, p, m, b) => {
      const r = await fetch(`${o}${p}`, {
        method: m,
        headers: { "Content-Type": "application/json" },
        body: b === undefined ? undefined : JSON.stringify(b),
      });
      return r.json();
    },
    ORIGIN,
    path,
    method,
    body,
  ) as Promise<T>;

async function shot(page: Page, name: string, fullPage = false) {
  await new Promise((r) => setTimeout(r, 250));
  await page.screenshot({ path: `${OUT}${name}.png`, fullPage });
  console.log(`  docs/screenshots/${name}.png`);
}

try {
  // --- admin, and the demo data ---------------------------------------------
  const admin = await tab(DESKTOP);
  await admin.goto(`${ORIGIN}/admin/enroll/${ADMIN_TOKEN}`, {
    waitUntil: "networkidle0",
  });
  await admin.click("button.primary");
  await wait(admin, "New code");

  const week = new Date(Date.now() + 7 * 86_400_000).toISOString();
  const cleaner = await call(admin, "/admin/api/codes", "POST", {
    label: "Cleaning",
    validUntil: week,
    maxUses: 4,
  });
  const family = await call(admin, "/admin/api/codes", "POST", {
    label: "Parents",
  });
  await call(admin, "/admin/api/codes", "POST", {
    label: "Courier",
    maxUses: 1,
  });

  // A few door attempts for the activity log: two entries and one typo.
  const door = await tab(PHONE);
  for (const code of [family.code, "123450", cleaner.code]) {
    await door.goto(`${ORIGIN}/k/${STATIC_PATH}`, {
      waitUntil: "networkidle0",
    });
    await call(door, "/api/unlock", "POST", { code });
  }

  const action = await call(admin, "/admin/api/actions", "POST", {
    slug: "garage",
    label: "Open the garage",
    script: "script.garage_open",
  });
  const test = await call(admin, "/admin/api/actions", "POST", {
    slug: "tapgate-test",
    label: "Tapgate test",
    script: "script.tapgate_test",
    homeOnly: true,
  });
  await call(admin, "/admin/api/actions", "POST", {
    slug: "alarm-off",
    label: "Disarm alarm",
    script: "script.alarm_off",
    requireSun: true,
  });
  await call(admin, `/admin/api/actions/${action.id}/roles/owner`, "PUT");
  await call(admin, `/admin/api/actions/${action.id}/roles/family`, "PUT");
  await call(admin, `/admin/api/actions/${test.id}/roles/owner`, "PUT");
  const { url: tagUrl } = await call(
    admin,
    `/admin/api/actions/${action.id}/token`,
    "POST",
  );

  const { tags } = await call<{
    tags: { uid: string; action_id: number | null }[];
  }>(admin, "/admin/api/actions");
  for (const t of tags.filter((x) => x.action_id === null).slice(0, 1)) {
    await call(admin, `/admin/api/tags/${t.uid}/action`, "PUT", {
      actionId: action.id,
    });
  }

  const users: Record<string, number> = {};
  for (const [name, role] of [
    ["alex", "owner"],
    ["sam", "family"],
    ["guest", "guests"],
  ] as const) {
    users[name] = (
      await call(admin, "/admin/api/action-users", "POST", { name })
    ).id;
    await call(
      admin,
      `/admin/api/action-users/${users[name]}/roles/${role}`,
      "PUT",
    );
  }

  // Two phones register passkeys and run the garage action.
  const phones: Page[] = [];
  for (const name of ["alex", "sam"]) {
    const phone = await tab(PHONE);
    await phone.bringToFront();
    const { url } = await call(
      admin,
      `/admin/api/action-users/${users[name]}/enroll`,
      "POST",
      { device: "pixel" },
    );
    await phone.goto(url, { waitUntil: "networkidle0" });
    await phone.click("button");
    await wait(phone, "Passkey saved");
    phones.push(phone);
  }
  for (const phone of phones) {
    await phone.bringToFront();
    await phone.goto(tagUrl, { waitUntil: "networkidle0" });
    await wait(phone, "Confirm with fingerprint");
    await phone.click("button");
    await wait(phone, "Done");
  }

  // --- the phone screens ------------------------------------------------------
  await door.bringToFront();
  await door.goto(`${ORIGIN}/k/${STATIC_PATH}`, { waitUntil: "networkidle0" });
  for (const n of ["4", "7", "1"]) {
    await door.evaluate((d) => [...document.querySelectorAll("button")].find((b) => b.textContent === d)?.click(), n);
  }
  await shot(door, "keypad");

  const phone = phones[0]!;
  await phone.bringToFront();
  await phone.goto(tagUrl, { waitUntil: "networkidle0" });
  await wait(phone, "Confirm with fingerprint");
  await shot(phone, "confirm");
  await phone.click("button");
  await wait(phone, "Done");
  await shot(phone, "done");

  // --- the admin page ---------------------------------------------------------
  await admin.bringToFront();
  await admin.goto(`${ORIGIN}/admin`, { waitUntil: "networkidle0" });
  await wait(admin, "Door activity");
  await shot(admin, "admin-door");

  await admin.click("nav.tabs button:nth-child(2)");
  await wait(admin, "Action users");
  await shot(admin, "admin-actions", true);
} finally {
  await browser.close();
}
