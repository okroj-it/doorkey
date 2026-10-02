/**
 * Drives the admin Actions tab end to end in a real browser: create an action
 * from the HA script picker, grant roles, issue a tag URL, create a user, mint
 * an enrolment link, register a passkey on a second "phone", run the action,
 * then tighten and tear everything down again.
 *
 *   bun test/fake-ha.ts &
 *   bun test/admin-actions.ts <admin-enroll-token>
 *
 * Expects doorkey on TEST_ORIGIN with DOORKEY_RP_ID=localhost, HA_URL pointing
 * at the fake HA, and an empty database apart from that admin enrolment.
 */
import puppeteer, { type Page } from "puppeteer-core";

const ORIGIN = process.env.TEST_ORIGIN ?? "http://localhost:18080";
const FAKE_HA = process.env.TEST_FAKE_HA ?? "http://127.0.0.1:18123";
const ADMIN_TOKEN = process.argv[2];
if (!ADMIN_TOKEN)
  throw new Error("usage: bun test/admin-actions.ts <admin-enroll-token>");

const pass: string[] = [];
const fail: string[] = [];
const check = (name: string, ok: boolean) => {
  (ok ? pass : fail).push(name);
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}`);
};

const scriptCalls = async () =>
  (
    (await (await fetch(`${FAKE_HA}/calls`)).json()) as {
      path: string;
      body: any;
    }[]
  ).filter((c) => c.path === "/api/services/script/turn_on");

const browser = await puppeteer.launch({
  executablePath: "/usr/bin/google-chrome-stable",
  headless: true,
  protocolTimeout: 30_000,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

/** Answers prompt() with the next queued answer and accepts every confirm(). */
const answers: string[] = [];

async function phone(): Promise<Page> {
  const page = await browser.newPage();
  await page.setViewport({ width: 1100, height: 900 });
  page.on("pageerror", (e) => console.log(`  [pageerror] ${e.message}`));
  page.on(
    "dialog",
    (d) =>
      void (d.type() === "prompt"
        ? d.accept(answers.shift() ?? "")
        : d.accept()),
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

async function waitText(
  page: Page,
  needle: string,
  timeout = 15000,
): Promise<boolean> {
  try {
    await page.waitForFunction(
      (n) => document.body.textContent?.includes(n),
      { timeout },
      needle,
    );
    return true;
  } catch {
    console.log(
      `  [page] ${(await page.evaluate(() => document.body.textContent ?? "")).replace(/\s+/g, " ").slice(0, 300)}`,
    );
    return false;
  }
}

async function waitGone(
  page: Page,
  needle: string,
  timeout = 15000,
): Promise<boolean> {
  try {
    await page.waitForFunction(
      (n) => !document.body.textContent?.includes(n),
      { timeout },
      needle,
    );
    return true;
  } catch {
    return false;
  }
}

/** Clicks the first button (or label) whose trimmed text is exactly `text`. */
async function press(page: Page, text: string): Promise<void> {
  const found = await page.evaluate((t) => {
    const el = [...document.querySelectorAll<HTMLElement>("button, label")].find(
      (e) => e.textContent?.trim() === t && !(e as HTMLButtonElement).disabled,
    );
    el?.click();
    return !!el;
  }, text);
  if (!found) throw new Error(`no enabled button "${text}"`);
}

/** The one-time secret panel's URL. */
const shownUrl = (page: Page) =>
  page
    .waitForSelector(".fresh code.url")
    .then((el) => el!.evaluate((e) => e.textContent?.trim() ?? ""));

async function typeRole(
  page: Page,
  index: number,
  role: string,
): Promise<void> {
  const inputs = await page.$$('input[placeholder="add role"]');
  await inputs[index]!.type(role);
  await inputs[index]!.press("Enter");
}

try {
  const admin = await phone();

  // --- sign in as admin and open the tab ------------------------------------
  await admin.goto(`${ORIGIN}/admin/enroll/${ADMIN_TOKEN}`, {
    waitUntil: "networkidle0",
  });
  await admin.click("button.primary");
  check("admin passkey enrolled", await waitText(admin, "New code"));

  await admin.click("nav.tabs button:nth-child(2)");
  check("the Actions tab opens", await waitText(admin, "No actions yet."));
  check(
    "the tab is in the URL hash",
    (await admin.evaluate(() => location.hash)) === "#actions",
  );

  // --- create an action from the script picker ------------------------------
  await admin.waitForSelector(
    "select[required] option[value='script.tapgate_test']",
  );
  check(
    "the script picker lists HA scripts only",
    await admin.evaluate(() => {
      const values = [
        ...document.querySelectorAll("select[required] option"),
      ].map((o) => (o as HTMLOptionElement).value);
      return (
        values.includes("script.garage_open") &&
        !values.includes("lock.tedee_go2")
      );
    }),
  );
  await admin.select("select[required]", "script.tapgate_test");
  const autofill = await admin.evaluate(() => {
    const inputs = [
      ...document.querySelectorAll("form input"),
    ] as HTMLInputElement[];
    return inputs.map((i) => i.value).filter(Boolean);
  });
  check(
    "picking a script fills label and slug",
    autofill.includes("Tapgate test") && autofill.includes("tapgate-test"),
  );
  await admin.click('form[aria-label="New action"] button.primary');
  check("the action card appears", await waitText(admin, "/a/tapgate-test"));
  check(
    "an action without roles says so",
    await waitText(admin, "nobody may run it"),
  );

  await typeRole(admin, 0, "owner");
  check(
    "a role can be allowed on the action",
    await waitGone(admin, "nobody may run it"),
  );

  // --- plain tag URL ---------------------------------------------------------
  await press(admin, "issue URL");
  const tagUrl = await shownUrl(admin);
  check(
    "issuing a tag URL shows it once",
    /\/a\/tapgate-test\?t=[A-Za-z0-9_-]{22}$/.test(tagUrl),
  );
  await press(admin, "dismiss");

  // --- a user, a role, an enrolment link --------------------------------------
  await admin.type('input[placeholder="Ola"]', "ola");
  await admin.click('form[aria-label="New user"] button.primary');
  check("the user card appears", await waitText(admin, "none yet"));
  await typeRole(admin, 1, "owner");
  await admin.waitForFunction(
    () => document.querySelectorAll(".chip").length >= 2,
  );

  answers.push("pixel");
  await press(admin, "new enrolment link");
  const enrollUrl = await shownUrl(admin);
  check(
    "an enrolment link is minted from the UI",
    /\/a\/enroll\/[A-Za-z0-9_-]{32}$/.test(enrollUrl),
  );

  // --- the user's phone: register, tap, confirm -------------------------------
  const ola = await phone();
  await ola.bringToFront();
  await ola.goto(enrollUrl, { waitUntil: "networkidle0" });
  check(
    "the link names the user and device",
    await waitText(ola, "ola · pixel"),
  );
  await ola.click("button");
  check(
    "the user registers a passkey",
    await waitText(ola, "Passkey saved"),
  );

  const before = (await scriptCalls()).length;
  await ola.goto(tagUrl, { waitUntil: "networkidle0" });
  await waitText(ola, "Confirm with fingerprint");
  await ola.click("button");
  check("the user runs the action", await waitText(ola, "Done"));
  check("HA got the script call", (await scriptCalls()).length === before + 1);

  // --- back in admin: it all shows up ---------------------------------------
  await admin.bringToFront();
  await admin.reload({ waitUntil: "networkidle0" });
  check(
    "a reload stays on the Actions tab",
    await waitText(admin, "/a/tapgate-test"),
  );
  check("the passkey is listed under the user", await waitText(admin, "pixel"));
  check(
    "the run is in the activity log",
    await admin.evaluate(() =>
      [...document.querySelectorAll(".pill")].some(
        (p) => p.textContent === "ran",
      ),
    ),
  );
  check(
    "roles table counts the use",
    await admin.evaluate(() =>
      [...document.querySelectorAll("tr")].some((r) =>
        /owner\s*1\s*1\s*in use/.test(r.textContent ?? ""),
      ),
    ),
  );

  // --- tighten: DNA required refuses the plain tag --------------------------
  await press(admin, "DNA tag required");
  check(
    "requiring DNA shows the plain tag as refused",
    await waitText(admin, "refused — DNA tag required"),
  );
  const refused = await (await fetch(tagUrl, { redirect: "manual" })).status;
  check("the plain tag URL now 404s", refused === 404);

  // --- tear down --------------------------------------------------------------
  await admin.click(".passkey button");
  check(
    "removing the passkey empties the list",
    await waitText(admin, "none yet"),
  );

  await press(admin, "delete");
  check(
    "deleting the action removes its card",
    await waitText(admin, "No actions yet."),
  );

  const log = await admin.evaluate(
    async (o) => (await fetch(`${o}/admin/api/log?limit=50`)).json(),
    ORIGIN,
  );
  const seen = new Set(
    (log as { events: { event: string }[] }).events.map((e) => e.event),
  );
  check(
    "every change is in the admin log",
    [
      "action_created",
      "action_role_allowed",
      "action_token_issued",
      "action_user_created",
      "action_user_granted",
      "action_enroll_link",
      "action_updated",
      "action_passkey_removed",
      "action_deleted",
    ].every((e) => seen.has(e)),
  );
} catch (err) {
  console.log(`  ERROR ${(err as Error).message.split("\n")[0]}`);
  fail.push("threw before completing");
} finally {
  await browser.close();
}

console.log(`\n  ${pass.length} passed, ${fail.length} failed`);
process.exit(fail.length ? 1 : 0);
