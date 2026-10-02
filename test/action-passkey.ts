/**
 * The whole tap-gated action flow in a real browser, with CDP virtual
 * authenticators standing in for two phones.
 *
 *   bun test/fake-ha.ts &
 *   bun test/action-passkey.ts <owner-enroll-token> <guest-enroll-token> <action-url>
 *
 * Expects doorkey on TEST_ORIGIN with DOORKEY_RP_ID=localhost and
 * HA_URL pointing at the fake HA, and the CLI to have set up:
 *   - a user with a role that may run the action  (owner-enroll-token)
 *   - a user whose roles may not run it           (guest-enroll-token)
 *   - the action's plain-tag URL from action:token (action-url)
 */
import puppeteer, { type Page } from "puppeteer-core";

const ORIGIN = process.env.TEST_ORIGIN ?? "http://localhost:18080";
const FAKE_HA = process.env.TEST_FAKE_HA ?? "http://127.0.0.1:18123";
const [OWNER_TOKEN, GUEST_TOKEN, ACTION_URL] = process.argv.slice(2);
if (!OWNER_TOKEN || !GUEST_TOKEN || !ACTION_URL) {
  throw new Error(
    "usage: bun test/action-passkey.ts <owner-token> <guest-token> <action-url>",
  );
}

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
  executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome-stable",
  headless: true,
  // Fail fast rather than hang for three minutes on a stuck evaluate.
  protocolTimeout: 30_000,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

/** A tab with its own virtual authenticator: one "phone". */
async function phone(): Promise<{
  page: Page;
  credentials: () => Promise<number>;
}> {
  const page = await browser.newPage();
  page.on("pageerror", (e) => console.log(`  [pageerror] ${e.message}`));
  const cdp = await page.createCDPSession();
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    },
  );
  return {
    page,
    credentials: async () =>
      (await cdp.send("WebAuthn.getCredentials", { authenticatorId }))
        .credentials.length,
  };
}

const text = (page: Page) =>
  page.evaluate(() => document.body.textContent ?? "");

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
      `  [page] ${(await text(page)).replace(/\s+/g, " ").slice(0, 200)}`,
    );
    return false;
  }
}

/** WebAuthn only works in the focused tab, and each phone is a tab. */
async function tap(page: Page, url: string): Promise<void> {
  await page.bringToFront();
  await page.goto(url, { waitUntil: "networkidle0" });
}

async function enroll(page: Page, token: string): Promise<boolean> {
  await page.bringToFront();
  await page.goto(`${ORIGIN}/a/enroll/${token}`, { waitUntil: "networkidle0" });
  await page.waitForSelector("button");
  await page.click("button");
  return waitText(page, "Passkey saved");
}

try {
  const owner = await phone();
  const guest = await phone();

  // --- enrolment ------------------------------------------------------------
  check(
    "the owner enrols an action passkey",
    await enroll(owner.page, OWNER_TOKEN),
  );
  check("a resident credential was created", (await owner.credentials()) === 1);
  check(
    "the guest enrols an action passkey",
    await enroll(guest.page, GUEST_TOKEN),
  );

  const spent = await owner.page.evaluate(
    async (o, t) =>
      (await fetch(`${o}/a/api/enroll/${t}/options`, { method: "POST" }))
        .status,
    ORIGIN,
    OWNER_TOKEN,
  );
  check("a spent enrolment link is rejected", spent === 404);

  // --- action passkeys are not admin passkeys -------------------------------
  const adminOpts = await owner.page.evaluate(
    async (o) =>
      (await fetch(`${o}/admin/api/auth/options`, { method: "POST" })).status,
    ORIGIN,
  );
  check(
    "an action passkey does not count as an admin passkey",
    adminOpts === 409,
  );

  // --- no tap, no session ---------------------------------------------------
  const noTap = await owner.page.evaluate(
    async (o) => (await fetch(`${o}/a/api/begin`, { method: "POST" })).status,
    ORIGIN,
  );
  check("begin without a tap is refused", noTap === 401);

  // --- the owner runs the action -------------------------------------------
  const before = (await scriptCalls()).length;
  await tap(owner.page, ACTION_URL);
  check(
    "the tap shows the confirm button",
    await waitText(owner.page, "Confirm with fingerprint"),
  );
  await owner.page.click("button");
  check(
    "confirming with the passkey runs the action",
    await waitText(owner.page, "Done"),
  );

  const calls = await scriptCalls();
  const last = calls.at(-1);
  check("exactly one script call reached HA", calls.length === before + 1);
  check(
    "the call carries the allowlisted script and who ran it",
    last?.body?.entity_id === "script.tapgate_test" &&
      last?.body?.variables?.tapgate_user === "owner",
  );

  const again = await owner.page.evaluate(
    async (o) => (await fetch(`${o}/a/api/begin`, { method: "POST" })).status,
    ORIGIN,
  );
  check("one run per tap: the session is spent", again === 401);

  // --- the guest's passkey is not offered, so nothing runs ------------------
  await tap(guest.page, ACTION_URL);
  await waitText(guest.page, "Confirm with fingerprint");
  await guest.page.click("button");
  const refused = await waitText(guest.page, "Cancelled", 20000);
  check("a passkey without the role cannot confirm", refused);
  check("and HA was not called", (await scriptCalls()).length === before + 1);

  // --- tapping again runs it again ------------------------------------------
  await tap(owner.page, ACTION_URL);
  await waitText(owner.page, "Confirm with fingerprint");
  await owner.page.click("button");
  check("a fresh tap runs it again", await waitText(owner.page, "Done"));
  check("two runs in total", (await scriptCalls()).length === before + 2);

  // --- a Polish browser gets the Polish page --------------------------------
  const pl = await browser.newPage();
  await pl.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, "languages", {
      get: () => ["pl-PL", "pl", "en"],
    });
  });
  await pl.bringToFront();
  await pl.goto(ACTION_URL, { waitUntil: "networkidle0" });
  check(
    "the tap page follows the browser language",
    await waitText(pl, "Potwierdź odciskiem"),
  );
  check(
    "and sets <html lang>",
    (await pl.evaluate(() => document.documentElement.lang)) === "pl",
  );
} catch (err) {
  console.log(`  ERROR ${(err as Error).message.split("\n")[0]}`);
  fail.push("threw before completing");
} finally {
  await browser.close();
}

console.log(`\n  ${pass.length} passed, ${fail.length} failed`);
process.exit(fail.length ? 1 : 0);
