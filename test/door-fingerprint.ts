/**
 * The door action: a fingerprint that unlocks the front door, in a real
 * browser with CDP virtual authenticators standing in for two phones.
 *
 *   bun test/fake-ha.ts &
 *   bun test/door-fingerprint.ts <owner-enroll-token> <guest-enroll-token> <door-action-url>
 *
 * Expects doorkey on TEST_ORIGIN (static tap mode, DOORKEY_RP_ID=localhost,
 * HA_URL at the fake HA) and the CLI to have set up:
 *   - the door action (action:add <slug> door), allowed for one role
 *   - a user with that role                          (owner-enroll-token)
 *   - a user without it                              (guest-enroll-token)
 *   - the door action's plain-tag URL from action:token (door-action-url)
 */
import puppeteer, { type Page } from "puppeteer-core";

const ORIGIN = process.env.TEST_ORIGIN ?? "http://localhost:18080";
const FAKE_HA = process.env.TEST_FAKE_HA ?? "http://127.0.0.1:18123";
const [OWNER_TOKEN, GUEST_TOKEN, DOOR_URL] = process.argv.slice(2);
if (!OWNER_TOKEN || !GUEST_TOKEN || !DOOR_URL) {
  throw new Error(
    "usage: bun test/door-fingerprint.ts <owner-token> <guest-token> <door-action-url>",
  );
}

const pass: string[] = [];
const fail: string[] = [];
const check = (name: string, ok: boolean) => {
  (ok ? pass : fail).push(name);
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}`);
};

/** Service calls that reached the fake HA, by service path. */
const haCalls = async (path: string) =>
  (
    (await (await fetch(`${FAKE_HA}/calls`)).json()) as {
      path: string;
      body: any;
    }[]
  ).filter((c) => c.path === path);
const unlocks = () => haCalls("/api/services/lock/unlock");
const locks = () => haCalls("/api/services/lock/lock");
const scripts = () => haCalls("/api/services/script/turn_on");

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome-stable",
  headless: true,
  protocolTimeout: 30_000,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

/** A tab with its own virtual authenticator: one "phone". */
async function phone(): Promise<Page> {
  const page = await browser.newPage();
  page.on("pageerror", (e) => console.log(`  [pageerror] ${e.message}`));
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
  await tap(page, `${ORIGIN}/a/enroll/${token}`);
  await page.waitForSelector("button");
  await page.click("button");
  return waitText(page, "Passkey saved");
}

try {
  const owner = await phone();
  const guest = await phone();
  check("the owner enrols a passkey", await enroll(owner, OWNER_TOKEN));
  check("the guest enrols a passkey", await enroll(guest, GUEST_TOKEN));

  // --- the door action from its own tag URL ---------------------------------
  // The fake HA logs the whole e2e run: compare counts, not totals.
  const before = (await unlocks()).length;
  const others = async () => (await locks()).length + (await scripts()).length;
  const othersBefore = await others();
  await tap(owner, DOOR_URL);
  await waitText(owner, "Confirm with fingerprint");
  await owner.click("button");
  check(
    "the owner's fingerprint opens the door",
    await waitText(owner, "Done"),
  );
  check(
    "exactly one lock.unlock reached HA",
    (await unlocks()).length === before + 1,
  );
  check(
    "it unlocks the configured lock",
    (await unlocks()).at(-1)?.body?.entity_id === "lock.front_door",
  );
  check(
    "the door action never locks or runs a script",
    (await others()) === othersBefore,
  );

  await tap(guest, DOOR_URL);
  await waitText(guest, "Confirm with fingerprint");
  await guest.click("button");
  check(
    "a passkey without the role cannot open it",
    await waitText(guest, "Cancelled", 20000),
  );
  check("and the lock was not called", (await unlocks()).length === before + 1);
} catch (err) {
  console.log(`  ERROR  ${(err as Error).message}`);
  fail.push("unexpected error");
} finally {
  await browser.close();
}

console.log(`\n  ${pass.length} passed, ${fail.length} failed`);
process.exit(fail.length ? 1 : 0);
