/**
 * The door action: a fingerprint that unlocks the front door, in a real
 * browser with CDP virtual authenticators standing in for two phones.
 *
 *   bun test/fake-ha.ts &
 *   bun test/door-fingerprint.ts <owner-enroll-token> <guest-enroll-token> <door-action-url> <keypad-url>
 *
 * Expects doorkey on TEST_ORIGIN (static tap mode, DOORKEY_RP_ID=localhost,
 * HA_URL at the fake HA) and the CLI to have set up:
 *   - the door action (action:add <slug> door), allowed for one role
 *   - a user with that role                          (owner-enroll-token)
 *   - a user without it                              (guest-enroll-token)
 *   - the door action's plain-tag URL from action:token (door-action-url)
 * and the keypad's static tag URL (keypad-url). The CLI is run again to
 * disable and re-enable the door action, with the environment inherited.
 */
import puppeteer, { type Page } from "puppeteer-core";

const ORIGIN = process.env.TEST_ORIGIN ?? "http://localhost:18080";
const FAKE_HA = process.env.TEST_FAKE_HA ?? "http://127.0.0.1:18123";
const [OWNER_TOKEN, GUEST_TOKEN, DOOR_URL, KEYPAD_URL] = process.argv.slice(2);
if (!OWNER_TOKEN || !GUEST_TOKEN || !DOOR_URL || !KEYPAD_URL) {
  throw new Error(
    "usage: bun test/door-fingerprint.ts <owner-token> <guest-token> <door-action-url> <keypad-url>",
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

/** The doorkey CLI, for the steps an admin would take. Returns its output. */
async function cli(...args: string[]): Promise<string> {
  const p = Bun.spawn(["bun", "cli/doorkey.ts", ...args], {
    env: { ...process.env, DOORKEY_TAP_MODE: "static" },
    stdout: "pipe",
  });
  const out = await new Response(p.stdout).text();
  if ((await p.exited) !== 0) throw new Error(`cli ${args.join(" ")} failed`);
  return out;
}

/** The door action's begin, as the keypad page would call it. */
const begin = (page: Page) =>
  page.evaluate(async () => {
    const res = await fetch("/a/api/begin", { method: "POST" });
    return { status: res.status, label: ((await res.json().catch(() => ({}))) as any).label };
  });

const hasFingerprintCookie = (page: Page) =>
  page.evaluate(() => document.cookie.split("; ").includes("doorkey_fp=1"));

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome-stable",
  headless: true,
  protocolTimeout: 30_000,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

/**
 * One "phone": its own browser context (own cookies, like a real phone) and
 * its own virtual authenticator.
 */
async function phone(): Promise<Page> {
  const page = await (await browser.createBrowserContext()).newPage();
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
  check("enrolling a door passkey marks the phone for fingerprint", await hasFingerprintCookie(owner));
  check("a passkey that may not open the door does not", !(await hasFingerprintCookie(guest)));

  // --- the keypad tap opens the door action too ------------------------------
  await tap(owner, KEYPAD_URL);
  const offered = await begin(owner);
  check("a keypad tap offers the door action", offered.status === 200 && offered.label === "Front door");

  await cli("action:disable", "front-door");
  await tap(owner, KEYPAD_URL);
  check("a disabled door action is not offered on the keypad", (await begin(owner)).status === 401);
  await cli("action:enable", "front-door");

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

  // --- the keypad page -------------------------------------------------------
  const KEY = 'button[aria-label="Open with fingerprint"]';
  const onKeypad = (page: Page) => page.evaluate(() => !!document.querySelector(".pad"));
  const n0 = (await unlocks()).length;

  await tap(owner, KEYPAD_URL);
  await owner.waitForSelector(".fp-main:not([disabled])");
  check("a phone that opens the door by fingerprint starts with the button", !(await onKeypad(owner)));
  await owner.click(".fp-main");
  check("one press opens the door", await waitText(owner, "Unlocked"));
  check("through lock.unlock", (await unlocks()).length === n0 + 1);
  check("and the phone stays marked for fingerprint", await hasFingerprintCookie(owner));

  await tap(owner, KEYPAD_URL);
  await owner.waitForSelector(".fp-main:not([disabled])");
  await owner.click("button.link");
  check("'Use code' shows the keypad, with the fingerprint key", (await onKeypad(owner)) && !!(await owner.$(KEY)));

  await tap(guest, KEYPAD_URL);
  await guest.waitForSelector(KEY);
  check("a phone without the cookie starts with the keypad", await onKeypad(guest));
  await guest.click(KEY);
  check("the guest's passkey cannot open the door from the keypad", await waitText(guest, "Cancelled", 20000));
  check("and stays on the keypad", await onKeypad(guest));
  check("nothing reached the lock", (await unlocks()).length === n0 + 1);

  // --- separate from the keypad lockout ---------------------------------------
  await tap(guest, KEYPAD_URL);
  for (let i = 0; i < 4; i++)
    await guest.evaluate(() =>
      fetch("/api/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: "000000" }),
      }),
    );
  // A valid code refused proves the lockout is on, not just a wrong code.
  const valid = (await cli("add", "lockout-check")).match(/code: (\d+)/)?.[1] ?? "";
  const lockedOut = await guest.evaluate(
    async (code) =>
      (
        await fetch("/api/unlock", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code }),
        })
      ).status,
    valid,
  );
  check("bad codes lock the keypad: even a valid code is refused", valid.length === 6 && lockedOut === 401);
  await tap(owner, KEYPAD_URL);
  await owner.waitForSelector(".fp-main:not([disabled])");
  await owner.click(".fp-main");
  check("the fingerprint still opens the door during a keypad lockout", await waitText(owner, "Unlocked"));
  check("two fingerprint unlocks from the keypad", (await unlocks()).length === n0 + 2);

  // --- the door action's own brake (last: it stays on for ten minutes) ---------
  await tap(guest, KEYPAD_URL);
  const garbage = () =>
    guest.evaluate(
      async () =>
        (
          await fetch("/a/api/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ response: { id: "not-a-passkey" } }),
          })
        ).status,
    );
  const statuses: number[] = [];
  for (let i = 0; i < 6; i++) statuses.push(await garbage());
  check(
    "five rejected passkeys pause fingerprint unlocks",
    statuses.slice(0, 5).every((s) => s === 401) && statuses[5] === 429,
  );
  await tap(owner, KEYPAD_URL);
  await owner.waitForSelector(".fp-main:not([disabled])");
  await owner.click(".fp-main");
  check("even for the owner, who is told to use the code", await waitText(owner, "Use the code or try later"));
  check("and the lock was not called while paused", (await unlocks()).length === n0 + 2);
} catch (err) {
  console.log(`  ERROR  ${(err as Error).message}`);
  fail.push("unexpected error");
} finally {
  await browser.close();
}

console.log(`\n  ${pass.length} passed, ${fail.length} failed`);
process.exit(fail.length ? 1 : 0);
