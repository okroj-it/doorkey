/**
 * Exercises the whole passkey admin flow against a real browser, using a CDP
 * virtual authenticator. Auth code that has never completed a ceremony is not
 * tested code, and this one guards the front door.
 *
 *   bun test/admin-passkey.ts
 *
 * Expects doorkey running on ORIGIN with DOORKEY_RP_ID=localhost, and an
 * enrolment token passed as argv[2].
 */
import puppeteer from "puppeteer-core";

const ORIGIN = process.env.TEST_ORIGIN ?? "http://localhost:18080";
const TOKEN = process.argv[2];
if (!TOKEN) throw new Error("usage: bun test/admin-passkey.ts <enrollment-token>");

const pass: string[] = [];
const fail: string[] = [];
const check = (name: string, ok: boolean) => {
  (ok ? pass : fail).push(name);
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}`);
};

const browser = await puppeteer.launch({
  executablePath: "/usr/bin/google-chrome-stable",
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

try {
  const page = await browser.newPage();
  page.on("console", (m) => {
    if (m.type() === "error") console.log(`  [browser] ${m.text()}`);
  });
  page.on("pageerror", (e) => console.log(`  [pageerror] ${e.message}`));
  const cdp = await page.createCDPSession();
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  // --- the admin surface gives nothing away before authentication ----------
  await page.goto(`${ORIGIN}/admin`, { waitUntil: "networkidle0" });
  const gated = await page.evaluate(() => document.body.textContent.includes("Sign in with passkey"));
  check("the unauthenticated shell shows only the passkey gate", gated);

  const codesUnauth = await page.evaluate(async (o) => {
    const r = await fetch(`${o}/admin/api/codes`);
    return r.status;
  }, ORIGIN);
  check("GET /admin/api/codes is 401 without a passkey", codesUnauth === 401);

  // --- enrolment ------------------------------------------------------------
  await page.goto(`${ORIGIN}/admin/enroll/${TOKEN}`, { waitUntil: "networkidle0" });
  await page.waitForSelector("button.primary");
  await page.click("button.primary");
  await page.waitForFunction(() => document.body.textContent.includes("New code"), { timeout: 15000 });
  check("passkey registration reaches the dashboard", true);

  const creds = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  check("a resident credential was created", creds.credentials.length === 1);

  // --- create a code through the UI ----------------------------------------
  await page.type('input[placeholder="Cleaner"]', "Gym Test");
  await page.click("form button.primary");
  await page.waitForSelector(".fresh strong", { timeout: 10000 });
  const shown = await page.$eval(".fresh strong", (el) => el.textContent?.trim() ?? "");
  check("creating a code shows the plaintext once", /^\d{6}$/.test(shown));

  const listed = await page.evaluate(() => document.body.textContent.includes("Gym Test"));
  check("the new code appears in the table", listed);

  // --- sign out, then sign back in with the passkey -------------------------
  await page.evaluate(async (o) => { await fetch(`${o}/admin/api/logout`, { method: "POST" }); }, ORIGIN);
  await page.goto(`${ORIGIN}/admin`, { waitUntil: "networkidle0" });
  const atLogin = await page.evaluate(() => document.body.textContent.includes("Sign in with passkey"));
  check("logging out returns you to the passkey gate", atLogin);

  await page.click("button.primary");
  try {
    await page.waitForFunction(() => document.body.textContent.includes("New code"), { timeout: 15000 });
    check("signing in with the passkey restores the dashboard", true);
  } catch {
    const text = await page.evaluate(() => document.body.textContent.replace(/\n+/g, " | "));
    console.log(`  [page after sign-in] ${text.slice(0, 300)}`);
    check("signing in with the passkey restores the dashboard", false);
  }

  // --- expiry ---------------------------------------------------------------
  const codes = await page.evaluate(async (o) => (await fetch(`${o}/admin/api/codes`)).json(), ORIGIN);
  const target = (codes as { id: number; label: string }[]).find((x) => x.label === "Gym Test");
  const iso = new Date(Date.now() + 86_400_000).toISOString();
  const patched = await page.evaluate(
    async (o, id, until) => {
      const r = await fetch(`${o}/admin/api/codes/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ validUntil: until }),
      });
      return r.status;
    },
    ORIGIN, target!.id, iso,
  );
  check("setting an expiry succeeds", patched === 200);

  const after = await page.evaluate(async (o) => (await fetch(`${o}/admin/api/codes`)).json(), ORIGIN);
  const updated = (after as { id: number; valid_until: string | null }[]).find((x) => x.id === target!.id);
  check("the expiry is persisted", updated?.valid_until !== null);

  // --- regenerating replaces the secret and invalidates the old one ---------
  const regen = await page.evaluate(
    async (o, id) => (await fetch(`${o}/admin/api/codes/${id}/regenerate`, { method: "POST" })).json(),
    ORIGIN, target!.id,
  );
  const fresh = (regen as { code: string }).code;
  check("regenerate issues a new six-digit code", /^\d{6}$/.test(fresh) && fresh !== shown);

  const tryAtDoor = async (code: string) =>
    page.evaluate(async (o, c) => {
      await fetch(`${o}/k/abc123secretpath`);
      const r = await fetch(`${o}/api/unlock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: c }),
      });
      return r.status;
    }, ORIGIN, code);

  check("the replaced code no longer opens the door", (await tryAtDoor(shown)) === 401);
  check("the regenerated code does open the door", (await tryAtDoor(fresh)) === 200);

  // --- the last passkey cannot be removed -----------------------------------
  const cred = await page.evaluate(async (o) => (await fetch(`${o}/admin/api/credentials`)).json(), ORIGIN);
  const delStatus = await page.evaluate(
    async (o, id) => (await fetch(`${o}/admin/api/credentials/${id}`, { method: "DELETE" })).status,
    ORIGIN, (cred as { id: number }[])[0]!.id,
  );
  check("removing the only passkey is refused", delStatus === 409);

  // --- a used enrolment link cannot be replayed -----------------------------
  const replay = await page.evaluate(
    async (o, t) => (await fetch(`${o}/admin/api/enroll/${t}/options`, { method: "POST" })).status,
    ORIGIN, TOKEN,
  );
  check("a spent enrolment link is rejected", replay === 404);
} catch (err) {
  console.log(`  ERROR ${(err as Error).message.split("\n")[0]}`);
  fail.push("threw before completing");
} finally {
  await browser.close();
}

console.log(`\n  ${pass.length} passed, ${fail.length} failed`);
process.exit(fail.length ? 1 : 0);
