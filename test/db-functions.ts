/**
 * The data-layer paths the browser suites never reach, run against a real
 * database: value types (dates, schedules, booleans, JSON, bytes), the RBAC
 * check, the list queries, and how constraint errors are classified.
 *
 *   DATABASE_URL=... bun test/db-functions.ts      # empty database
 *
 * Run by scripts/e2e.sh for Postgres and SQLite.
 */
import { createCipheriv, randomBytes } from "node:crypto";
import { unwrapKey, wrapKey } from "../src/auth/kek.ts";
import { hashCode } from "../src/codes.ts";
import { constraintKind } from "../src/db-values.ts";
import * as db from "../src/db.ts";
import { encodeTagCode } from "../src/tag-code.ts";
import { enrolTag, setTagActiveByUid } from "../src/tags.ts";

const fail: string[] = [];
const check = (name: string, ok: boolean) => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) fail.push(name);
};
const near = (a: unknown, b: Date) =>
  a instanceof Date && Math.abs(a.getTime() - b.getTime()) < 1000;

await db.migrate();

// --- guest codes: dates, schedules, booleans --------------------------------

const schedule = [{ dow: [1, 3], from: "07:00", to: "09:00" }];
const until = new Date(Date.now() + 86_400_000);
const code = await db.insertCode(
  "db-functions",
  hashCode("424242"),
  schedule,
  null,
  until.toISOString(),
  3,
);
const row = await db.findByHash(hashCode("424242"));
check(
  "schedule round-trips as an object",
  Bun.deepEquals(row?.schedule, schedule),
);
check("valid_until comes back as a Date", near(row?.valid_until, until));
check("active comes back as a boolean", row?.active === true);

const lockAt = new Date(Date.now() + 60_000);
await db.lockCode(code, lockAt);
check(
  "lockCode stores the Date",
  near((await db.findByHash(hashCode("424242")))?.locked_until, lockAt),
);

await db.logAttempt("bad_code", null, "192.0.2.1", "test");
await db.logAttempt("bad_code", null, "192.0.2.1", "test");
const failures = await db.failuresSince(new Date(Date.now() - 60_000));
check(
  "failuresSince counts as a number",
  typeof failures === "number" && failures >= 2,
);

// --- passkeys and enrolment -------------------------------------------------

await db.saveCredential(
  "db-functions",
  `cred-${Date.now()}`,
  new Uint8Array([1, 2, 3]),
  0,
  ["internal", "hybrid"],
);
const cred = (await db.listCredentials()).find(
  (c) => c.label === "db-functions",
);
const transports =
  typeof cred?.transports === "string"
    ? JSON.parse(cred.transports)
    : cred?.transports;
check(
  "credential transports round-trip as an array",
  Bun.deepEquals(transports, ["internal", "hybrid"]),
);
check("public key comes back as a Buffer", Buffer.isBuffer(cred?.public_key));

await db.createEnrollment(
  "tok-db-functions",
  "db-functions",
  new Date(Date.now() + 900_000),
);
const enrolment = await db.findEnrollment("tok-db-functions");
check(
  "enrolment expiry comes back as a Date",
  enrolment?.expires_at instanceof Date && enrolment.expires_at > new Date(),
);

// --- actions, roles, tags ---------------------------------------------------

const user = await db.insertActionUser("db-functions-user");
const role = await db.ensureRole("db-functions-role");
const action = await db.insertAction(
  "db-functions-act",
  "x",
  "script.x",
  false,
  false,
);
await db.grantUserRole(user, role);
await db.allowActionRole(action, role);
check(
  "userMayRun is true for a shared role",
  (await db.userMayRun(user, action)) === true,
);
const roles = (await db.listActions()).find(
  (a) => a.slug === "db-functions-act",
)?.roles;
check(
  "listActions roles is an array",
  Array.isArray(roles) && roles.includes("db-functions-role"),
);

try {
  await db.insertActionUser("db-functions-user");
  check("a duplicate user is refused", false);
} catch (e) {
  check(
    "a duplicate user classifies as unique",
    constraintKind(e) === "unique",
  );
}

await db.insertTag(
  new Uint8Array([0x04, 1, 2, 3, 4, 5, 6]),
  "db-functions-tag",
  new Uint8Array([9]),
);
await db.linkTagToAction("04010203040506", action);
const tag = (await db.listTags()).find(
  (t: { label: string }) => t.label === "db-functions-tag",
);
check(
  "listTags gives the UID as hex with its action",
  tag?.uid === "04010203040506" && tag?.action === "db-functions-act",
);
const linked = (await db.listActions()).find(
  (a) => a.slug === "db-functions-act",
);
check(
  "listActions lists the linked tag",
  Bun.deepEquals(linked?.tags, ["db-functions-tag"]),
);
const users = await db.listActionUsers();
check(
  "listActionUsers gives roles and a passkey count",
  Bun.deepEquals(users.find((u) => u.name === "db-functions-user")?.roles, [
    "db-functions-role",
  ]) && typeof users[0]?.passkeys === "number",
);

// The RESTRICT that keeps a deleted action's tag from opening the door.
try {
  await db.deleteAction(action);
  check("deleting an action with a linked tag is refused", false);
} catch (e) {
  check(
    "RESTRICT on a linked tag classifies as foreign_key",
    constraintKind(e) === "foreign_key",
  );
}

// --- tag enrolment from a tag code -----------------------------------------

const k3 = new Uint8Array(16).fill(7);
const tagUid = new Uint8Array([0x04, 9, 8, 7, 6, 5, 4]);
const porchCode = encodeTagCode({ uid: tagUid, wrapped: wrapKey(k3), label: "Porch" });
const enrolled = await enrolTag(porchCode);
check("a tag code enrols the tag", !enrolled.replaced && enrolled.uid === "04090807060504" && enrolled.label === "Porch");
const porch = await db.findTagByUid(tagUid);
check("the enrolled key unwraps to the tag's K3", porch !== null && Buffer.from(unwrapKey(porch.mac_key_enc)).equals(Buffer.from(k3)));
const again = await enrolTag(porchCode, "Back porch");
check("re-enrolling replaces instead of duplicating", again.replaced && again.label === "Back porch" && again.id === enrolled.id);

// Wrapped with some other KEK: must be refused, not saved to fail every tap.
const otherKek = randomBytes(32);
const nonce = randomBytes(12);
const cipher = createCipheriv("aes-256-gcm", otherKek, nonce);
const foreign = Buffer.concat([nonce, cipher.update(k3), cipher.final(), cipher.getAuthTag()]);
try {
  await enrolTag(encodeTagCode({ uid: new Uint8Array([0x04, 1, 1, 1, 1, 1, 1]), wrapped: foreign, label: "x" }));
  check("a code wrapped with another KEK is refused", false);
} catch (e) {
  check("a code wrapped with another KEK is refused", String(e).includes("different KEK"));
}

check("disabling by UID works", (await setTagActiveByUid("04090807060504", false)) && (await db.findTagByUid(tagUid))?.active === false);

console.log(fail.length ? `\n  ${fail.length} failed` : "\n  all passed");
await db.sql.end();
process.exit(fail.length ? 1 : 0);
