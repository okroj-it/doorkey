#!/usr/bin/env bun
/**
 * Command-line management: guest codes, admin passkeys, and tap-gated actions
 * with their users and roles. Run it inside the container (docker exec,
 * podman exec, kubectl exec). Minting admin passkey links is CLI-only, so
 * shell access to the container is the root of trust for /admin.
 */
import { randomBytes } from "node:crypto";
import { config } from "../src/config.ts";
import { generateCode, hashCode } from "../src/codes.ts";
import { hashToken, newToken } from "../src/actions/policy.ts";
import * as db from "../src/db.ts";
import { enrolTag, setTagActiveByUid } from "../src/tags.ts";
import {
  createEnrollment,
  deleteCredential,
  listCredentials,
  migrate,
  sql,
  type ScheduleWindow,
} from "../src/db.ts";

const DOWS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/** "tue 09:00-12:00" or "mon,wed,fri 07:00-09:00; sat 10:00-14:00" */
function parseSchedule(spec: string): ScheduleWindow[] {
  return spec.split(";").map((part) => {
    const m = part.trim().match(/^([a-z,]+)\s+(\d{2}:\d{2})-(\d{2}:\d{2})$/i);
    if (!m) throw new Error(`bad schedule window: "${part.trim()}"`);
    const [, days, from, to] = m as unknown as [string, string, string, string];
    const dow = days.toLowerCase().split(",").map((d) => {
      const i = DOWS.indexOf(d);
      if (i < 0) throw new Error(`unknown day "${d}" (use ${DOWS.join(",")})`);
      return i;
    });
    return { dow, from, to };
  });
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
}

async function add(args: string[]): Promise<void> {
  const label = args[0];
  if (!label || label.startsWith("--")) throw new Error("usage: add <label> [options]");

  const scheduleSpec = flag(args, "schedule");
  const schedule = scheduleSpec ? parseSchedule(scheduleSpec) : null;
  const validFrom = flag(args, "from") ?? null;
  const validUntil = flag(args, "until") ?? null;
  const maxUsesRaw = flag(args, "max-uses");
  const maxUses = maxUsesRaw ? Number(maxUsesRaw) : null;
  const digits = Number(flag(args, "digits") ?? 6);

  const code = generateCode(digits);
  const id = await db.insertCode(label, hashCode(code), schedule, validFrom, validUntil, maxUses);

  console.log(`\n  ${label}  (id ${id})`);
  console.log(`  code: ${code}`);
  console.log(`\n  Shown once. Only the HMAC is stored.\n`);
}

async function list(): Promise<void> {
  const rows = await db.listCodes();
  if (rows.length === 0) return console.log("no codes");
  console.table(
    rows.map((r) => ({
      id: r.id,
      label: r.label,
      state: !r.active ? "revoked" : r.locked_until && new Date(r.locked_until as string) > new Date() ? "locked" : "active",
      uses: `${r.use_count}${r.max_uses ? `/${r.max_uses}` : ""}`,
      until: r.valid_until ? new Date(r.valid_until as string).toISOString().slice(0, 10) : "",
      last_used: r.last_used_at ? new Date(r.last_used_at as string).toISOString().slice(0, 16).replace("T", " ") : "",
      schedule: r.schedule ? JSON.stringify(r.schedule) : "",
    })),
  );
}

async function setActive(id: string | undefined, active: boolean): Promise<void> {
  if (!id) throw new Error("usage: revoke|enable <id>");
  await db.setCodeActive(Number(id), active);
  console.log(`code ${id} ${active ? "enabled" : "revoked"}`);
}

async function log(args: string[]): Promise<void> {
  const n = Number(flag(args, "tail") ?? 40);
  const rows = await db.recentAttempts(n);
  if (rows.length === 0) return console.log("no attempts logged");
  console.table(
    rows.reverse().map((r) => ({
      ts: r.ts.toISOString().slice(0, 19).replace("T", " "),
      result: r.result,
      label: r.label ?? "",
      ip: r.src_ip ?? "",
    })),
  );
}

/**
 * Minting an enrolment link is the only way a passkey is ever added, so
 * shell access to the container is the root of trust for the admin surface.
 */
async function adminEnroll(args: string[]): Promise<void> {
  const label = args[0];
  if (!label || label.startsWith("--")) throw new Error("usage: admin:enroll <label>");
  const minutes = Number(flag(args, "minutes") ?? 15);
  const token = randomBytes(24).toString("base64url");
  await createEnrollment(token, label, new Date(Date.now() + minutes * 60_000));
  console.log(`\n  ${config.admin.origin}/admin/enroll/${token}\n`);
  console.log(`  Valid ${minutes} minutes, single use. Open it and register the passkey.\n`);
}

async function adminList(): Promise<void> {
  const rows = await listCredentials();
  if (rows.length === 0) return console.log("no passkeys enrolled");
  console.table(
    rows.map((r) => ({
      id: r.id,
      label: r.label,
      created: r.created_at.toISOString().slice(0, 16).replace("T", " "),
      last_used: r.last_used_at
        ? r.last_used_at.toISOString().slice(0, 16).replace("T", " ")
        : "never",
    })),
  );
}

async function adminRevoke(id: string | undefined): Promise<void> {
  if (!id) throw new Error("usage: admin:revoke <id>");
  await deleteCredential(Number(id));
  console.log(`passkey ${id} removed`);
}

// --- tap-gated actions -----------------------------------------------------
//
// Users and their passkeys are separate from admin passkeys; who may run an
// action is decided by roles shared between the user and the action.

function arg(args: string[], i: number, usage: string): string {
  const v = args[i];
  if (!v || v.startsWith("--")) throw new Error(`usage: ${usage}`);
  return v;
}

async function needUser(name: string): Promise<db.ActionUser> {
  const u = await db.findActionUserByName(name);
  if (!u) throw new Error(`no user "${name}" (user:add it first)`);
  return u;
}

async function needAction(slug: string): Promise<db.ActionRow> {
  const a = await db.findActionBySlug(slug);
  if (!a) throw new Error(`no action "${slug}" (action:add it first)`);
  return a;
}

async function needRole(name: string): Promise<number> {
  const r = await db.findRole(name);
  if (r === null) throw new Error(`no role "${name}"`);
  return r;
}

const ts = (d: unknown) =>
  d ? new Date(d as string).toISOString().slice(0, 16).replace("T", " ") : "";

async function actionsCli(cmd: string, args: string[]): Promise<boolean> {
  switch (cmd) {
    case "users": {
      const rows = await db.listActionUsers();
      if (rows.length === 0) console.log("no action users");
      else console.table(rows.map((r) => ({ ...r, roles: (r.roles as string[]).join(","), last_used_at: ts(r.last_used_at) })));
      return true;
    }
    case "user:add": {
      const name = arg(args, 0, "user:add <name>");
      const id = await db.insertActionUser(name);
      console.log(`user ${name} added (id ${id}). Next: user:grant ${name} <role>, user:enroll ${name} <device>`);
      return true;
    }
    case "user:enroll": {
      const usage = "user:enroll <name> <device> [--minutes 15]";
      const user = await needUser(arg(args, 0, usage));
      const device = arg(args, 1, usage);
      const minutes = Number(flag(args, "minutes") ?? 15);
      const token = randomBytes(24).toString("base64url");
      await db.createActionEnrollment(token, user.id, device, new Date(Date.now() + minutes * 60_000));
      console.log(`\n  ${config.admin.origin}/a/enroll/${token}\n`);
      console.log(`  Valid ${minutes} minutes, single use. Open it on ${device} and register the passkey.\n`);
      return true;
    }
    case "user:disable":
    case "user:enable": {
      const user = await needUser(arg(args, 0, `${cmd} <name>`));
      await db.setActionUserActive(user.id, cmd === "user:enable");
      console.log(`user ${user.name} ${cmd === "user:enable" ? "enabled" : "disabled"}`);
      return true;
    }
    case "user:reset": {
      const user = await needUser(arg(args, 0, "user:reset <name>"));
      const n = await db.deleteActionCredentials(user.id);
      console.log(`removed ${n} passkey(s) of ${user.name}`);
      return true;
    }
    case "user:grant":
    case "user:ungrant": {
      const usage = `${cmd} <name> <role>`;
      const user = await needUser(arg(args, 0, usage));
      const roleName = arg(args, 1, usage);
      if (cmd === "user:grant") {
        await db.grantUserRole(user.id, await db.ensureRole(roleName));
        console.log(`${user.name} now has role ${roleName}`);
      } else {
        await db.revokeUserRole(user.id, await needRole(roleName));
        console.log(`${user.name} no longer has role ${roleName}`);
      }
      return true;
    }
    case "actions": {
      const rows = await db.listActions();
      if (rows.length === 0) console.log("no actions");
      else
        console.table(
          rows.map((r) => ({
            slug: r.slug,
            label: r.label,
            script: r.script_entity,
            dna: r.require_sun ? "required" : "",
            home: r.home_only ? "only" : "",
            token: r.has_token ? "yes" : "",
            state: r.active ? "active" : "disabled",
            roles: (r.roles as string[]).join(","),
            tags: (r.tags as string[]).join(","),
            last_run: ts(r.last_run_at),
          })),
        );
      return true;
    }
    case "action:add": {
      const usage = "action:add <slug> <script.entity> [--label TEXT] [--sun] [--home-only]";
      const slug = arg(args, 0, usage);
      const script = arg(args, 1, usage);
      if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(slug)) throw new Error("slug: lowercase letters, digits and -");
      if (!/^script\.[a-z0-9_]+$/.test(script)) throw new Error("the entity must be a script.*");
      const label = flag(args, "label") ?? slug;
      const id = await db.insertAction(slug, label, script, args.includes("--sun"), args.includes("--home-only"));
      console.log(`action ${slug} added (id ${id}). Next: action:allow ${slug} <role>, then action:token or action:link-tag`);
      return true;
    }
    case "action:token": {
      // Rotates: the old URL stops working, so rewrite the tag.
      const action = await needAction(arg(args, 0, "action:token <slug>"));
      if (action.require_sun) throw new Error(`${action.slug} requires a DNA tag; plain tokens would be refused`);
      const token = newToken();
      await db.setActionToken(action.id, hashToken(token, config.pepper));
      console.log(`\n  ${config.admin.origin}/a/${action.slug}?t=${token}\n`);
      console.log(`  Write this URL to the NFC tag. Shown once; any previous URL is now dead.\n`);
      return true;
    }
    case "action:untoken": {
      const action = await needAction(arg(args, 0, "action:untoken <slug>"));
      await db.setActionToken(action.id, null);
      console.log(`plain-tag URL for ${action.slug} removed`);
      return true;
    }
    case "action:allow":
    case "action:deny": {
      const usage = `${cmd} <slug> <role>`;
      const action = await needAction(arg(args, 0, usage));
      const roleName = arg(args, 1, usage);
      if (cmd === "action:allow") {
        await db.allowActionRole(action.id, await db.ensureRole(roleName));
        console.log(`role ${roleName} may run ${action.slug}`);
      } else {
        await db.disallowActionRole(action.id, await needRole(roleName));
        console.log(`role ${roleName} may no longer run ${action.slug}`);
      }
      return true;
    }
    case "action:link-tag": {
      const usage = "action:link-tag <slug> <tag uid hex>";
      const action = await needAction(arg(args, 0, usage));
      const uid = arg(args, 1, usage).toLowerCase();
      if (!/^[0-9a-f]{14}$/.test(uid)) throw new Error("uid must be 7 bytes of hex");
      if (!(await db.linkTagToAction(uid, action.id))) throw new Error(`no tag with uid ${uid}`);
      console.log(`tag ${uid} now opens ${action.slug} (and no longer the door)`);
      return true;
    }
    case "action:unlink-tag": {
      const uid = arg(args, 0, "action:unlink-tag <tag uid hex>").toLowerCase();
      if (!(await db.linkTagToAction(uid, null))) throw new Error(`no tag with uid ${uid}`);
      console.log(`tag ${uid} opens the door again`);
      return true;
    }
    case "action:disable":
    case "action:enable": {
      const action = await needAction(arg(args, 0, `${cmd} <slug>`));
      await db.setActionActive(action.id, cmd === "action:enable");
      console.log(`action ${action.slug} ${cmd === "action:enable" ? "enabled" : "disabled"}`);
      return true;
    }
    case "action:remove": {
      const action = await needAction(arg(args, 0, "action:remove <slug>"));
      try {
        await db.deleteAction(action.id);
      } catch {
        throw new Error(`a tag is still linked to ${action.slug}; action:unlink-tag it first`);
      }
      console.log(`action ${action.slug} removed`);
      return true;
    }
    case "action:log": {
      const rows = await db.recentActionEvents(Number(flag(args, "tail") ?? 40));
      if (rows.length === 0) console.log("no action events");
      else console.table(rows.reverse().map((r) => ({ ...r, ts: ts(r.ts) })));
      return true;
    }
  }
  return false;
}

// --- DNA tags ----------------------------------------------------------------

async function tagsList(): Promise<void> {
  const rows = await db.listTags();
  if (rows.length === 0) return console.log("no tags");
  console.table(
    rows.map((t: Record<string, unknown>) => ({
      uid: t.uid,
      label: t.label,
      state: t.active ? "active" : "disabled",
      opens: t.action ?? "the door",
      counter: t.last_counter,
      last_used: ts(t.last_used_at),
    })),
  );
}

async function tagAdd(args: string[]): Promise<void> {
  const code = args[0];
  if (!code || code.startsWith("--")) throw new Error("usage: tag:add <code> [--label TEXT]");
  const t = await enrolTag(code, flag(args, "label"));
  console.log(`tag ${t.uid} "${t.label}" ${t.replaced ? "re-enrolled (key replaced)" : "enrolled"} - it opens the door until linked to an action`);
}

async function tagActive(cmd: string, uid: string | undefined): Promise<void> {
  if (!uid) throw new Error(`usage: ${cmd} <uid>`);
  const active = cmd === "tag:enable";
  if (!(await setTagActiveByUid(uid.toLowerCase(), active))) throw new Error(`no tag with uid ${uid}`);
  console.log(`tag ${uid} ${active ? "enabled" : "disabled"}`);
}

const [cmd, ...rest] = process.argv.slice(2);
try {
  await migrate();
  switch (cmd) {
    case "add": await add(rest); break;
    case "list": await list(); break;
    case "revoke": await setActive(rest[0], false); break;
    case "enable": await setActive(rest[0], true); break;
    case "log": await log(rest); break;
    case "admin:enroll": await adminEnroll(rest); break;
    case "admin:list": await adminList(); break;
    case "admin:revoke": await adminRevoke(rest[0]); break;
    case "tags": await tagsList(); break;
    case "tag:add": await tagAdd(rest); break;
    case "tag:enable":
    case "tag:disable": await tagActive(cmd, rest[0]); break;
    case "db:checkpoint":
      console.log((await db.checkpoint()) ? "checkpointed" : "nothing to do (not SQLite)");
      break;
    default:
      if (cmd && (await actionsCli(cmd, rest))) break;
      console.log(`usage: bun cli/doorkey.ts <command>

  add <label> [--schedule "tue 09:00-12:00"] [--from ISO] [--until ISO]
              [--max-uses N] [--digits 6]
  list
  revoke <id>
  enable <id>
  log [--tail 40]

  admin:enroll <label> [--minutes 15]   mint a single-use passkey enrolment link
  admin:list                            enrolled passkeys
  admin:revoke <id>                     remove a passkey

  tags                                  provisioned DNA tags
  tag:add <code> [--label TEXT]         enrol a tag from the code tagtui / provision.py print
  tag:disable|tag:enable <uid>
  db:checkpoint                         SQLite: fold the WAL into the file (before a backup)

  tap-gated actions (users and passkeys are separate from admin):
  users                                 action users, roles, passkeys
  user:add <name>
  user:enroll <name> <device> [--minutes 15]   single-use passkey enrolment link
  user:grant|user:ungrant <name> <role>
  user:disable|user:enable <name>
  user:reset <name>                     remove all of a user's passkeys
  actions                               actions, roles, tags
  action:add <slug> <script.x> [--label TEXT] [--sun] [--home-only]
  action:allow|action:deny <slug> <role>
  action:token <slug>                   (re)issue the plain-tag URL, shown once
  action:untoken <slug>                 stop accepting the plain-tag URL
  action:link-tag <slug> <uid>          a DNA tag opens this action, not the door
  action:unlink-tag <uid>               back to opening the door
  action:disable|action:enable <slug>
  action:remove <slug>
  action:log [--tail 40]
`);
      process.exit(cmd ? 1 : 0);
  }
} catch (err) {
  console.error(`error: ${(err as Error).message}`);
  process.exit(1);
} finally {
  await sql.end();
}
