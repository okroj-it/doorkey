import { SQL } from "bun";
import { config } from "./config.ts";
import { type Dialect, normaliseRow, param } from "./db-values.ts";

export const sql = new SQL({ url: config.databaseUrl, max: 5 });
const dialect: Dialect = sql.options.adapter === "sqlite" ? "sqlite" : "postgres";

/**
 * `sql` with the values the drivers disagree on handled explicitly: see
 * db-values.ts. Same tagged-template shape, so a query only swaps the tag,
 * and the same loose `any[]` default for untyped queries.
 */
export async function q<T = any[]>(
  strings: TemplateStringsArray,
  ...values: unknown[]
): Promise<T> {
  const rows = (await sql(strings, ...values.map((v) => param(v, dialect)))) as Record<string, unknown>[];
  return rows.map(normaliseRow) as T;
}

export type AttemptResult =
  | "granted"
  | "bad_code"
  | "inactive"
  | "expired"
  | "out_of_schedule"
  | "exhausted"
  | "code_locked"
  | "system_locked";

export interface CodeRow {
  id: number;
  label: string;
  active: boolean;
  valid_from: Date | null;
  valid_until: Date | null;
  schedule: ScheduleWindow[] | string | null;
  max_uses: number | null;
  use_count: number;
  failed_streak: number;
  locked_until: Date | null;
  created_at: Date;
  last_used_at: Date | null;
}

/** dow follows JS getDay(): 0 = Sunday. */
export interface ScheduleWindow {
  dow: number[];
  from: string;
  to: string;
}

const MIGRATIONS = ["001_init.sql", "002_admin.sql", "003_tags.sql", "004_actions.sql"];

export async function migrate(): Promise<void> {
  for (const name of MIGRATIONS) {
    const ddl = await Bun.file(new URL(`../db/${name}`, import.meta.url)).text();
    await sql.unsafe(ddl);
  }
}

export async function findByHash(hash: Buffer): Promise<CodeRow | null> {
  const rows = await q<CodeRow[]>`
    SELECT id, label, active, valid_from, valid_until, schedule, max_uses,
           use_count, failed_streak, locked_until, created_at, last_used_at
      FROM codes
     WHERE code_hash = ${hash}
     LIMIT 1`;
  return rows[0] ?? null;
}

export async function logAttempt(
  result: AttemptResult,
  codeId: number | null,
  srcIp: string | null,
  userAgent: string | null,
): Promise<void> {
  await q`
    INSERT INTO attempts (code_id, result, src_ip, user_agent)
    VALUES (${codeId}, ${result}, ${srcIp}, ${userAgent})`;
}

export async function getState(key: string): Promise<string | null> {
  const rows = await q<{ v: string }[]>`
    SELECT v FROM system_state WHERE k = ${key}`;
  return rows[0]?.v ?? null;
}

export async function setState(key: string, value: string): Promise<void> {
  await q`
    INSERT INTO system_state (k, v) VALUES (${key}, ${value})
    ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`;
}

export async function recordGrant(codeId: number): Promise<void> {
  await q`
    UPDATE codes
       SET use_count     = use_count + 1,
           last_used_at  = ${new Date()},
           failed_streak = 0,
           locked_until  = NULL
     WHERE id = ${codeId}`;
}

/** Returns the code's failure streak after incrementing it. */
export async function recordCodeFailure(codeId: number): Promise<number> {
  const rows = await q<{ failed_streak: number }[]>`
    UPDATE codes
       SET failed_streak = failed_streak + 1
     WHERE id = ${codeId}
     RETURNING failed_streak`;
  return rows[0]?.failed_streak ?? 0;
}

export async function lockCode(codeId: number, until: Date): Promise<void> {
  await q`UPDATE codes SET locked_until = ${until} WHERE id = ${codeId}`;
}

export async function failuresSince(since: Date): Promise<number> {
  const rows = await q<{ n: number }[]>`
    SELECT count(*) AS n
      FROM attempts
     WHERE ts >= ${since}
       AND result NOT IN ('granted', 'system_locked')`;
  return rows[0]?.n ?? 0;
}

export async function lastGrant(): Promise<{ label: string; ts: Date } | null> {
  const rows = await q<{ label: string; ts: Date }[]>`
    SELECT c.label, a.ts
      FROM attempts a
      JOIN codes c ON c.id = a.code_id
     WHERE a.result = 'granted'
     ORDER BY a.ts DESC
     LIMIT 1`;
  return rows[0] ?? null;
}


// --- admin -----------------------------------------------------------------

export interface AdminCredential {
  id: number;
  label: string;
  credential_id: string;
  public_key: Uint8Array;
  counter: number;
  transports: string[] | string | null;
  created_at: Date;
  last_used_at: Date | null;
}

export async function listCredentials(): Promise<AdminCredential[]> {
  return q<AdminCredential[]>`
    SELECT id, label, credential_id, public_key, counter, transports,
           created_at, last_used_at
      FROM admin_credentials ORDER BY id`;
}

export async function findCredential(credentialId: string): Promise<AdminCredential | null> {
  const rows = await q<AdminCredential[]>`
    SELECT id, label, credential_id, public_key, counter, transports,
           created_at, last_used_at
      FROM admin_credentials WHERE credential_id = ${credentialId} LIMIT 1`;
  return rows[0] ?? null;
}

export async function saveCredential(
  label: string,
  credentialId: string,
  publicKey: Uint8Array,
  counter: number,
  transports: string[] | null,
): Promise<void> {
  await q`
    INSERT INTO admin_credentials (label, credential_id, public_key, counter, transports)
    VALUES (${label}, ${credentialId}, ${Buffer.from(publicKey)}, ${counter},
            ${transports})`;
}

export async function touchCredential(id: number, counter: number): Promise<void> {
  await q`
    UPDATE admin_credentials SET counter = ${counter}, last_used_at = ${new Date()}
     WHERE id = ${id}`;
}

export async function deleteCredential(id: number): Promise<void> {
  await q`DELETE FROM admin_credentials WHERE id = ${id}`;
}

export interface Enrollment {
  token: string;
  label: string;
  expires_at: Date;
  used_at: Date | null;
}

export async function createEnrollment(
  token: string,
  label: string,
  expiresAt: Date,
): Promise<void> {
  await q`
    INSERT INTO admin_enrollments (token, label, expires_at)
    VALUES (${token}, ${label}, ${expiresAt})`;
}

export async function findEnrollment(token: string): Promise<Enrollment | null> {
  const rows = await q<Enrollment[]>`
    SELECT token, label, expires_at, used_at
      FROM admin_enrollments WHERE token = ${token} LIMIT 1`;
  return rows[0] ?? null;
}

export async function consumeEnrollment(token: string): Promise<void> {
  await q`UPDATE admin_enrollments SET used_at = ${new Date()} WHERE token = ${token}`;
}

export async function logAdminEvent(
  event: string,
  detail: string | null,
  srcIp: string | null,
): Promise<void> {
  await q`
    INSERT INTO admin_events (event, detail, src_ip)
    VALUES (${event}, ${detail}, ${srcIp})`;
}

export async function recentAdminEvents(limit: number) {
  return q<{ ts: Date; event: string; detail: string | null; src_ip: string | null }[]>`
    SELECT ts, event, detail, src_ip FROM admin_events ORDER BY ts DESC LIMIT ${limit}`;
}

// --- code management (used by both the CLI and the admin UI) ---------------

export async function listCodes() {
  return q<Record<string, unknown>[]>`
    SELECT id, label, active, use_count, max_uses, valid_from, valid_until,
           schedule, locked_until, created_at, last_used_at
      FROM codes ORDER BY id`;
}

export async function insertCode(
  label: string,
  hash: Buffer,
  schedule: unknown | null,
  validFrom: string | null,
  validUntil: string | null,
  maxUses: number | null,
): Promise<number> {
  const rows = await q<{ id: number }[]>`
    INSERT INTO codes (label, code_hash, schedule, valid_from, valid_until, max_uses)
    VALUES (${label}, ${hash}, ${schedule}, ${validFrom},
            ${validUntil}, ${maxUses})
    RETURNING id`;
  return rows[0]!.id;
}

export async function setCodeActive(id: number, active: boolean): Promise<void> {
  await q`
    UPDATE codes SET active = ${active}, locked_until = NULL, failed_streak = 0
     WHERE id = ${id}`;
}

export async function deleteCode(id: number): Promise<void> {
  await q`DELETE FROM codes WHERE id = ${id}`;
}

/**
 * Codes are stored as an HMAC and cannot be read back — so a forgotten code is
 * replaced, never recovered. Keeps the label, schedule and expiry; resets the
 * use count, since this is a new secret.
 */
export async function regenerateCode(id: number, hash: Buffer): Promise<string | null> {
  const rows = await q<{ label: string }[]>`
    UPDATE codes
       SET code_hash = ${hash}, use_count = 0, failed_streak = 0,
           locked_until = NULL, active = TRUE
     WHERE id = ${id}
     RETURNING label`;
  return rows[0]?.label ?? null;
}

export async function setCodeExpiry(id: number, validUntil: string | null): Promise<void> {
  await q`UPDATE codes SET valid_until = ${validUntil} WHERE id = ${id}`;
}

export async function recentAttempts(limit: number) {
  return q<{ ts: Date; result: string; label: string | null; src_ip: string | null }[]>`
    SELECT a.ts, a.result, c.label, a.src_ip
      FROM attempts a LEFT JOIN codes c ON c.id = a.code_id
     ORDER BY a.ts DESC LIMIT ${limit}`;
}

export interface TagRow {
  id: number;
  uid: Buffer;
  label: string;
  active: boolean;
  mac_key_enc: Buffer;
  last_counter: number;
  /** Null for the door; otherwise the one action this tag opens. */
  action_id: number | null;
}

export async function findTagByUid(uid: Uint8Array): Promise<TagRow | null> {
  const rows = await q`
    select id, uid, label, active, mac_key_enc, last_counter, action_id
      from tags where uid = ${Buffer.from(uid)} limit 1`;
  return rows[0] ?? null;
}

/**
 * Advance the replay counter, but only forwards.
 *
 * The `last_counter < ${counter}` guard is what actually enforces replay
 * protection: two taps racing with the same captured URL cannot both win,
 * because the second update matches no row. Returns false if it lost.
 */
export async function advanceTagCounter(id: number, counter: number): Promise<boolean> {
  const rows = await q`
    update tags set last_counter = ${counter}, last_used_at = ${new Date()}
     where id = ${id} and last_counter < ${counter}
     returning id`;
  return rows.length > 0;
}

export async function listTags() {
  const rows = await q`
    select t.id, t.uid, t.label, t.active, t.last_counter,
           t.action_id, a.slug as action, t.created_at, t.last_used_at
      from tags t left join actions a on a.id = t.action_id
     order by t.created_at`;
  return rows.map((r: { uid: Buffer }) => ({ ...r, uid: r.uid.toString("hex") }));
}

export async function insertTag(
  uid: Uint8Array,
  label: string,
  macKeyEnc: Uint8Array,
): Promise<number> {
  const rows = await q`
    insert into tags (uid, label, mac_key_enc)
    values (${Buffer.from(uid)}, ${label}, ${Buffer.from(macKeyEnc)})
    on conflict (uid) do update
      set label = excluded.label,
          mac_key_enc = excluded.mac_key_enc
    returning id`;
  return rows[0].id;
}

export async function setTagActive(id: number, active: boolean): Promise<void> {
  await q`update tags set active = ${active} where id = ${id}`;
}

// --- actions ---------------------------------------------------------------

export interface ActionRow {
  id: number;
  slug: string;
  label: string;
  script_entity: string;
  require_sun: boolean;
  home_only: boolean;
  token_hash: Buffer | null;
  active: boolean;
}

export async function findActionBySlug(slug: string): Promise<ActionRow | null> {
  const rows = await q<ActionRow[]>`
    select id, slug, label, script_entity, require_sun, home_only, token_hash, active
      from actions where slug = ${slug} limit 1`;
  return rows[0] ?? null;
}

export async function findActionById(id: number): Promise<ActionRow | null> {
  const rows = await q<ActionRow[]>`
    select id, slug, label, script_entity, require_sun, home_only, token_hash, active
      from actions where id = ${id} limit 1`;
  return rows[0] ?? null;
}

export async function insertAction(
  slug: string,
  label: string,
  scriptEntity: string,
  requireSun: boolean,
  homeOnly: boolean,
): Promise<number> {
  const rows = await q<{ id: number }[]>`
    insert into actions (slug, label, script_entity, require_sun, home_only)
    values (${slug}, ${label}, ${scriptEntity}, ${requireSun}, ${homeOnly})
    returning id`;
  return rows[0]!.id;
}

export async function setActionToken(id: number, tokenHash: Buffer | null): Promise<void> {
  await q`update actions set token_hash = ${tokenHash} where id = ${id}`;
}

export async function setActionActive(id: number, active: boolean): Promise<void> {
  await q`update actions set active = ${active} where id = ${id}`;
}

export async function markActionRun(id: number): Promise<void> {
  await q`update actions set last_run_at = ${new Date()} where id = ${id}`;
}

/** Fails (foreign key) while a tag is still linked to it - unlink it first. */
export async function deleteAction(id: number): Promise<void> {
  await q`delete from actions where id = ${id}`;
}

export async function linkTagToAction(uidHex: string, actionId: number | null): Promise<boolean> {
  const rows = await q`
    update tags set action_id = ${actionId}
     where uid = ${Buffer.from(uidHex, "hex")}
     returning id`;
  return rows.length > 0;
}

/** Group (owner id, name) pairs into sorted name lists per owner. */
function namesBy(pairs: { owner: number; name: string }[]): Map<number, string[]> {
  const out = new Map<number, string[]>();
  for (const { owner, name } of pairs) out.set(owner, [...(out.get(owner) ?? []), name]);
  for (const names of out.values()) names.sort();
  return out;
}

export async function listActions() {
  const [actions, roles, tags] = await Promise.all([
    q<Record<string, unknown>[]>`
      select id, slug, label, script_entity, require_sun, home_only,
             token_hash is not null as has_token, active, last_run_at
        from actions order by slug`,
    q<{ owner: number; name: string }[]>`
      select ar.action_id as owner, r.name
        from action_roles ar join roles r on r.id = ar.role_id`,
    q<{ owner: number; name: string }[]>`
      select action_id as owner, label as name from tags where action_id is not null`,
  ]);
  const rolesOf = namesBy(roles);
  const tagsOf = namesBy(tags);
  return actions.map((a): Record<string, unknown> => ({
    ...a,
    roles: rolesOf.get(a.id as number) ?? [],
    tags: tagsOf.get(a.id as number) ?? [],
  }));
}

// --- action users, roles and passkeys ---------------------------------------

export interface ActionUser {
  id: number;
  name: string;
  active: boolean;
}

export async function findActionUserByName(name: string): Promise<ActionUser | null> {
  const rows = await q<ActionUser[]>`
    select id, name, active from action_users where name = ${name} limit 1`;
  return rows[0] ?? null;
}

export async function findActionUser(id: number): Promise<ActionUser | null> {
  const rows = await q<ActionUser[]>`
    select id, name, active from action_users where id = ${id} limit 1`;
  return rows[0] ?? null;
}

export async function insertActionUser(name: string): Promise<number> {
  const rows = await q<{ id: number }[]>`
    insert into action_users (name) values (${name}) returning id`;
  return rows[0]!.id;
}

export async function setActionUserActive(id: number, active: boolean): Promise<void> {
  await q`update action_users set active = ${active} where id = ${id}`;
}

export async function listActionUsers() {
  const [users, roles] = await Promise.all([
    q<Record<string, unknown>[]>`
      select u.id, u.name, u.active,
             (select count(*) from action_credentials c where c.user_id = u.id) as passkeys,
             (select max(c.last_used_at) from action_credentials c where c.user_id = u.id) as last_used_at
        from action_users u order by u.name`,
    q<{ owner: number; name: string }[]>`
      select ur.user_id as owner, r.name
        from user_roles ur join roles r on r.id = ur.role_id`,
  ]);
  const rolesOf = namesBy(roles);
  return users.map((u): Record<string, unknown> => ({ ...u, roles: rolesOf.get(u.id as number) ?? [] }));
}

export async function ensureRole(name: string): Promise<number> {
  const rows = await q<{ id: number }[]>`
    insert into roles (name) values (${name})
    on conflict (name) do update set name = excluded.name
    returning id`;
  return rows[0]!.id;
}

export async function findRole(name: string): Promise<number | null> {
  const rows = await q<{ id: number }[]>`select id from roles where name = ${name}`;
  return rows[0]?.id ?? null;
}

export async function grantUserRole(userId: number, roleId: number): Promise<void> {
  await q`
    insert into user_roles (user_id, role_id) values (${userId}, ${roleId})
    on conflict do nothing`;
}

export async function revokeUserRole(userId: number, roleId: number): Promise<void> {
  await q`delete from user_roles where user_id = ${userId} and role_id = ${roleId}`;
}

export async function allowActionRole(actionId: number, roleId: number): Promise<void> {
  await q`
    insert into action_roles (action_id, role_id) values (${actionId}, ${roleId})
    on conflict do nothing`;
}

export async function disallowActionRole(actionId: number, roleId: number): Promise<void> {
  await q`delete from action_roles where action_id = ${actionId} and role_id = ${roleId}`;
}

/** The RBAC decision: the user shares at least one role with the action. */
export async function userMayRun(userId: number, actionId: number): Promise<boolean> {
  const rows = await q<{ ok: boolean }[]>`
    select exists (
      select 1
        from action_roles ar
        join user_roles ur on ur.role_id = ar.role_id
       where ar.action_id = ${actionId} and ur.user_id = ${userId}
    ) as ok`;
  return rows[0]?.ok === true;
}

export interface ActionCredential {
  id: number;
  user_id: number;
  label: string;
  credential_id: string;
  public_key: Uint8Array;
  counter: number;
  transports: string[] | string | null;
}

export async function findActionCredential(credentialId: string): Promise<ActionCredential | null> {
  const rows = await q<ActionCredential[]>`
    select id, user_id, label, credential_id, public_key, counter, transports
      from action_credentials where credential_id = ${credentialId} limit 1`;
  return rows[0] ?? null;
}

export async function listUserCredentialIds(userId: number): Promise<string[]> {
  const rows = await q<{ credential_id: string }[]>`
    select credential_id from action_credentials where user_id = ${userId}`;
  return rows.map((r) => r.credential_id);
}

/**
 * Passkeys of active users allowed to run this action. Offered as
 * allowCredentials so the phone only proposes passkeys that can succeed - in
 * particular, never the admin passkey on the same RP id.
 */
export async function eligibleCredentials(actionId: number) {
  return q<{ credential_id: string; transports: string[] | string | null }[]>`
    select distinct c.credential_id, c.transports
      from action_credentials c
      join action_users u on u.id = c.user_id and u.active
      join user_roles ur on ur.user_id = u.id
      join action_roles ar on ar.role_id = ur.role_id
     where ar.action_id = ${actionId}`;
}

export async function saveActionCredential(
  userId: number,
  label: string,
  credentialId: string,
  publicKey: Uint8Array,
  counter: number,
  transports: string[] | null,
): Promise<void> {
  await q`
    insert into action_credentials (user_id, label, credential_id, public_key, counter, transports)
    values (${userId}, ${label}, ${credentialId}, ${Buffer.from(publicKey)}, ${counter},
            ${transports})`;
}

export async function touchActionCredential(id: number, counter: number): Promise<void> {
  await q`
    update action_credentials set counter = ${counter}, last_used_at = ${new Date()}
     where id = ${id}`;
}

export async function deleteActionCredentials(userId: number): Promise<number> {
  const rows = await q`delete from action_credentials where user_id = ${userId} returning id`;
  return rows.length;
}

export interface ActionEnrollment {
  token: string;
  user_id: number;
  label: string;
  expires_at: Date;
  used_at: Date | null;
}

export async function createActionEnrollment(
  token: string,
  userId: number,
  label: string,
  expiresAt: Date,
): Promise<void> {
  await q`
    insert into action_enrollments (token, user_id, label, expires_at)
    values (${token}, ${userId}, ${label}, ${expiresAt})`;
}

export async function findActionEnrollment(token: string): Promise<ActionEnrollment | null> {
  const rows = await q<ActionEnrollment[]>`
    select token, user_id, label, expires_at, used_at
      from action_enrollments where token = ${token} limit 1`;
  return rows[0] ?? null;
}

/** Single use, enforced in SQL: of two racing verifies only one consumes it. */
export async function consumeActionEnrollment(token: string): Promise<boolean> {
  const rows = await q`
    update action_enrollments set used_at = ${new Date()}
     where token = ${token} and used_at is null
     returning token`;
  return rows.length > 0;
}

export type ActionResult =
  | "ran"
  | "not_allowed"
  | "bad_passkey"
  | "not_home"
  | "inactive"
  | "ha_error";

export async function logActionEvent(e: {
  result: ActionResult;
  actionId: number | null;
  userId: number | null;
  via: "sun" | "token" | null;
  tagId: number | null;
  srcIp: string | null;
  userAgent: string | null;
}): Promise<void> {
  await q`
    insert into action_events (action_id, user_id, result, via, tag_id, src_ip, user_agent)
    values (${e.actionId}, ${e.userId}, ${e.result}, ${e.via}, ${e.tagId},
            ${e.srcIp}, ${e.userAgent})`;
}

export async function recentActionEvents(limit: number) {
  return q<Record<string, unknown>[]>`
    select e.ts, e.result, e.via, a.slug as action, u.name as user, t.label as tag, e.src_ip
      from action_events e
      left join actions a on a.id = e.action_id
      left join action_users u on u.id = e.user_id
      left join tags t on t.id = e.tag_id
     order by e.ts desc limit ${limit}`;
}

// --- action management from /admin -----------------------------------------

export async function updateAction(
  id: number,
  patch: { label?: string; requireSun?: boolean; homeOnly?: boolean; active?: boolean },
): Promise<boolean> {
  const rows = await q`
    update actions
       set label       = coalesce(${patch.label ?? null}, label),
           require_sun = coalesce(${patch.requireSun ?? null}, require_sun),
           home_only   = coalesce(${patch.homeOnly ?? null}, home_only),
           active      = coalesce(${patch.active ?? null}, active)
     where id = ${id}
     returning id`;
  return rows.length > 0;
}

export async function listRoles() {
  return q<{ id: number; name: string; users: number; actions: number }[]>`
    select r.id, r.name,
           (select count(*) from user_roles ur where ur.role_id = r.id) as users,
           (select count(*) from action_roles ar where ar.role_id = r.id) as actions
      from roles r order by r.name`;
}

/** Only an unused role can be deleted; returns false if it is still in use. */
export async function deleteUnusedRole(name: string): Promise<boolean> {
  const rows = await q`
    delete from roles
     where name = ${name}
       and not exists (select 1 from user_roles where role_id = roles.id)
       and not exists (select 1 from action_roles where role_id = roles.id)
     returning id`;
  return rows.length > 0;
}

export async function listAllActionCredentials() {
  return q<{ id: number; user_id: number; label: string; created_at: Date; last_used_at: Date | null }[]>`
    select id, user_id, label, created_at, last_used_at
      from action_credentials order by created_at`;
}

export async function deleteActionCredential(id: number): Promise<boolean> {
  const rows = await q`delete from action_credentials where id = ${id} returning id`;
  return rows.length > 0;
}
