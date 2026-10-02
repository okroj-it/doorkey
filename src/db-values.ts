/**
 * The values Postgres and SQLite drivers disagree on, made explicit.
 *
 * Parameters: Bun's SQLite adapter binds a Date or a plain object as NULL
 * and spreads an array over several parameters, so dates are sent as
 * ISO-8601 UTC text and objects and arrays as JSON text. Postgres casts that
 * text to the column's type.
 *
 * Rows: SQLite returns dates as text, booleans as 0/1, JSON as text and bytes
 * as a plain Uint8Array. Columns are recognised by name - the schema follows
 * these conventions - and turned back into what the rest of the code expects.
 * Values already of the right type pass through, so Postgres rows are
 * unchanged.
 */

const DATE_COLUMN = /^(ts|valid_from|valid_until|locked_until|.+_at)$/;
const BOOL_COLUMNS = new Set(["active", "require_sun", "home_only", "has_token", "ok"]);
const JSON_COLUMNS = new Set(["schedule", "transports", "roles", "tags"]);
const COUNT_COLUMNS = new Set(["n", "users", "actions", "passkeys"]);

export function param(v: unknown): unknown {
  if (v === undefined || v === null) return null;
  if (v instanceof Date) return v.toISOString();
  if (v instanceof Uint8Array) return v;
  if (typeof v === "object") return JSON.stringify(v);
  return v;
}

function value(column: string, v: unknown): unknown {
  if (v === null || v === undefined) return null;
  if (v instanceof Uint8Array && !Buffer.isBuffer(v)) return Buffer.from(v);
  if (DATE_COLUMN.test(column) && typeof v === "string") return new Date(v);
  if (BOOL_COLUMNS.has(column) && typeof v === "number") return v !== 0;
  if (JSON_COLUMNS.has(column) && typeof v === "string") return JSON.parse(v);
  if (COUNT_COLUMNS.has(column) && (typeof v === "string" || typeof v === "bigint")) return Number(v);
  return v;
}

export function normaliseRow<T extends Record<string, unknown>>(row: T): T {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) out[k] = value(k, v);
  return out as T;
}
