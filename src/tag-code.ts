/**
 * The one-line code that enrols a provisioned NTAG 424 DNA tag without
 * database access: tagtui and tools/provision.py print it, the admin page
 * and `cli/doorkey.ts tag:add` take it.
 *
 *   dktag1.<uid, 7 bytes hex>.<wrapped K3, 44 bytes hex>.<label, base64url>
 *
 * The tag's MAC key travels only wrapped with the KEK (nonce || ct || tag,
 * as in auth/kek.ts), so the code is useless to anyone without the KEK. The
 * server proves it holds the same KEK by unwrapping before it saves the tag.
 */

export const TAG_CODE_PREFIX = "dktag1";
const UID_BYTES = 7;
const WRAPPED_BYTES = 12 + 16 + 16;
const MAX_LABEL = 64;

export interface TagCode {
  uid: Uint8Array;
  wrapped: Uint8Array;
  label: string;
}

export function encodeTagCode(c: TagCode): string {
  return [
    TAG_CODE_PREFIX,
    Buffer.from(c.uid).toString("hex"),
    Buffer.from(c.wrapped).toString("hex"),
    Buffer.from(c.label, "utf8").toString("base64url"),
  ].join(".");
}

function hex(s: string, bytes: number, what: string): Uint8Array {
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`, "i").test(s)) {
    throw new Error(`${what} must be ${bytes} bytes of hex`);
  }
  return Buffer.from(s, "hex");
}

/** Throws with a message fit to show the person who pasted it. */
export function decodeTagCode(input: string): TagCode {
  const parts = input.trim().split(".");
  if (parts[0] !== TAG_CODE_PREFIX) throw new Error(`not a tag code (expected ${TAG_CODE_PREFIX}.…)`);
  if (parts.length !== 4) throw new Error("a tag code has four parts separated by dots");
  const [, uidHex, wrappedHex, label64] = parts as [string, string, string, string];
  const uid = hex(uidHex, UID_BYTES, "the UID");
  const wrapped = hex(wrappedHex, WRAPPED_BYTES, "the wrapped key");
  if (!/^[A-Za-z0-9_-]*$/.test(label64)) throw new Error("the label is not base64url");
  const label = Buffer.from(label64, "base64url").toString("utf8").trim();
  if (!label || label.length > MAX_LABEL) throw new Error(`the label must be 1-${MAX_LABEL} characters`);
  return { uid, wrapped, label };
}
