import { unwrapKey } from "./auth/kek.ts";
import { config } from "./config.ts";
import * as db from "./db.ts";
import { decodeTagCode } from "./tag-code.ts";

export interface Enrolled {
  id: number;
  uid: string;
  label: string;
  /** The UID was already enrolled; its key and label were replaced. */
  replaced: boolean;
}

/**
 * Enrol a provisioned tag from its tag code. Refused unless this server's
 * KEK unwraps the key: a tag wrapped with another KEK would be saved fine
 * and then fail every tap without a word.
 */
export async function enrolTag(code: string, label?: string): Promise<Enrolled> {
  if (!config.tap.kek) {
    throw new Error("this server has no DOORKEY_TAG_KEK - enrolling DNA tags needs DOORKEY_TAP_MODE=sun");
  }
  const c = decodeTagCode(code);
  try {
    unwrapKey(c.wrapped);
  } catch {
    throw new Error("the tag's key was wrapped with a different KEK than this server's DOORKEY_TAG_KEK");
  }
  const name = label?.trim() || c.label;
  const replaced = (await db.findTagByUid(c.uid)) !== null;
  const id = await db.insertTag(c.uid, name, c.wrapped);
  return { id, uid: Buffer.from(c.uid).toString("hex"), label: name, replaced };
}

/** Enable or disable a tag by its UID (hex). False if there is no such tag. */
export async function setTagActiveByUid(uidHex: string, active: boolean): Promise<boolean> {
  if (!/^[0-9a-f]{14}$/i.test(uidHex)) throw new Error("the UID must be 7 bytes of hex");
  const tag = await db.findTagByUid(Buffer.from(uidHex, "hex"));
  if (!tag) return false;
  await db.setTagActive(tag.id, active);
  return true;
}
