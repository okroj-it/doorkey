import type { TapRequest } from "./index.ts";
import { advanceTagCounter, findTagByUid, type TagRow } from "../db.ts";
import { config } from "../config.ts";
import { unwrapKey } from "./kek.ts";
import { decryptPicc, hexToBytes, sunMac, timingSafeEqual } from "./sun-crypto.ts";

/**
 * NTAG 424 DNA SUN verification.
 *
 * On each tap the chip emits a URL carrying `picc` (its UID and a monotonic
 * read counter, encrypted with the meta key) and `cmac` (AES-CMAC over that
 * data with the MAC key). Verifying the CMAC proves the physical tag was
 * tapped; checking that the counter has advanced rejects replays.
 *
 * Key split, and why:
 *   K2 (meta, shared)   decrypts the PICC blob. Shared across tags so one
 *                       decrypt yields the UID and lookup is an index hit
 *                       rather than a scan over every enrolled tag. Leaking it
 *                       exposes UIDs and counters - never the ability to forge.
 *   K3 (MAC, per tag)   authenticates the tap. This is the one that protects
 *                       the door, so it is never shared.
 *   K0 (app, per tag)   can reconfigure the chip. Derived from the offline
 *                       master and never present in this service at all.
 *
 * Every failure returns false and logs nothing identifying: a caller cannot
 * learn whether a UID is enrolled, whether the MAC was close, or how far the
 * counter was behind. The route turns false into a 404, so a probe cannot
 * distinguish a bad tap from a path that was never routed.
 */
export async function verifySun(req: TapRequest): Promise<boolean> {
  const tag = await verifySunTag(req.query);
  // A tag linked to an action opens only that action, never the door.
  return tag !== null && tag.action_id === null;
}

/**
 * The verification itself, shared by the door and tap-gated actions. Returns
 * the tag once its MAC checked out and its counter advanced, else null.
 */
export async function verifySunTag(query: URLSearchParams): Promise<TagRow | null> {
  const piccHex = query.get("picc");
  const cmacHex = query.get("cmac");
  if (!piccHex || !cmacHex) return null;

  let piccEnc: Uint8Array;
  let mac: Uint8Array;
  try {
    piccEnc = hexToBytes(piccHex);
    mac = hexToBytes(cmacHex);
  } catch {
    return null;
  }
  if (piccEnc.length !== 16 || mac.length !== 8) return null;

  let picc;
  try {
    picc = decryptPicc(hexToBytes(config.tap.metaKey), piccEnc);
  } catch {
    return null; // not our ciphertext, or no UID/counter in the plaintext
  }

  const tag = await findTagByUid(picc.uid);
  if (!tag || !tag.active) return null;

  // A wrong or freshly rotated KEK makes AES-GCM throw. Fail closed and
  // silently, like every other failure here: a 500 would both leak that this
  // UID is enrolled and turn a key rotation into a flood of stack traces.
  let macKey: Uint8Array;
  try {
    macKey = unwrapKey(tag.mac_key_enc);
  } catch {
    return null;
  }

  const expected = sunMac(macKey, picc, new Uint8Array(0));
  if (!timingSafeEqual(expected, mac)) return null;

  // Monotonic counter, compared in SQL so two concurrent replays of the same
  // captured URL cannot both win - the loser updates no row.
  return (await advanceTagCounter(tag.id, picc.readCounter)) ? tag : null;
}
