/**
 * NTAG 424 DNA SUN cryptography (NXP AN12196).
 *
 * Pure functions, no I/O: everything here is verifiable against the test
 * vectors NXP publishes, which is why it lives apart from the lookup and
 * replay logic in ntag424.ts.
 *
 * Node's AES-CMAC is not exposed, so it is built from AES-128-ECB below.
 */
import { createCipheriv, createDecipheriv } from "node:crypto";

const BLOCK = 16;

/** Bytes is generic over its buffer in TS 5.7+; subarray() and
 * Buffer-backed arrays widen to ArrayBufferLike, so use one alias throughout. */
type Bytes = Uint8Array<ArrayBufferLike>;

function xor(a: Bytes, b: Bytes): Bytes {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/** Double in GF(2^128) - the subkey derivation of RFC 4493. */
function dbl(x: Bytes): Bytes {
  const out = new Uint8Array(BLOCK);
  let carry = 0;
  for (let i = BLOCK - 1; i >= 0; i--) {
    const v = (x[i]! << 1) | carry;
    out[i] = v & 0xff;
    carry = (x[i]! & 0x80) ? 1 : 0;
  }
  if (x[0]! & 0x80) out[BLOCK - 1] = out[BLOCK - 1]! ^ 0x87;
  return out;
}

function aesEcbBlock(key: Bytes, block: Bytes): Bytes {
  const c = createCipheriv("aes-128-ecb", key, null);
  c.setAutoPadding(false);
  return Uint8Array.from(Buffer.concat([c.update(block), c.final()]));
}

/** AES-CMAC (RFC 4493). Used for the session key and the tap MAC. */
export function cmac(key: Bytes, msg: Bytes): Bytes {
  const l = aesEcbBlock(key, new Uint8Array(BLOCK));
  const k1 = dbl(l);
  const k2 = dbl(k1);

  const complete = msg.length > 0 && msg.length % BLOCK === 0;
  const nBlocks = complete ? msg.length / BLOCK : Math.floor(msg.length / BLOCK) + 1;

  let last: Bytes;
  if (complete) {
    last = xor(msg.subarray((nBlocks - 1) * BLOCK), k1);
  } else {
    const rest = msg.subarray((nBlocks - 1) * BLOCK);
    const padded = new Uint8Array(BLOCK);
    padded.set(rest);
    padded[rest.length] = 0x80;
    last = xor(padded, k2);
  }

  let x: Bytes = new Uint8Array(BLOCK);
  for (let i = 0; i < nBlocks - 1; i++) {
    x = aesEcbBlock(key, xor(x, msg.subarray(i * BLOCK, (i + 1) * BLOCK)));
  }
  return aesEcbBlock(key, xor(x, last));
}

/** AES-128-CBC decrypt with a zero IV and no padding. */
export function aesCbcDecrypt(key: Bytes, data: Bytes): Bytes {
  const d = createDecipheriv("aes-128-cbc", key, new Uint8Array(BLOCK));
  d.setAutoPadding(false);
  return Uint8Array.from(Buffer.concat([d.update(data), d.final()]));
}

export interface PiccData {
  uid: Bytes;      // 7 bytes
  readCounter: number;  // 3-byte LE counter, monotonic per tag
}

/**
 * Decrypt the `picc` parameter with K2 (SDMMetaRead).
 *
 * Plaintext is a tag byte, then UID and counter as selected at provisioning.
 * Bit 0x80 means a UID is present, 0x40 a read counter; we require both,
 * because a tap without a UID cannot be attributed to a tag and one without a
 * counter cannot be replay-checked.
 */
export function decryptPicc(metaKey: Bytes, piccEnc: Bytes): PiccData {
  if (piccEnc.length !== 16) throw new Error(`picc must be 16 bytes, got ${piccEnc.length}`);
  const p = aesCbcDecrypt(metaKey, piccEnc);

  const tag = p[0]!;
  if (!(tag & 0x80)) throw new Error("picc carries no UID");
  if (!(tag & 0x40)) throw new Error("picc carries no read counter");

  const uid = p.subarray(1, 8);
  const ctr = p.subarray(8, 11);
  return { uid, readCounter: ctr[0]! | (ctr[1]! << 8) | (ctr[2]! << 16) };
}

/**
 * Session MAC key, then the tap CMAC. AN12196 s 4.4: derive SV2 from the
 * decrypted UID and counter, CMAC it under K3, then CMAC the message under
 * that - and the tag only emits every other byte of the result.
 */
export function sunMac(macKey: Bytes, picc: PiccData, message: Bytes): Bytes {
  const sv2 = new Uint8Array(16);
  sv2.set([0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80], 0);
  sv2.set(picc.uid, 6);
  sv2[13] = picc.readCounter & 0xff;
  sv2[14] = (picc.readCounter >> 8) & 0xff;
  sv2[15] = (picc.readCounter >> 16) & 0xff;

  const sessionKey = cmac(macKey, sv2);
  const full = cmac(sessionKey, message);

  const truncated = new Uint8Array(8);
  for (let i = 0; i < 8; i++) truncated[i] = full[i * 2 + 1]!;
  return truncated;
}

/** Constant-time compare - never leak how much of a MAC matched. */
export function timingSafeEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function hexToBytes(hex: string): Bytes {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
