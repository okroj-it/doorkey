/**
 * Key-encryption key for tag key material.
 *
 * Tag keys are derived on the workstation from an offline master and stored
 * here only in wrapped form, so a stolen database dump is inert without the
 * KEK in the environment. The offline master never reaches this service: it can verify a
 * tap, but it cannot reconfigure a tag.
 *
 * AES-256-GCM, stored as nonce(12) || ciphertext(16) || authTag(16).
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { config } from "../config.ts";

const NONCE = 12;
const TAG = 16;

function kek(): Buffer {
  const raw = Buffer.from(config.tap.kek, "hex");
  if (raw.length !== 32) {
    throw new Error("DOORKEY_TAG_KEK must be 32 bytes (64 hex chars)");
  }
  return raw;
}

export function wrapKey(plain: Uint8Array): Buffer {
  const nonce = randomBytes(NONCE);
  const c = createCipheriv("aes-256-gcm", kek(), nonce);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]);
}

export function unwrapKey(wrapped: Uint8Array): Uint8Array {
  const buf = Buffer.from(wrapped);
  if (buf.length <= NONCE + TAG) throw new Error("wrapped key too short");
  const nonce = buf.subarray(0, NONCE);
  const ct = buf.subarray(NONCE, buf.length - TAG);
  const tag = buf.subarray(buf.length - TAG);

  const d = createDecipheriv("aes-256-gcm", kek(), nonce);
  d.setAuthTag(tag);
  // Throws if the KEK is wrong or the row was tampered with - which is the
  // point: a modified key column fails loudly rather than verifying nothing.
  return Uint8Array.from(Buffer.concat([d.update(ct), d.final()]));
}
