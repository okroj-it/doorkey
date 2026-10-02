/**
 * AN12196 test vectors. These prove the crypto before any tag is provisioned -
 * if a real tap later fails, the fault is in provisioning or lookup, not here.
 */
import { expect, test } from "bun:test";
import { cmac, decryptPicc, hexToBytes, sunMac, timingSafeEqual } from "../src/auth/sun-crypto.ts";

// RFC 4493 - the CMAC construction everything else is built on.
const RFC_KEY = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");

test("AES-CMAC: empty message (RFC 4493)", () => {
  expect(Buffer.from(cmac(RFC_KEY, new Uint8Array(0))).toString("hex"))
    .toBe("bb1d6929e95937287fa37d129b756746");
});

test("AES-CMAC: 16-byte message (RFC 4493)", () => {
  const msg = hexToBytes("6bc1bee22e409f96e93d7e117393172a");
  expect(Buffer.from(cmac(RFC_KEY, msg)).toString("hex"))
    .toBe("070a16b46b4d4144f79bdd9dd04a287c");
});

test("AES-CMAC: 40-byte message (RFC 4493)", () => {
  const msg = hexToBytes(
    "6bc1bee22e409f96e93d7e117393172a" +
    "ae2d8a571e03ac9c9eb76fac45af8e51" +
    "30c81c46a35ce411",
  );
  expect(Buffer.from(cmac(RFC_KEY, msg)).toString("hex"))
    .toBe("dfa66747de9ae63030ca32611497c827");
});

// AN12196 worked example: zero meta key, published ciphertext.
//
// The UID and counter below are what this ciphertext decrypts to. They are
// corroborated by the MAC test underneath, which reproduces NXP's published
// CMAC *from these values* - a wrong decryption could not yield the right MAC.
test("decryptPicc recovers UID and counter (AN12196)", () => {
  const metaKey = new Uint8Array(16);
  const picc = hexToBytes("EF963FF7828658A599F3041510671E88");
  const out = decryptPicc(metaKey, picc);
  expect(Buffer.from(out.uid).toString("hex").toUpperCase()).toBe("04DE5F1EACC040");
  expect(out.readCounter).toBe(61);
});

test("sunMac matches the tag's CMAC (AN12196)", () => {
  const metaKey = new Uint8Array(16);
  const macKey = new Uint8Array(16);
  const picc = decryptPicc(metaKey, hexToBytes("EF963FF7828658A599F3041510671E88"));
  // SDM over the PICC data alone: the message is empty.
  const mac = sunMac(macKey, picc, new Uint8Array(0));
  expect(Buffer.from(mac).toString("hex").toUpperCase()).toBe("94EED9EE65337086");
});

test("timingSafeEqual", () => {
  expect(timingSafeEqual(hexToBytes("00ff"), hexToBytes("00ff"))).toBe(true);
  expect(timingSafeEqual(hexToBytes("00ff"), hexToBytes("00fe"))).toBe(false);
  expect(timingSafeEqual(hexToBytes("00ff"), hexToBytes("00"))).toBe(false);
});

test("decryptPicc rejects data without UID or counter", () => {
  // Encrypt a plaintext whose tag byte claims neither field is present.
  expect(() => decryptPicc(new Uint8Array(16), new Uint8Array(16))).toThrow();
});
