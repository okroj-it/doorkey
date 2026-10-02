import { describe, expect, test } from "bun:test";
import { decodeTagCode, encodeTagCode } from "../src/tag-code.ts";

// Shared with tools/tagtui (Rust) and tools/provision.py: all three must
// produce exactly this string for these inputs.
const UID = Buffer.from("04de5f1eacc040", "hex");
const WRAPPED = Buffer.from(Array.from({ length: 44 }, (_, i) => i));
const VECTOR =
  "dktag1.04de5f1eacc040.000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b.RnJvbnQgZG9vcg";

describe("tag codes", () => {
  test("encode matches the shared vector", () => {
    expect(encodeTagCode({ uid: UID, wrapped: WRAPPED, label: "Front door" })).toBe(VECTOR);
  });

  test("decode round-trips, tolerating surrounding whitespace", () => {
    const c = decodeTagCode(`  ${VECTOR}\n`);
    expect(Buffer.from(c.uid).toString("hex")).toBe("04de5f1eacc040");
    expect(Buffer.from(c.wrapped)).toEqual(WRAPPED);
    expect(c.label).toBe("Front door");
    // Non-ASCII labels survive
    const pl = encodeTagCode({ uid: UID, wrapped: WRAPPED, label: "Garaż" });
    expect(decodeTagCode(pl).label).toBe("Garaż");
  });

  test("garbage is refused with a readable reason", () => {
    expect(() => decodeTagCode("hello")).toThrow("not a tag code");
    expect(() => decodeTagCode("dktag1.04de5f1eacc040")).toThrow("four parts");
    expect(() => decodeTagCode(VECTOR.replace("04de5f1eacc040", "04de5f"))).toThrow("the UID must be 7 bytes");
    expect(() => decodeTagCode(VECTOR.replace("2a2b.", "2a.")) ).toThrow("the wrapped key must be 44 bytes");
    expect(() => decodeTagCode(VECTOR.replace("RnJvbnQgZG9vcg", ""))).toThrow("the label must be");
    expect(() => decodeTagCode(VECTOR.replace("RnJvbnQgZG9vcg", "a+b"))).toThrow("not base64url");
  });
});
