import { describe, expect, test } from "bun:test";
import {
  decideTap,
  hashToken,
  ipInCidrs,
  newToken,
  parseCidrs,
  tokenMatches,
  type TapAction,
} from "../src/actions/policy.ts";

const PEPPER = "test-pepper";

function action(over: Partial<TapAction> = {}): TapAction {
  return { id: 7, require_sun: false, token_hash: null, active: true, ...over };
}

describe("tokens", () => {
  test("new tokens are 128-bit base64url and distinct", () => {
    const a = newToken();
    expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(newToken()).not.toBe(a);
  });

  test("match only the stored hash", () => {
    const t = newToken();
    const h = hashToken(t, PEPPER);
    expect(tokenMatches(t, h, PEPPER)).toBe(true);
    expect(tokenMatches(newToken(), h, PEPPER)).toBe(false);
    expect(tokenMatches(t, h, "other-pepper")).toBe(false);
    expect(tokenMatches(null, h, PEPPER)).toBe(false);
    expect(tokenMatches(t, null, PEPPER)).toBe(false);
  });

  test("are domain-separated from a bare HMAC of the same string", async () => {
    const { createHmac } = await import("node:crypto");
    const t = "123456";
    const bare = createHmac("sha256", PEPPER).update(t).digest();
    expect(tokenMatches(t, bare, PEPPER)).toBe(false);
  });
});

describe("decideTap", () => {
  const linked = { id: 3, action_id: 7 };

  test("a DNA tag linked to this action opens it", () => {
    expect(decideTap(action(), true, linked, false)).toEqual({
      via: "sun",
      tagId: 3,
    });
    expect(
      decideTap(action({ require_sun: true }), true, linked, false),
    ).toEqual({
      via: "sun",
      tagId: 3,
    });
  });

  test("a door tag or another action's tag does not", () => {
    expect(
      decideTap(action(), true, { id: 3, action_id: null }, true),
    ).toBeNull();
    expect(decideTap(action(), true, { id: 3, action_id: 8 }, true)).toBeNull();
  });

  test("a failed DNA tap is not rescued by a valid token", () => {
    expect(decideTap(action(), true, null, true)).toBeNull();
  });

  test("plain token opens it unless DNA is required", () => {
    expect(decideTap(action(), false, null, true)).toEqual({
      via: "token",
      tagId: null,
    });
    expect(
      decideTap(action({ require_sun: true }), false, null, true),
    ).toBeNull();
    expect(decideTap(action(), false, null, false)).toBeNull();
  });

  test("an inactive action opens for nothing", () => {
    expect(decideTap(action({ active: false }), true, linked, true)).toBeNull();
    expect(decideTap(action({ active: false }), false, null, true)).toBeNull();
  });
});

describe("home CIDRs", () => {
  const home = parseCidrs("203.0.113.7/32, 192.168.1.0/24, 2001:db8:42::/48");

  test("IPv4", () => {
    expect(ipInCidrs("203.0.113.7", home)).toBe(true);
    expect(ipInCidrs("203.0.113.8", home)).toBe(false);
    expect(ipInCidrs("192.168.1.7", home)).toBe(true);
    expect(ipInCidrs("192.168.2.7", home)).toBe(false);
    expect(ipInCidrs("::ffff:192.168.1.7", home)).toBe(true);
  });

  test("IPv6", () => {
    expect(ipInCidrs("2001:db8:42:1::5", home)).toBe(true);
    expect(ipInCidrs("2001:DB8:42::", home)).toBe(true);
    expect(ipInCidrs("2001:db8:43::1", home)).toBe(false);
    expect(ipInCidrs("::1", home)).toBe(false);
  });

  test("no address, garbage, or no CIDRs means not home", () => {
    expect(ipInCidrs(null, home)).toBe(false);
    expect(ipInCidrs("not-an-ip", home)).toBe(false);
    expect(ipInCidrs("192.168.1.300", home)).toBe(false);
    expect(ipInCidrs("192.168.1.7", parseCidrs(""))).toBe(false);
  });

  test("bare address means a single host", () => {
    const one = parseCidrs("10.0.0.1");
    expect(ipInCidrs("10.0.0.1", one)).toBe(true);
    expect(ipInCidrs("10.0.0.2", one)).toBe(false);
  });

  test("garbage CIDRs throw at startup", () => {
    expect(() => parseCidrs("10.0.0.0/33")).toThrow();
    expect(() => parseCidrs("nope/8")).toThrow();
    expect(() => parseCidrs("1:2:3:4:5:6:7:8:9::/64")).toThrow();
  });
});
