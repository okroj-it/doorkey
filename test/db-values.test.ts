import { describe, expect, test } from "bun:test";
import { normaliseRow, param } from "../src/db-values.ts";

describe("param", () => {
  test("dates go out as ISO-8601 UTC text, for both", () => {
    const d = new Date(Date.UTC(2026, 9, 2, 21, 30));
    expect([param(d, "sqlite"), param(d, "postgres")]).toEqual(["2026-10-02T21:30:00.000Z", "2026-10-02T21:30:00.000Z"]);
  });
  test("objects and arrays: JSON text for SQLite, untouched for Postgres", () => {
    const schedule = [{ dow: [1, 3], from: "07:00", to: "09:00" }];
    expect(param(schedule, "sqlite")).toBe('[{"dow":[1,3],"from":"07:00","to":"09:00"}]');
    expect(param(["internal", "hybrid"], "sqlite")).toBe('["internal","hybrid"]');
    expect(param(schedule, "postgres")).toBe(schedule);
  });
  test("bytes, scalars and null pass through", () => {
    const b = Buffer.from([1, 2]);
    expect(param(b, "sqlite")).toBe(b);
    const scalars = ["x", 3, true, null, undefined].map((v) => param(v, "sqlite"));
    expect(scalars).toEqual(["x", 3, true, null, null]);
  });
});

describe("normaliseRow", () => {
  test("SQLite-shaped rows come back as the code expects", () => {
    const row = normaliseRow({
      id: 7,
      label: "Cleaner",
      active: 1,
      require_sun: 0,
      created_at: "2026-10-02T21:30:00.000Z",
      locked_until: null,
      schedule: '[{"dow":[1],"from":"07:00","to":"09:00"}]',
      roles: '["owner"]',
      n: "3",
      public_key: new Uint8Array([9, 8]),
    });
    expect(row.active).toBe(true);
    expect(row.require_sun).toBe(false);
    expect(row.created_at).toEqual(new Date("2026-10-02T21:30:00.000Z"));
    expect(row.locked_until).toBeNull();
    expect(row.schedule).toEqual([{ dow: [1], from: "07:00", to: "09:00" }]);
    expect(row.roles).toEqual(["owner"]);
    expect(row.n).toBe(3);
    expect(Buffer.isBuffer(row.public_key)).toBe(true);
    expect([row.id, row.label]).toEqual([7, "Cleaner"]);
  });

  test("Postgres-shaped rows are left alone", () => {
    const at = new Date();
    const key = Buffer.from([1]);
    const row = normaliseRow({ active: true, created_at: at, schedule: [{ dow: [0] }], roles: [], public_key: key, n: 2 });
    expect(row).toEqual({ active: true, created_at: at, schedule: [{ dow: [0] }], roles: [], public_key: key, n: 2 });
    expect(row.public_key).toBe(key);
  });
});
