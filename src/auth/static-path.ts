import { timingSafeEqual } from "node:crypto";
import { config } from "../config.ts";

export function verifyStaticPath(token: string): boolean {
  const got = Buffer.from(token);
  const want = Buffer.from(config.tap.staticPath);
  return got.length === want.length && timingSafeEqual(got, want);
}
