import { config } from "../config.ts";
import { verifyStaticPath } from "./static-path.ts";
import { verifySun } from "./ntag424.ts";

/**
 * Proof that someone physically tapped the tag by the door.
 *
 *   static  a long random path segment written to an NTAG213. Stops internet
 *           scanning — nobody finds the keypad by guessing — but the path is
 *           fixed, so anyone who has tapped the tag keeps it.
 *   sun     NTAG 424 DNA Secure Dynamic Messaging. Every tap emits a fresh,
 *           signed, counter-protected URL: real proof of a physical tap, and
 *           replays are rejected.
 *   dev     always true. Local development only.
 */
export interface TapRequest {
  token: string;
  query: URLSearchParams;
}

export async function verifyTap(req: TapRequest): Promise<boolean> {
  switch (config.tap.mode) {
    case "static":
      return verifyStaticPath(req.token);
    case "sun":
      return verifySun(req);
    case "dev":
      return true;
  }
}
