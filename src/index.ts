/**
 * Entry point. As a Home Assistant app the settings come from the Supervisor
 * and /data, and they have to be in place before config.ts reads the
 * environment - so the server is loaded only after that.
 */
import { isAppMode, prepareAppEnv } from "./app-mode.ts";

if (isAppMode()) {
  console.log("doorkey: running as a Home Assistant app");
  await prepareAppEnv();
}

export default (await import("./server.ts")).default;
