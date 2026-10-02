/**
 * Imported first by every entry point (server and CLI). As a Home Assistant
 * app the settings come from the Supervisor and /data, and they have to be
 * in process.env before config.ts reads it: a module's top-level await
 * finishes before the imports listed after it are evaluated.
 */
import { isAppMode, prepareAppEnv } from "./app-mode.ts";

if (isAppMode()) {
  const cli = /[\\/]cli[\\/][^\\/]+$/.test(process.argv[1] ?? "");
  if (!cli) console.log("doorkey: running as a Home Assistant app");
  await prepareAppEnv({ mqtt: !cli });
}
