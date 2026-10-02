/**
 * As a Home Assistant app the settings come from the Supervisor and /data,
 * and they have to be in process.env before config.ts reads it - so
 * config.ts imports this module: a module is evaluated only after the
 * top-level await of its own imports has finished. (Importing it first from
 * an entry point is not enough: sibling imports do not wait for each other.)
 */
import { isAppMode, prepareAppEnv } from "./app-mode.ts";

if (isAppMode()) {
  const cli = /[\\/]cli[\\/][^\\/]+$/.test(process.argv[1] ?? "");
  if (!cli) console.log("doorkey: running as a Home Assistant app");
  await prepareAppEnv({ mqtt: !cli });
}
