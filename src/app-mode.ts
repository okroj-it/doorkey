/**
 * Running as a Home Assistant app (add-on): the Supervisor starts the
 * container with SUPERVISOR_TOKEN set. DOORKEY_MODE=app forces app mode,
 * DOORKEY_MODE=standalone forces it off.
 */
export function isAppMode(): boolean {
  const mode = process.env.DOORKEY_MODE;
  if (mode === "app") return true;
  if (mode === "standalone") return false;
  return Boolean(process.env.SUPERVISOR_TOKEN);
}
