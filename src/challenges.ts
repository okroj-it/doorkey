/**
 * WebAuthn challenges are single-use and short-lived. They live in memory
 * rather than the database because the deployment is a single replica with a
 * Recreate strategy - a restart mid-ceremony just means retrying the tap.
 *
 * Shared by admin and action passkeys; callers namespace their keys.
 */
const challenges = new Map<string, { challenge: string; expires: number }>();
const CHALLENGE_TTL_MS = 120_000;

export function putChallenge(key: string, challenge: string): void {
  challenges.set(key, { challenge, expires: Date.now() + CHALLENGE_TTL_MS });
}

export function takeChallenge(key: string): string | null {
  const entry = challenges.get(key);
  challenges.delete(key);
  if (!entry || entry.expires < Date.now()) return null;
  return entry.challenge;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of challenges) if (v.expires < now) challenges.delete(k);
}, 60_000).unref();
