import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { config } from "../config.ts";
import { putChallenge, takeChallenge } from "../challenges.ts";
import * as db from "../db.ts";

/**
 * Passkeys for tap-gated actions. Same RP id as the admin passkeys, but a
 * different user handle per action user, so the authenticator keeps them as
 * separate entries and neither overwrites the admin passkey. Which table a
 * credential is in decides what it can do.
 */

type RegistrationResponse = Parameters<
  typeof verifyRegistrationResponse
>[0]["response"];
type AuthenticationResponse = Parameters<
  typeof verifyAuthenticationResponse
>[0]["response"];

function userHandle(userId: number): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`doorkey-action:${userId}`);
}

function transportsOf(raw: string[] | string | null) {
  const list = typeof raw === "string" ? (JSON.parse(raw) as string[]) : raw;
  return (list ?? undefined) as AuthenticatorTransport[] | undefined;
}

export async function registrationOptions(token: string, user: db.ActionUser) {
  const existing = await db.listUserCredentialIds(user.id);
  const options = await generateRegistrationOptions({
    rpName: config.admin.rpName,
    rpID: config.admin.rpId,
    userID: userHandle(user.id),
    // Shown in the phone's passkey list next to the admin passkey.
    userName: `${user.name} (actions)`,
    userDisplayName: `${user.name} (actions)`,
    attestationType: "none",
    excludeCredentials: existing.map((id) => ({ id })),
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
  });
  putChallenge(`action-reg:${token}`, options.challenge);
  return options;
}

export async function verifyRegistration(
  token: string,
  userId: number,
  label: string,
  response: unknown,
): Promise<boolean> {
  const challenge = takeChallenge(`action-reg:${token}`);
  if (!challenge) return false;

  let result;
  try {
    result = await verifyRegistrationResponse({
      response: response as RegistrationResponse,
      expectedChallenge: challenge,
      expectedOrigin: config.admin.origin,
      expectedRPID: config.admin.rpId,
      requireUserVerification: true,
    });
  } catch {
    return false;
  }
  if (!result.verified || !result.registrationInfo) return false;

  const { credential } = result.registrationInfo;
  await db.saveActionCredential(
    userId,
    label,
    credential.id,
    credential.publicKey,
    credential.counter,
    credential.transports ?? null,
  );
  return true;
}

/**
 * Offers only passkeys that could succeed for this action. Returns null when
 * nobody is allowed to run it, so the page can say so instead of opening a
 * passkey prompt that can only fail.
 */
export async function authenticationOptions(key: string, actionId: number) {
  const eligible = await db.eligibleCredentials(actionId);
  if (eligible.length === 0) return null;
  const options = await generateAuthenticationOptions({
    rpID: config.admin.rpId,
    userVerification: "required",
    allowCredentials: eligible.map((c) => ({
      id: c.credential_id,
      transports: transportsOf(c.transports),
    })),
  });
  putChallenge(`action-auth:${key}`, options.challenge);
  return options;
}

/** Returns the verified action credential, or null. Never throws on bad input. */
export async function verifyAuthentication(
  key: string,
  response: unknown,
): Promise<db.ActionCredential | null> {
  const challenge = takeChallenge(`action-auth:${key}`);
  if (!challenge) return null;

  const id = (response as { id?: unknown } | null)?.id;
  if (typeof id !== "string") return null;

  // An admin passkey is simply not found here.
  const credential = await db.findActionCredential(id);
  if (!credential) return null;

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: response as AuthenticationResponse,
      expectedChallenge: challenge,
      expectedOrigin: config.admin.origin,
      expectedRPID: config.admin.rpId,
      requireUserVerification: true,
      credential: {
        id: credential.credential_id,
        publicKey: new Uint8Array(credential.public_key),
        counter: Number(credential.counter),
        transports: transportsOf(credential.transports),
      },
    });
  } catch {
    return null;
  }
  if (!result.verified) return null;

  await db.touchActionCredential(
    credential.id,
    result.authenticationInfo.newCounter,
  );
  return credential;
}
