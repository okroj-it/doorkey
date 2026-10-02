import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { config } from "../config.ts";
import { putChallenge, takeChallenge } from "../challenges.ts";
import * as db from "../db.ts";

const USER_ID = new TextEncoder().encode("doorkey-admin");

export async function registrationOptions(token: string, label: string) {
  const existing = await db.listCredentials();
  const options = await generateRegistrationOptions({
    rpName: config.admin.rpName,
    rpID: config.admin.rpId,
    userID: USER_ID,
    userName: label,
    userDisplayName: label,
    attestationType: "none",
    // Refuse to enrol a key that is already enrolled.
    excludeCredentials: existing.map((c) => ({ id: c.credential_id })),
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
  });
  putChallenge(`admin-reg:${token}`, options.challenge);
  return options;
}

export async function verifyRegistration(
  token: string,
  label: string,
  response: unknown,
): Promise<boolean> {
  const challenge = takeChallenge(`admin-reg:${token}`);
  if (!challenge) return false;

  const result = await verifyRegistrationResponse({
    response: response as Parameters<typeof verifyRegistrationResponse>[0]["response"],
    expectedChallenge: challenge,
    expectedOrigin: config.admin.origin,
    expectedRPID: config.admin.rpId,
    requireUserVerification: true,
  });

  if (!result.verified || !result.registrationInfo) return false;
  const { credential } = result.registrationInfo;
  await db.saveCredential(
    label,
    credential.id,
    credential.publicKey,
    credential.counter,
    credential.transports ?? null,
  );
  return true;
}

export async function authenticationOptions(sessionKey: string) {
  const options = await generateAuthenticationOptions({
    rpID: config.admin.rpId,
    userVerification: "required",
  });
  putChallenge(`admin-auth:${sessionKey}`, options.challenge);
  return options;
}

export async function verifyAuthentication(
  sessionKey: string,
  response: unknown,
): Promise<string | null> {
  const challenge = takeChallenge(`admin-auth:${sessionKey}`);
  if (!challenge) return null;

  const body = response as { id?: string };
  if (!body.id) return null;

  const credential = await db.findCredential(body.id);
  if (!credential) return null;

  const result = await verifyAuthenticationResponse({
    response: response as Parameters<typeof verifyAuthenticationResponse>[0]["response"],
    expectedChallenge: challenge,
    expectedOrigin: config.admin.origin,
    expectedRPID: config.admin.rpId,
    requireUserVerification: true,
    credential: {
      id: credential.credential_id,
      publicKey: new Uint8Array(credential.public_key),
      counter: Number(credential.counter),
      transports: (typeof credential.transports === "string"
        ? JSON.parse(credential.transports)
        : credential.transports) ?? undefined,
    },
  });

  if (!result.verified) return null;
  await db.touchCredential(credential.id, result.authenticationInfo.newCounter);
  return credential.label;
}
