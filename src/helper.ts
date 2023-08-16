import crypto from "crypto";
import cbor from "cbor";

function generateRandomUserId() {
  return crypto.randomBytes(8).toString("hex");
}

function verifyAuthenticatorDataAndAttestation(authenticatorData: any, attestationObject: any, clientDataJSON: any) {
  const authenticatorDataBuffer = base64URLDecode(authenticatorData);
  const attestationObjectBuffer = base64URLDecode(attestationObject);
  const clientDataJSONBuffer = base64URLDecode(clientDataJSON);

  // Verify authenticator data
  // Authenticator data includes flags, counters, and other information
  // Ensure flags are set correctly and counters are valid
  const { flags, counter } = extractAuthenticatorData(authenticatorDataBuffer);
  console.log("flags", flags, "counter", counter);

  // Verify attestation object
  // This involves parsing and validating the attestation object
  // Ensure attestation statement format, public key, and other details

  // Verify client data JSON
  // This involves parsing and validating the client data JSON
  // Ensure challenge matches, origin is correct, and type is webauthn.get

  if (verifyClientDataJSON(clientDataJSONBuffer) && verifyAttestationObject(attestationObjectBuffer)) {
    return true;
  }

  return false;
}

export function base64URLDecode(input: string) {
  // Convert base64 URL-safe to base64 (add padding if needed)
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");

  // Convert base64 to binary buffer
  const binaryBuffer = Buffer.from(base64, "base64");

  // Convert binary buffer to Uint8Array
  return new Uint8Array(binaryBuffer);
}

export function base64URLToString(input: string) {
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");

  while (base64.length % 4 !== 0) {
    base64 += "=";
  }

  return base64;
}

function extractAuthenticatorData(authenticatorData: Uint8Array) {
  // Authenticator data is a binary buffer (Uint8Array)
  // It has a specific structure defined by the FIDO2/WebAuthn specification

  // Flags (bit flags indicating various properties)
  const flags = authenticatorData[32]; // Flags are at index 32

  // Counter (a counter value indicating the usage of the authenticator)
  const counter = authenticatorData.slice(33, 37); // Counter is at index 33 to 36

  // Other data may be included in the authenticator data
  // For example, attested credential data, extensions, etc.

  return {
    flags,
    counter,
  };
}

export function verifyClientDataJSON(
  clientDataJSON: Uint8Array,
  expectedChallenge: string = "dT3857_x",
  expectedOrigin: string = "http://localhost:3000"
) {
  const clientDataString = new TextDecoder().decode(clientDataJSON);
  const clientData = JSON.parse(clientDataString);

  console.log("clientData", clientData);
  console.log("expectedChallenge", expectedChallenge);

  // Verify challenge
  const challenge = base64URLToString(clientData.challenge);

  if (challenge !== expectedChallenge) {
    return false;
  }

  // Verify origin
  const origin = clientData.origin;
  if (origin !== expectedOrigin) {
    return false;
  }

  // Verify type (should be "webauthn.get")
  const type = clientData.type;
  if (type !== "webauthn.create") {
    return false;
  }

  return true;
}

function verifyAttestationObject(attestationObject: Uint8Array) {
  // Parse attestation object (assuming it's CBOR encoded)
  const attestationObjectArray = new Uint8Array(attestationObject);
  const parsedAttestationObject = cbor.decode(attestationObjectArray);
  console.log("parsedAttestationObject", parsedAttestationObject);

  // Verify that the attestation object includes "fmt" field (format)
  if (!parsedAttestationObject.hasOwnProperty("fmt")) {
    return false;
  }

  // Perform attestation format-specific verification
  // This could involve verifying the attestation statement, certificate, etc.

  return true;
}

export { generateRandomUserId, verifyAuthenticatorDataAndAttestation, extractAuthenticatorData };
