import crypto from "crypto";
import cbor from "cbor";

function generateRandomUserId() {
  return crypto.randomBytes(8).toString("hex");
}

function verifyAuthenticatorDataAndAttestation(authenticatorData: string, attestationObject: string, clientDataJSON: string) {
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

function base64URLDecode(input: string) {
  // Convert base64 URL-safe to base64 (add padding if needed)
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");

  // Convert base64 to binary buffer
  const binaryBuffer = Buffer.from(base64, "base64");

  // Convert binary buffer to Uint8Array
  return new Uint8Array(binaryBuffer);
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

function verifyClientDataJSON(clientDataJSON: Uint8Array, expectedChallenge: string = "dT3857_x", expectedOrigin: string = "http://localhost:3000") {
  const clientDataString = new TextDecoder().decode(clientDataJSON);
  const clientData = JSON.parse(clientDataString);

  console.log("clientData", clientData);

  // Verify challenge
  const challenge = clientData.challenge;
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
function parseAuthData(buffer: any){
  let rpIdHash = buffer.slice(0,32);
  buffer = buffer.slice(32);

  let flagsBuf = buffer.slice(0,1);
  buffer = buffer.slice(1);
  let flagsInt = flagsBuf[0];
  let flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt
  }
  let counterBuf = buffer.slice(0,4);
  buffer = buffer.slice(4);

  let counter = counterBuf.readUInt32BE(0);
  let aaguid = undefined;
  let credID = undefined;
  let COSEPublicKey = undefined;
  if(flags.at){
    aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0,2);
    buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    credID = buffer.slice(0, credIDLen);
    buffer = buffer.slice(credIDLen);
    COSEPublicKey = buffer;
  }
  console.log("authData: " + {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey});
  return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}

}

function verifyAttestationObject(attestationObject: Uint8Array) {
  // Parse attestation object (assuming it's CBOR encoded)
  const attestationObjectArray = new Uint8Array(attestationObject);
  const parsedAttestationObject = cbor.decode(attestationObjectArray);
  console.log("parsedAttestationObject", parsedAttestationObject);

  parseAuthData(parsedAttestationObject.authData);

  // Verify that the attestation object includes "fmt" field (format)
  if (!parsedAttestationObject.hasOwnProperty("fmt")) {
    return false;
  }

  // Perform attestation format-specific verification
  // This could involve verifying the attestation statement, certificate, etc.

  return true;
}

export { generateRandomUserId, verifyAuthenticatorDataAndAttestation, extractAuthenticatorData };
