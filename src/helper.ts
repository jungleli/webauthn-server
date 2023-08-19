import crypto from "crypto";
import cbor from "cbor";
import elliptic from 'elliptic';
const base64url = require('base64url');
const jsrsasign = require('jsrsasign');
const NodeRSA = require('node-rsa');

function generateRandomUserId() {
  return crypto.randomBytes(8).toString("hex");
}

let COSEKEYS = {
  'kty': 1,
  'alg': 3,
  'crv': -1,
  'x': -2,
  'y': -3,
  'n': -1,
  'e': -2
}

let COSEKTY = {
  'OKP': 1,
  'EC2': 2,
  'RSA': 3
}

let COSERSASCHEME = {
  '-3': 'pss-sha256',
  '-39': 'pss-sha512',
  '-38': 'pss-sha384',
  '-65535': 'pkcs1-sha1',
  '-257': 'pkcs1-sha256',
  '-258': 'pkcs1-sha384',
  '-259': 'pkcs1-sha512'
}

var COSECRV = {
  '1': 'p256',
  '2': 'p384',
  '3': 'p521'
}

var COSEALGHASH = {
  '-257': 'sha256',
  '-258': 'sha384',
  '-259': 'sha512',
  '-65535': 'sha1',
  '-39': 'sha512',
  '-38': 'sha384',
  '-37': 'sha256',
  '-260': 'sha256',
  '-261': 'sha512',
  '-7': 'sha256',
  '-36': 'sha512'
}

export function verifySignature(signature: any, authenticatorData: any, clientDataJSON: any, COSEPublicKey: any){
  const clientDataHash = crypto.createHash("sha256").update(clientDataJSON).digest("hex");
  console.log("clientDataHash:" + clientDataHash);
  const src = authenticatorData + "." + clientDataHash;
  console.log("src: "+ src);
  console.log()
  const isValid = (src: string, COSEPublicKey: any, signature:string) =>{
    const isValid = crypto.createVerify("SHA256").update(Buffer.from(src)).verify(Buffer.from(COSEPublicKey), signature, "base64");
    console.log("===verify signature:" + isValid);
  return isValid;
}
return false;
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

  // Verify origin
  const origin = clientData.origin;
  if (origin !== expectedOrigin) {
    return false;
  }

  // Verify type (should be "webauthn.get")
  const type = clientData.type;
  if (type !== "webauthn.get") {
    return false;
  }

  return true;
}

export function verifyChallenge(
  clientDataJSON: Uint8Array,
  expectedChallenge: string
) {
  const clientDataString = new TextDecoder().decode(clientDataJSON);
  const clientData = JSON.parse(clientDataString);

  console.log("clientData", clientData);
  console.log("expectedChallenge", expectedChallenge);

  // Verify challenge
  const challenge = base64URLToString(clientData.challenge);
  return challenge === expectedChallenge;
}
function parseAuthData(buffer: any) {
  let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
  let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
  let flagsInt = flagsBuf[0];
  let flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt
  }

  let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
  let counter = counterBuf.readUInt32BE(0);

  let aaguid = undefined;
  let credID = undefined;
  let COSEPublicKey = undefined;

  if (flags.at) {
    aaguid = buffer.slice(0, 16); buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen);
    COSEPublicKey = buffer;
  }
  // console.log("=====COSEPublicKey", cbor.decode(COSEPublicKey));
  // parsePublicKey(COSEPublicKey);

  return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey: cbor.decode(COSEPublicKey) }

}

const parsePublicKey = (COSEPublicKey: ArrayBuffer) => {
  let pubKeyCose = cbor.decode(COSEPublicKey);

  return pubKeyCose;

  //console.log("=====pubKeyCose", pubKeyCose);
  
  // @ts-ignore
  let hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
  if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
    let x = pubKeyCose.get(COSEKEYS.x);
    let y = pubKeyCose.get(COSEKEYS.y);

    let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);

    // let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);
    // @ts-ignore
    let ec = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
    let key = ec.keyFromPublic(ansiKey);
    //console.log('=====key',key,'=====ansiKey',ansiKey);

    const pubKey = {
      kty:'',
      alg:'',
      crv:'',
      x:'',
      y:''

    }
    
    // @ts-ignore
    // signatureIsValid = key.verify(signatureBaseHash, signatureBuffer)
  } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
    // @ts-ignore
    let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];

    let key = new NodeRSA(undefined, { signingScheme });
    key.importKey({
      n: pubKeyCose.get(COSEKEYS.n),
      e: 65537,
    }, 'components-public');

    // signatureIsValid = key.verify(signatureBaseBuffer, signatureBuffer)
  } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
    let x = pubKeyCose.get(COSEKEYS.x);
    // let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

    let key = new elliptic.eddsa('ed25519');
    key.keyFromPublic(x)

    // signatureIsValid = key.verify(signatureBaseHash, signatureBuffer)
  }
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

const parseAttestationObject = (attestationObject: Uint8Array) => {
  const attestationObjectArray = new Uint8Array(attestationObject);
  const parsedAttestationObject = cbor.decode(attestationObjectArray);
 // console.log("======parsedAttestationObject", parsedAttestationObject);
  return parseAuthData(parsedAttestationObject.authData);
}

export { generateRandomUserId, verifyAuthenticatorDataAndAttestation, extractAuthenticatorData, parseAuthData, parseAttestationObject };
