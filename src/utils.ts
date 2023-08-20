import { COSEALG, COSEKEYS } from "./coseTypes";
import crypto from "node:crypto";
import { Encoder } from "cbor-x";
import { AsnParser } from "@peculiar/asn1-schema";
import { ECDSASigValue } from "@peculiar/asn1-ecc";

export async function toHash(data: Uint8Array | string, algorithm = -7): Promise<Uint8Array> {
  if (typeof data === "string") {
    data = fromUTF8String(data);
  }

  const digest = isoCryptoDigest(data, algorithm);

  return digest;
}

export function fromUTF8String(utf8String: string): Uint8Array {
  const encoder = new globalThis.TextEncoder();
  return encoder.encode(utf8String);
}

export async function isoCryptoDigest(data: Uint8Array, algorithm: COSEALG): Promise<Uint8Array> {
  const subtleAlgorithm = mapCoseAlgToWebCryptoAlg(algorithm);

  const hashed = await crypto.webcrypto.subtle.digest(subtleAlgorithm, data);

  return new Uint8Array(hashed);
}

export function mapCoseAlgToWebCryptoAlg(alg: COSEALG) {
  if ([COSEALG.RS1].indexOf(alg) >= 0) {
    return "SHA-1";
  } else if ([COSEALG.ES256, COSEALG.PS256, COSEALG.RS256].indexOf(alg) >= 0) {
    return "SHA-256";
  } else if ([COSEALG.ES384, COSEALG.PS384, COSEALG.RS384].indexOf(alg) >= 0) {
    return "SHA-384";
  } else if ([COSEALG.ES512, COSEALG.PS512, COSEALG.RS512, COSEALG.EdDSA].indexOf(alg) >= 0) {
    return "SHA-512";
  }

  throw new Error(`Could not map COSE alg value of ${alg} to a WebCrypto alg`);
}

function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

export function unwrapEC2Signature(signature: Uint8Array): Uint8Array {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }

  const finalSignature = concatBuffer([rBytes, sBytes]);

  return finalSignature;
}

export function concatBuffer(arrays: Uint8Array[]): Uint8Array {
  let pointer = 0;
  const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);

  const toReturn = new Uint8Array(totalLength);

  arrays.forEach((arr) => {
    toReturn.set(arr, pointer);
    pointer += arr.length;
  });

  return toReturn;
}

export function convertAAGUIDToString(aaguid: Uint8Array): string {
  // Raw Hex: adce000235bcc60a648b0b25f1f05503
  const hex = Array.from(aaguid, (i) => i.toString(16).padStart(2, "0")).join("");
  const segments: string[] = [
    hex.slice(0, 8), // 8
    hex.slice(8, 12), // 4
    hex.slice(12, 16), // 4
    hex.slice(16, 20), // 4
    hex.slice(20, 32), // 8
  ];

  // Formatted: adce0002-35bc-c60a-648b-0b25f1f05503
  return segments.join("-");
}

export function convertCOSEtoPKCS(cosePublicKey: Uint8Array): Uint8Array {
  // This is a little sloppy, I'm using COSEPublicKeyEC2 since it could have both x and y, but when
  // there's no y it means it's probably better typed as COSEPublicKeyOKP. I'll leave this for now
  // and revisit it later if it ever becomes an actual problem.
  const struct = new Encoder({ mapsAsObjects: false, tagUint8Array: false }).decodeMultiple(cosePublicKey) as any;

  const tag = Uint8Array.from([0x04]);
  const x = struct.get(COSEKEYS.x);
  const y = struct.get(COSEKEYS.y);

  if (!x) {
    throw new Error("COSE public key was missing x");
  }

  if (y) {
    return concatBuffer([tag, x, y]);
  }

  return concatBuffer([tag, x]);
}

export async function importKey(opts: {
  keyData: JsonWebKey;
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
}): Promise<CryptoKey> {
  const { keyData, algorithm } = opts;

  return crypto.webcrypto.subtle.importKey("jwk", keyData, algorithm, false, ["verify"]);
}
