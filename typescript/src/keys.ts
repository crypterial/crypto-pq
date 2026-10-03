import { bytes, equal } from "./bytes.ts";
import {
  CONTEXT_0,
  OCTET_STRING,
  SEQUENCE,
  Reader,
  decodePrivateKey,
  decodePublicKey,
  element,
  encodePrivateKey,
  encodePublicKey,
  invalid,
  keyFormat,
  only,
  pemDecode,
  pemEncode,
} from "./encoding.ts";
import { CryptoPQError } from "./errors.ts";

const PUBLIC = "PUBLIC KEY";

const PRIVATE = "PRIVATE KEY";

export interface KeyGenOptions {
  selfTest?: boolean;
}

export interface ImportedPrivateKey {
  readonly octets: Uint8Array | null;

  readonly raw: Uint8Array | null;

  readonly publicKey: Uint8Array | null;
}

export function requireBool(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") {
    throw new CryptoPQError("INVALID_OPTION", `${name} must be a boolean`);
  }

  return value;
}

export function requireLength(data: Uint8Array, length: number, name: string): Uint8Array {
  if (data.length !== length) {
    throw new CryptoPQError("INVALID_LENGTH", `${name} must be ${length} bytes`);
  }

  return data;
}

// A raw key of the wrong length is INVALID_LENGTH; inside DER or PEM it is an encoding error.
export function requireKeyLength(key: Uint8Array, length: number, format: unknown, name: string): Uint8Array {
  if (format !== "raw" && key.length !== length) {
    throw invalid(`${name} must be ${length} bytes`);
  }

  return requireLength(key, length, name);
}

export function readOptions<T extends object>(value: T | undefined): Partial<T> {
  if (value === undefined || value === null) {
    return {};
  }

  if (typeof value !== "object") {
    throw new TypeError("options must be an object");
  }

  return value;
}

export function selfTest(value: KeyGenOptions | undefined): boolean {
  const { selfTest = true } = readOptions(value);

  return requireBool(selfTest, "selfTest");
}

function unsupported(): CryptoPQError {
  return new CryptoPQError("UNSUPPORTED", "this algorithm has no standard DER encoding");
}

function mismatchedAlgorithm(): CryptoPQError {
  return new CryptoPQError("ALGORITHM_MISMATCH", "the key belongs to another algorithm");
}

// PEM input is decoded into a new buffer, which the caller wipes once it has copied the key out.
function derInput(format: string, data: unknown, label: string): [Uint8Array, boolean] {
  if (format === "pem") {
    return [pemDecode(label, typeof data === "string" ? data : bytes(data, "data")), true];
  }

  return [bytes(data, "data"), false];
}

export function exportPublic(format: unknown, oid: Uint8Array | null, raw: Uint8Array): Uint8Array | string {
  const kind = keyFormat(format);

  if (kind === "raw") {
    return raw.slice();
  }

  if (oid === null) {
    throw unsupported();
  }

  const der = encodePublicKey(oid, raw);

  return kind === "der" ? der : pemEncode(PUBLIC, der);
}

export function importPublic(format: unknown, data: unknown, oid: Uint8Array | null): Uint8Array {
  const kind = keyFormat(format);

  if (kind === "raw") {
    return bytes(data, "data").slice();
  }

  if (oid === null) {
    throw unsupported();
  }

  const [der] = derInput(kind, data, PUBLIC);

  const [found, key] = decodePublicKey(der);

  if (!equal(found, oid)) {
    throw mismatchedAlgorithm();
  }

  return key.slice();
}

export function exportPrivate(
  format: unknown,
  oid: Uint8Array | null,
  octets: () => Uint8Array,
  raw: Uint8Array,
): Uint8Array | string {
  const kind = keyFormat(format);

  if (kind === "raw") {
    return raw.slice();
  }

  if (oid === null) {
    throw unsupported();
  }

  const content = octets();

  const der = encodePrivateKey(oid, content);

  content.fill(0);

  if (kind === "der") {
    return der;
  }

  const pem = pemEncode(PRIVATE, der);

  der.fill(0);

  return pem;
}

// Raw input gives { raw }; PKCS#8 input whose algorithm matches gives the privateKey octets and
// the optional public key. Every returned buffer is a copy owned by the caller.
export function importPrivate(format: unknown, data: unknown, oid: Uint8Array | null): ImportedPrivateKey {
  const kind = keyFormat(format);

  if (kind === "raw") {
    return { octets: null, raw: bytes(data, "data").slice(), publicKey: null };
  }

  if (oid === null) {
    throw unsupported();
  }

  const [der, owned] = derInput(kind, data, PRIVATE);

  try {
    const [found, octets, publicKey] = decodePrivateKey(der);

    if (!equal(found, oid)) {
      throw mismatchedAlgorithm();
    }

    return { octets: octets.slice(), raw: null, publicKey: publicKey === null ? null : publicKey.slice() };
  } finally {
    if (owned) {
      der.fill(0);
    }
  }
}

// ML-KEM and ML-DSA private keys: CHOICE { seed [0] IMPLICIT OCTET STRING, expandedKey OCTET
// STRING, both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }.
export function encodeSeedChoice(key: Uint8Array, seed: boolean): Uint8Array {
  return element(seed ? CONTEXT_0 : OCTET_STRING, key);
}

export function decodeSeedChoice(
  octets: Uint8Array,
  seedSize: number,
  expandedSize: number | null,
): { seed: Uint8Array | null; expanded: Uint8Array | null } {
  let seed: Uint8Array | null = null;

  let expanded: Uint8Array | null = null;

  const tag = octets.length > 0 ? octets[0] : undefined;

  if (tag === CONTEXT_0) {
    seed = only(octets, CONTEXT_0);
  } else if (tag === OCTET_STRING) {
    expanded = only(octets, OCTET_STRING);
  } else if (tag === SEQUENCE) {
    const reader = new Reader(only(octets, SEQUENCE));

    seed = reader.read(OCTET_STRING);

    expanded = reader.read(OCTET_STRING);

    reader.finish();
  } else {
    throw invalid("unknown private key form");
  }

  if (seed !== null && seed.length !== seedSize) {
    throw invalid("the seed has the wrong length");
  }

  if (expanded !== null && expanded.length !== expandedSize) {
    throw invalid("the expanded key has the wrong length");
  }

  return { seed: seed === null ? null : seed.slice(), expanded: expanded === null ? null : expanded.slice() };
}

export function mismatch(message: string): CryptoPQError {
  return new CryptoPQError("INVALID_PRIVATE_KEY", message);
}
