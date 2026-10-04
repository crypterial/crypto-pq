import assert from "node:assert/strict";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { type Fields, MemoryStore, PRE_HASHES, hex, records, toHex, utf8 } from "./vectors.ts";

// The checks of the vectors under vectors/cross, computed by the Python reference: keys and their
// encodings, hazmat signatures with every pre-hash, implicit rejection, state blobs, and the error
// code of every malformed input. cross.test.ts runs the slow ones on worker threads.
type Algorithm = pq.KemAlgorithm | pq.SignatureAlgorithm | pq.StatefulSignatureAlgorithm;

interface Exportable {
  exportKey(format: pq.KeyFormat): Uint8Array | string;
}

export interface Outcome {
  readonly result: string;

  readonly output?: Uint8Array;

  readonly remaining?: bigint;
}

const ALGORITHMS = new Map<string, Algorithm>(
  [
    pq.ML_KEM_512,
    pq.ML_KEM_768,
    pq.ML_KEM_1024,
    pq.X_WING,
    pq.ML_DSA_44,
    pq.ML_DSA_65,
    pq.ML_DSA_87,
    pq.SLH_DSA_SHA2_128S,
    pq.SLH_DSA_SHA2_128F,
    pq.SLH_DSA_SHA2_192S,
    pq.SLH_DSA_SHA2_192F,
    pq.SLH_DSA_SHA2_256S,
    pq.SLH_DSA_SHA2_256F,
    pq.SLH_DSA_SHAKE_128S,
    pq.SLH_DSA_SHAKE_128F,
    pq.SLH_DSA_SHAKE_192S,
    pq.SLH_DSA_SHAKE_192F,
    pq.SLH_DSA_SHAKE_256S,
    pq.SLH_DSA_SHAKE_256F,
    pq.HSS_LMS,
    pq.XMSS,
    pq.XMSS_MT,
  ].map((algorithm): [string, Algorithm] => [algorithm.name, algorithm]),
);

const ENCODINGS = [
  ["der", "Der"],
  ["pem", "Pem"],
] as const;

const parsed = new Map<string, [Fields, Fields][]>();

export function vectors(name: string, field: string): [Fields, Fields][] {
  let found = parsed.get(name);

  if (found === undefined) {
    found = records(name, field);

    parsed.set(name, found);
  }

  return found;
}

function algorithm<T extends Algorithm>(name: string, kind: abstract new (...args: never[]) => T): T {
  const found = ALGORITHMS.get(name);

  assert.ok(found instanceof kind, `unknown algorithm ${name}`);

  return found;
}

function bytes(value: Uint8Array | string): Uint8Array {
  return typeof value === "string" ? utf8(value) : value;
}

function exported(key: Exportable, format: pq.KeyFormat): string {
  return toHex(bytes(key.exportKey(format)));
}

// PEM text with one character per byte, as a string import would receive it.
export function latin1(data: Uint8Array): string {
  return Array.from(data, (byte) => String.fromCharCode(byte)).join("");
}

function preHash(name: string | undefined): pq.HashAlgorithm | pq.XofAlgorithm | undefined {
  return name === undefined || name === "none" ? undefined : PRE_HASHES[name];
}

function parameters(record: Fields): pq.StatefulParameters {
  if (record.parameters !== undefined) {
    return record.parameters;
  }

  const ots = record.ots.split(",");

  return record.lms.split(",").map((lms, i): readonly [string, string] => [lms, ots[i]]);
}

// Record indices with the costliest first, so that no worker is left with a long task at the end:
// an SLH-DSA "s" set and an XMSS tree of height 10 cost the most.
function heaviestFirst(name: string, field: string): [string, number][] {
  const found = vectors(name, field);

  const cost = (index: number) => {
    const [header, record] = found[index];

    const set = record.parameters ?? header.algorithm;

    return (/SLH-DSA.*s$/.test(set) ? 10 : 1) * (set.includes("_10_") ? 30 : 1) * (set.includes("SHAKE") ? 3 : 1);
  };

  return found
    .map((_, index) => index)
    .sort((a, b) => cost(b) - cost(a))
    .map((index) => [name, index]);
}

export function kem(index: number): void {
  const [header, record] = vectors("cross/kem.txt", "seed")[index];

  const scheme = algorithm(header.algorithm, pq.KemAlgorithm);

  const context = `${scheme.name} tcId ${record.tcId}`;

  const seed = hex(record.seed);

  const pair = hazmat.generateKeyPair(scheme, seed);

  assert.equal(exported(pair.publicKey, "raw"), record.publicKey, context);

  assert.equal(exported(pair.privateKey, "raw"), record.seed, context);

  assert.ok(scheme.importPublicKey(hex(record.publicKey), "raw").equals(pair.publicKey), context);

  const keys = [pair.privateKey, scheme.importPrivateKey(seed, "raw")];

  if (record.expandedKey !== undefined) {
    for (const [format, suffix] of ENCODINGS) {
      const encoded = hex(record[`publicKey${suffix}`]);

      assert.equal(exported(pair.publicKey, format), toHex(encoded), context);

      assert.ok(scheme.importPublicKey(encoded, format).equals(pair.publicKey), context);

      const secret = hex(record[`privateKey${suffix}`]);

      assert.equal(exported(pair.privateKey, format), toHex(secret), context);

      assert.equal(exported(scheme.importPrivateKey(secret, format), "raw"), record.seed, context);
    }

    assert.ok(scheme.importPublicKey(latin1(hex(record.publicKeyPem)), "pem").equals(pair.publicKey), context);

    const expanded = scheme.importPrivateKey(hex(record.expandedKey), "raw");

    assert.equal(exported(expanded, "raw"), record.expandedKey, context);

    assert.ok(expanded.publicKey.equals(pair.publicKey), context);

    for (const [format, suffix] of ENCODINGS) {
      const encoded = hex(record[`expandedKey${suffix}`]);

      assert.equal(exported(expanded, format), toHex(encoded), context);

      assert.equal(exported(scheme.importPrivateKey(encoded, format), "raw"), record.expandedKey, context);
    }

    const both = scheme.importPrivateKey(hex(record.bothKeyDer), "der");

    assert.equal(exported(both, "der"), record.privateKeyDer, context);

    keys.push(expanded);
  }

  const encapsulation = hazmat.encapsulate(pair.publicKey, hex(record.randomness));

  assert.equal(toHex(encapsulation.ciphertext), record.ciphertext, context);

  assert.equal(toHex(encapsulation.sharedSecret), record.sharedSecret, context);

  for (const key of keys) {
    assert.equal(toHex(key.decapsulate(encapsulation.ciphertext)), record.sharedSecret, context);

    assert.equal(toHex(key.decapsulate(hex(record.tamperedCiphertext))), record.rejectedSecret, context);
  }
}

export function signatureTasks(name: string): [string, number][] {
  return heaviestFirst(name, "signature");
}

export function signature([name, index]: [string, number]): void {
  const [header, record] = vectors(name, "signature")[index];

  const scheme = algorithm(header.algorithm, pq.SignatureAlgorithm);

  const seed = hex(header.seed);

  const pair = hazmat.generateKeyPair(scheme, seed);

  if (record.signature === undefined) {
    signatureKey(scheme, pair, seed, record);

    return;
  }

  const context = `${scheme.name} ${record.mode} ${record.preHash}`;

  const message = hex(record.message);

  const options = { context: hex(record.context), preHash: preHash(record.preHash) };

  const signed =
    record.mode === "hazmat"
      ? hazmat.sign(pair.privateKey, message, hex(record.randomness), options)
      : pair.privateKey.sign(message, { ...options, deterministic: true });

  assert.equal(toHex(signed), record.signature, context);

  assert.ok(hazmat.verify(pair.publicKey, signed, message, options), context);

  assert.equal(pair.publicKey.verify(signed, message, options), record.publicVerify === "true", context);
}

function signatureKey(
  scheme: pq.SignatureAlgorithm,
  pair: pq.SignatureKeyPair,
  seed: Uint8Array,
  record: Fields,
): void {
  const context = `${scheme.name} key`;

  assert.equal(exported(pair.publicKey, "raw"), record.publicKey, context);

  assert.ok(scheme.importPublicKey(hex(record.publicKey), "raw").equals(pair.publicKey), context);

  // ML-DSA keeps its seed as the raw private key; SLH-DSA has the 4n-byte key.
  const raw = record.privateKey ?? toHex(seed);

  assert.equal(exported(pair.privateKey, "raw"), raw, context);

  assert.ok(scheme.importPrivateKey(hex(raw), "raw").publicKey.equals(pair.publicKey), context);

  for (const [format, suffix] of ENCODINGS) {
    const encoded = hex(record[`publicKey${suffix}`]);

    assert.equal(exported(pair.publicKey, format), toHex(encoded), context);

    assert.ok(scheme.importPublicKey(encoded, format).equals(pair.publicKey), context);

    const secret = hex(record[`privateKey${suffix}`]);

    assert.equal(exported(pair.privateKey, format), toHex(secret), context);

    assert.equal(exported(scheme.importPrivateKey(secret, format), "raw"), raw, context);
  }

  assert.ok(scheme.importPublicKey(latin1(hex(record.publicKeyPem)), "pem").equals(pair.publicKey), context);

  if (record.expandedKey === undefined) {
    return;
  }

  const expanded = scheme.importPrivateKey(hex(record.expandedKey), "raw");

  assert.equal(exported(expanded, "raw"), record.expandedKey, context);

  assert.ok(expanded.publicKey.equals(pair.publicKey), context);

  for (const [format, suffix] of ENCODINGS) {
    const encoded = hex(record[`expandedKey${suffix}`]);

    assert.equal(exported(expanded, format), toHex(encoded), context);

    assert.equal(exported(scheme.importPrivateKey(encoded, format), "raw"), record.expandedKey, context);
  }

  assert.equal(exported(scheme.importPrivateKey(hex(record.bothKeyDer), "der"), "der"), record.privateKeyDer, context);
}

export function statefulTasks(name: string): [string, number][] {
  return heaviestFirst(name, "stateAfter");
}

export function stateful([name, index]: [string, number]): void {
  const [header, record] = vectors(name, "stateAfter")[index];

  const scheme = algorithm(header.algorithm, pq.StatefulSignatureAlgorithm);

  const context = `${scheme.name} tcId ${record.tcId}`;

  const message = hex(record.message);

  const remaining = BigInt(record.remaining);

  const store = new MemoryStore();

  const pair = hazmat.generateStatefulKeyPair(scheme, hex(record.seed), {
    parameters: parameters(record),
    stateStore: store,
    index: BigInt(record.index),
  });

  assert.equal(toHex(store.state ?? new Uint8Array()), record.state, context);

  assert.equal(exported(pair.publicKey, "raw"), record.publicKey, context);

  for (const [format, suffix] of ENCODINGS) {
    const encoded = hex(record[`publicKey${suffix}`]);

    assert.equal(exported(pair.publicKey, format), toHex(encoded), context);

    assert.ok(scheme.importPublicKey(encoded, format).equals(pair.publicKey), context);
  }

  assert.equal(pair.privateKey.remainingSignatures(), remaining, context);

  assert.equal(toHex(pair.privateKey.sign(message)), record.signature, context);

  assert.equal(toHex(store.state ?? new Uint8Array()), record.stateAfter, context);

  assert.equal(pair.privateKey.remainingSignatures(), remaining - 1n, context);

  assert.ok(pair.publicKey.verify(hex(record.signature), message), context);

  // The key loaded from the first state signs at the same index, the same way.
  const reloaded = new MemoryStore(hex(record.state));

  const loaded = scheme.loadPrivateKey(reloaded);

  assert.ok(loaded.publicKey.equals(pair.publicKey), context);

  assert.equal(loaded.remainingSignatures(), remaining, context);

  assert.equal(toHex(loaded.sign(message)), record.signature, context);

  assert.equal(toHex(reloaded.state ?? new Uint8Array()), record.stateAfter, context);

  assert.equal(loaded.remainingSignatures(), remaining - 1n, context);
}

function field(record: Fields, name: string): Uint8Array {
  return hex(record[name] ?? "");
}

// Runs one record of cross/errors.txt, whose input is `data` (bytes, or a string for PEM).
export function execute(header: Fields, record: Fields, data: Uint8Array | string): Outcome {
  const found = ALGORITHMS.get(header.algorithm);

  const format = record.format as pq.KeyFormat;

  const [key, message, randomness] = [field(record, "key"), field(record, "message"), field(record, "randomness")];

  const options = { context: field(record, "context"), preHash: preHash(record.preHash) };

  const input = data as Uint8Array;

  try {
    if (found instanceof pq.KemAlgorithm) {
      switch (record.operation) {
        case "importPublicKey":
          return { result: "ok", output: bytes(found.importPublicKey(data, format).exportKey("raw")) };
        case "importPrivateKey":
          return { result: "ok", output: bytes(found.importPrivateKey(data, format).publicKey.exportKey("raw")) };
        case "exportPublicKey":
          return { result: "ok", output: bytes(hazmat.generateKeyPair(found, key).publicKey.exportKey(format)) };
        case "exportPrivateKey":
          return { result: "ok", output: bytes(hazmat.generateKeyPair(found, key).privateKey.exportKey(format)) };
        case "generate":
          return { result: "ok", output: bytes(hazmat.generateKeyPair(found, input).publicKey.exportKey("raw")) };
        case "encapsulate": {
          const encapsulation = hazmat.encapsulate(found.importPublicKey(key, "raw"), randomness);

          return { result: "ok", output: new Uint8Array([...encapsulation.sharedSecret, ...encapsulation.ciphertext]) };
        }
        case "decapsulate":
          return { result: "ok", output: found.importPrivateKey(key, "raw").decapsulate(input) };
      }
    } else if (found instanceof pq.SignatureAlgorithm) {
      switch (record.operation) {
        case "importPublicKey":
          return { result: "ok", output: bytes(found.importPublicKey(data, format).exportKey("raw")) };
        case "importPrivateKey":
          return { result: "ok", output: bytes(found.importPrivateKey(data, format).publicKey.exportKey("raw")) };
        case "generate":
          return { result: "ok", output: bytes(hazmat.generateKeyPair(found, input).publicKey.exportKey("raw")) };
        case "sign":
          return {
            result: "ok",
            output: found.importPrivateKey(key, "raw").sign(message, { ...options, deterministic: true }),
          };
        case "hazmatSign":
          return {
            result: "ok",
            output: hazmat.sign(found.importPrivateKey(key, "raw"), message, randomness, options),
          };
        case "verify":
          return { result: String(found.importPublicKey(key, "raw").verify(input, message, options)) };
        case "hazmatVerify":
          return { result: String(hazmat.verify(found.importPublicKey(key, "raw"), input, message, options)) };
      }
    } else if (found instanceof pq.StatefulSignatureAlgorithm) {
      switch (record.operation) {
        case "importPublicKey":
          return { result: "ok", output: bytes(found.importPublicKey(data, format).exportKey("raw")) };
        case "generate": {
          const pair = hazmat.generateStatefulKeyPair(found, input, {
            parameters: parameters(record),
            stateStore: new MemoryStore(),
            index: BigInt(record.index),
          });

          return {
            result: "ok",
            output: bytes(pair.publicKey.exportKey("raw")),
            remaining: pair.privateKey.remainingSignatures(),
          };
        }
        case "loadPrivateKey": {
          const privateKey = found.loadPrivateKey(new MemoryStore(input));

          return {
            result: "ok",
            output: bytes(privateKey.publicKey.exportKey("raw")),
            remaining: privateKey.remainingSignatures(),
          };
        }
        case "sign":
          return { result: "ok", output: found.loadPrivateKey(new MemoryStore(input)).sign(message) };
        case "verify":
          return { result: String(found.importPublicKey(key, "raw").verify(input, message)) };
      }
    }
  } catch (error) {
    if (error instanceof pq.CryptoPQError) {
      return { result: error.code };
    }

    throw error;
  }

  throw new Error(`unknown operation ${record.operation} for ${header.algorithm}`);
}
