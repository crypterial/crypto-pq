import assert from "node:assert/strict";
import process from "node:process";
import { test } from "node:test";

import { Reader, decodePrivateKey, decodePublicKey, element, encodePublicKey, objectIdentifier, pemDecode, pemEncode } from "../src/encoding.ts";
import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { decodeSeedChoice, encodeSeedChoice } from "../src/keys.ts";
import { parallel } from "./parallel.ts";
import { COUNTERS, SharedStore } from "./shared-store.ts";
import { MemoryStore, concat, hex, isCode, records, toHex } from "./vectors.ts";

// Untrusted input gets only the defined errors: random and mutated encodings, signatures,
// ciphertexts and state blobs go through every parsing path, accepted inputs must round-trip, and
// nothing may throw anything else. A deterministic generator keeps every run reproducible;
// CRYPTO_PQ_FUZZ=1 runs many more rounds.
const FUZZ = Boolean(process.env.CRYPTO_PQ_FUZZ);

const SCALE = FUZZ ? 50 : 1;

type Format = "raw" | "der" | "pem";

const FORMATS: Format[] = ["raw", "der", "pem"];

const MASK = (1n << 64n) - 1n;

// SplitMix64, the generator of every implementation's robustness tests.
class Random {
  #state: bigint;

  constructor(seed: number) {
    this.#state = BigInt(seed);
  }

  next(): bigint {
    this.#state = (this.#state + 0x9e3779b97f4a7c15n) & MASK;

    let z = this.#state;

    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK;

    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK;

    return z ^ (z >> 31n);
  }

  below(bound: number): number {
    return Number(this.next() % BigInt(bound));
  }

  bytes(size: number): Uint8Array {
    return Uint8Array.from({ length: size }, () => Number(this.next() & 0xffn));
  }

  choice<T>(items: readonly T[]): T {
    return items[this.below(items.length)];
  }
}

function pattern(size: number, first = 0): Uint8Array {
  return Uint8Array.from({ length: size }, (_, i) => (first + i) & 0xff);
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function ascii(text: string): Uint8Array {
  return Uint8Array.from(text, (character) => character.charCodeAt(0));
}

const TAGS = [0x02, 0x03, 0x04, 0x06, 0x30, 0x80, 0x81, 0xa0];

// Indefinite, gigabytes, non-minimal, five bytes long, and plain wrong lengths.
const LENGTHS = [[0x80], [0x84, 0xff, 0xff, 0xff, 0xff], [0x84, 0x7f, 0xff, 0xff, 0xff], [0x83, 0xff, 0xff, 0xff], [0x82, 0xff, 0xff], [0x81, 0x05], [0x81, 0x7f], [0x82, 0x00, 0x80], [0x85, 0x01, 0x00, 0x00, 0x00, 0x00], [0x00], [0x01], [0x7f]];

const SPACES = [" ", "\t", "\n", "\r\n", "\v", "\f"];

// The OIDs of every algorithm and of SHA-256, those of the stateful schemes, and broken ones.
const OIDS: Uint8Array[] = [
  ...[1, 2, 3, 4].map((arc) => element(0x06, objectIdentifier(`2.16.840.1.101.3.4.4.${arc}`))),
  ...Array.from({ length: 32 }, (_, i) => element(0x06, objectIdentifier(`2.16.840.1.101.3.4.3.${16 + i}`))),
  ...["2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.9.16.3.17", "1.3.6.1.5.5.7.6.34", "1.3.6.1.5.5.7.6.35"].map((dotted) => element(0x06, objectIdentifier(dotted))),
  Uint8Array.of(0x06, 0x00),
  Uint8Array.of(0x06, 0x01, 0x00),
  Uint8Array.of(0x06, 0x81, 0x01, 0x2a),
];

function splice(data: Uint8Array, start: number, end: number, insert: ArrayLike<number> = []): Uint8Array {
  return concat(data.subarray(0, start), Uint8Array.from(insert), data.subarray(Math.min(end, data.length)));
}

function tagPosition(rng: Random, data: Uint8Array): number | null {
  for (let i = 0; i < 16; i++) {
    const position = rng.below(data.length);

    if (TAGS.includes(data[position]) && position + 1 < data.length) {
      return position;
    }
  }

  return null;
}

function oidPosition(rng: Random, data: Uint8Array): number | null {
  const starts: number[] = [];

  for (let i = 0; i + 1 < data.length; i++) {
    if (data[i] === 0x06 && data[i + 1] < 0x10 && i + 2 + data[i + 1] <= data.length) {
      starts.push(i);
    }
  }

  return starts.length > 0 ? rng.choice(starts) : null;
}

// One random edit: bits, bytes, insertions, deletions, truncation, DER length fields (huge,
// indefinite, non-minimal), tags, OIDs, or a slice of another valid encoding.
function mutate(rng: Random, input: Uint8Array, others: readonly Uint8Array[] = []): Uint8Array {
  if (input.length === 0) {
    return rng.bytes(rng.below(16));
  }

  let data = input.slice();

  const operation = rng.below(11);

  const position = rng.below(data.length);

  // An edit that does not apply (no tag, no OID, nothing to splice from) duplicates a slice.
  const header = operation === 6 || operation === 7 ? tagPosition(rng, data) : null;

  const start = operation === 8 ? oidPosition(rng, data) : null;

  if (operation === 0) {
    data[position] ^= 1 << rng.below(8);
  } else if (operation === 1) {
    const random = rng.below(256);

    data[position] = rng.choice([0x00, 0x01, 0x7f, 0x80, 0xff, random]);
  } else if (operation === 2) {
    data = splice(data, position, position, rng.bytes(1 + rng.below(4)));
  } else if (operation === 3) {
    data = splice(data, position, position + 1 + rng.below(4));
  } else if (operation === 4) {
    data = data.slice(0, position);
  } else if (operation === 5) {
    data = concat(data, rng.bytes(1 + rng.below(32)));
  } else if (operation === 6 && header !== null) {
    const first = data[header + 1];

    const size = 1 + (first & 0x80 ? first & 0x7f : 0);

    data = splice(data, header + 1, header + 1 + size, rng.below(2) === 1 ? rng.choice(LENGTHS) : [rng.below(256)]);
  } else if (operation === 7 && header !== null) {
    const random = rng.below(256);

    data[header] = rng.below(2) === 1 ? rng.choice(TAGS) : random;
  } else if (operation === 8 && start !== null) {
    data = splice(data, start, start + 2 + data[start + 1], rng.choice(OIDS));
  } else if (operation === 9 && others.length > 0) {
    const other = rng.choice(others);

    const from = rng.below(other.length + 1);

    const piece = other.subarray(from, from + rng.below(64));

    data = splice(data, position, position + rng.below(64), piece);
  } else {
    const end = Math.min(data.length, position + 1 + rng.below(16));

    data = splice(data, position, position, data.slice(position, end));
  }

  return data;
}

function isSpace(byte: number): boolean {
  return byte === 0x20 || (byte >= 0x09 && byte <= 0x0d);
}

function mutatePem(rng: Random, input: Uint8Array): Uint8Array {
  const operation = rng.below(8);

  const position = rng.below(input.length + 1);

  if (operation === 0) {
    return splice(input, position, position, ascii(rng.choice(SPACES).repeat(1 + rng.below(3))));
  }

  if (operation === 1) {
    return splice(input, position, position, [0x80 + rng.below(128)]);
  }

  if (operation === 2) {
    return splice(input, position, position, [0x3d]);
  }

  const text = String.fromCharCode(...input);

  if (operation === 3) {
    return ascii(rng.below(2) === 1 ? text.replace("PUBLIC", "PRIVATE") : text.replace("PRIVATE", "PUBLIC"));
  }

  if (operation === 4) {
    return ascii(text.replaceAll("\n", ""));
  }

  if (operation === 5) {
    const width = 1 + rng.below(80);

    const compact = input.filter((byte) => !isSpace(byte));

    const lines: Uint8Array[] = [];

    for (let i = 0; i < compact.length; i += width) {
      lines.push(compact.subarray(i, i + width), Uint8Array.of(0x0a));
    }

    return concat(...lines);
  }

  return mutate(rng, input);
}

function* inputs(rng: Random, seeds: readonly Uint8Array[], rounds: number): Generator<Uint8Array> {
  for (let round = 0; round < rounds; round++) {
    if (rng.below(8) === 0) {
      yield rng.bytes(rng.below(96));

      continue;
    }

    let data = rng.choice(seeds);

    for (let edits = 1 + rng.below(3); edits > 0; edits--) {
      data = mutate(rng, data, seeds);
    }

    yield data;
  }
}

// Runs one call; a CryptoPQError must carry one of the codes, and anything else thrown fails.
function guarded<T>(codes: readonly pq.ErrorCode[], what: string, data: Uint8Array, run: () => T): T | null {
  try {
    return run();
  } catch (error) {
    assert.ok(error instanceof pq.CryptoPQError && codes.includes(error.code), `${what}: ${String(error)} for ${toHex(data)}`);

    return null;
  }
}

function asBytes(encoded: Uint8Array | string): Uint8Array {
  return typeof encoded === "string" ? ascii(encoded) : encoded;
}

interface Exportable {
  exportKey(format: Format): Uint8Array | string;
}

// An accepted key exports to the encoding it came from: byte for byte in raw and DER, which are
// canonical, and to the same DER inside PEM, which allows any whitespace.
function sameEncoding(key: Exportable, data: Uint8Array, format: Format, label: string): void {
  const exported = asBytes(key.exportKey(format));

  if (format === "pem") {
    assert.ok(same(pemDecode(label, data), pemDecode(label, exported)), `PEM round trip of ${toHex(data)}`);
  } else {
    assert.ok(same(exported, data), `round trip of ${toHex(data)}`);
  }
}

function stableExports(key: Exportable, load: (data: Uint8Array, format: Format) => Exportable): void {
  for (const format of FORMATS) {
    let exported: Uint8Array;

    try {
      exported = asBytes(key.exportKey(format));
    } catch (error) {
      assert.ok(isCode("UNSUPPORTED")(error));

      continue;
    }

    assert.ok(same(asBytes(load(exported, format).exportKey("raw")), asBytes(key.exportKey("raw"))));
  }
}

function importCodes(format: Format, check: pq.ErrorCode, der = true): pq.ErrorCode[] {
  if (format === "raw") {
    return ["INVALID_LENGTH", check];
  }

  return der ? ["INVALID_ENCODING", "ALGORITHM_MISMATCH", check] : ["UNSUPPORTED"];
}

const KEMS = [pq.ML_KEM_512, pq.ML_KEM_768, pq.ML_KEM_1024, pq.X_WING];

const SLH_DSA = [
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
];

// The fast sets by default; every set in a long run.
const SIGNATURES = [pq.ML_DSA_44, pq.ML_DSA_65, pq.ML_DSA_87, ...SLH_DSA.filter((algorithm) => FUZZ || algorithm.name.endsWith("f"))];

const PRE_HASHES: [number, pq.HashAlgorithm | pq.XofAlgorithm][] = [
  [112, pq.SHA_224],
  [128, pq.SHA_256],
  [192, pq.SHA_384],
  [256, pq.SHA_512],
  [112, pq.SHA_512_224],
  [128, pq.SHA_512_256],
  [112, pq.SHA3_224],
  [128, pq.SHA3_256],
  [192, pq.SHA3_384],
  [256, pq.SHA3_512],
  [128, pq.SHAKE128],
  [256, pq.SHAKE256],
];

function isMlDsa(algorithm: pq.SignatureAlgorithm): boolean {
  return algorithm.name.startsWith("ML-DSA");
}

// Seed and randomness sizes, and the collision strength each algorithm requires.
function kemSizes(algorithm: pq.KemAlgorithm): [number, number] {
  return algorithm === pq.X_WING ? [32, 64] : [64, 32];
}

function signatureSizes(algorithm: pq.SignatureAlgorithm): [number, number] {
  return isMlDsa(algorithm) ? [32, 32] : [(3 * algorithm.publicKeySize) / 2, algorithm.publicKeySize / 2];
}

function strength(algorithm: pq.SignatureAlgorithm): number {
  return isMlDsa(algorithm) ? { "ML-DSA-44": 128, "ML-DSA-65": 192, "ML-DSA-87": 256 }[algorithm.name]! : 4 * algorithm.publicKeySize;
}

function kemFixtures(): [pq.KemAlgorithm, pq.KemKeyPair, pq.Encapsulation][] {
  return KEMS.map((algorithm) => {
    const [seed, randomness] = kemSizes(algorithm);

    const pair = hazmat.generateKeyPair(algorithm, pattern(seed));

    return [algorithm, pair, hazmat.encapsulate(pair.publicKey, pattern(randomness, 0x80))];
  });
}

test("DER decoders take any bytes", () => {
  const pair = hazmat.generateKeyPair(pq.ML_KEM_512, pattern(64));

  const seeds = [asBytes(pair.publicKey.exportKey("der")), asBytes(pair.privateKey.exportKey("der")), encodeSeedChoice(new Uint8Array(1632), false)];

  const rng = new Random(1);

  for (const data of inputs(rng, seeds, 3000 * SCALE)) {
    const reader = new Reader(data);

    const tag = rng.choice(TAGS);

    let offset = 0;

    for (;;) {
      const content = guarded(["INVALID_ENCODING"], "read", data, () => reader.read(tag));

      if (content === null) {
        break;
      }

      const encoded = element(tag, content);

      assert.ok(same(encoded, data.subarray(offset, offset + encoded.length)));

      offset += encoded.length;
    }

    const publicKey = guarded(["INVALID_ENCODING"], "public key", data, () => decodePublicKey(data));

    if (publicKey !== null) {
      assert.ok(same(encodePublicKey(...publicKey), data));
    }

    guarded(["INVALID_ENCODING"], "private key", data, () => decodePrivateKey(data));

    const choice = guarded(["INVALID_ENCODING"], "seed choice", data, () => decodeSeedChoice(data, 64, 1632));

    if (choice !== null) {
      const { seed, expanded } = choice;

      const encoded = seed !== null && expanded !== null ? element(0x30, concat(element(0x04, seed), element(0x04, expanded))) : encodeSeedChoice((seed ?? expanded)!, seed !== null);

      assert.ok(same(encoded, data));
    }
  }
});

test("PEM decoding takes any text", () => {
  const pair = hazmat.generateKeyPair(pq.ML_DSA_44, pattern(32));

  const seeds = [ascii(pair.publicKey.exportKey("pem")), ascii(pair.privateKey.exportKey("pem")), ascii("-----BEGIN PUBLIC KEY-----END PUBLIC KEY-----")];

  const rng = new Random(2);

  for (let round = 0; round < 1500 * SCALE; round++) {
    let text = rng.choice(seeds);

    for (let edits = 1 + rng.below(3); edits > 0; edits--) {
      text = mutatePem(rng, text);
    }

    const label = rng.choice(["PUBLIC KEY", "PRIVATE KEY"]);

    const input = rng.below(2) === 1 ? text : String.fromCharCode(...text);

    const der = guarded(["INVALID_ENCODING"], "pem", text, () => pemDecode(label, input));

    if (der !== null) {
      assert.ok(same(pemDecode(label, pemEncode(label, der)), der));
    }
  }
});

test("key import takes any bytes", () => {
  const rng = new Random(3);

  // The expanded private keys of the first ACVP key generation record of each parameter set.
  const expandedKeys = new Map<string, Uint8Array>();

  for (const [header, record] of records("acvp/ML-KEM-keyGen.txt", "dk")) {
    if (!expandedKeys.has(header.parameterSet)) {
      expandedKeys.set(header.parameterSet, hex(record.dk));
    }
  }

  for (const [algorithm, pair] of kemFixtures()) {
    const der = algorithm !== pq.X_WING;

    const dk = expandedKeys.get(algorithm.name);

    const expanded = dk === undefined ? null : algorithm.importPrivateKey(dk, "raw");

    for (const format of FORMATS) {
      const seeds = (key: Exportable) => [der || format === "raw" ? asBytes(key.exportKey(format)) : asBytes(pair.publicKey.exportKey("raw")), ...(key === pair.privateKey && expanded !== null ? [asBytes(expanded.exportKey(format))] : [])];

      for (const data of inputs(rng, seeds(pair.publicKey), 25 * SCALE)) {
        const key = guarded(importCodes(format, "INVALID_PUBLIC_KEY", der), algorithm.name, data, () => algorithm.importPublicKey(data, format));

        if (key !== null) {
          sameEncoding(key, data, format, "PUBLIC KEY");

          stableExports(key, (encoded, again) => algorithm.importPublicKey(encoded, again));

          assert.equal(hazmat.encapsulate(key, new Uint8Array(kemSizes(algorithm)[1])).ciphertext.length, algorithm.ciphertextSize);
        }
      }

      for (const data of inputs(rng, seeds(pair.privateKey), 25 * SCALE)) {
        const key = guarded(importCodes(format, "INVALID_PRIVATE_KEY", der), algorithm.name, data, () => algorithm.importPrivateKey(data, format));

        if (key !== null) {
          if (format === "raw") {
            assert.ok(same(asBytes(key.exportKey("raw")), data));
          }

          stableExports(key, (encoded, again) => algorithm.importPrivateKey(encoded, again));

          // A key from a seed decapsulates what its public key encapsulates. FIPS 203 checks
          // only the hash of the public part of an expanded key, so one with another secret
          // vector is accepted and gives the implicit rejection, SHAKE256(z || c).
          const encapsulation = hazmat.encapsulate(key.publicKey, new Uint8Array(kemSizes(algorithm)[1]));

          const secret = key.decapsulate(encapsulation.ciphertext);

          const raw = asBytes(key.exportKey("raw"));

          if (!same(secret, encapsulation.sharedSecret)) {
            assert.notEqual(raw.length, kemSizes(algorithm)[0]);

            assert.ok(same(secret, pq.SHAKE256.digest(concat(raw.subarray(raw.length - 32), encapsulation.ciphertext), 32)));
          }
        }
      }
    }
  }

  for (const algorithm of SIGNATURES) {
    const pair = hazmat.generateKeyPair(algorithm, pattern(signatureSizes(algorithm)[0]));

    const rounds = (isMlDsa(algorithm) ? 25 : algorithm.name.endsWith("s") ? 1 : 4) * SCALE;

    for (const format of FORMATS) {
      for (const data of inputs(rng, [asBytes(pair.publicKey.exportKey(format))], rounds)) {
        const key = guarded(importCodes(format, "INVALID_LENGTH"), algorithm.name, data, () => algorithm.importPublicKey(data, format));

        if (key !== null) {
          sameEncoding(key, data, format, "PUBLIC KEY");

          stableExports(key, (encoded, again) => algorithm.importPublicKey(encoded, again));
        }
      }

      for (const data of inputs(rng, [asBytes(pair.privateKey.exportKey(format))], rounds)) {
        const key = guarded(importCodes(format, "INVALID_PRIVATE_KEY"), algorithm.name, data, () => algorithm.importPrivateKey(data, format));

        if (key === null) {
          continue;
        }

        if (format === "raw") {
          assert.ok(same(asBytes(key.exportKey("raw")), data));
        }

        stableExports(key, (encoded, again) => algorithm.importPrivateKey(encoded, again));

        if (isMlDsa(algorithm)) {
          const signature = hazmat.sign(key, ascii("accepted"), new Uint8Array(32));

          assert.ok(key.publicKey.verify(signature, ascii("accepted")));
        } else {
          const n = algorithm.publicKeySize / 2;

          assert.ok(same(asBytes(key.exportKey("raw")).subarray(2 * n), asBytes(key.publicKey.exportKey("raw"))));
        }
      }
    }
  }

  const stateful: [pq.StatefulSignatureAlgorithm, string, number][] = [
    [pq.HSS_LMS, "000000010000000a00000005", 40],
    [pq.HSS_LMS, "000000080000001400000010", 40],
    [pq.XMSS, "00000001", 64],
    [pq.XMSS, "00000015", 48],
    [pq.XMSS_MT, "00000031", 48],
    [pq.XMSS_MT, "00000008", 64],
  ];

  for (const [algorithm, prefix, size] of stateful) {
    const raw = concat(Uint8Array.from(prefix.match(/../g)!, (pair) => parseInt(pair, 16)), pattern(size));

    const imported = algorithm.importPublicKey(raw, "raw");

    for (const format of FORMATS) {
      for (const data of inputs(rng, [asBytes(imported.exportKey(format))], 150 * SCALE)) {
        const codes: pq.ErrorCode[] = format === "raw" ? ["INVALID_PUBLIC_KEY"] : ["INVALID_ENCODING", "ALGORITHM_MISMATCH", "INVALID_PUBLIC_KEY"];

        const key = guarded(codes, algorithm.name, data, () => algorithm.importPublicKey(data, format));

        if (key !== null) {
          sameEncoding(key, data, format, "PUBLIC KEY");

          stableExports(key, (encoded, again) => algorithm.importPublicKey(encoded, again));

          assert.equal(key.verify(new Uint8Array(64), new Uint8Array()), false);
        }
      }
    }
  }
});

// FIPS 203 checks only the hash of the public part of an expanded key, so one whose secret vector
// was changed is accepted and decapsulates to the implicit rejection, SHAKE256(z || c).
test("an inconsistent expanded ML-KEM key decapsulates to the implicit rejection", () => {
  const seen = new Set<string>();

  for (const [header, record] of records("acvp/ML-KEM-keyGen.txt", "dk")) {
    if (seen.has(header.parameterSet)) {
      continue;
    }

    seen.add(header.parameterSet);

    const algorithm = KEMS.find((candidate) => candidate.name === header.parameterSet)!;

    const dk = hex(record.dk);

    dk[0] ^= 1;

    const key = algorithm.importPrivateKey(dk, "raw");

    const encapsulation = hazmat.encapsulate(key.publicKey, pattern(32, 0x80));

    const rejection = pq.SHAKE256.digest(concat(dk.subarray(dk.length - 32), encapsulation.ciphertext), 32);

    assert.ok(same(key.decapsulate(encapsulation.ciphertext), rejection));
  }

  assert.equal(seen.size, 3);
});

test("PEM import takes any text", () => {
  const rng = new Random(10);

  const kem = hazmat.generateKeyPair(pq.ML_KEM_768, pattern(64));

  const dsa = hazmat.generateKeyPair(pq.ML_DSA_44, pattern(32));

  const cases: [Uint8Array, (data: Uint8Array, format: Format) => Exportable, boolean][] = [
    [ascii(kem.publicKey.exportKey("pem")), (data, format) => pq.ML_KEM_768.importPublicKey(data, format), true],
    [ascii(kem.privateKey.exportKey("pem")), (data, format) => pq.ML_KEM_768.importPrivateKey(data, format), false],
    [ascii(dsa.publicKey.exportKey("pem")), (data, format) => pq.ML_DSA_44.importPublicKey(data, format), true],
    [ascii(dsa.privateKey.exportKey("pem")), (data, format) => pq.ML_DSA_44.importPrivateKey(data, format), false],
  ];

  for (let round = 0; round < 300 * SCALE; round++) {
    const [seed, load, isPublic] = rng.choice(cases);

    let text = seed;

    for (let edits = 1 + rng.below(3); edits > 0; edits--) {
      text = mutatePem(rng, text);
    }

    const codes: pq.ErrorCode[] = ["INVALID_ENCODING", "ALGORITHM_MISMATCH", isPublic ? "INVALID_PUBLIC_KEY" : "INVALID_PRIVATE_KEY"];

    const key = guarded(codes, "pem", text, () => load(text, "pem"));

    if (key !== null && isPublic) {
      sameEncoding(key, text, "pem", "PUBLIC KEY");
    } else if (key !== null) {
      stableExports(key, load);
    }
  }

  assert.throws(() => pq.ML_KEM_768.importPublicKey(7 as unknown as Uint8Array, "der"), TypeError);

  assert.throws(() => pq.ML_KEM_768.importPublicKey("text" as unknown as Uint8Array, "raw"), TypeError);

  for (const format of ["jwk", "RAW", "", null, 1]) {
    assert.throws(() => pq.ML_KEM_768.importPublicKey(new Uint8Array(), format as Format), isCode("INVALID_OPTION"));
  }
});

test("verification takes any signature, message, context and pre-hash", () => {
  const rng = new Random(6);

  for (const algorithm of SIGNATURES) {
    const size = algorithm.signatureSize;

    let publicKey: pq.SignaturePublicKey;

    let message = new Uint8Array();

    let signature = new Uint8Array(size);

    const real = isMlDsa(algorithm);

    // SLH-DSA keys are expensive to make, so verification gets a public key of the right size,
    // which is all that it checks, and an all-zero signature.
    if (real) {
      const pair = hazmat.generateKeyPair(algorithm, pattern(32));

      publicKey = pair.publicKey;

      message = ascii("crypto-pq robustness");

      signature = hazmat.sign(pair.privateKey, message, pattern(32, 0x60), { context: ascii("context") });
    } else {
      publicKey = algorithm.importPublicKey(pattern(algorithm.publicKeySize, 0x20), "raw");
    }

    for (let round = 0; round < (real ? 60 : 6) * SCALE; round++) {
      let candidate: Uint8Array;

      if (rng.below(8) !== 0) {
        candidate = signature;

        for (let edits = 1 + rng.below(2); edits > 0; edits--) {
          candidate = mutate(rng, candidate);
        }
      } else {
        candidate = rng.bytes(rng.below(size + 2));
      }

      if (rng.below(2) === 1) {
        const resized = new Uint8Array(size);

        resized.set(candidate.subarray(0, size));

        candidate = resized;
      }

      const text = rng.below(2) === 1 ? mutate(rng, message) : message;

      const randomContext = rng.bytes(rng.below(300));

      const context = rng.choice([ascii("context"), new Uint8Array(), randomContext, new Uint8Array(255), new Uint8Array(256)]);

      const choice = rng.below(PRE_HASHES.length + 1);

      const preHash = choice < PRE_HASHES.length ? PRE_HASHES[choice][1] : undefined;

      const policy = rng.below(4) !== 0;

      const options = { context, preHash };

      const valid = guarded([], algorithm.name, candidate, () => (policy ? publicKey.verify(candidate, text, options) : hazmat.verify(publicKey, candidate, text, options)));

      assert.equal(typeof valid, "boolean");

      const weak = policy && choice < PRE_HASHES.length && PRE_HASHES[choice][0] < strength(algorithm);

      if (valid) {
        assert.ok(!weak && context.length <= 255 && candidate.length === size);

        assert.ok(real && same(candidate, signature) && same(text, message) && same(context, ascii("context")) && preHash === undefined, `${algorithm.name} accepted ${toHex(candidate)}`);
      }
    }

    assert.throws(() => publicKey.verify(signature, message, { preHash: "SHA-512" as unknown as pq.HashAlgorithm }), isCode("INVALID_OPTION"));

    assert.throws(() => publicKey.verify("signature" as unknown as Uint8Array, message), TypeError);
  }

  const levels: [string, string][] = [
    ["LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2"],
    ["LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1"],
  ];

  const hss = hazmat.generateStatefulKeyPair(pq.HSS_LMS, pattern(40), { parameters: levels, stateStore: new MemoryStore(), index: 33n });

  const mt = hazmat.generateStatefulKeyPair(pq.XMSS_MT, pattern(72), { parameters: "XMSSMT-SHA2_20/4_192", stateStore: new MemoryStore(), index: 7n });

  const message = ascii("crypto-pq robustness");

  const cases: [pq.StatefulSignatureAlgorithm, Uint8Array, Uint8Array][] = [
    [pq.HSS_LMS, asBytes(hss.publicKey.exportKey("raw")), hss.privateKey.sign(message)],
    [pq.XMSS_MT, asBytes(mt.publicKey.exportKey("raw")), mt.privateKey.sign(message)],
    [pq.XMSS, concat(Uint8Array.of(0, 0, 0, 0x0d), pattern(48)), new Uint8Array(4 + 24 + (51 + 10) * 24)],
  ];

  for (const [algorithm, raw, signature] of cases) {
    const publicKey = algorithm.importPublicKey(raw, "raw");

    for (let round = 0; round < 60 * SCALE; round++) {
      const candidate = rng.below(8) !== 0 ? mutate(rng, signature) : rng.bytes(rng.below(signature.length + 2));

      const text = rng.below(2) === 1 ? mutate(rng, message) : message;

      const valid = guarded([], algorithm.name, candidate, () => publicKey.verify(candidate, text));

      if (valid) {
        assert.ok(same(candidate, signature) && same(text, message), `${algorithm.name} accepted ${toHex(candidate)}`);
      }
    }
  }

  for (let round = 0; round < 300 * SCALE; round++) {
    const algorithm = rng.choice([pq.HSS_LMS, pq.XMSS, pq.XMSS_MT]);

    const raw = mutate(rng, rng.choice(cases)[1]);

    const publicKey = guarded(["INVALID_PUBLIC_KEY"], algorithm.name, raw, () => algorithm.importPublicKey(raw, "raw"));

    if (publicKey !== null) {
      const signature = rng.bytes(rng.below(4096));

      assert.equal(typeof guarded([], algorithm.name, signature, () => publicKey.verify(signature, new Uint8Array())), "boolean");
    }
  }
});

test("decapsulation takes any ciphertext", () => {
  const rng = new Random(8);

  for (const [algorithm, pair, encapsulation] of kemFixtures()) {
    const size = algorithm.ciphertextSize;

    for (let round = 0; round < 60 * SCALE; round++) {
      let candidate = rng.below(8) !== 0 ? mutate(rng, encapsulation.ciphertext) : rng.bytes(rng.below(size + 2));

      if (rng.below(2) === 1) {
        const resized = new Uint8Array(size);

        resized.set(candidate.subarray(0, size));

        candidate = resized;
      }

      const secret = guarded(candidate.length === size ? [] : ["INVALID_LENGTH"], algorithm.name, candidate, () => pair.privateKey.decapsulate(candidate));

      if (candidate.length !== size) {
        assert.equal(secret, null);
      } else {
        assert.equal(secret!.length, 32);

        // Implicit rejection: any other ciphertext gives a different secret.
        assert.equal(same(secret!, encapsulation.sharedSecret), same(candidate, encapsulation.ciphertext), toHex(candidate));
      }
    }
  }
});

const XMSS_SHAPES: [number, number][] = [
  [20, 2],
  [20, 4],
  [40, 2],
  [40, 4],
  [40, 8],
  [60, 3],
  [60, 6],
  [60, 12],
];

// [n, h, d] of an XMSS or XMSS^MT code point.
function xmssParameters(multi: boolean, oid: number): [number, number, number] | null {
  const families: [number, number][] = multi
    ? [
        [0x01, 32],
        [0x21, 24],
        [0x29, 32],
        [0x31, 24],
      ]
    : [
        [0x01, 32],
        [0x0d, 24],
        [0x10, 32],
        [0x13, 24],
      ];

  for (const [base, n] of families) {
    const offset = oid - base;

    if (multi && offset >= 0 && offset < 8) {
      return [n, ...XMSS_SHAPES[offset]];
    }

    if (!multi && offset >= 0 && offset < 3) {
      return [n, [10, 16, 20][offset], 1];
    }
  }

  return null;
}

// [n, w or h, family] of an LM-OTS or LMS type code.
function otsType(code: number): [number, number, number] | null {
  return code >= 1 && code <= 16 ? [[32, 24, 32, 24][(code - 1) >> 2], [1, 2, 4, 8][(code - 1) & 3], (code - 1) >> 2] : null;
}

function lmsType(code: number): [number, number, number] | null {
  return code >= 5 && code <= 24 ? [[32, 24, 32, 24][Math.floor((code - 5) / 5)], [5, 10, 15, 20, 25][(code - 5) % 5], Math.floor((code - 5) / 5)] : null;
}

function otsP(n: number, w: number): number {
  const u = Math.ceil((8 * n) / w);

  return u + Math.ceil((((1 << w) - 1) * u).toString(2).length / w);
}

function u32(data: Uint8Array, offset: number): number {
  return new DataView(data.buffer, data.byteOffset).getUint32(offset);
}

function u64(data: Uint8Array, offset: number): bigint {
  return new DataView(data.buffer, data.byteOffset).getBigUint64(offset);
}

function sealed(body: Uint8Array): Uint8Array {
  return concat(body, pq.SHA_256.digest(body).subarray(0, 16));
}

// What loading a state blob must give, from the format rules alone: the error code, or the index,
// the capacity and the number of hash calls that building the key's trees takes.
function expectedState(algorithm: pq.StatefulSignatureAlgorithm, state: Uint8Array): pq.ErrorCode | [bigint, bigint, number] {
  if (state.length < 18) {
    return "INVALID_PRIVATE_KEY";
  }

  const full = state.subarray(0, state.length - 16);

  if (!same(pq.SHA_256.digest(full).subarray(0, 16), state.subarray(state.length - 16)) || full[0] !== 1) {
    return "INVALID_PRIVATE_KEY";
  }

  if (full[1] !== [pq.HSS_LMS, pq.XMSS, pq.XMSS_MT].indexOf(algorithm) + 1) {
    return "ALGORITHM_MISMATCH";
  }

  const body = full.subarray(2);

  if (algorithm !== pq.HSS_LMS) {
    const parameters = body.length >= 4 ? xmssParameters(algorithm === pq.XMSS_MT, u32(body, 0)) : null;

    if (parameters === null || body.length !== 12 + 3 * parameters[0]) {
      return "INVALID_PRIVATE_KEY";
    }

    const [n, h, d] = parameters;

    return [u64(body, 4), 1n << BigInt(h), d * 2 ** (h / d) * (2 * n + 3) * 16];
  }

  const count = body.length > 0 ? body[0] : 0;

  if (body.length < 1 + 8 * count || count < 1 || count > 8) {
    return "INVALID_PRIVATE_KEY";
  }

  const levels: [[number, number, number], [number, number, number]][] = [];

  for (let i = 0; i < count; i++) {
    const lms = lmsType(u32(body, 1 + 8 * i));

    const ots = otsType(u32(body, 5 + 8 * i));

    if (lms === null || ots === null) {
      return "INVALID_PRIVATE_KEY";
    }

    levels.push([lms, ots]);
  }

  const [m, , family] = levels[0][0];

  const height = levels.reduce((total, [[, h]]) => total + h, 0);

  if (levels.some(([lms, ots]) => lms[0] !== m || lms[2] !== family || ots[0] !== m || ots[2] !== family) || height > 60) {
    return "INVALID_PRIVATE_KEY";
  }

  const rest = body.subarray(1 + 8 * count);

  if (rest.length !== 16 + m + 8) {
    return "INVALID_PRIVATE_KEY";
  }

  const cost = levels.reduce((total, [[n, h], [, w]]) => total + otsP(n, w) * 2 ** (h + w), 0);

  return [u64(rest, 16 + m), 1n << BigInt(height), cost];
}

// Random edits of a state blob, mostly resealed so that they reach the parser behind the
// checksum: level counts, type codes, indices at and beyond the capacity, and byte edits.
function mutateState(rng: Random, state: Uint8Array): Uint8Array {
  let body = state.slice(0, state.length - 16);

  const indexOffset = state[1] === 1 && state.length >= 24 ? state.length - 24 : 6;

  const operation = rng.below(6);

  if (operation === 0 && body.length > 2) {
    body[2] = rng.choice([0, 1, 2, 3, 8, 9, 0x80, 0xff]);
  } else if (operation === 1 && body.length > 6) {
    const offset = body[1] === 1 ? 3 + 8 * rng.below(Math.max(1, body[2])) + 4 * rng.below(2) : 2;

    const small = rng.below(48);

    const large = Number(rng.next() & 0xffffffffn);

    const value = rng.choice([small, large, 0]);

    if (offset + 4 <= body.length) {
      new DataView(body.buffer).setUint32(offset, value);
    }
  } else if (operation === 2 && body.length >= indexOffset + 8) {
    const top = 1n << BigInt(rng.choice([5, 10, 20, 40, 60, 64]));

    const value = rng.choice([0n, 1n, top - 1n, top, top + 1n, MASK]) & MASK;

    new DataView(body.buffer).setBigUint64(indexOffset, value);
  } else {
    body = mutate(rng, body);
  }

  return rng.below(4) !== 0 ? sealed(body) : concat(body, state.subarray(state.length - 16));
}

function storedState(algorithm: pq.StatefulSignatureAlgorithm, parameters: pq.StatefulParameters, seed: Uint8Array, index: bigint): Uint8Array {
  const store = new MemoryStore();

  hazmat.generateStatefulKeyPair(algorithm, seed, { parameters, stateStore: store, index });

  return store.state!;
}

function checkState(algorithm: pq.StatefulSignatureAlgorithm, state: Uint8Array, budget: number): void {
  const expected = expectedState(algorithm, state);

  if (typeof expected === "string") {
    assert.throws(() => algorithm.loadPrivateKey(new MemoryStore(state)), isCode(expected), `${algorithm.name} loaded ${toHex(state)}`);

    return;
  }

  const [index, capacity, cost] = expected;

  if (index > capacity) {
    assert.throws(() => algorithm.loadPrivateKey(new MemoryStore(state)), isCode("INVALID_PRIVATE_KEY"));

    return;
  }

  if (cost > budget) {
    return;
  }

  const store = new MemoryStore(state);

  const key = guarded([], algorithm.name, state, () => algorithm.loadPrivateKey(store));

  assert.equal(key!.remainingSignatures(), capacity - index);

  if (index === capacity) {
    assert.throws(() => key!.sign(ascii("m")), isCode("KEY_EXHAUSTED"));

    return;
  }

  const signature = key!.sign(ascii("m"));

  assert.ok(key!.publicKey.verify(signature, ascii("m")));

  const next = state.slice(0, state.length - 16);

  new DataView(next.buffer).setBigUint64(algorithm === pq.HSS_LMS ? next.length - 8 : 6, index + 1n);

  assert.ok(same(store.state!, sealed(next)));
}

test("state loading takes any blob", () => {
  const rng = new Random(9);

  const seeds = [
    storedState(pq.HSS_LMS, [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"]], pattern(40), 3n),
    storedState(
      pq.HSS_LMS,
      [
        ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"],
        ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"],
      ],
      pattern(40),
      3n,
    ),
    storedState(pq.XMSS, "XMSS-SHA2_10_256", pattern(96), 3n),
    storedState(pq.XMSS_MT, "XMSSMT-SHAKE256_20/4_192", pattern(72), 3n),
  ];

  for (let round = 0; round < 200 * SCALE; round++) {
    let state = rng.choice(seeds);

    for (let edits = 1 + rng.below(2); edits > 0; edits--) {
      state = state.length >= 18 ? mutateState(rng, state) : rng.bytes(rng.below(160));
    }

    // Mostly the algorithm the blob names, so that more blobs get past the kind check.
    const named = [pq.HSS_LMS, pq.XMSS, pq.XMSS_MT][state.length > 1 ? state[1] - 1 : -1];

    checkState(named !== undefined && rng.below(4) !== 0 ? named : rng.choice([pq.HSS_LMS, pq.XMSS, pq.XMSS_MT]), state, 1 << 17);
  }

  for (const value of ["state", 7, new Uint8Array(17), [1, 2, 3]]) {
    assert.throws(() => pq.XMSS.loadPrivateKey(new MemoryStore(value as Uint8Array)), isCode("INVALID_PRIVATE_KEY"));
  }
});

test("state blobs that claim many levels or indices are refused", () => {
  const state = storedState(pq.HSS_LMS, [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"]], new Uint8Array(40), 0n);

  const body = state.subarray(0, state.length - 16);

  const load = (bytes: Uint8Array) => assert.throws(() => pq.HSS_LMS.loadPrivateKey(new MemoryStore(sealed(bytes))), isCode("INVALID_PRIVATE_KEY"));

  for (const count of [0, 2, 9, 0xff]) {
    const claimed = body.slice();

    claimed[2] = count;

    load(claimed);

    if (count !== 2) {
      const level = Uint8Array.of(0, 0, 0, 10, 0, 0, 0, 5);

      load(concat(claimed.subarray(0, 3), ...Array.from({ length: count }, () => level), claimed.subarray(11)));
    }
  }

  const tall = concat(Uint8Array.of(1, 1, 3), ...Array.from({ length: 3 }, () => Uint8Array.of(0, 0, 0, 14, 0, 0, 0, 5)), new Uint8Array(48));

  load(tall);

  for (const index of [33n, MASK]) {
    const beyond = body.slice();

    new DataView(beyond.buffer).setBigUint64(beyond.length - 8, index);

    load(beyond);
  }

  const mt = storedState(pq.XMSS_MT, "XMSSMT-SHA2_60/12_256", new Uint8Array(96), 0n);

  for (const index of [(1n << 60n) + 1n, MASK]) {
    const beyond = mt.slice(0, mt.length - 16);

    new DataView(beyond.buffer).setBigUint64(6, index);

    assert.throws(() => pq.XMSS_MT.loadPrivateKey(new MemoryStore(sealed(beyond))), isCode("INVALID_PRIVATE_KEY"));
  }
});

// The message whose byte i is i mod 251, and its digests from an independent implementation.
function largeMessage(): Uint8Array {
  const message = new Uint8Array(16 << 20);

  for (let i = 0; i < message.length; i++) {
    message[i] = i % 251;
  }

  return message;
}

const DIGESTS: [pq.HashAlgorithm, string][] = [
  [pq.SHA_224, "81e763ef9866bdefa03f5c58819e12ba2bc7dd6913eb36e8ec666036"],
  [pq.SHA_256, "287507f403176f1f5b22b9a4d9cb49f7d7f88ac19e406b5ae87ce109564846bd"],
  [pq.SHA_384, "4bc9798cec40d12e4f7198b89e0a5d4b7e7474ec255f3280b126bd3bc141103ca9a906d12fa05c0c5eb50f2bef840908"],
  [pq.SHA_512, "ef9941360046598bd9a89eb56a4440e46255bfa79529f9d3a8813aa899d5c64d8cc75f0c023b8d82ec41cc60ae69d311a80fb9ad372bf3d149574a87bc195c08"],
  [pq.SHA_512_224, "181650285d94081ca60b6dad6cb501607c0b47b793d95f4b3fe703ef"],
  [pq.SHA_512_256, "61fb65258a2a6ca095a709e2d1026483ef0d5dab44e374f55599d867e0d5d2f9"],
  [pq.SHA3_224, "3e121e54d1b7d67d8a6489426c33d7a5078089e9f7ff736786fc2cf3"],
  [pq.SHA3_256, "acade24d564f1dae78e26ca4615bc8061dda3835de1bb7afde3ef0d32a931191"],
  [pq.SHA3_384, "4934100bb50d9a97d1463c521a58ca562a59e07b6753076e45a824d8545df2358c346274ad7809ffeaac2e56a9cef7fb"],
  [pq.SHA3_512, "314cd6d2e1cc05dfc4c8429541a2877becd82e9def2333f26a4eb7f72cffe758289f9185ddae4bb5017ad7019933404f241787ac650e505530f2973d3233a88d"],
];

test("16 MiB messages hash as an independent implementation does", () => {
  const message = largeMessage();

  for (const [algorithm, expected] of DIGESTS) {
    assert.equal(toHex(algorithm.digest(message)), expected, algorithm.name);

    const hasher = algorithm.create();

    for (let offset = 0; offset < message.length; offset += 1_000_003) {
      hasher.update(message.subarray(offset, offset + 1_000_003));
    }

    assert.equal(toHex(hasher.digest()), expected);
  }

  assert.equal(toHex(pq.SHAKE128.digest(message, 32)), "8a38dce3e6592d50867536f5f352abd74e486bdbfe48c43b8372d55e6547110a");

  assert.equal(toHex(pq.SHAKE256.digest(message, 64)), "525fa10737fa7538afe5df929cfadb606e52a2b2e2f0e4c5626510e720319b7366c387167707535aa23a5d027a155150fe5c73c329f2113d1220a8d9d7b9a5e3");

  assert.equal(toHex(pq.HMAC_SHA_256.digest(pattern(32), message)), "e9fb7e5b1f5d2702eba341df5e51ec9e4ed48db395f66dff93e30808b88f0750");
});

test("16 MiB and empty messages sign and verify; contexts stop at 255 bytes", () => {
  const message = largeMessage();

  const changed = message.slice();

  changed[changed.length - 1] ^= 1;

  const longest = pattern(255);

  for (const algorithm of [pq.ML_DSA_44, pq.SLH_DSA_SHA2_128F]) {
    const { privateKey, publicKey } = hazmat.generateKeyPair(algorithm, pattern(signatureSizes(algorithm)[0]));

    const cases: [Uint8Array, Uint8Array, pq.HashAlgorithm | pq.XofAlgorithm | undefined][] = [
      [message, new Uint8Array(), undefined],
      [new Uint8Array(), new Uint8Array(255), undefined],
      [message, longest, pq.SHA_512],
      [new Uint8Array(), new Uint8Array(), pq.SHAKE256],
    ];

    for (const [text, context, preHash] of cases) {
      const signature = privateKey.sign(text, { context, preHash, deterministic: true });

      assert.ok(publicKey.verify(signature, text, { context, preHash }));

      assert.ok(!publicKey.verify(signature, text.length > 0 ? changed : Uint8Array.of(0), { context, preHash }));

      assert.ok(!publicKey.verify(signature, text, { context: concat(context, Uint8Array.of(0)), preHash }));
    }

    assert.throws(() => privateKey.sign(new Uint8Array(), { context: new Uint8Array(256) }), isCode("INVALID_CONTEXT"));
  }

  const hss = pq.HSS_LMS.generateKeyPair({ parameters: [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"]], stateStore: new MemoryStore() });

  const mt = pq.XMSS_MT.generateKeyPair({ parameters: "XMSSMT-SHA2_20/4_192", stateStore: new MemoryStore() });

  for (const text of [message, new Uint8Array()]) {
    for (const pair of [hss, mt]) {
      const signature = pair.privateKey.sign(text);

      assert.ok(pair.publicKey.verify(signature, text));

      assert.ok(!pair.publicKey.verify(signature, text.length > 0 ? changed : Uint8Array.of(0)));
    }
  }
});

function base64(data: Uint8Array): string {
  return pemEncode("X", data)
    .split("\n")
    .filter((line) => !line.startsWith("-----"))
    .join("");
}

test("PEM with very long lines or huge bodies", () => {
  // The last base64 quantum of an ML-DSA-44 key carries two unused bits, which must be zero.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  const pem = hazmat.generateKeyPair(pq.ML_DSA_44, pattern(32)).publicKey.exportKey("pem");

  const last = pem.lastIndexOf("=") - 1;

  const flipped = pem.slice(0, last) + alphabet[alphabet.indexOf(pem[last]) ^ 1] + pem.slice(last + 1);

  assert.throws(() => pq.ML_DSA_44.importPublicKey(flipped, "pem"), isCode("INVALID_ENCODING"));

  const pair = hazmat.generateKeyPair(pq.ML_KEM_768, pattern(64));

  const body = base64(asBytes(pair.publicKey.exportKey("der")));

  const narrow = `-----BEGIN PUBLIC KEY-----\n${body.split("").join("\n")}\n-----END PUBLIC KEY-----\n`;

  assert.ok(pq.ML_KEM_768.importPublicKey(narrow, "pem").equals(pair.publicKey));

  const wide = `-----BEGIN PUBLIC KEY-----${body}-----END PUBLIC KEY-----`;

  assert.ok(pq.ML_KEM_768.importPublicKey(wide, "pem").equals(pair.publicKey));

  const huge = base64(concat(Uint8Array.of(0x30, 0x84, 0x00, 0xff, 0xff, 0xff), new Uint8Array(4 << 20)));

  for (const text of [huge, huge.slice(0, -1)]) {
    assert.throws(() => pq.ML_KEM_768.importPublicKey(`-----BEGIN PUBLIC KEY-----\n${text}\n-----END PUBLIC KEY-----\n`, "pem"), isCode("INVALID_ENCODING"));
  }
});

// A length field that claims gigabytes is refused before anything that large is allocated; one
// with a needless leading zero byte, and a PKCS#8 version above 1, are refused too.
test("DER lengths that claim gigabytes", () => {
  const pair = hazmat.generateKeyPair(pq.ML_DSA_65, pattern(32));

  const publicKey = asBytes(pair.publicKey.exportKey("der"));

  const privateKey = asBytes(pair.privateKey.exportKey("der"));

  const cases = [
    concat(Uint8Array.of(0x30, 0x84, 0xff, 0xff, 0xff, 0xff), publicKey.subarray(4)),
    concat(Uint8Array.of(0x30, 0x84, 0x7f, 0xff, 0xff, 0xff), publicKey.subarray(4)),
    concat(publicKey.subarray(0, 4), Uint8Array.of(0x30, 0x84, 0xff, 0xff, 0xff, 0xf0), publicKey.subarray(6)),
    concat(publicKey.subarray(0, 17), Uint8Array.of(0x03, 0x84, 0xff, 0xff, 0xff, 0xff), publicKey.subarray(21)),
    concat(privateKey.subarray(0, 2), Uint8Array.of(0x02, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00)),
    concat(privateKey.subarray(0, 20), Uint8Array.of(0x04, 0x84, 0x40, 0x00, 0x00, 0x00), privateKey.subarray(22)),
    concat(Uint8Array.of(0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00), publicKey.subarray(4)),
    concat(Uint8Array.of(0x30, 0x80), publicKey.subarray(4), Uint8Array.of(0, 0)),
    concat(Uint8Array.of(0x30, 0x83, 0x00, 0x07, 0xb2), publicKey.subarray(4)),
    concat(Uint8Array.of(0x30, 0x82, 0x07, 0xb3), publicKey.subarray(4, 17), Uint8Array.of(0x03, 0x83, 0x00, 0x07, 0xa1), publicKey.subarray(21)),
    concat(privateKey.subarray(0, 4), Uint8Array.of(2), privateKey.subarray(5)),
  ];

  const before = process.memoryUsage().arrayBuffers;

  for (const data of cases) {
    assert.throws(() => pq.ML_DSA_65.importPublicKey(data, "der"), isCode("INVALID_ENCODING"));

    assert.throws(() => pq.ML_DSA_65.importPrivateKey(data, "der"), isCode("INVALID_ENCODING"));

    assert.throws(() => pq.ML_DSA_65.importPublicKey(`-----BEGIN PUBLIC KEY-----\n${base64(data)}\n-----END PUBLIC KEY-----\n`, "pem"), isCode("INVALID_ENCODING"));
  }

  assert.ok(process.memoryUsage().arrayBuffers - before < 64 << 20);
});

const LEVELS: [string, string][] = [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"]];

// Keys loaded from one store sign in a random order: the compare-and-swap lets one of them claim
// each index, or each range of indices with reserve, and the others get STATE_CONFLICT and reload.
// A key uses every index it claimed, so all of them are used, each once.
test("keys sharing a store never use an index twice", () => {
  const rng = new Random(12);

  for (const reserve of [1, 3]) {
    const store = new MemoryStore();

    pq.HSS_LMS.generateKeyPair({ parameters: LEVELS, stateStore: store });

    const keys = Array.from({ length: 6 }, () => pq.HSS_LMS.loadPrivateKey(store, { reserve }));

    const indices: number[] = [];

    while (keys.length > 0) {
      const which = rng.below(keys.length);

      try {
        indices.push(u32(keys[which].sign(ascii("m")), 4));
      } catch (error) {
        assert.ok(error instanceof pq.CryptoPQError && (error.code === "STATE_CONFLICT" || error.code === "KEY_EXHAUSTED"));

        if (error.code === "KEY_EXHAUSTED") {
          keys.splice(which, 1);
        } else {
          keys[which] = pq.HSS_LMS.loadPrivateKey(store, { reserve });
        }
      }
    }

    assert.deepEqual(
      indices.sort((a, b) => a - b),
      Array.from({ length: 32 }, (_, i) => i),
    );
  }
});

// The same on worker threads: each loads the key from a store in shared memory and counts the
// indices it signs with.
test("worker threads sharing a store never use an index twice", async () => {
  const buffer = new SharedArrayBuffer(COUNTERS + 4 * 32);

  pq.HSS_LMS.generateKeyPair({ parameters: LEVELS, stateStore: new SharedStore(buffer) });

  await parallel(new URL("./shared-store.ts", import.meta.url), "signFromSharedStore", Array.from({ length: 4 }, () => buffer));

  assert.deepEqual(Array.from(new Int32Array(buffer, COUNTERS)), Array.from({ length: 32 }, () => 1));

  assert.equal(pq.HSS_LMS.loadPrivateKey(new SharedStore(buffer)).remainingSignatures(), 0n);
});

// Every implementation runs these rounds on the same inputs, made by the same generator from
// byte-identical keys, and hashes each input with its outcome: an error code, true or false, or
// OK and the result. Equal digests mean that all five implementations accept, refuse and compute
// alike on untrusted input.
const TRANSCRIPT_ROUNDS = 96;

const TRANSCRIPT_BUDGET = 1 << 14;

const TRANSCRIPTS = [
  "4d454f3aca564e383f51723ee3814f1fe105a61b1fd38c536e2ea675d78fabe7",
  "db3f28b7c8f7949f104d15d6de629e0dea7fca38f38c970d520278617dc99474",
  "aafe47ac9480c88402b7974385fac0547b2f4d611f36ec692ca2748e5dec949e",
  "ce9fd19a166b8a384fab4dafffed98c85dd9fb7f3e2ab789f33c832cda8b199d",
  "14d657260a5c207db5e73e9dbaac6d3458b0ba16e507f256bea8fac9fd0f2a0a",
  "19d93bae7a287d14492808654d0580f1043443ad3cf6710e043ea34c462b3307",
  "38a35f3547d4414788484ce0b4b836a27f72fba19931a9f3680cbcadd6d5d97a",
  "7b468ce2966d2edd458ed4a62183bf6d4c06e182509a7773c505a3cb2ae12e58",
  "b2ecff951172fdfdd464c3b4bed07055c3041b64d0c11dc6c9bc62eae7cc0b0e",
  "57986f97a5d291a67f8a875f558d59a535f2157155e13b83b364a6a1cca5dc7d",
  "b46878b67dab92d46731b18b1c63b71f24e7ec4cb53bca10ec36540ca1b4b054",
];

class Transcript {
  readonly #hasher = pq.SHA_256.create();

  add(data: Uint8Array, selector: number, code: string, output: Uint8Array = new Uint8Array()): void {
    for (const part of [data, Uint8Array.of(selector), ascii(code), output]) {
      const length = new Uint8Array(4);

      new DataView(length.buffer).setUint32(0, part.length);

      this.#hasher.update(concat(length, part));
    }
  }

  hex(): string {
    return toHex(this.#hasher.digest());
  }
}

function outcome<T>(run: () => T): [string, T | null] {
  try {
    return ["OK", run()];
  } catch (error) {
    if (!(error instanceof pq.CryptoPQError)) {
      throw error;
    }

    return [error.code, null];
  }
}

// Random bytes, or the seed with up to three edits, so that some inputs stay valid.
function edited(rng: Random, seed: Uint8Array, others: readonly Uint8Array[]): Uint8Array {
  if (rng.below(8) === 0) {
    return rng.bytes(rng.below(96));
  }

  let data = seed;

  for (let edits = rng.below(4); edits > 0; edits--) {
    data = mutate(rng, data, others);
  }

  return data;
}

function resized(rng: Random, data: Uint8Array, size: number): Uint8Array {
  if (rng.below(2) === 0) {
    return data;
  }

  const out = new Uint8Array(size);

  out.set(data.subarray(0, size));

  return out;
}

type Seed = [Uint8Array, number, number];

type Import = (data: Uint8Array, format: Format) => Uint8Array;

function importCase(rng: Random, transcript: Transcript, seeds: readonly Seed[], imports: readonly Import[]): void {
  const others = seeds.map(([encoding]) => encoding);

  for (let round = 0; round < TRANSCRIPT_ROUNDS; round++) {
    const [encoding, choice, seedFormat] = seeds[rng.below(seeds.length)];

    const data = edited(rng, encoding, others);

    const format = rng.below(4) === 0 ? rng.below(3) : seedFormat;

    const [code, raw] = outcome(() => imports[choice](data, FORMATS[format]));

    transcript.add(data, 3 * choice + format, code, raw ?? new Uint8Array());
  }
}

function signatureCase(rng: Random, transcript: Transcript, signature: Uint8Array, verify: (data: Uint8Array, context: Uint8Array) => boolean): void {
  for (let round = 0; round < TRANSCRIPT_ROUNDS; round++) {
    const data = resized(rng, edited(rng, signature, [signature]), signature.length);

    const context = rng.below(2) === 0 ? ascii("context") : new Uint8Array();

    transcript.add(data, context.length, verify(data, context) ? "true" : "false");
  }
}

function exportsOf(key: Exportable, choice = 0): Seed[] {
  return FORMATS.map((format, number) => [asBytes(key.exportKey(format)), choice, number]);
}

function importer(algorithm: { importPublicKey(data: Uint8Array, format: Format): Exportable }, privateKey = false): Import {
  return (data, format) => {
    const load = privateKey ? (algorithm as unknown as { importPrivateKey(data: Uint8Array, format: Format): Exportable }).importPrivateKey : algorithm.importPublicKey;

    return asBytes(load.call(algorithm, data, format).exportKey("raw"));
  };
}

// Loading builds the key's trees, so a valid state of a key larger than the budget is only
// recorded as skipped.
function stateCase(rng: Random, transcript: Transcript, base: Uint8Array): void {
  const stateful = [pq.HSS_LMS, pq.XMSS, pq.XMSS_MT];

  for (let round = 0; round < TRANSCRIPT_ROUNDS; round++) {
    let state = base;

    for (let edits = 1 + rng.below(2); edits > 0; edits--) {
      state = state.length >= 18 ? mutateState(rng, state) : rng.bytes(rng.below(160));
    }

    const named = state.length > 1 && state[1] >= 1 && state[1] <= 3;

    const choice = named && rng.below(4) !== 0 ? state[1] - 1 : rng.below(3);

    const algorithm = stateful[choice];

    const expected = expectedState(algorithm, state);

    if (typeof expected !== "string" && expected[2] > TRANSCRIPT_BUDGET) {
      transcript.add(state, choice, "SKIP");

      continue;
    }

    try {
      const key = algorithm.loadPrivateKey(new MemoryStore(state));

      const remaining = new Uint8Array(8);

      new DataView(remaining.buffer).setBigUint64(0, key.remainingSignatures());

      transcript.add(state, choice, "OK", concat(asBytes(key.publicKey.exportKey("raw")), remaining));
    } catch (error) {
      assert.ok(error instanceof pq.CryptoPQError);

      transcript.add(state, choice, error.code);
    }
  }
}

test("all implementations agree on untrusted input", () => {
  const message = ascii("crypto-pq transcript");

  const kem = hazmat.generateKeyPair(pq.ML_KEM_768, pattern(64));

  const encapsulation = hazmat.encapsulate(kem.publicKey, pattern(32, 0x80));

  const xwing = hazmat.generateKeyPair(pq.X_WING, pattern(32));

  const dsa = hazmat.generateKeyPair(pq.ML_DSA_44, pattern(32));

  const signature = hazmat.sign(dsa.privateKey, message, pattern(32, 0x60), { context: ascii("context") });

  const slh = hazmat.generateKeyPair(pq.SLH_DSA_SHA2_128F, pattern(48));

  const levels: [string, string][] = [
    ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"],
    ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"],
  ];

  const hss = hazmat.generateStatefulKeyPair(pq.HSS_LMS, pattern(40), { parameters: levels, stateStore: new MemoryStore(), index: 33n });

  const hssSignature = hss.privateKey.sign(message);

  const state = storedState(pq.HSS_LMS, levels.slice(0, 1), pattern(40), 3n);

  const xmssPublic = concat(Uint8Array.of(0, 0, 0, 1), pattern(64));

  const xmssMtPublic = concat(Uint8Array.of(0, 0, 0, 0x31), pattern(48));

  const statefulSeeds: Seed[] = [...exportsOf(hss.publicKey), [xmssPublic, 1, 0], [xmssMtPublic, 2, 0], [asBytes(pq.XMSS_MT.importPublicKey(xmssMtPublic, "raw").exportKey("der")), 2, 1]];

  const statefulImports = [pq.HSS_LMS, pq.XMSS, pq.XMSS_MT].map((algorithm) => importer(algorithm));

  const ciphertext = encapsulation.ciphertext;

  const cases: ((rng: Random, transcript: Transcript) => void)[] = [
    (rng, t) => importCase(rng, t, exportsOf(kem.publicKey), [importer(pq.ML_KEM_768)]),
    (rng, t) => importCase(rng, t, exportsOf(kem.privateKey), [importer(pq.ML_KEM_768, true)]),
    (rng, t) =>
      importCase(
        rng,
        t,
        [
          [asBytes(xwing.publicKey.exportKey("raw")), 0, 0],
          [asBytes(xwing.privateKey.exportKey("raw")), 1, 0],
        ],
        [importer(pq.X_WING), importer(pq.X_WING, true)],
      ),
    (rng, t) => importCase(rng, t, exportsOf(dsa.publicKey), [importer(pq.ML_DSA_44)]),
    (rng, t) => importCase(rng, t, exportsOf(dsa.privateKey), [importer(pq.ML_DSA_44, true)]),
    (rng, t) => importCase(rng, t, [...exportsOf(slh.publicKey), ...exportsOf(slh.privateKey, 1)], [importer(pq.SLH_DSA_SHA2_128F), importer(pq.SLH_DSA_SHA2_128F, true)]),
    (rng, t) => importCase(rng, t, statefulSeeds, statefulImports),
    (rng, t) => signatureCase(rng, t, signature, (data, context) => dsa.publicKey.verify(data, message, { context })),
    (rng, t) => {
      for (let round = 0; round < TRANSCRIPT_ROUNDS; round++) {
        const data = resized(rng, edited(rng, ciphertext, [ciphertext]), ciphertext.length);

        const [code, secret] = outcome(() => kem.privateKey.decapsulate(data));

        t.add(data, 0, code, secret ?? new Uint8Array());
      }
    },
    (rng, t) => signatureCase(rng, t, hssSignature, (data, context) => hss.publicKey.verify(data, concat(message, context))),
    (rng, t) => stateCase(rng, t, state),
  ];

  const digests: string[] = [];

  for (const [number, run] of cases.entries()) {
    const transcript = new Transcript();

    run(new Random(101 + number), transcript);

    digests.push(transcript.hex());
  }

  assert.deepEqual(digests, TRANSCRIPTS);
});

// Structures that random edits rarely build: an HSS signature cut inside a field or inside a
// signed child key, counts and leaf indices beyond their range, and hint sections that claim more
// than omega hints, repeat an index or leave padding. Verification refuses every one.
test("verification refuses crafted structures", () => {
  const message = ascii("crypto-pq edge");

  const levels: [string, string][] = [
    ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"],
    ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"],
  ];

  const pair = hazmat.generateStatefulKeyPair(pq.HSS_LMS, pattern(40), { parameters: levels, stateStore: new MemoryStore(), index: 33n });

  const signature = pair.privateKey.sign(message);

  // Nspk, then the first LMS signature (4956 bytes), the signed child key (48) and the second.
  const end = 4 + 4956;

  const lengths = [0, 1, 3, 4, 5, 8, 12, signature.length - 1, ...Array.from({ length: 51 }, (_, i) => end - 1 + i)];

  for (const length of lengths) {
    assert.equal(pair.publicKey.verify(signature.subarray(0, length), message), false, `${length} bytes`);
  }

  assert.ok(pair.publicKey.verify(signature, message));

  assert.ok(!pair.publicKey.verify(concat(signature, Uint8Array.of(0)), message));

  for (const [offset, value] of [
    [0, 0],
    [0, 2],
    [0, 0x7fffffff],
    [0, 0xffffffff],
    [4, 32],
    [4, 0xffffffff],
    [end + 48, 32],
    [end + 48, 0xffffffff],
  ]) {
    const edited = signature.slice();

    new DataView(edited.buffer).setUint32(offset, value);

    assert.ok(!pair.publicKey.verify(edited, message), `${value} at ${offset}`);
  }

  // Level counts outside 1 to 8 make a malformed public key.
  for (const count of [0, 9, 0xffffffff]) {
    const raw = asBytes(pair.publicKey.exportKey("raw")).slice();

    new DataView(raw.buffer).setUint32(0, count);

    assert.throws(() => pq.HSS_LMS.importPublicKey(raw, "raw"), isCode("INVALID_PUBLIC_KEY"));
  }

  const dsa = hazmat.generateKeyPair(pq.ML_DSA_44, pattern(32));

  const valid = hazmat.sign(dsa.privateKey, message, new Uint8Array(32));

  // ML-DSA-44: omega = 80 hint positions, then k = 4 cumulative counts.
  for (const counts of [
    [81, 82, 83, 84],
    [200, 201, 202, 203],
    [80, 80, 80, 80],
    [255, 255, 255, 255],
    [5, 3, 3, 3],
    [0, 0, 0, 0],
  ]) {
    for (const repeat of [false, true]) {
      const edited = valid.slice();

      const hints = edited.length - 84;

      for (let i = 0; i < 80; i++) {
        edited[hints + i] = i;
      }

      if (repeat) {
        edited[hints + 1] = 0;
      }

      edited.set(counts, hints + 80);

      assert.ok(!dsa.publicKey.verify(edited, message), String(counts));
    }
  }

  // The valid signature with a nonzero byte after its last hint: the encoding must be canonical.
  const used = valid[valid.length - 1];

  if (used < 80) {
    const edited = valid.slice();

    edited[edited.length - 84 + used] = 1;

    assert.ok(dsa.publicKey.verify(valid, message));

    assert.ok(!dsa.publicKey.verify(edited, message));
  }

  const xmss: [pq.StatefulSignatureAlgorithm, number, number, number[]][] = [
    [pq.XMSS, 0x0d, 4 + 24 + 61 * 24, [0, 0, 4, 0]],
    [pq.XMSS, 0x0d, 4 + 24 + 61 * 24, [0xff, 0xff, 0xff, 0xff]],
    [pq.XMSS_MT, 0x22, 3 + 24 + (4 * 51 + 20) * 24, [0x10, 0, 0]],
    [pq.XMSS_MT, 0x22, 3 + 24 + (4 * 51 + 20) * 24, [0xff, 0xff, 0xff]],
  ];

  for (const [algorithm, oid, size, index] of xmss) {
    const key = algorithm.importPublicKey(concat(Uint8Array.of(0, 0, 0, oid), pattern(48)), "raw");

    const edited = new Uint8Array(size);

    edited.set(index);

    assert.ok(!key.verify(edited, message), `${algorithm.name} index ${String(index)}`);
  }
});
