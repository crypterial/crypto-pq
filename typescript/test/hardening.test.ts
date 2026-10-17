import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

import { ML_DSA, SLH_DSA, STATEFUL_SIGNATURES, X_WING_HASH } from "../src/families.ts";
import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { MemoryStore, throwsCode, toHex } from "./vectors.ts";

// The input boundary: every array argument is read once, through the built-in getters of its
// internal slots, into an array of the library's making. The tests below hand over Uint8Array
// subclasses whose length, buffer, byteOffset, byteLength, subarray, slice, set and species call the
// library again: none of them may run, and no result may change. The state store's read and update,
// the only caller code that runs inside an operation, call the library too: no scratch is in use
// across them, so the signatures stay the same.

const OTHER = Uint8Array.from({ length: 300 }, (_, i) => (i * 7 + 3) & 0xff);

const OTHER_KEY = Uint8Array.from({ length: 40 }, (_, i) => (i * 11 + 5) & 0xff);

let reentered = 0;

let others: { kem: pq.KemKeyPair; signature: pq.SignatureKeyPair } | null = null;

// Work that runs through every module-level scratch: hashes, MACs, a KDF, a KEM and a signature.
function reenter(): void {
  reentered++;

  others ??= {
    kem: hazmat.generateKeyPair(pq.ML_KEM_768, OTHER.subarray(0, 64)),
    signature: hazmat.generateKeyPair(pq.ML_DSA_44, OTHER.subarray(0, 32)),
  };

  pq.SHA_256.digest(OTHER);

  pq.SHA_512.digest(OTHER);

  pq.SHA3_256.digest(OTHER);

  pq.SHAKE256.digest(OTHER, 64);

  pq.BLAKE2B_512.digest(OTHER);

  pq.HMAC_SHA_256.digest(OTHER_KEY, OTHER);

  pq.HMAC_SHA_512.digest(OTHER_KEY, OTHER);

  pq.KMAC128.digest(OTHER_KEY, OTHER);

  pq.BLAKE2B_MAC.digest(OTHER_KEY, OTHER);

  pq.HKDF_SHA_512.derive(OTHER_KEY, 64, { salt: OTHER_KEY, info: OTHER });

  others.kem.publicKey.encapsulate();

  hazmat.sign(others.signature.privateKey, OTHER, OTHER.subarray(0, 32));
}

class Hostile extends Uint8Array {}

const HOSTILE_GETTERS: PropertyDescriptorMap = Object.fromEntries(
  ["length", "byteLength", "byteOffset"].map((name) => [name, { get: () => (reenter(), 3) }]),
);

Object.defineProperties(Hostile.prototype, {
  ...HOSTILE_GETTERS,
  buffer: { get: () => (reenter(), new ArrayBuffer(8)) },
  subarray: { value: () => (reenter(), new Uint8Array(5)) },
  slice: { value: () => (reenter(), new Uint8Array(5)) },
  set: { value: () => reenter() },
  fill: { value: () => reenter() },
});

Object.defineProperty(Hostile, Symbol.species, { get: () => (reenter(), Uint8Array) });

// data's bytes in a Hostile array, which also has its own length and subarray, written through the
// built-in set, as Hostile's own would call the library.
function hostile(data: Uint8Array): Uint8Array {
  const out = new Hostile(data.length);

  Uint8Array.prototype.set.call(out, data);

  Object.defineProperty(out, "length", { get: () => (reenter(), 1) });

  Object.defineProperty(out, "subarray", { value: () => (reenter(), new Uint8Array(2)) });

  return out;
}

function same(name: string, plain: () => unknown, attacked: () => unknown): void {
  const expected = plain();

  const before = reentered;

  const actual = attacked();

  assert.equal(reentered, before, `${name}: a redefined property of an input ran`);

  assert.deepEqual(normalize(actual), normalize(expected), name);
}

function normalize(value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return toHex(value);
  }

  if (typeof value === "object" && value !== null && "ciphertext" in value && "sharedSecret" in value) {
    const { ciphertext, sharedSecret } = value as pq.Encapsulation;

    return [toHex(ciphertext), toHex(sharedSecret)];
  }

  return value;
}

const SIZES = [0, 3, 64, 65, 200, 1000];

function message(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i * 13 + length) & 0xff);
}

test("hashes and XOFs read hostile arrays through the built-in getters only", () => {
  for (const length of SIZES) {
    const data = message(length);

    for (const algorithm of [pq.SHA_256, pq.SHA_512, pq.SHA3_256, pq.BLAKE2B_512, pq.BLAKE2S_256, pq.ASCON_HASH256]) {
      same(`${algorithm.name}/${length}`, () => algorithm.digest(data), () => algorithm.digest(hostile(data)));

      same(
        `${algorithm.name} streaming/${length}`,
        () => algorithm.create().update(data).update(data).digest(),
        () => algorithm.create().update(hostile(data)).update(hostile(data)).digest(),
      );
    }

    for (const algorithm of [pq.SHAKE128, pq.SHAKE256, pq.ASCON_XOF128]) {
      same(`${algorithm.name}/${length}`, () => algorithm.digest(data, 70), () => algorithm.digest(hostile(data), 70));
    }

    const custom = message(20);

    same(
      `cSHAKE128/${length}`,
      () => pq.CSHAKE128.configure({ customization: custom }).digest(data, 32),
      () => pq.CSHAKE128.configure({ customization: hostile(custom) }).digest(hostile(data), 32),
    );
  }
});

test("MACs and HKDF read hostile keys, data and tags through the built-in getters only", () => {
  for (const length of SIZES) {
    const data = message(length);

    const key = message(length === 0 ? 32 : Math.min(length, 64));

    for (const algorithm of [pq.HMAC_SHA_256, pq.HMAC_SHA_512, pq.KMAC128, pq.BLAKE2B_MAC, pq.BLAKE2S_MAC]) {
      const macKey = algorithm === pq.BLAKE2S_MAC ? key.subarray(0, Math.min(key.length, 32)) : key;

      same(
        `${algorithm.name}/${length}`,
        () => algorithm.digest(macKey, data),
        () => algorithm.digest(hostile(macKey), hostile(data)),
      );

      const tag = algorithm.digest(macKey, data);

      same(
        `${algorithm.name} verify/${length}`,
        () => algorithm.verify(macKey, data, tag),
        () => algorithm.verify(hostile(macKey), hostile(data), hostile(tag)),
      );

      same(
        `${algorithm.name} streaming/${length}`,
        () => algorithm.create(macKey).update(data).digest(),
        () => algorithm.create(hostile(macKey)).update(hostile(data)).digest(),
      );
    }

    for (const kdf of [pq.HKDF_SHA_256, pq.HKDF_SHA_512]) {
      const salt = message(17);

      same(
        `${kdf.name}/${length}`,
        () => kdf.derive(key, 100, { salt, info: data }),
        () => kdf.derive(hostile(key), 100, { salt: hostile(salt), info: hostile(data) }),
      );
    }
  }
});

test("KEMs read hostile seeds, randomness, keys and ciphertexts through the built-in getters only", () => {
  for (const [algorithm, seedSize, randomnessSize] of [
    [pq.ML_KEM_512, 64, 32],
    [pq.ML_KEM_768, 64, 32],
    [pq.X_WING, 32, 64],
  ] as const) {
    const seed = message(seedSize);

    const randomness = message(randomnessSize + 1).subarray(1);

    const pair = hazmat.generateKeyPair(algorithm, seed);

    same(
      `${algorithm.name} keygen`,
      () => hazmat.generateKeyPair(algorithm, seed).publicKey.exportKey("raw"),
      () => hazmat.generateKeyPair(algorithm, hostile(seed)).publicKey.exportKey("raw"),
    );

    same(
      `${algorithm.name} encaps`,
      () => hazmat.encapsulate(pair.publicKey, randomness),
      () => hazmat.encapsulate(pair.publicKey, hostile(randomness)),
    );

    const { ciphertext } = hazmat.encapsulate(pair.publicKey, randomness);

    same(
      `${algorithm.name} decaps`,
      () => pair.privateKey.decapsulate(ciphertext),
      () => pair.privateKey.decapsulate(hostile(ciphertext)),
    );

    const raw = pair.publicKey.exportKey("raw");

    same(
      `${algorithm.name} import`,
      () => hazmat.encapsulate(algorithm.importPublicKey(raw, "raw"), randomness),
      () => hazmat.encapsulate(algorithm.importPublicKey(hostile(raw), "raw"), randomness),
    );
  }
});

test("signatures read hostile messages, contexts, randomness and signatures through the built-in getters only", () => {
  for (const [algorithm, seedSize] of [
    [pq.ML_DSA_44, 32],
    [pq.SLH_DSA_SHA2_128F, 48],
    [pq.SLH_DSA_SHAKE_128F, 48],
  ] as const) {
    const pair = hazmat.generateKeyPair(algorithm, message(seedSize));

    const randomness = message(algorithm === pq.ML_DSA_44 ? 32 : 16);

    for (const length of [0, 64, 200]) {
      const data = message(length);

      const context = message(9);

      same(
        `${algorithm.name} sign/${length}`,
        () => hazmat.sign(pair.privateKey, data, randomness, { context }),
        () => hazmat.sign(pair.privateKey, hostile(data), hostile(randomness), { context: hostile(context) }),
      );

      const signature = pair.privateKey.sign(data, { context, deterministic: true });

      same(
        `${algorithm.name} deterministic sign/${length}`,
        () => pair.privateKey.sign(data, { context, deterministic: true }),
        () => pair.privateKey.sign(hostile(data), { context: hostile(context), deterministic: true }),
      );

      same(
        `${algorithm.name} verify/${length}`,
        () => pair.publicKey.verify(signature, data, { context }),
        () => pair.publicKey.verify(hostile(signature), hostile(data), { context: hostile(context) }),
      );
    }
  }
});

// A store whose read and update run the library first.
class ReentrantStore extends MemoryStore {
  override read(): Uint8Array | null {
    reenter();

    return super.read();
  }

  override update(previous: Uint8Array | null, next: Uint8Array): boolean {
    reenter();

    return super.update(previous, next);
  }
}

test("stateful keys sign the same with hostile messages and with a store that runs the library", () => {
  for (const [algorithm, parameters, seedSize] of [
    [pq.HSS_LMS, [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"]], 40],
    [pq.HSS_LMS, [["LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8"], ["LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8"]], 48],
    [pq.XMSS_MT, "XMSSMT-SHA2_20/4_256", 96],
  ] as const) {
    const seed = message(seedSize);

    const plainStore = new MemoryStore();

    const plain = hazmat.generateStatefulKeyPair(algorithm, seed, { parameters, stateStore: plainStore });

    const reentrantStore = new ReentrantStore();

    const before = reentered;

    const attacked = hazmat.generateStatefulKeyPair(algorithm, hostile(seed), {
      parameters,
      stateStore: reentrantStore,
    });

    assert.ok(reentered > before, "the store ran");

    assert.equal(toHex(attacked.publicKey.exportKey("raw")), toHex(plain.publicKey.exportKey("raw")));

    for (let i = 0; i < 6; i++) {
      const data = message(40 + 50 * i);

      const signature = plain.privateKey.sign(data);

      const attackedSignature = attacked.privateKey.sign(hostile(data));

      assert.equal(toHex(attackedSignature), toHex(signature), `${algorithm.name} signature ${i}`);

      same(
        `${algorithm.name} verify ${i}`,
        () => plain.publicKey.verify(signature, data),
        () => plain.publicKey.verify(hostile(signature), hostile(data)),
      );
    }

    const loaded = algorithm.loadPrivateKey(new ReentrantStore(reentrantStore.state));

    const data = message(77);

    assert.equal(toHex(loaded.sign(data)), toHex(plain.privateKey.sign(data)), `${algorithm.name} after loading`);
  }
});

test("a proxy is refused and an array of another realm is read like one of this realm", () => {
  const data = message(100);

  assert.throws(() => pq.SHA_256.digest(new Proxy(data, {})), TypeError);

  const foreign = runInNewContext("new Uint8Array(100)") as Uint8Array;

  Uint8Array.prototype.set.call(foreign, data);

  assert.equal(toHex(pq.SHA_256.digest(foreign)), toHex(pq.SHA_256.digest(data)));
});

// data's bytes in an array, and what detaches its buffer, or shrinks the buffer below the array's end.
function detachable(data: Uint8Array): [Uint8Array, () => void] {
  const copy = data.slice();

  return [copy, () => structuredClone(copy.buffer, { transfer: [copy.buffer] })];
}

function shrinkable(data: Uint8Array): [Uint8Array, () => void] {
  const buffer = new ArrayBuffer(data.length, { maxByteLength: data.length });

  const view = new Uint8Array(buffer, 0, data.length);

  view.set(data);

  return [view, () => buffer.resize(3)];
}

// An array without readable bytes, its buffer detached or resized below it, is refused rather than
// read as empty; an empty array is read as empty.
test("arrays without readable bytes are refused", () => {
  for (const make of [detachable, shrinkable]) {
    const [data, change] = make(message(100));

    change();

    throwsCode("INVALID_LENGTH", () => pq.SHA_256.digest(data));

    throwsCode("INVALID_LENGTH", () => pq.HMAC_SHA_256.digest(message(32), data));

    throwsCode("INVALID_LENGTH", () => pq.SHAKE128.create().update(data));
  }

  assert.equal(toHex(pq.SHA_256.digest(new Uint8Array(0))), toHex(pq.SHA_256.digest(message(0))));

  assert.equal(toHex(pq.SHA_256.digest(new Uint8Array(new ArrayBuffer(8), 8))), toHex(pq.SHA_256.digest(message(0))));
});

// Option getters and state stores are caller code that may detach or shrink an input given beside
// them: a call reads its inputs only once that code has run, refuses an input that no longer has
// readable bytes, with INVALID_LENGTH, and keeps its WebAssembly instance. An input that tracks the
// length of its buffer is read at the length it has by then.
test("inputs that caller code detaches or shrinks are refused", () => {
  const families = [X_WING_HASH, ML_DSA, SLH_DSA, STATEFUL_SIGNATURES];

  const before = families.map((family) => family.select());

  const dsa = hazmat.generateKeyPair(pq.ML_DSA_44, message(32));

  const slh = hazmat.generateKeyPair(pq.SLH_DSA_SHAKE_128F, message(48));

  const data = message(70);

  const signature = dsa.privateKey.sign(data);

  const prk = pq.HKDF_SHA_512.extract(message(40));

  const addrnd = message(16);

  // Options whose field runs change when it is read.
  const options = (field: string, change: () => void) => ({
    get [field]() {
      change();

      return undefined;
    },
  });

  type Case = [string, Uint8Array, (input: Uint8Array, change: () => void) => unknown];

  const cases: Case[] = [
    ["HKDF derive", message(40), (ikm, change) => pq.HKDF_SHA_256.derive(ikm, 32, options("salt", change))],
    ["HKDF extract", message(40), (ikm, change) => pq.HKDF_SHA_384.extract(ikm, options("info", change))],
    ["HKDF expand", prk, (key, change) => pq.HKDF_SHA_512.expand(key, 64, options("info", change))],
    ["ML-DSA sign", data, (text, change) => dsa.privateKey.sign(text, options("context", change))],
    ["ML-DSA verify", data, (text, change) => dsa.publicKey.verify(signature, text, options("context", change))],
    ["ML-DSA signature", signature, (s, change) => dsa.publicKey.verify(s, data, options("preHash", change))],
    ["SLH-DSA sign", data, (text, change) => hazmat.sign(slh.privateKey, text, addrnd, options("context", change))],
  ];

  for (const make of [detachable, shrinkable]) {
    for (const [name, input, run] of cases) {
      const [given, change] = make(input);

      throwsCode("INVALID_LENGTH", () => run(given, change), `${name} (${make.name})`);
    }

    const store = new MemoryStore();

    hazmat.generateStatefulKeyPair(pq.HSS_LMS, message(40), {
      parameters: [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"]],
      stateStore: store,
    });

    const [text, change] = make(data);

    const changing: pq.StateStore = {
      read: () => store.read(),
      update(previous, next) {
        change();

        return store.update(previous, next);
      },
    };

    const key = pq.HSS_LMS.loadPrivateKey(changing);

    throwsCode("INVALID_LENGTH", () => key.sign(text), `stateful sign (${make.name})`);

    assert.equal(key.remainingSignatures(), 31n, "the refused message used its index");
  }

  const buffer = new ArrayBuffer(40, { maxByteLength: 40 });

  const tracking = new Uint8Array(buffer);

  tracking.set(message(40));

  const shrinking = {
    get salt() {
      buffer.resize(10);

      return undefined;
    },
  };

  assert.equal(
    toHex(pq.HKDF_SHA_256.derive(tracking, 32, shrinking)),
    toHex(pq.HKDF_SHA_256.derive(message(40).subarray(0, 10), 32)),
  );

  const after = families.map((family) => family.select());

  assert.ok(after.every((core, i) => core === before[i] && (core === null || core.live)), "an instance was discarded");
});
