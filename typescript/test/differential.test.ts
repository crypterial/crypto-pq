import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import process from "node:process";
import { test } from "node:test";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import * as mldsa from "../src/mldsa.ts";
import { BACKEND } from "./backend.ts";
import { MemoryStore, toHex } from "./vectors.ts";

// The WebAssembly backend against the TypeScript one on random inputs: every output and every error
// code must agree, and keys of one backend must work with the other's. CRYPTO_PQ_FUZZ=1 runs many
// more rounds; CRYPTO_PQ_SEED=n repeats a run, whose seed every failure names.
const FUZZ = Boolean(process.env.CRYPTO_PQ_FUZZ);

const ROUNDS = FUZZ ? 40 : 2;

const SEED = Number(process.env.CRYPTO_PQ_SEED ?? Math.floor(Math.random() * 2 ** 32));

const MASK = (1n << 64n) - 1n;

// SplitMix64, as in robustness.test.ts.
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

  // A copy of data with one byte changed.
  mutate(data: Uint8Array): Uint8Array {
    const out = data.slice();

    if (out.length > 0) {
      out[this.below(out.length)] ^= 1 << this.below(8);
    }

    return out;
  }
}

const BACKENDS = ["js", "wasm"] as const;

function withBackend<T>(backend: pq.Backend, run: () => T): T {
  pq.setBackend(backend);

  try {
    return run();
  } finally {
    pq.setBackend(BACKEND);
  }
}

// Makes one value on each backend.
function made<T>(make: () => T): [T, T] {
  return [withBackend("js", make), withBackend("wasm", make)];
}

// What an operation gives, comparable across backends: its bytes, its value, or the code of the
// error it throws.
function outcome(run: () => unknown): string {
  try {
    const value = run();

    if (value instanceof Uint8Array) {
      return toHex(value);
    }

    if (typeof value === "object" && value !== null && "exportKey" in value) {
      return toHex((value as { exportKey(format: "raw"): Uint8Array }).exportKey("raw"));
    }

    return String(value);
  } catch (error) {
    if (error instanceof pq.CryptoPQError) {
      return `error ${error.code}`;
    }

    throw error;
  }
}

// The outcomes of one operation per backend, which must agree.
function agree(context: string, ...runs: (() => unknown)[]): string {
  const [first, ...rest] = runs.map(outcome);

  for (const other of rest) {
    assert.equal(other, first, `${context} (CRYPTO_PQ_SEED=${SEED})`);
  }

  return first;
}

// The same operation run once with each backend selected, for operations without a key.
function agreeOnBackends(context: string, run: () => unknown): string {
  return agree(context, ...BACKENDS.map((backend) => () => withBackend(backend, run)));
}

test("KEM: WebAssembly against TypeScript", () => {
  const random = new Random(SEED);

  for (const algorithm of [pq.ML_KEM_512, pq.ML_KEM_768, pq.ML_KEM_1024, pq.X_WING]) {
    const xWing = algorithm === pq.X_WING;

    const formats = xWing ? (["raw"] as const) : (["raw", "der", "pem"] as const);

    for (let round = 0; round < ROUNDS; round++) {
      const context = `${algorithm.name} round ${round}`;

      const seed = random.bytes(xWing ? 32 : 64);

      const pairs = made(() => hazmat.generateKeyPair(algorithm, seed));

      for (const format of formats) {
        agree(`${context} public ${format}`, ...pairs.map((pair) => () => pair.publicKey.exportKey(format)));

        agree(`${context} private ${format}`, ...pairs.map((pair) => () => pair.privateKey.exportKey(format)));
      }

      const randomness = random.bytes(xWing ? 64 : 32);

      const encapsulations = pairs.map((pair) => hazmat.encapsulate(pair.publicKey, randomness));

      agree(
        `${context} encapsulation`,
        ...encapsulations.map(({ ciphertext, sharedSecret }) => () => [toHex(ciphertext), toHex(sharedSecret)]),
      );

      const ciphertexts = [
        encapsulations[0].ciphertext,
        random.mutate(encapsulations[0].ciphertext),
        random.bytes(algorithm.ciphertextSize),
      ];

      for (const ciphertext of [...ciphertexts, random.bytes(algorithm.ciphertextSize - 1)]) {
        agree(`${context} decapsulation`, ...pairs.map((pair) => () => pair.privateKey.decapsulate(ciphertext)));
      }

      // Keys of each backend encapsulate to the other's.
      const fresh = made(() => algorithm.generateKeyPair());

      for (const from of fresh) {
        const { sharedSecret, ciphertext } = from.publicKey.encapsulate();

        const imported = made(() => algorithm.importPrivateKey(from.privateKey.exportKey("raw"), "raw"));

        for (const key of imported) {
          assert.deepEqual(key.decapsulate(ciphertext), sharedSecret, context);
        }
      }

      const publicKey = pairs[0].publicKey.exportKey("raw");

      for (const data of [
        publicKey,
        random.mutate(publicKey),
        random.bytes(algorithm.publicKeySize),
        random.bytes(7),
      ]) {
        agreeOnBackends(`${context} public import`, () => algorithm.importPublicKey(data, "raw"));
      }

      if (!xWing) {
        const der = pairs[0].privateKey.exportKey("der");

        const expanded = withBackend("js", () => algorithm.importPrivateKey(der, "der"));

        const key = expanded.exportKey("raw");

        for (const data of [key, random.mutate(key), random.mutate(der)]) {
          agreeOnBackends(`${context} private import`, () =>
            algorithm.importPrivateKey(data, data === key ? "raw" : "der"),
          );
        }
      }
    }
  }
});

const PRE_HASHES = [
  undefined,
  pq.SHA_224,
  pq.SHA_256,
  pq.SHA_384,
  pq.SHA_512,
  pq.SHA_512_224,
  pq.SHA_512_256,
  pq.SHA3_224,
  pq.SHA3_256,
  pq.SHA3_384,
  pq.SHA3_512,
  pq.SHAKE128,
  pq.SHAKE256,
];

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

const ML_DSA_PARAMETERS = new Map([
  [pq.ML_DSA_44, mldsa.ML_DSA_44],
  [pq.ML_DSA_65, mldsa.ML_DSA_65],
  [pq.ML_DSA_87, mldsa.ML_DSA_87],
]);

test("signatures: WebAssembly against TypeScript", () => {
  const random = new Random(SEED + 1);

  // The small SLH-DSA sets sign slowly in TypeScript: each runs once, or in every round when fuzzing.
  const algorithms = [pq.ML_DSA_44, pq.ML_DSA_65, pq.ML_DSA_87, ...SLH_DSA];

  for (const algorithm of algorithms) {
    const rounds = algorithm.name.endsWith("s") && !FUZZ ? 1 : ROUNDS;

    const params = ML_DSA_PARAMETERS.get(algorithm);

    for (let round = 0; round < rounds; round++) {
      const context = `${algorithm.name} round ${round}`;

      const seed = random.bytes(params === undefined ? (3 * algorithm.publicKeySize) / 2 : 32);

      const pairs = made(() => hazmat.generateKeyPair(algorithm, seed));

      for (const format of ["raw", "der", "pem"] as const) {
        agree(`${context} public ${format}`, ...pairs.map((pair) => () => pair.publicKey.exportKey(format)));

        agree(`${context} private ${format}`, ...pairs.map((pair) => () => pair.privateKey.exportKey(format)));
      }

      const message = random.bytes(random.below(300));

      const options = {
        context: random.bytes(random.below(10) === 0 ? 256 : random.below(40)),
        preHash: random.choice(PRE_HASHES),
      };

      const signature = agree(
        `${context} deterministic`,
        ...pairs.map((pair) => () => pair.privateKey.sign(message, { ...options, deterministic: true })),
      );

      const randomness = random.bytes(params === undefined ? algorithm.publicKeySize / 2 : 32);

      agree(
        `${context} hazmat`,
        ...pairs.map((pair) => () => hazmat.sign(pair.privateKey, message, randomness, options)),
      );

      if (!signature.startsWith("error")) {
        const bytes = Uint8Array.from(Buffer.from(signature, "hex"));

        for (const candidate of [bytes, random.mutate(bytes), bytes.subarray(1)]) {
          for (const verifyOptions of [options, { ...options, context: random.bytes(3) }]) {
            agree(
              `${context} verify`,
              ...pairs.map((pair) => () => pair.publicKey.verify(candidate, message, verifyOptions)),
            );

            agree(
              `${context} hazmat verify`,
              ...pairs.map((pair) => () => hazmat.verify(pair.publicKey, candidate, message, verifyOptions)),
            );
          }
        }
      }

      // Hedged signatures of each backend verify with the other's key.
      const hedged = pairs.map((pair) => pair.privateKey.sign(message));

      assert.ok(pairs[0].publicKey.verify(hedged[1], message), context);

      assert.ok(pairs[1].publicKey.verify(hedged[0], message), context);

      if (params !== undefined) {
        const [, sk] = mldsa.keygenInternal(seed, params);

        for (const data of [sk, random.mutate(sk), random.bytes(31)]) {
          agreeOnBackends(`${context} private import`, () => algorithm.importPrivateKey(data, "raw"));
        }
      } else {
        const sk = random.mutate(pairs[0].privateKey.exportKey("raw"));

        agreeOnBackends(`${context} private import`, () => algorithm.importPrivateKey(sk, "raw"));
      }
    }
  }
});

test("hashing: WebAssembly against TypeScript", () => {
  const random = new Random(SEED + 2);

  const hashes = [
    pq.SHA_224,
    pq.SHA_256,
    pq.SHA_384,
    pq.SHA_512,
    pq.SHA_512_224,
    pq.SHA_512_256,
    pq.SHA3_224,
    pq.SHA3_256,
    pq.SHA3_384,
    pq.SHA3_512,
  ];

  const size = () => (random.below(8) === 0 ? 33000 + random.below(40000) : random.below(1000));

  for (let round = 0; round < 8 * ROUNDS; round++) {
    const data = random.bytes(size());

    const cut = random.below(data.length + 1);

    for (const hash of hashes) {
      const context = `${hash.name} ${data.length}`;

      const states = made(() => hash.create().update(data.subarray(0, cut)));

      agree(context, ...states.map((state) => () => state.update(data.subarray(cut)).digest()), () =>
        hash.digest(data),
      );

      agreeOnBackends(context, () => hash.digest(data));
    }

    for (const xof of [pq.SHAKE128, pq.SHAKE256]) {
      const context = `${xof.name} ${data.length}`;

      const lengths = [random.below(200), size(), random.below(3)];

      const states = made(() => xof.create().update(data));

      agree(context, ...states.map((state) => () => lengths.map((length) => toHex(state.read(length))).join()));

      agree(`${context} update after read`, ...states.map((state) => () => state.update(data)));

      agreeOnBackends(context, () => xof.digest(data, lengths[1]));

      const length = random.choice([-1, 1.5, Number.NaN]);

      agreeOnBackends(`${context} length`, () => xof.digest(data, length));
    }

    for (const hmac of [pq.HMAC_SHA_224, pq.HMAC_SHA_256, pq.HMAC_SHA_384, pq.HMAC_SHA_512]) {
      const key = random.bytes(random.below(300));

      const context = `${hmac.name} ${key.length} ${data.length}`;

      const tag = agreeOnBackends(context, () => hmac.digest(key, data));

      const bytes = Uint8Array.from(Buffer.from(tag, "hex"));

      const states = made(() => hmac.create(key).update(data.subarray(0, cut)));

      agree(context, ...states.map((state) => () => state.update(data.subarray(cut)).digest()));

      for (const candidate of [bytes, random.mutate(bytes), bytes.subarray(1)]) {
        agreeOnBackends(`${context} verify`, () => hmac.verify(key, data, candidate));

        agree(`${context} verify`, ...states.map((state) => () => state.verify(candidate)));
      }
    }
  }
});

test("stateful signatures: WebAssembly against TypeScript", () => {
  const random = new Random(SEED + 3);

  const OTS = ["W1", "W2", "W4", "W8"];

  // Each setup chooses parameters and gives their seed size and total height.
  const setups: [pq.StatefulSignatureAlgorithm, () => [pq.StatefulParameters, number, number]][] = [
    [
      pq.HSS_LMS,
      () => {
        const levels = 1 + random.below(2);

        const [tree, ots, m] = random.choice([
          ["SHA256_M24", "SHA256_N24", 24],
          ["SHA256_M32", "SHA256_N32", 32],
          ["SHAKE_M24", "SHAKE_N24", 24],
        ] as const);

        const chosen = Array.from({ length: levels }, () => [`LMS_${tree}_H5`, `LMOTS_${ots}_${random.choice(OTS)}`]);

        return [chosen as [string, string][], 16 + m, 5 * levels];
      },
    ],
    [
      pq.XMSS_MT,
      () =>
        random.choice([
          ["XMSSMT-SHA2_20/4_256", 96, 20],
          ["XMSSMT-SHAKE256_20/4_192", 72, 20],
        ]),
    ],
  ];

  if (FUZZ) {
    setups.push([
      pq.XMSS,
      () =>
        random.choice([
          ["XMSS-SHA2_10_256", 96, 10],
          ["XMSS-SHAKE256_10_192", 72, 10],
        ]),
    ]);
  }

  for (const [algorithm, parameters] of setups) {
    for (let round = 0; round < ROUNDS; round++) {
      const [chosen, seedSize, height] = parameters();

      const context = `${algorithm.name} ${JSON.stringify(chosen)} round ${round}`;

      const seed = random.bytes(seedSize);

      // Room for the signatures below, the last one by a key loaded at the next index.
      const index = BigInt(random.below(2 ** height - 8));

      const stores = [new MemoryStore(), new MemoryStore()];

      const pairs = BACKENDS.map((backend, i) =>
        withBackend(backend, () =>
          hazmat.generateStatefulKeyPair(algorithm, seed, { parameters: chosen, stateStore: stores[i], index }),
        ),
      );

      agree(`${context} public key`, ...pairs.map((pair) => () => pair.publicKey.exportKey("raw")));

      agree(`${context} state`, ...stores.map((store) => () => store.state));

      for (let i = 0; i < 3; i++) {
        const message = random.bytes(random.below(100));

        const signature = agree(
          `${context} signature ${i}`,
          ...pairs.map((pair) => () => pair.privateKey.sign(message)),
        );

        const bytes = Uint8Array.from(Buffer.from(signature, "hex"));

        for (const candidate of [bytes, random.mutate(bytes)]) {
          agree(`${context} verify`, ...pairs.map((pair) => () => pair.publicKey.verify(candidate, message)));
        }
      }

      const caches = pairs.map((pair) => pair.privateKey.exportTreeCache());

      agree(`${context} tree cache`, ...caches.map((cache) => () => cache));

      // Each backend loads the other's state and cache, and refuses a damaged one alike.
      for (const [store, cache] of [
        [stores[0], caches[1]],
        [stores[1], caches[0]],
      ] as const) {
        const message = random.bytes(9);

        agree(
          `${context} load`,
          ...BACKENDS.map(
            (backend) => () =>
              withBackend(backend, () =>
                algorithm.loadPrivateKey(new MemoryStore(store.state), { treeCache: cache }).sign(message),
              ),
          ),
        );

        for (const damaged of [random.mutate(cache), cache.subarray(0, cache.length - 1)]) {
          agree(
            `${context} damaged cache`,
            ...BACKENDS.map(
              (backend) => () =>
                withBackend(backend, () =>
                  algorithm.loadPrivateKey(new MemoryStore(store.state), { treeCache: damaged }),
                ),
            ),
          );
        }

        const state = random.mutate(store.state as Uint8Array);

        agree(
          `${context} damaged state`,
          ...BACKENDS.map(
            (backend) => () => withBackend(backend, () => algorithm.loadPrivateKey(new MemoryStore(state))),
          ),
        );
      }
    }
  }
});
