import { performance } from "node:perf_hooks";
import process from "node:process";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";

// Times one batch of iterations and returns the elapsed milliseconds.
type Run = (iterations: number) => number;

interface Case {
  readonly name: string;

  // Iteration counts stay multiples of this, so that every timed batch covers whole cycles of work
  // that repeats: the 16 ML-DSA messages, or the lower trees a stateful key rebuilds.
  readonly period: number;

  prepare(): Run;
}

const TARGET_MS = 1000;

const MESSAGES = Array.from({ length: 16 }, (_, i) => bytes(32, 31 * i));

function bytes(length: number, salt: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (salt + i) & 0xff);
}

function sync(operation: (i: number) => unknown): Run {
  return (iterations) => {
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      operation(i);
    }

    return performance.now() - start;
  };
}

// Grows the batch until one takes TARGET_MS, as testing.B does, and reports that batch.
function measure(run: Run, period: number): [number, number] {
  let iterations = period;

  for (;;) {
    const elapsed = run(iterations);

    if (elapsed >= TARGET_MS) {
      return [iterations, elapsed];
    }

    const predicted = elapsed > 0 ? Math.ceil((1.2 * TARGET_MS * iterations) / elapsed) : 100 * iterations;

    const next = Math.max(iterations + period, Math.min(predicted, 100 * iterations));

    iterations = period * Math.ceil(next / period);
  }
}

class MemoryStore implements pq.StateStore {
  #state: Uint8Array | null = null;

  read(): Uint8Array | null {
    return this.#state;
  }

  update(previous: Uint8Array | null, next: Uint8Array): boolean {
    const current = this.#state;

    if (previous === null || current === null ? previous !== current : !same(previous, current)) {
      return false;
    }

    this.#state = next;

    return true;
  }
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}

function memo<T>(create: () => T): () => T {
  let value: T | undefined;

  return () => (value ??= create());
}

function hashCases(): Case[] {
  const short = bytes(64, 1);

  const long = bytes(1024, 2);

  const cases: [string, (i: number) => unknown][] = [
    ["sha-256/64B", () => pq.SHA_256.digest(short)],
    ["sha-256/1KiB", () => pq.SHA_256.digest(long)],
    ["sha-512/1KiB", () => pq.SHA_512.digest(long)],
    ["sha3-256/1KiB", () => pq.SHA3_256.digest(long)],
    ["shake128/1KiB", () => pq.SHAKE128.digest(long, 32)],
    ["shake256/1KiB", () => pq.SHAKE256.digest(long, 64)],
  ];

  return cases.map(([name, operation]) => ({ name, period: 1, prepare: () => sync(operation) }));
}

function kemCases(algorithm: pq.KemAlgorithm, seedSize: number): Case[] {
  const seed = bytes(seedSize, 3);

  const pair = memo(() => hazmat.generateKeyPair(algorithm, seed));

  return [
    { name: `${algorithm.name}/keygen`, period: 1, prepare: () => sync(() => hazmat.generateKeyPair(algorithm, seed)) },
    {
      name: `${algorithm.name}/encaps`,
      period: 1,
      prepare() {
        const { publicKey } = pair();

        return sync(() => publicKey.encapsulate());
      },
    },
    {
      name: `${algorithm.name}/decaps`,
      period: 1,
      prepare() {
        const { publicKey, privateKey } = pair();

        const { ciphertext } = publicKey.encapsulate();

        return sync(() => privateKey.decapsulate(ciphertext));
      },
    },
  ];
}

// ML-DSA signs the 16 messages in turn, because the number of rejection rounds depends on the
// message; SLH-DSA signs one message.
function signatureCases(algorithm: pq.SignatureAlgorithm, seedSize: number, rotate: boolean): Case[] {
  const seed = bytes(seedSize, 4);

  const period = rotate ? MESSAGES.length : 1;

  const message = (i: number) => MESSAGES[rotate ? i & 15 : 0];

  const pair = memo(() => hazmat.generateKeyPair(algorithm, seed));

  return [
    { name: `${algorithm.name}/keygen`, period: 1, prepare: () => sync(() => hazmat.generateKeyPair(algorithm, seed)) },
    {
      name: `${algorithm.name}/sign`,
      period,
      prepare() {
        const { privateKey } = pair();

        return sync((i) => privateKey.sign(message(i), { deterministic: true }));
      },
    },
    {
      name: `${algorithm.name}/verify`,
      period,
      prepare() {
        const { publicKey, privateKey } = pair();

        const sign = (i: number) => privateKey.sign(message(i), { deterministic: true });

        const signatures = Array.from({ length: period }, (_, i) => sign(i));

        return sync((i) => publicKey.verify(signatures[i % period], message(i)));
      },
    },
  ];
}

// A stateful key is regenerated outside the timed region when it runs out of signatures.
function statefulCases(
  name: string,
  algorithm: pq.StatefulSignatureAlgorithm,
  parameters: pq.StatefulParameters,
  seedSize: number,
  period: number,
): Case[] {
  const seed = bytes(seedSize, 5);

  const generate = () => hazmat.generateStatefulKeyPair(algorithm, seed, { parameters, stateStore: new MemoryStore() });

  return [
    { name: `${name}/keygen`, period: 1, prepare: () => sync(generate) },
    {
      name: `${name}/sign`,
      period,
      prepare() {
        let { privateKey } = generate();

        return (iterations) => {
          let elapsed = 0;

          let start = performance.now();

          for (let i = 0; i < iterations; i++) {
            if (privateKey.remainingSignatures() === 0n) {
              elapsed += performance.now() - start;

              ({ privateKey } = generate());

              start = performance.now();
            }

            privateKey.sign(MESSAGES[i & 15]);
          }

          return elapsed + performance.now() - start;
        };
      },
    },
    {
      name: `${name}/verify`,
      period: 1,
      prepare() {
        const { publicKey, privateKey } = generate();

        const signature = privateKey.sign(MESSAGES[0]);

        return sync(() => publicKey.verify(signature, MESSAGES[0]));
      },
    },
  ];
}

const SLH_DSA: [pq.SignatureAlgorithm, number][] = [
  [pq.SLH_DSA_SHA2_128S, 16],
  [pq.SLH_DSA_SHA2_128F, 16],
  [pq.SLH_DSA_SHA2_192S, 24],
  [pq.SLH_DSA_SHA2_192F, 24],
  [pq.SLH_DSA_SHA2_256S, 32],
  [pq.SLH_DSA_SHA2_256F, 32],
  [pq.SLH_DSA_SHAKE_128S, 16],
  [pq.SLH_DSA_SHAKE_128F, 16],
  [pq.SLH_DSA_SHAKE_192S, 24],
  [pq.SLH_DSA_SHAKE_192F, 24],
  [pq.SLH_DSA_SHAKE_256S, 32],
  [pq.SLH_DSA_SHAKE_256F, 32],
];

const CASES: Case[] = [
  ...hashCases(),
  ...kemCases(pq.ML_KEM_512, 64),
  ...kemCases(pq.ML_KEM_768, 64),
  ...kemCases(pq.ML_KEM_1024, 64),
  ...kemCases(pq.X_WING, 32),
  ...signatureCases(pq.ML_DSA_44, 32, true),
  ...signatureCases(pq.ML_DSA_65, 32, true),
  ...signatureCases(pq.ML_DSA_87, 32, true),
  ...SLH_DSA.flatMap(([algorithm, n]) => signatureCases(algorithm, 3 * n, false)),
  ...statefulCases("HSS-H10-W4", pq.HSS_LMS, [["LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4"]], 48, 1),
  ...statefulCases(
    "HSS-H5H5-W8",
    pq.HSS_LMS,
    [
      ["LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8"],
      ["LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8"],
    ],
    48,
    32,
  ),
  ...statefulCases("XMSS-SHA2_10_256", pq.XMSS, "XMSS-SHA2_10_256", 96, 1),
  ...statefulCases("XMSSMT-SHA2_20/4_256", pq.XMSS_MT, "XMSSMT-SHA2_20/4_256", 96, 32),
];

const filter = process.argv[2] ?? "";

for (const { name, period, prepare } of CASES) {
  if (!name.includes(filter)) {
    continue;
  }

  const [iterations, elapsed] = measure(prepare(), period);

  const micros = ((1000 * elapsed) / iterations).toFixed(2);

  console.log(`${name.padEnd(28)}  ${String(iterations).padStart(9)}  ${micros.padStart(14)}`);
}
