import assert from "node:assert/strict";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { type Fields, concat, hex, preHash, records, throwsCode, toHex } from "./vectors.ts";

// The ACVP generation checks, run by slhdsa.test.ts on worker threads with one record per task.
export const ALGORITHMS: Record<string, pq.SignatureAlgorithm> = Object.fromEntries(
  [
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
  ].map((algorithm) => [algorithm.name, algorithm]),
);

const KEY_GENERATION = "acvp/SLH-DSA-keyGen.txt";

const SIGNATURE_GENERATION = "acvp/SLH-DSA-sigGen.txt";

const parsed = new Map<string, [Fields, Fields][]>();

function vectors(name: string, field: string): [Fields, Fields][] {
  let found = parsed.get(name);

  if (found === undefined) {
    found = records(name, field);

    parsed.set(name, found);
  }

  return found;
}

// Record indices with the slow parameter sets first, so that no worker is left with a long task at
// the end: an "s" set costs about ten times an "f" set, and SHAKE about three times SHA-2.
function heaviestFirst(name: string, field: string): number[] {
  const found = vectors(name, field);

  const cost = (index: number) => {
    const set = found[index][0].parameterSet;

    return (set.endsWith("s") ? 10 : 1) * (set.includes("SHAKE") ? 3 : 1);
  };

  return found.map((_, index) => index).sort((a, b) => cost(b) - cost(a));
}

export function keyGenerationTasks(): number[] {
  return heaviestFirst(KEY_GENERATION, "sk");
}

export function signatureGenerationTasks(): number[] {
  return heaviestFirst(SIGNATURE_GENERATION, "signature");
}

export function keyGeneration(index: number): void {
  const [header, record] = vectors(KEY_GENERATION, "sk")[index];

  const algorithm = ALGORITHMS[header.parameterSet];

  const context = `tcId = ${record.tcId} (${header.parameterSet})`;

  const sk = hex(record.sk);

  const pair = hazmat.generateKeyPair(algorithm, concat(hex(record.skSeed), hex(record.skPrf), hex(record.pkSeed)));

  assert.equal(toHex(pair.publicKey.exportKey("raw")), record.pk.toLowerCase(), context);

  assert.equal(toHex(pair.privateKey.exportKey("raw")), record.sk.toLowerCase(), context);

  assert.ok(algorithm.importPrivateKey(sk, "raw").publicKey.equals(pair.publicKey), context);

  const corrupted = sk.slice();

  corrupted[corrupted.length - 1] ^= 1;

  throwsCode("INVALID_PRIVATE_KEY", () => algorithm.importPrivateKey(corrupted, "raw"), context);
}

export function signatureGeneration(index: number): void {
  const [header, record] = vectors(SIGNATURE_GENERATION, "signature")[index];

  const algorithm = ALGORITHMS[header.parameterSet];

  const sk = hex(record.sk);

  const privateKey = algorithm.importPrivateKey(sk, "raw");

  const n = sk.length / 4;

  const randomness = header.deterministic === "true" ? sk.slice(2 * n, 3 * n) : hex(record.additionalRandomness);

  const signature = hazmat.sign(privateKey, hex(record.message), randomness, {
    context: hex(record.context),
    preHash: preHash(header, record),
  });

  assert.equal(toHex(signature), record.signature.toLowerCase(), `tcId = ${record.tcId} (${header.parameterSet})`);
}
