import assert from "node:assert/strict";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { type Fields, MemoryStore, hex, records, toHex } from "./vectors.ts";

// The reference vector checks, run by xmss.test.ts on worker threads with one record per task.
const VECTORS = "xmss/xmss.txt";

let parsed: [Fields, Fields][] | null = null;

function vectors(): [Fields, Fields][] {
  parsed ??= records(VECTORS, "signature");

  return parsed;
}

// Record indices with the costliest first: signing builds one tree of 2^(h/d) leaves per layer,
// and SHAKE256 costs about three times SHA-256.
export function referenceVectorTasks(): number[] {
  const cost = (index: number) => {
    const name = vectors()[index][1].name;

    const [, h, d = "1"] = /_(\d+)(?:\/(\d+))?_/.exec(name) ?? [];

    return Number(d) * 2 ** (Number(h) / Number(d)) * (name.includes("SHAKE") ? 3 : 1);
  };

  return vectors()
    .map((_, index) => index)
    .sort((a, b) => cost(b) - cost(a));
}

export async function referenceVector(index: number): Promise<void> {
  const [, record] = vectors()[index];

  const name = record.name;

  const context = `${name} index ${record.index}`;

  const algorithm = name.startsWith("XMSSMT") ? pq.XMSS_MT : pq.XMSS;

  const message = hex(record.message);

  const signature = hex(record.signature);

  const publicKey = algorithm.importPublicKey(hex(record.publicKey), "raw");

  assert.ok(publicKey.verify(signature, message), context);

  const tampered = signature.slice();

  tampered[tampered.length - 1] ^= 1;

  assert.ok(!publicKey.verify(tampered, message), context);

  const pair = await hazmat.generateStatefulKeyPair(algorithm, hex(record.seed), {
    parameters: name,
    stateStore: new MemoryStore(),
    index: BigInt(record.index),
  });

  assert.equal(toHex(pair.publicKey.exportKey("raw")), record.publicKey.toLowerCase(), context);

  assert.equal(toHex(await pair.privateKey.sign(message)), record.signature.toLowerCase(), context);
}
