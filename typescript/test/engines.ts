import process from "node:process";

import * as pq from "../src/index.ts";
import {
  execute,
  kem,
  latin1,
  signature,
  signatureTasks,
  stateful,
  statefulTasks,
  treeCache,
  vectors,
} from "./cross-checks.ts";
import {
  asconVectors,
  blake2Derived,
  blake2Kats,
  blake2Rfc,
  cshakeVectors,
  hkdfVectors,
  kmacVectors,
} from "./symmetric-vectors.ts";
import { hex, toHex } from "./vectors.ts";

// The cross vectors, the error code of every malformed input and the official vectors of HKDF,
// cSHAKE, KMAC, BLAKE2 and Ascon, on WebAssembly and in TypeScript, for engines that run the
// package's sources without node:test, Deno and Bun among them. The slow SLH-DSA and XMSS vectors
// run on WebAssembly only. Usage: deno run --allow-read --allow-env
// test/engines.ts, bun test/engines.ts or node test/engines.ts; exits with status 1 on any failure.

const engine = globalThis as { Deno?: { version: { deno: string } }; Bun?: { version: string } };

const name =
  engine.Deno !== undefined
    ? `deno ${engine.Deno.version.deno}`
    : engine.Bun !== undefined
      ? `bun ${engine.Bun.version}`
      : `node ${process.versions.node}`;

const ALGORITHMS = [pq.ML_KEM_768, pq.X_WING, pq.ML_DSA_65, pq.SLH_DSA_SHA2_128F, pq.HSS_LMS, pq.SHA_256, pq.KMAC256];

function errorCodes(): number {
  let checked = 0;

  for (const [header, record] of vectors("cross/errors.txt", "result")) {
    const data = hex(record.input ?? "");

    for (const value of record.format === "pem" ? [data, latin1(data)] : [data]) {
      const outcome = execute(header, record, value);

      const output = record.output !== undefined && toHex(outcome.output ?? new Uint8Array()) !== record.output;

      const remaining = record.remaining !== undefined && outcome.remaining !== BigInt(record.remaining);

      if (outcome.result !== record.result || output || remaining) {
        throw new Error(`${header.algorithm}: ${record.name}: got ${outcome.result}, expected ${record.result}`);
      }

      checked++;
    }
  }

  return checked;
}

let failed = false;

for (const backend of ["wasm", "js"] as const) {
  pq.setBackend(backend);

  const start = performance.now();

  try {
    const chosen = ALGORITHMS.map((algorithm) => algorithm.backend);

    if (chosen.some((value) => value !== backend)) {
      throw new Error(`the families run on ${chosen.join(", ")}`);
    }

    let checked = 0;

    vectors("cross/kem.txt", "seed").forEach((_, index) => {
      kem(index);

      checked++;
    });

    vectors("cross/treecache.txt", "treeCache").forEach((_, index) => {
      treeCache(index);

      checked++;
    });

    const files = backend === "wasm" ? ["mldsa", "slhdsa"] : ["mldsa"];

    for (const file of files) {
      for (const task of signatureTasks(`cross/${file}.txt`)) {
        signature(task);

        checked++;
      }
    }

    for (const file of backend === "wasm" ? ["hss", "xmss"] : ["hss"]) {
      for (const task of statefulTasks(`cross/${file}.txt`)) {
        stateful(task);

        checked++;
      }
    }

    checked += errorCodes();

    for (const check of [blake2Rfc, blake2Kats, blake2Derived, asconVectors, cshakeVectors, kmacVectors, hkdfVectors]) {
      checked += check();
    }

    const seconds = ((performance.now() - start) / 1000).toFixed(1);

    console.log(`${name} backend ${backend}: ${checked} checks passed in ${seconds} s`);
  } catch (error) {
    failed = true;

    console.log(`${name} backend ${backend}: FAILED ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`);
  }
}

process.exitCode = failed ? 1 : 0;
