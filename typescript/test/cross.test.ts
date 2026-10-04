import assert from "node:assert/strict";
import { test } from "node:test";

import { execute, kem, latin1, signatureTasks, statefulTasks, vectors } from "./cross-checks.ts";
import { parallel } from "./parallel.ts";
import { hex, toHex } from "./vectors.ts";

const CHECKS = new URL("./cross-checks.ts", import.meta.url);

test("cross KEM vectors", () => {
  vectors("cross/kem.txt", "seed").forEach((_, index) => kem(index));
});

test("cross ML-DSA vectors", () => parallel(CHECKS, "signature", signatureTasks("cross/mldsa.txt")));

test("cross SLH-DSA vectors", () => parallel(CHECKS, "signature", signatureTasks("cross/slhdsa.txt")));

test("cross HSS vectors", () => parallel(CHECKS, "stateful", statefulTasks("cross/hss.txt")));

test("cross XMSS vectors", () => parallel(CHECKS, "stateful", statefulTasks("cross/xmss.txt")));

// Every disagreement is collected, so that one run lists them all. PEM input is also given as a
// string, which the import functions accept too.
test("cross error codes", async () => {
  const cases = vectors("cross/errors.txt", "result");

  const failures: string[] = [];

  for (const [header, record] of cases) {
    const data = hex(record.input ?? "");

    for (const value of record.format === "pem" ? [data, latin1(data)] : [data]) {
      const outcome = await execute(header, record, value);

      const output = record.output !== undefined && toHex(outcome.output ?? new Uint8Array()) !== record.output;

      const remaining = record.remaining !== undefined && outcome.remaining !== BigInt(record.remaining);

      if (outcome.result !== record.result || output || remaining) {
        const kind = typeof value === "string" ? " (string)" : "";

        failures.push(`${header.algorithm}: ${record.name}${kind}: got ${outcome.result}, expected ${record.result}`);
      }
    }
  }

  assert.deepEqual(failures, [], `${failures.length} of ${cases.length} cases disagree`);
});
