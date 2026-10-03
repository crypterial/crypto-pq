import assert from "node:assert/strict";
import { test } from "node:test";

import * as pq from "../src/index.ts";
import { parallel } from "./parallel.ts";
import { MemoryStore, rejectsCode, utf8 } from "./vectors.ts";
import { referenceVectorTasks } from "./xmss-vectors.ts";

test("XMSS reference vectors", () => {
  return parallel(new URL("./xmss-vectors.ts", import.meta.url), "referenceVector", referenceVectorTasks());
});

test("XMSS state handling", async () => {
  const store = new MemoryStore();

  const pair = await pq.XMSS_MT.generateKeyPair({ parameters: "XMSSMT-SHAKE256_20/4_192", stateStore: store });

  const signature = await pair.privateKey.sign(utf8("message"));

  assert.ok(pair.publicKey.verify(signature, utf8("message")));

  const loaded = await pq.XMSS_MT.loadPrivateKey(store);

  assert.equal(loaded.remainingSignatures(), (1n << 20n) - 1n);

  for (const format of ["raw", "der", "pem"] as const) {
    assert.ok(pq.XMSS_MT.importPublicKey(pair.publicKey.exportKey(format), format).equals(pair.publicKey));
  }

  await rejectsCode("INVALID_OPTION", () =>
    pq.XMSS.generateKeyPair({ parameters: "XMSSMT-SHAKE256_20/4_192", stateStore: new MemoryStore() }),
  );

  assert.equal(pq.XMSS_MT.name, "XMSS^MT");

  assert.equal(pq.HSS_LMS.name, "HSS/LMS");
});
