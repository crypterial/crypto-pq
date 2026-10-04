import assert from "node:assert/strict";
import { test } from "node:test";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { parallel } from "./parallel.ts";
import { MemoryStore, throwsCode, utf8 } from "./vectors.ts";
import { referenceVectorTasks } from "./xmss-vectors.ts";

test("XMSS reference vectors", () => {
  return parallel(new URL("./xmss-vectors.ts", import.meta.url), "referenceVector", referenceVectorTasks());
});

test("XMSS state handling", () => {
  const store = new MemoryStore();

  const pair = pq.XMSS_MT.generateKeyPair({ parameters: "XMSSMT-SHAKE256_20/4_192", stateStore: store });

  const signature = pair.privateKey.sign(utf8("message"));

  assert.ok(pair.publicKey.verify(signature, utf8("message")));

  const loaded = pq.XMSS_MT.loadPrivateKey(store);

  assert.equal(loaded.remainingSignatures(), (1n << 20n) - 1n);

  for (const format of ["raw", "der", "pem"] as const) {
    assert.ok(pq.XMSS_MT.importPublicKey(pair.publicKey.exportKey(format), format).equals(pair.publicKey));
  }

  throwsCode("INVALID_OPTION", () =>
    pq.XMSS.generateKeyPair({ parameters: "XMSSMT-SHAKE256_20/4_192", stateStore: new MemoryStore() }),
  );

  assert.equal(pq.XMSS_MT.name, "XMSS^MT");

  assert.equal(pq.HSS_LMS.name, "HSS/LMS");
});

// A key keeps each upper layer's part of the signature until the index leaves the subtree it
// signs; a key made at the same index, with nothing kept, must give the same bytes. Index 1024
// starts a new tree on layers 0 and 1 and a new leaf on layer 2.
test("XMSS^MT keeps the upper layers' signatures", () => {
  const parameters = "XMSSMT-SHA2_20/4_192";

  const seed = Uint8Array.from({ length: 72 }, (_, i) => i);

  const pair = hazmat.generateStatefulKeyPair(pq.XMSS_MT, seed, { parameters, stateStore: new MemoryStore(), index: 1022n });

  for (let index = 1022n; index < 1027n; index++) {
    const message = utf8(`message ${index}`);

    const fresh = hazmat.generateStatefulKeyPair(pq.XMSS_MT, seed, { parameters, stateStore: new MemoryStore(), index });

    const signature = pair.privateKey.sign(message);

    assert.deepEqual(signature, fresh.privateKey.sign(message), `index ${index}`);

    assert.ok(pair.publicKey.verify(signature, message), `index ${index}`);
  }
});
