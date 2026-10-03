import assert from "node:assert/strict";
import { test } from "node:test";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { parallel } from "./parallel.ts";
import { ALGORITHMS, keyGenerationTasks, signatureGenerationTasks } from "./slhdsa-vectors.ts";
import { concat, der, hex, preHash, records, throwsCode, utf8 } from "./vectors.ts";

const CHECKS = new URL("./slhdsa-vectors.ts", import.meta.url);

test("SLH-DSA ACVP key generation", () => parallel(CHECKS, "keyGeneration", keyGenerationTasks()));

test("SLH-DSA ACVP signature generation", () => parallel(CHECKS, "signatureGeneration", signatureGenerationTasks()));

test("SLH-DSA ACVP signature verification", () => {
  for (const [header, record] of records("acvp/SLH-DSA-sigVer.txt", "signature")) {
    const publicKey = ALGORITHMS[header.parameterSet].importPublicKey(hex(record.pk), "raw");

    const result = hazmat.verify(publicKey, hex(record.signature), hex(record.message), {
      context: hex(record.context),
      preHash: preHash(header, record),
    });

    assert.equal(result, record.testPassed === "true", `tcId = ${record.tcId} (${record.reason})`);
  }
});

test("SLH-DSA round trip", () => {
  const algorithm = pq.SLH_DSA_SHAKE_128F;

  const pair = algorithm.generateKeyPair({ selfTest: false });

  const message = utf8("message");

  const context = utf8("context");

  const signature = pair.privateKey.sign(message, { context, deterministic: true });

  assert.ok(pair.publicKey.verify(signature, message, { context }));

  const pkSeed = pair.publicKey.exportKey("raw").subarray(0, 16);

  assert.deepEqual(signature, hazmat.sign(pair.privateKey, message, pkSeed, { context }));

  assert.ok(!pair.publicKey.verify(signature, message));

  assert.ok(!pair.publicKey.verify(signature.subarray(1), message, { context }));

  for (const format of ["raw", "der", "pem"] as const) {
    assert.ok(algorithm.importPublicKey(pair.publicKey.exportKey(format), format).equals(pair.publicKey));

    const privateKey = algorithm.importPrivateKey(pair.privateKey.exportKey(format), format);

    assert.deepEqual(privateKey.exportKey("raw"), pair.privateKey.exportKey("raw"));
  }

  assert.equal(pair.privateKey.exportKey("raw").length, 64);

  throwsCode("INVALID_OPTION", () => pair.privateKey.sign(utf8("m"), { preHash: pq.SHA_224 }));

  throwsCode("INVALID_LENGTH", () => algorithm.importPrivateKey(new Uint8Array(63), "raw"));

  const oid = der(0x06, hex("60864801650304031b"));

  const short = der(0x30, concat(der(0x02, Uint8Array.of(0)), der(0x30, oid), der(0x04, new Uint8Array(63))));

  throwsCode("INVALID_ENCODING", () => algorithm.importPrivateKey(short, "der"));
});

// RFC 9909, Appendix C: an SLH-DSA-SHA2-128s private key in PKCS#8.
test("SLH-DSA RFC 9909 private key", () => {
  const pem =
    "-----BEGIN PRIVATE KEY-----\n" +
    "MFICAQAwCwYJYIZIAWUDBAMUBECiJjvKRYYINlIxYASVI9YhZ3+tkNUetgZ6Mn4N\n" +
    "HmSlASuBCex3fKpOHwJMz8+Ul9mRgFCSgPQlavKwevgCibSU\n" +
    "-----END PRIVATE KEY-----\n";

  const privateKey = pq.SLH_DSA_SHA2_128S.importPrivateKey(pem, "pem");

  assert.equal(privateKey.exportKey("pem"), pem);
});
