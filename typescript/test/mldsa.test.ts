import assert from "node:assert/strict";
import { test } from "node:test";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { PRE_HASHES, concat, der, hex, preHash, records, throwsCode, toHex, utf8 } from "./vectors.ts";

const ALGORITHMS: Record<string, pq.SignatureAlgorithm> = {
  "ML-DSA-44": pq.ML_DSA_44,
  "ML-DSA-65": pq.ML_DSA_65,
  "ML-DSA-87": pq.ML_DSA_87,
};

const OIDS: Record<string, Uint8Array> = Object.fromEntries(
  Object.keys(ALGORITHMS).map((name, i) => [name, der(0x06, concat(hex("6086480165030403"), Uint8Array.of(17 + i)))]),
);

function pkcs8(name: string, privateKey: Uint8Array): Uint8Array {
  return der(0x30, concat(der(0x02, Uint8Array.of(0)), der(0x30, OIDS[name]), der(0x04, privateKey)));
}

test("ML-DSA ACVP key generation", () => {
  for (const [header, record] of records("acvp/ML-DSA-keyGen.txt", "sk")) {
    const name = header.parameterSet;

    const algorithm = ALGORITHMS[name];

    const context = `tcId = ${record.tcId}`;

    const seed = hex(record.seed);

    const sk = hex(record.sk);

    const pair = hazmat.generateKeyPair(algorithm, seed);

    assert.equal(toHex(pair.publicKey.exportKey("raw")), record.pk.toLowerCase(), context);

    assert.deepEqual(pair.privateKey.exportKey("raw"), seed, context);

    const expanded = algorithm.importPrivateKey(sk, "raw");

    assert.equal(toHex(expanded.publicKey.exportKey("raw")), record.pk.toLowerCase(), context);

    assert.deepEqual(expanded.exportKey("raw"), sk, context);

    if (record.tcId === "1") {
      for (const format of ["der", "pem"] as const) {
        assert.deepEqual(algorithm.importPrivateKey(expanded.exportKey(format), format).exportKey("raw"), sk, context);
      }
    }

    const both = pkcs8(name, der(0x30, concat(der(0x04, seed), der(0x04, sk))));

    assert.deepEqual(algorithm.importPrivateKey(both, "der").exportKey("raw"), seed, context);

    const corrupted = sk.slice();

    corrupted[corrupted.length - 1] ^= 1;

    throwsCode("INVALID_PRIVATE_KEY", () => algorithm.importPrivateKey(corrupted, "raw"), context);
  }
});

test("ML-DSA ACVP signature generation", () => {
  for (const [header, record] of records("acvp/ML-DSA-sigGen.txt", "signature")) {
    const algorithm = ALGORITHMS[header.parameterSet];

    const context = `tcId = ${record.tcId}`;

    const privateKey =
      header.keyFormat === "seed"
        ? hazmat.generateKeyPair(algorithm, hex(record.seed)).privateKey
        : algorithm.importPrivateKey(hex(record.sk), "raw");

    assert.equal(toHex(privateKey.publicKey.exportKey("raw")), record.pk.toLowerCase(), context);

    const randomness = header.deterministic === "true" ? new Uint8Array(32) : hex(record.rnd);

    const message = hex(record.message);

    const options = { context: hex(record.context), preHash: preHash(header, record) };

    const signature = hazmat.sign(privateKey, message, randomness, options);

    assert.equal(toHex(signature), record.signature.toLowerCase(), context);

    assert.ok(hazmat.verify(privateKey.publicKey, signature, message, options), context);
  }
});

test("ML-DSA ACVP signature verification", () => {
  for (const [header, record] of records("acvp/ML-DSA-sigVer.txt", "signature")) {
    const publicKey = ALGORITHMS[header.parameterSet].importPublicKey(hex(record.pk), "raw");

    const result = hazmat.verify(publicKey, hex(record.signature), hex(record.message), {
      context: hex(record.context),
      preHash: preHash(header, record),
    });

    assert.equal(result, record.testPassed === "true", `tcId = ${record.tcId} (${record.reason})`);
  }
});

test("ML-DSA Wycheproof verification", () => {
  for (const [header, record] of records("wycheproof/mldsa_verify.txt", "tcId")) {
    const algorithm = ALGORITHMS[header.parameterSet];

    const context = `tcId = ${record.tcId} (${header.parameterSet})`;

    const key = hex(header.publicKey);

    if (key.length !== algorithm.publicKeySize) {
      throwsCode("INVALID_LENGTH", () => algorithm.importPublicKey(key, "raw"), context);

      continue;
    }

    const publicKey = algorithm.importPublicKey(key, "raw");

    if (header.publicKeyDer) {
      assert.ok(algorithm.importPublicKey(hex(header.publicKeyDer), "der").equals(publicKey), context);
    }

    const result = publicKey.verify(hex(record.sig), hex(record.msg), { context: hex(record.ctx ?? "") });

    assert.equal(result, record.result === "valid", context);
  }
});

test("ML-DSA Wycheproof deterministic signing", () => {
  for (const [header, record] of records("wycheproof/mldsa_sign_seed.txt", "tcId")) {
    if (!("msg" in record)) {
      continue;
    }

    const algorithm = ALGORITHMS[header.parameterSet];

    const context = `tcId = ${record.tcId} (${header.parameterSet})`;

    const seed = hex(header.privateSeed);

    const options = { context: hex(record.ctx ?? "") };

    const flags = record.flags ?? "";

    if (flags.includes("IncorrectPrivateKeyLength")) {
      throwsCode("INVALID_LENGTH", () => hazmat.generateKeyPair(algorithm, seed), context);

      continue;
    }

    const privateKey = header.privateKeyPkcs8
      ? algorithm.importPrivateKey(hex(header.privateKeyPkcs8), "der")
      : hazmat.generateKeyPair(algorithm, seed).privateKey;

    assert.equal(toHex(privateKey.publicKey.exportKey("raw")), header.publicKey.toLowerCase(), context);

    if (flags.includes("InvalidContext")) {
      throwsCode("INVALID_CONTEXT", () => privateKey.sign(hex(record.msg), options), context);
    } else if (flags.includes("Randomized")) {
      assert.ok(privateKey.publicKey.verify(hex(record.sig), hex(record.msg), options), context);
    } else {
      const signature = privateKey.sign(hex(record.msg), { ...options, deterministic: true });

      assert.equal(toHex(signature), record.sig.toLowerCase(), context);
    }
  }
});

test("ML-DSA round trip", () => {
  for (const algorithm of Object.values(ALGORITHMS)) {
    const name = algorithm.name;

    const pair = algorithm.generateKeyPair();

    const message = utf8("message");

    const context = utf8("context");

    const signature = pair.privateKey.sign(message, { context });

    assert.equal(signature.length, algorithm.signatureSize, name);

    assert.ok(pair.publicKey.verify(signature, message, { context }), name);

    assert.ok(!pair.publicKey.verify(signature, message), name);

    assert.ok(!pair.publicKey.verify(signature, utf8("other"), { context }), name);

    assert.ok(!pair.publicKey.verify(signature.subarray(1), message, { context }), name);

    assert.ok(!pair.publicKey.verify(signature, message, { context: new Uint8Array(256) }), name);

    throwsCode("INVALID_CONTEXT", () => pair.privateKey.sign(message, { context: new Uint8Array(256) }), name);

    const deterministic = pair.privateKey.sign(message, { deterministic: true });

    assert.deepEqual(deterministic, pair.privateKey.sign(message, { deterministic: true }), name);

    assert.notDeepEqual(pair.privateKey.sign(message), pair.privateKey.sign(message), name);

    const hashed = pair.privateKey.sign(message, { preHash: pq.SHA_512 });

    assert.ok(pair.publicKey.verify(hashed, message, { preHash: pq.SHA_512 }), name);

    assert.ok(!pair.publicKey.verify(hashed, message), name);

    throwsCode("INVALID_OPTION", () => pair.privateKey.sign(message, { preHash: pq.SHA_224 }), name);

    const invalid = { preHash: "SHA-512" as unknown as pq.HashAlgorithm };

    throwsCode("INVALID_OPTION", () => pair.publicKey.verify(hashed, message, invalid), name);

    const nonBoolean = { deterministic: 1 as unknown as boolean };

    throwsCode("INVALID_OPTION", () => pair.privateKey.sign(message, nonBoolean), name);
  }
});

test("ML-DSA pre-hash strength", () => {
  const allowed: Record<string, string[]> = {
    "ML-DSA-44": [
      "SHA2-256",
      "SHA2-384",
      "SHA2-512",
      "SHA2-512/256",
      "SHA3-256",
      "SHA3-384",
      "SHA3-512",
      "SHAKE-128",
      "SHAKE-256",
    ],
    "ML-DSA-65": ["SHA2-384", "SHA2-512", "SHA3-384", "SHA3-512", "SHAKE-256"],
    "ML-DSA-87": ["SHA2-512", "SHA3-512", "SHAKE-256"],
  };

  const message = utf8("m");

  for (const [name, algorithm] of Object.entries(ALGORITHMS)) {
    const privateKey = hazmat.generateKeyPair(algorithm, new Uint8Array(32)).privateKey;

    for (const [label, function_] of Object.entries(PRE_HASHES)) {
      const context = `${name} ${label}`;

      const options = { preHash: function_ };

      if (allowed[name].includes(label)) {
        const signature = privateKey.sign(message, options);

        assert.ok(privateKey.publicKey.verify(signature, message, options), context);
      } else {
        throwsCode("INVALID_OPTION", () => privateKey.sign(message, options), context);

        const signature = hazmat.sign(privateKey, message, new Uint8Array(32), options);

        assert.ok(hazmat.verify(privateKey.publicKey, signature, message, options), context);

        assert.ok(!privateKey.publicKey.verify(signature, message, options), context);
      }
    }
  }
});

test("ML-DSA formats", () => {
  for (const [name, algorithm] of Object.entries(ALGORITHMS)) {
    const pair = algorithm.generateKeyPair({ selfTest: false });

    for (const format of ["raw", "der", "pem"] as const) {
      assert.ok(algorithm.importPublicKey(pair.publicKey.exportKey(format), format).equals(pair.publicKey), name);

      const privateKey = algorithm.importPrivateKey(pair.privateKey.exportKey(format), format);

      assert.deepEqual(privateKey.exportKey("raw"), pair.privateKey.exportKey("raw"), name);
    }

    assert.deepEqual(pair.privateKey.exportKey("der").subarray(-34, -32), Uint8Array.of(0x80, 0x20), name);

    const expanded = hazmat.generateKeyPair(algorithm, pair.privateKey.exportKey("raw"));

    assert.ok(expanded.publicKey.equals(pair.publicKey), name);

    const other = algorithm !== pq.ML_DSA_44 ? pq.ML_DSA_44 : pq.ML_DSA_65;

    throwsCode("ALGORITHM_MISMATCH", () => other.importPublicKey(pair.publicKey.exportKey("der"), "der"), name);

    throwsCode("INVALID_LENGTH", () => algorithm.importPrivateKey(new Uint8Array(33), "raw"), name);
  }
});

test("signature encodings", () => {
  const pair = pq.ML_DSA_44.generateKeyPair({ selfTest: false });

  const name = "ML-DSA-44";

  const raw = pair.publicKey.exportKey("raw");

  const spki = (key: Uint8Array) => der(0x30, concat(der(0x30, OIDS[name]), der(0x03, concat(Uint8Array.of(0), key))));

  assert.ok(pq.ML_DSA_44.importPublicKey(spki(raw), "der").equals(pair.publicKey));

  throwsCode("INVALID_ENCODING", () => pq.ML_DSA_44.importPublicKey(spki(raw.subarray(1)), "der"));

  throwsCode("INVALID_LENGTH", () => pq.ML_DSA_44.importPublicKey(raw.subarray(1), "raw"));

  const seed = pair.privateKey.exportKey("raw");

  const oneAsymmetricKey = (version: number, key: Uint8Array) =>
    der(
      0x30,
      concat(
        der(0x02, Uint8Array.of(version)),
        der(0x30, OIDS[name]),
        der(0x04, der(0x80, seed)),
        der(0x81, concat(Uint8Array.of(0), key)),
      ),
    );

  assert.deepEqual(pq.ML_DSA_44.importPrivateKey(oneAsymmetricKey(1, raw), "der").exportKey("raw"), seed);

  const wrongPublicKey = raw.slice();

  wrongPublicKey[0] ^= 1;

  throwsCode("INVALID_PRIVATE_KEY", () => pq.ML_DSA_44.importPrivateKey(oneAsymmetricKey(1, wrongPublicKey), "der"));

  throwsCode("INVALID_ENCODING", () => pq.ML_DSA_44.importPrivateKey(oneAsymmetricKey(0, raw), "der"));

  const mismatched = pkcs8(name, der(0x30, concat(der(0x04, seed), der(0x04, new Uint8Array(2560)))));

  throwsCode("INVALID_PRIVATE_KEY", () => pq.ML_DSA_44.importPrivateKey(mismatched, "der"));

  const pem = pair.privateKey.exportKey("pem");

  assert.deepEqual(pq.ML_DSA_44.importPrivateKey(`\n  ${pem}\n\n`, "pem").exportKey("raw"), seed);

  throwsCode("INVALID_ENCODING", () => pq.ML_DSA_44.importPrivateKey(pem.replace("PRIVATE", "PUBLIC"), "pem"));

  throwsCode("INVALID_ENCODING", () => pq.ML_DSA_44.importPrivateKey(pem.replace("M", "*"), "pem"));

  throwsCode("INVALID_ENCODING", () => pq.ML_DSA_44.importPrivateKey(pem.replace("M", "é"), "pem"));

  assert.throws(() => pair.privateKey.sign("message" as unknown as Uint8Array), TypeError);

  const badContext = { context: "c" as unknown as Uint8Array };

  assert.throws(() => pair.publicKey.verify(new Uint8Array(), utf8("m"), badContext), TypeError);

  assert.equal(pq.SLH_DSA_SHA2_128S.name, "SLH-DSA-SHA2-128s");

  assert.ok(Object.isFrozen(pq.ML_DSA_65));
});
