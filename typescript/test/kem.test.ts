import assert from "node:assert/strict";
import { test } from "node:test";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { concat, der, hex, isCode, records, throwsCode, toHex } from "./vectors.ts";

const ALGORITHMS: Record<string, pq.KemAlgorithm> = {
  "ML-KEM-512": pq.ML_KEM_512,
  "ML-KEM-768": pq.ML_KEM_768,
  "ML-KEM-1024": pq.ML_KEM_1024,
};

const OIDS: Record<string, Uint8Array> = Object.fromEntries(
  Object.keys(ALGORITHMS).map((name, i) => [name, der(0x06, concat(hex("6086480165030404"), Uint8Array.of(i + 1)))]),
);

function pkcs8(name: string, privateKey: Uint8Array): Uint8Array {
  return der(0x30, concat(der(0x02, Uint8Array.of(0)), der(0x30, OIDS[name]), der(0x04, privateKey)));
}

function checkImport(
  function_: (data: Uint8Array) => unknown,
  data: Uint8Array,
  passed: string,
  context: string,
): void {
  if (passed === "true") {
    function_(data);
  } else {
    assert.throws(() => function_(data), pq.CryptoPQError, context);
  }
}

test("ML-KEM ACVP key generation", () => {
  for (const [header, record] of records("acvp/ML-KEM-keyGen.txt", "dk")) {
    const name = header.parameterSet;

    const algorithm = ALGORITHMS[name];

    const context = `tcId = ${record.tcId}`;

    const seed = concat(hex(record.d), hex(record.z));

    const ek = record.ek.toLowerCase();

    const dk = hex(record.dk);

    const pair = hazmat.generateKeyPair(algorithm, seed);

    assert.equal(toHex(pair.publicKey.exportKey("raw")), ek, context);

    assert.deepEqual(pair.privateKey.exportKey("raw"), seed, context);

    const expanded = algorithm.importPrivateKey(dk, "raw");

    assert.equal(toHex(expanded.publicKey.exportKey("raw")), ek, context);

    assert.deepEqual(expanded.exportKey("raw"), dk, context);

    for (const format of ["der", "pem"] as const) {
      assert.deepEqual(algorithm.importPrivateKey(expanded.exportKey(format), format).exportKey("raw"), dk, context);
    }

    const both = pkcs8(name, der(0x30, concat(der(0x04, seed), der(0x04, dk))));

    assert.deepEqual(algorithm.importPrivateKey(both, "der").exportKey("raw"), seed, context);
  }
});

test("ML-KEM ACVP encapsulation and decapsulation", () => {
  for (const [header, record] of records("acvp/ML-KEM-encapDecap.txt", "tcId")) {
    const algorithm = ALGORITHMS[header.parameterSet];

    const context = `tcId = ${record.tcId} (${header.function})`;

    if (header.function === "encapsulation") {
      const publicKey = algorithm.importPublicKey(hex(record.ek), "raw");

      const result = hazmat.encapsulate(publicKey, hex(record.m));

      assert.equal(toHex(result.ciphertext), record.c.toLowerCase(), context);

      assert.equal(toHex(result.sharedSecret), record.k.toLowerCase(), context);
    } else if (header.function === "decapsulation") {
      const privateKey =
        header.keyFormat === "seed"
          ? hazmat.generateKeyPair(algorithm, concat(hex(record.d), hex(record.z))).privateKey
          : algorithm.importPrivateKey(hex(record.dk), "raw");

      assert.equal(toHex(privateKey.decapsulate(hex(record.c))), record.k.toLowerCase(), context);
    } else if (header.function === "encapsulationKeyCheck") {
      checkImport((data) => algorithm.importPublicKey(data, "raw"), hex(record.ek), record.testPassed, context);
    } else {
      checkImport((data) => algorithm.importPrivateKey(data, "raw"), hex(record.dk), record.testPassed, context);
    }
  }
});

test("ML-KEM Wycheproof decapsulation", () => {
  for (const [header, record] of records("wycheproof/mlkem.txt", "tcId")) {
    const algorithm = ALGORITHMS[header.parameterSet];

    const context = `tcId = ${record.tcId} (${header.parameterSet})`;

    const seed = hex(record.seed);

    const c = hex(record.c);

    if (record.result === "valid") {
      const pair = hazmat.generateKeyPair(algorithm, seed);

      assert.equal(toHex(pair.publicKey.exportKey("raw")), record.ek.toLowerCase(), context);

      assert.equal(toHex(pair.privateKey.decapsulate(c)), record.K.toLowerCase(), context);
    } else if (seed.length !== 64) {
      throwsCode("INVALID_LENGTH", () => hazmat.generateKeyPair(algorithm, seed), context);
    } else {
      const privateKey = hazmat.generateKeyPair(algorithm, seed).privateKey;

      throwsCode("INVALID_LENGTH", () => privateKey.decapsulate(c), context);
    }
  }
});

test("ML-KEM Wycheproof encapsulation", () => {
  for (const [header, record] of records("wycheproof/mlkem_encaps.txt", "tcId")) {
    const algorithm = ALGORITHMS[header.parameterSet];

    const context = `tcId = ${record.tcId} (${header.parameterSet})`;

    const ek = hex(record.ek);

    if (record.result === "valid") {
      const result = hazmat.encapsulate(algorithm.importPublicKey(ek, "raw"), hex(record.m));

      assert.equal(toHex(result.ciphertext), record.c.toLowerCase(), context);

      assert.equal(toHex(result.sharedSecret), record.K.toLowerCase(), context);
    } else {
      const code = ek.length !== algorithm.publicKeySize ? "INVALID_LENGTH" : "INVALID_PUBLIC_KEY";

      throwsCode(code, () => algorithm.importPublicKey(ek, "raw"), context);
    }
  }
});

test("ML-KEM Wycheproof expanded decapsulation", () => {
  for (const [header, record] of records("wycheproof/mlkem_semi_expanded_decaps.txt", "tcId")) {
    const algorithm = ALGORITHMS[header.parameterSet];

    const context = `tcId = ${record.tcId} (${header.parameterSet})`;

    const dk = hex(record.dk);

    const c = hex(record.c);

    const flags = record.flags ?? "";

    if (record.result === "valid") {
      const privateKey = algorithm.importPrivateKey(dk, "raw");

      assert.equal(toHex(privateKey.publicKey.exportKey("raw")), record.ek.toLowerCase(), context);

      assert.equal(toHex(privateKey.decapsulate(c)), record.K.toLowerCase(), context);
    } else if (flags.includes("IncorrectCiphertextLength")) {
      const privateKey = algorithm.importPrivateKey(dk, "raw");

      throwsCode("INVALID_LENGTH", () => privateKey.decapsulate(c), context);
    } else if (flags.includes("IncorrectDecapsulationKeyLength")) {
      throwsCode("INVALID_LENGTH", () => algorithm.importPrivateKey(dk, "raw"), context);
    } else {
      throwsCode("INVALID_PRIVATE_KEY", () => algorithm.importPrivateKey(dk, "raw"), context);
    }
  }
});

test("KEM round trip", () => {
  for (const algorithm of [...Object.values(ALGORITHMS), pq.X_WING]) {
    const context = algorithm.name;

    const pair = algorithm.generateKeyPair();

    const encapsulation = pair.publicKey.encapsulate();

    assert.equal(encapsulation.ciphertext.length, algorithm.ciphertextSize, context);

    assert.equal(encapsulation.sharedSecret.length, algorithm.sharedSecretSize, context);

    assert.deepEqual(pair.privateKey.decapsulate(encapsulation.ciphertext), encapsulation.sharedSecret, context);

    const tampered = encapsulation.ciphertext.slice();

    tampered[0] ^= 1;

    assert.notDeepEqual(pair.privateKey.decapsulate(tampered), encapsulation.sharedSecret, context);

    throwsCode("INVALID_LENGTH", () => pair.privateKey.decapsulate(encapsulation.ciphertext.subarray(1)), context);

    assert.equal(pair.publicKey.exportKey("raw").length, algorithm.publicKeySize, context);

    assert.equal(algorithm.generateKeyPair({ selfTest: false }).publicKey.algorithm, algorithm, context);

    throwsCode("INVALID_OPTION", () => algorithm.generateKeyPair({ selfTest: 1 as unknown as boolean }), context);
  }
});

// Keys compute what they derive on first use and keep it: repeated use of one key, through its own
// public key, an imported copy or the private key imported in expanded form, must agree with fresh
// keys every time.
test("KEM key caches", () => {
  const keys = new Map<pq.KemAlgorithm, [Uint8Array, Uint8Array | null]>();

  for (const [header, record] of records("acvp/ML-KEM-keyGen.txt", "dk")) {
    keys.set(ALGORITHMS[header.parameterSet], [concat(hex(record.d), hex(record.z)), hex(record.dk)]);
  }

  keys.set(pq.X_WING, [Uint8Array.from({ length: 32 }, (_, i) => i), null]);

  for (const [algorithm, [seed, dk]] of keys) {
    const pair = hazmat.generateKeyPair(algorithm, seed);

    // The cache lives with the public key, which the private key reads: one per key pair.
    assert.equal(pair.privateKey.publicKey, pair.publicKey);

    const imported = algorithm.importPublicKey(pair.publicKey.exportKey("raw"), "raw");

    const expanded = dk === null ? pair.privateKey : algorithm.importPrivateKey(dk, "raw");

    for (let round = 0; round < 3; round++) {
      const randomness = Uint8Array.from({ length: algorithm === pq.X_WING ? 64 : 32 }, (_, i) => i + 7 * round);

      const want = hazmat.encapsulate(hazmat.generateKeyPair(algorithm, seed).publicKey, randomness);

      for (const publicKey of [pair.publicKey, imported, expanded.publicKey]) {
        const got = hazmat.encapsulate(publicKey, randomness);

        assert.deepEqual([got.ciphertext, got.sharedSecret], [want.ciphertext, want.sharedSecret], algorithm.name);
      }

      for (const privateKey of [pair.privateKey, expanded]) {
        assert.deepEqual(privateKey.decapsulate(want.ciphertext), want.sharedSecret, algorithm.name);
      }
    }
  }
});

test("KEM formats", () => {
  for (const algorithm of Object.values(ALGORITHMS)) {
    const context = algorithm.name;

    const pair = algorithm.generateKeyPair();

    for (const format of ["raw", "der", "pem"] as const) {
      const exported = pair.publicKey.exportKey(format);

      assert.ok(algorithm.importPublicKey(exported, format).equals(pair.publicKey), `${context} ${format}`);

      const privateKey = algorithm.importPrivateKey(pair.privateKey.exportKey(format), format);

      assert.ok(privateKey.publicKey.equals(pair.publicKey), `${context} ${format}`);
    }

    const pem = pair.publicKey.exportKey("pem");

    assert.ok(pem.startsWith("-----BEGIN PUBLIC KEY-----\n"), context);

    assert.ok(algorithm.importPublicKey(new TextEncoder().encode(pem), "pem").equals(pair.publicKey), context);

    assert.ok(pair.privateKey.exportKey("pem").startsWith("-----BEGIN PRIVATE KEY-----\n"), context);

    assert.deepEqual(pair.privateKey.exportKey("der").subarray(-66, -64), Uint8Array.of(0x80, 0x40), context);

    throwsCode("INVALID_OPTION", () => pair.publicKey.exportKey("jwk" as "raw"), context);

    const trailing = concat(pair.publicKey.exportKey("der"), Uint8Array.of(0));

    throwsCode("INVALID_ENCODING", () => algorithm.importPublicKey(trailing, "der"), context);

    throwsCode("INVALID_ENCODING", () => algorithm.importPublicKey(pair.privateKey.exportKey("pem"), "pem"), context);

    throwsCode("INVALID_LENGTH", () => algorithm.importPrivateKey(new Uint8Array(63), "raw"), context);
  }

  const pair = pq.ML_KEM_768.generateKeyPair();

  throwsCode("ALGORITHM_MISMATCH", () => pq.ML_KEM_512.importPublicKey(pair.publicKey.exportKey("der"), "der"));

  throwsCode("ALGORITHM_MISMATCH", () => pq.ML_KEM_1024.importPrivateKey(pair.privateKey.exportKey("pem"), "pem"));
});

test("KEM input types", () => {
  const pair = pq.ML_KEM_512.generateKeyPair();

  const encoded = pair.publicKey.exportKey("der");

  assert.throws(() => pq.ML_KEM_512.importPublicKey(toHex(encoded), "der"), TypeError);

  assert.throws(() => pq.ML_KEM_512.importPublicKey(Array.from(encoded) as unknown as Uint8Array, "raw"), TypeError);

  assert.throws(() => pair.privateKey.decapsulate("ciphertext" as unknown as Uint8Array), TypeError);

  assert.throws(() => hazmat.generateKeyPair(pq.SHA_256 as unknown as pq.KemAlgorithm, new Uint8Array(64)), TypeError);

  assert.ok(Object.isFrozen(pq.ML_KEM_512));

  assert.equal(pq.ML_KEM_768.name, "ML-KEM-768");

  assert.equal(pq.X_WING.name, "X-Wing");

  assert.ok(!pair.publicKey.equals(pq.ML_KEM_512.generateKeyPair().publicKey));
});

test("X-Wing", () => {
  for (const [, record] of records("xwing/test-vectors.txt", "seed")) {
    const context = record.seed.slice(0, 16);

    const pair = hazmat.generateKeyPair(pq.X_WING, hex(record.seed));

    assert.equal(toHex(pair.publicKey.exportKey("raw")), record.pk.toLowerCase(), context);

    assert.equal(toHex(pair.privateKey.exportKey("raw")), record.sk.toLowerCase(), context);

    const result = hazmat.encapsulate(pair.publicKey, hex(record.eseed));

    assert.equal(toHex(result.ciphertext), record.ct.toLowerCase(), context);

    assert.equal(toHex(result.sharedSecret), record.ss.toLowerCase(), context);

    assert.deepEqual(pair.privateKey.decapsulate(result.ciphertext), result.sharedSecret, context);
  }

  const pair = pq.X_WING.generateKeyPair();

  for (const format of ["der", "pem"] as const) {
    throwsCode("UNSUPPORTED", () => pair.publicKey.exportKey(format));

    throwsCode("UNSUPPORTED", () => pq.X_WING.importPrivateKey(new Uint8Array(), format));
  }

  const imported = pq.X_WING.importPrivateKey(pair.privateKey.exportKey("raw"), "raw");

  assert.ok(imported.publicKey.equals(pair.publicKey));

  const unreduced = pair.publicKey.exportKey("raw");

  unreduced[0] = 0xff;

  unreduced[1] |= 0x0f;

  throwsCode("INVALID_PUBLIC_KEY", () => pq.X_WING.importPublicKey(unreduced, "raw"));

  throwsCode("INVALID_LENGTH", () => pq.X_WING.importPublicKey(unreduced.subarray(1), "raw"));

  assert.throws(() => hazmat.encapsulate(pair.publicKey, new Uint8Array(32)), isCode("INVALID_LENGTH"));
});

test("DER and PEM strictness", () => {
  const pair = pq.ML_KEM_512.generateKeyPair({ selfTest: false });

  const key = pair.publicKey.exportKey("raw");

  const oid = der(0x06, concat(hex("6086480165030404"), Uint8Array.of(1)));

  const spki = (algorithm: Uint8Array, bits: Uint8Array) => der(0x30, concat(algorithm, bits));

  const bits = der(0x03, concat(Uint8Array.of(0), key));

  assert.ok(pq.ML_KEM_512.importPublicKey(spki(der(0x30, oid), bits), "der").equals(pair.publicKey));

  const invalid: [string, Uint8Array][] = [
    ["long form below 128", spki(concat(Uint8Array.of(0x30, 0x81, oid.length), oid), bits)],
    ["leading zero length byte", spki(der(0x30, oid), concat(Uint8Array.of(0x03, 0x83, 0x00, 0x03, 0x21, 0), key))],
    ["five length bytes", spki(der(0x30, oid), concat(Uint8Array.of(0x03, 0x85, 0, 0, 0, 0x03, 0x21, 0), key))],
    ["indefinite length", spki(der(0x30, oid), concat(Uint8Array.of(0x03, 0x80, 0), key))],
    ["unused bits", spki(der(0x30, oid), der(0x03, concat(Uint8Array.of(1), key)))],
    ["parameters present", spki(der(0x30, concat(oid, Uint8Array.of(0x05, 0))), bits)],
    ["inner key too short", spki(der(0x30, oid), der(0x03, concat(Uint8Array.of(0), key.subarray(1))))],
    ["truncated", spki(der(0x30, oid), bits).subarray(0, 100)],
    ["empty", new Uint8Array()],
  ];

  for (const [name, encoding] of invalid) {
    throwsCode("INVALID_ENCODING", () => pq.ML_KEM_512.importPublicKey(encoding, "der"), name);
  }

  const pem = pair.privateKey.exportKey("pem");

  const body = pem.split("\n").slice(1, -2).join("");

  const lines = `${body.slice(0, 10)}\r\n ${body.slice(10)}\t`;

  const rewrapped = `-----BEGIN PRIVATE KEY-----\r\n${lines}\n-----END PRIVATE KEY-----`;

  assert.ok(pq.ML_KEM_512.importPrivateKey(rewrapped, "pem").publicKey.equals(pair.publicKey));

  assert.ok(body.endsWith("=") && !body.endsWith("=="));

  const last = body.at(-2) as string;

  const noncanonical = pem.replace(`${last}=`, `${String.fromCharCode(last.charCodeAt(0) ^ 1)}=`);

  throwsCode("INVALID_ENCODING", () => pq.ML_KEM_512.importPrivateKey(noncanonical, "pem"));

  throwsCode("INVALID_ENCODING", () => pq.ML_KEM_512.importPrivateKey(pem.replace("=", "A"), "pem"));

  throwsCode("INVALID_ENCODING", () => pq.ML_KEM_512.importPrivateKey(`x${pem}`, "pem"));

  throwsCode("INVALID_OPTION", () => pq.ML_KEM_512.importPrivateKey(pem, "PEM" as "pem"));
});

test("RNG failures", () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "crypto") as PropertyDescriptor;

  const replace = (value: unknown) => Object.defineProperty(globalThis, "crypto", { value, configurable: true });

  try {
    replace(undefined);

    throwsCode("RNG_FAILURE", () => pq.ML_KEM_512.generateKeyPair());

    replace({
      getRandomValues() {
        throw new Error("no entropy");
      },
    });

    assert.throws(
      () => pq.ML_DSA_44.generateKeyPair(),
      (error: unknown) => isCode("RNG_FAILURE")(error) && (error as Error).cause instanceof Error,
    );
  } finally {
    Object.defineProperty(globalThis, "crypto", original);
  }

  assert.equal(pq.ML_KEM_512.generateKeyPair().publicKey.algorithm, pq.ML_KEM_512);
});
