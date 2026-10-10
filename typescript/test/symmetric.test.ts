import assert from "node:assert/strict";
import { test } from "node:test";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import {
  BLAKE2,
  HKDF,
  asconVectors,
  blake2Derived,
  blake2Kats,
  blake2Rfc,
  cshakeVectors,
  hkdfVectors,
  kmacVectors,
} from "./symmetric-vectors.ts";
import { throwsCode, toHex, utf8 } from "./vectors.ts";

test("BLAKE2: RFC 7693 examples and self-test", () => {
  blake2Rfc();
});

test("BLAKE2: reference KATs, unkeyed and with the longest key", () => {
  blake2Kats();
});

test("BLAKE2: salt, personalization, keys and lengths", () => {
  blake2Derived();
});

test("Ascon: the designers' KATs and the byte-aligned ACVP tests", () => {
  asconVectors();
});

test("cSHAKE: SP 800-185 examples and the byte-aligned ACVP tests", () => {
  cshakeVectors();
});

test("KMAC: SP 800-185 examples, ACVP and Wycheproof", () => {
  kmacVectors();
});

test("HKDF: RFC 5869, Wycheproof and ACVP", () => {
  hkdfVectors();
});

test("HKDF: lengths and options", () => {
  for (const algorithm of Object.values(HKDF)) {
    const size = algorithm.prkSize;

    const ikm = utf8("input key material");

    const prk = algorithm.extract(ikm);

    assert.equal(prk.length, size);

    assert.deepEqual(algorithm.extract(ikm, { salt: new Uint8Array(size) }), prk);

    assert.deepEqual(algorithm.derive(ikm, 255 * size), algorithm.expand(prk, 255 * size));

    for (const length of [0, -1, 1.5, Number.NaN, 255 * size + 1]) {
      throwsCode("INVALID_LENGTH", () => algorithm.derive(ikm, length));

      throwsCode("INVALID_LENGTH", () => algorithm.expand(prk, length));
    }

    throwsCode("INVALID_LENGTH", () => algorithm.expand(prk.subarray(1), 32));

    assert.equal(algorithm.expand(new Uint8Array(size + 100), 32).length, 32);

    throwsCode("INVALID_OPTION", () => algorithm.extract(ikm, { info: Uint8Array.of(1) }));

    throwsCode("INVALID_OPTION", () => algorithm.expand(prk, 32, { salt: Uint8Array.of(1) }));

    assert.deepEqual(algorithm.extract(ikm, { info: new Uint8Array() }), prk);

    assert.throws(() => algorithm.derive("ikm" as unknown as Uint8Array, 32), TypeError);

    assert.throws(() => algorithm.derive(ikm, 32, { salt: "salt" as unknown as Uint8Array }), TypeError);

    assert.ok(Object.isFrozen(algorithm));
  }

  assert.deepEqual(
    Object.values(HKDF).map((algorithm) => [algorithm.name, algorithm.prkSize]),
    [
      ["HKDF-SHA-256", 32],
      ["HKDF-SHA-384", 48],
      ["HKDF-SHA-512", 64],
    ],
  );
});

test("configure: options, defaults and refusals", () => {
  const sixteen = new Uint8Array(16).fill(1);

  // No options, or the defaults, give the algorithm configure started from.
  for (const algorithm of [pq.SHA_256, pq.BLAKE2B_256, pq.BLAKE2S_128, pq.ASCON_HASH256]) {
    assert.equal(algorithm.configure(), algorithm);

    assert.equal(algorithm.configure({ salt: new Uint8Array() }), algorithm);
  }

  for (const algorithm of [pq.SHAKE128, pq.CSHAKE256, pq.ASCON_XOF128, pq.ASCON_CXOF128]) {
    assert.equal(algorithm.configure({}), algorithm);
  }

  for (const algorithm of [pq.HMAC_SHA_256, pq.KMAC128, pq.KMAC256, pq.BLAKE2B_MAC, pq.BLAKE2S_MAC]) {
    assert.equal(algorithm.configure(), algorithm);

    assert.equal(algorithm.configure({ customization: new Uint8Array(), xof: false }), algorithm);
  }

  assert.equal(pq.KMAC128.configure({ length: 32 }), pq.KMAC128);

  assert.equal(pq.BLAKE2S_MAC.configure({ length: 32 }), pq.BLAKE2S_MAC);

  // A configured algorithm configures from its base: no options go back to it, and options do not
  // add up.
  const salted = pq.BLAKE2B_512.configure({ salt: sixteen });

  assert.equal(salted.configure(), pq.BLAKE2B_512);

  const personal = salted.configure({ personalization: sixteen });

  const expected = pq.BLAKE2B_512.configure({ personalization: sixteen }).digest(utf8("abc"));

  assert.deepEqual(personal.digest(utf8("abc")), expected);

  assert.equal(salted.name, "BLAKE2b-512");

  assert.equal(salted.digestSize, 64);

  assert.ok(Object.isFrozen(salted));

  const longer = pq.KMAC128.configure({ length: 100, customization: utf8("S") });

  assert.equal(longer.digestSize, 100);

  assert.equal(longer.configure({ xof: true }).digestSize, 32);

  // Zero-padding: a short salt equals the same salt padded to the field.
  const short = pq.BLAKE2S_256.configure({ salt: Uint8Array.of(1, 2, 3), personalization: Uint8Array.of(4) });

  const padded = pq.BLAKE2S_256.configure({
    salt: Uint8Array.of(1, 2, 3, 0, 0, 0, 0, 0),
    personalization: Uint8Array.of(4, 0, 0, 0, 0, 0, 0, 0),
  });

  assert.deepEqual(short.digest(utf8("abc")), padded.digest(utf8("abc")));

  const refused: [string, () => unknown][] = [
    ["salt on SHA-256", () => pq.SHA_256.configure({ salt: Uint8Array.of(1) })],
    ["personalization on SHA3-256", () => pq.SHA3_256.configure({ personalization: Uint8Array.of(1) })],
    ["salt on Ascon-Hash256", () => pq.ASCON_HASH256.configure({ salt: Uint8Array.of(1) })],
    ["17-byte BLAKE2b salt", () => pq.BLAKE2B_256.configure({ salt: new Uint8Array(17) })],
    ["9-byte BLAKE2s personalization", () => pq.BLAKE2S_256.configure({ personalization: new Uint8Array(9) })],
    ["customization on SHAKE128", () => pq.SHAKE128.configure({ customization: Uint8Array.of(1) })],
    ["customization on Ascon-XOF128", () => pq.ASCON_XOF128.configure({ customization: Uint8Array.of(1) })],
    ["257-byte Ascon-CXOF128 customization", () => pq.ASCON_CXOF128.configure({ customization: new Uint8Array(257) })],
    ["length on HMAC", () => pq.HMAC_SHA_256.configure({ length: 32 })],
    ["customization on HMAC", () => pq.HMAC_SHA_512.configure({ customization: Uint8Array.of(1) })],
    ["xof on HMAC", () => pq.HMAC_SHA_384.configure({ xof: true })],
    ["salt on HMAC", () => pq.HMAC_SHA_224.configure({ salt: Uint8Array.of(1) })],
    ["3-byte KMAC", () => pq.KMAC128.configure({ length: 3 })],
    ["0-byte KMAC", () => pq.KMAC256.configure({ length: 0 })],
    ["fractional KMAC length", () => pq.KMAC256.configure({ length: 4.5 })],
    ["KMAC length as a string", () => pq.KMAC256.configure({ length: "32" as unknown as number })],
    ["salt on KMAC", () => pq.KMAC128.configure({ salt: Uint8Array.of(1) })],
    ["xof as a number", () => pq.KMAC128.configure({ xof: 1 as unknown as boolean })],
    ["65-byte BLAKE2b-MAC", () => pq.BLAKE2B_MAC.configure({ length: 65 })],
    ["33-byte BLAKE2s-MAC", () => pq.BLAKE2S_MAC.configure({ length: 33 })],
    ["0-byte BLAKE2s-MAC", () => pq.BLAKE2S_MAC.configure({ length: 0 })],
    ["customization on BLAKE2b-MAC", () => pq.BLAKE2B_MAC.configure({ customization: Uint8Array.of(1) })],
    ["xof on BLAKE2s-MAC", () => pq.BLAKE2S_MAC.configure({ xof: true })],
    ["17-byte BLAKE2b-MAC salt", () => pq.BLAKE2B_MAC.configure({ salt: new Uint8Array(17) })],
  ];

  for (const [name, configure] of refused) {
    throwsCode("INVALID_OPTION", configure, name);
  }

  assert.equal(pq.ASCON_CXOF128.configure({ customization: new Uint8Array(256) }).name, "Ascon-CXOF128");

  assert.equal(pq.KMAC128.configure({ length: 4 }).digest(new Uint8Array(), new Uint8Array()).length, 4);

  assert.throws(() => pq.BLAKE2B_256.configure({ salt: "salt" as unknown as Uint8Array }), TypeError);

  assert.throws(() => pq.BLAKE2B_256.configure(3 as unknown as pq.HashOptions), TypeError);

  // cSHAKE's function name is hazmat's; hazmat takes cSHAKE only.
  throwsCode("INVALID_OPTION", () => hazmat.configureCshake(pq.SHAKE128, utf8("KMAC"), new Uint8Array()));

  assert.equal(hazmat.configureCshake(pq.CSHAKE128, new Uint8Array(), new Uint8Array()), pq.CSHAKE128);

  const notXof = pq.SHA_256 as unknown as pq.XofAlgorithm;

  assert.throws(() => hazmat.configureCshake(notXof, utf8("N"), utf8("S")), TypeError);
});

// N and S both empty make cSHAKE equal to SHAKE (SP 800-185, 3.3).
test("cSHAKE without customization is SHAKE", () => {
  const data = utf8("crypto-pq");

  assert.deepEqual(pq.CSHAKE128.digest(data, 200), pq.SHAKE128.digest(data, 200));

  assert.deepEqual(pq.CSHAKE256.create().update(data).read(300), pq.SHAKE256.digest(data, 300));
});

test("MAC keys, tags and verification", () => {
  const data = utf8("message");

  for (const [mac, limit] of [
    [pq.BLAKE2B_MAC, 64],
    [pq.BLAKE2S_MAC, 32],
  ] as const) {
    for (const length of [0, limit + 1]) {
      const key = new Uint8Array(length);

      throwsCode("INVALID_LENGTH", () => mac.digest(key, data), `${mac.name} ${length}`);

      throwsCode("INVALID_LENGTH", () => mac.create(key), `${mac.name} ${length}`);

      assert.equal(mac.verify(key, data, new Uint8Array(mac.digestSize)), false);
    }

    for (const length of [1, limit]) {
      assert.equal(mac.digest(new Uint8Array(length), data).length, mac.digestSize);
    }
  }

  // HMAC and KMAC take any key, short KMAC keys included.
  for (const mac of [pq.HMAC_SHA_256, pq.KMAC128, pq.KMAC256]) {
    for (const length of [0, 1, 15, 300]) {
      const key = new Uint8Array(length).fill(7);

      const tag = mac.digest(key, data);

      assert.ok(mac.verify(key, data, tag), `${mac.name} ${length}`);

      assert.ok(!mac.verify(key, data, tag.subarray(1)), `${mac.name} ${length}`);

      assert.ok(!mac.verify(key, data, Uint8Array.of(...tag, 0)), `${mac.name} ${length}`);
    }
  }

  // KMACXOF binds no length: a shorter tag is a prefix of a longer one, which KMAC's is not.
  const key = utf8("key");

  const short = pq.KMAC256.configure({ xof: true, length: 16 }).digest(key, data);

  const long = pq.KMAC256.configure({ xof: true, length: 48 }).digest(key, data);

  assert.deepEqual(long.subarray(0, 16), short);

  assert.notDeepEqual(pq.KMAC256.configure({ length: 48 }).digest(key, data).subarray(0, 16), short);

  const names = [pq.KMAC128, pq.KMAC256, pq.BLAKE2B_MAC, pq.BLAKE2S_MAC].map((mac) => [mac.name, mac.digestSize]);

  assert.deepEqual(names, [
    ["KMAC128", 32],
    ["KMAC256", 64],
    ["BLAKE2b-MAC", 64],
    ["BLAKE2s-MAC", 32],
  ]);
});

test("XOF reads of the new XOFs", () => {
  const abc = utf8("abc");

  for (const xof of [pq.CSHAKE128.configure({ customization: abc }), pq.ASCON_XOF128, pq.ASCON_CXOF128]) {
    const state = xof.create().update(abc);

    const out = [0, 1, 7, 9, 135, 1, 167, 200, 496].map((n) => toHex(state.read(n))).join("");

    assert.equal(out, toHex(xof.digest(abc, 1016)), xof.name);

    throwsCode("UNSUPPORTED", () => state.update(abc), xof.name);
  }
});

test("hash properties of the new hash functions", () => {
  for (const [name, algorithm] of [...Object.entries(BLAKE2), ["Ascon-Hash256", pq.ASCON_HASH256] as const]) {
    assert.equal(algorithm.name, name);

    assert.equal(algorithm.digest(new Uint8Array()).length, algorithm.digestSize);

    assert.ok(Object.isFrozen(algorithm));

    const hasher = algorithm.create().update(utf8("abc"));

    assert.deepEqual(hasher.digest(), hasher.digest());

    assert.deepEqual(hasher.update(utf8("def")).digest(), algorithm.digest(utf8("abcdef")));
  }

  const names = [pq.CSHAKE128, pq.CSHAKE256, pq.ASCON_XOF128, pq.ASCON_CXOF128].map((xof) => xof.name);

  assert.deepEqual(names, ["cSHAKE128", "cSHAKE256", "Ascon-XOF128", "Ascon-CXOF128"]);
});

// FIPS 204 and FIPS 205 approve only hash functions with a NIST OID as pre-hashes.
test("signatures refuse the new hash functions as pre-hashes", () => {
  const pair = pq.ML_DSA_44.generateKeyPair();

  const message = utf8("message");

  const signature = pair.privateKey.sign(message);

  const refused = [
    pq.BLAKE2B_512,
    pq.BLAKE2S_256,
    pq.ASCON_HASH256,
    pq.CSHAKE256,
    pq.ASCON_XOF128,
    pq.BLAKE2B_512.configure({ salt: Uint8Array.of(1) }),
    pq.CSHAKE256.configure({ customization: Uint8Array.of(1) }),
  ];

  for (const preHash of refused) {
    throwsCode("INVALID_OPTION", () => pair.privateKey.sign(message, { preHash }), preHash.name);

    const randomness = new Uint8Array(32);

    throwsCode("INVALID_OPTION", () => hazmat.sign(pair.privateKey, message, randomness, { preHash }), preHash.name);

    assert.equal(pair.publicKey.verify(signature, message, { preHash }), false, preHash.name);

    assert.equal(hazmat.verify(pair.publicKey, signature, message, { preHash }), false, preHash.name);
  }

  const mac = pq.KMAC256 as unknown as pq.XofAlgorithm;

  throwsCode("INVALID_OPTION", () => pair.privateKey.sign(message, { preHash: mac }));

  const approved = { preHash: pq.SHAKE256 };

  assert.ok(pair.publicKey.verify(pair.privateKey.sign(message, approved), message, approved));
});
