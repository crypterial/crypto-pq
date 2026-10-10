import assert from "node:assert/strict";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { hex, pieces, records, throwsCode, toHex } from "./vectors.ts";

// Every entry of the vector files of HKDF, cSHAKE, KMAC, BLAKE2 and Ascon, on the current backend:
// the one-shot functions, the incremental ones fed in uneven pieces, and verification. Each check
// returns the number of entries it ran, which it also asserts, so that none passes on zero entries.
// symmetric.test.ts runs them under node:test, test/engines.ts under Deno and Bun.

export const BLAKE2: Record<string, pq.HashAlgorithm> = {
  "BLAKE2b-160": pq.BLAKE2B_160,
  "BLAKE2b-256": pq.BLAKE2B_256,
  "BLAKE2b-384": pq.BLAKE2B_384,
  "BLAKE2b-512": pq.BLAKE2B_512,
  "BLAKE2s-128": pq.BLAKE2S_128,
  "BLAKE2s-160": pq.BLAKE2S_160,
  "BLAKE2s-224": pq.BLAKE2S_224,
  "BLAKE2s-256": pq.BLAKE2S_256,
};

const KMAC: Record<string, pq.MacAlgorithm> = { KMAC128: pq.KMAC128, KMAC256: pq.KMAC256 };

const CSHAKE: Record<string, pq.XofAlgorithm> = { cSHAKE128: pq.CSHAKE128, cSHAKE256: pq.CSHAKE256 };

export const HKDF: Record<string, pq.KdfAlgorithm> = {
  "HKDF-SHA-256": pq.HKDF_SHA_256,
  "HKDF-SHA-384": pq.HKDF_SHA_384,
  "HKDF-SHA-512": pq.HKDF_SHA_512,
};

// The digest one-shot and in pieces, which must both be expected.
function checkHash(algorithm: pq.HashAlgorithm, data: Uint8Array, expected: string, context: string): void {
  assert.equal(toHex(algorithm.digest(data)), expected, context);

  const hasher = algorithm.create();

  for (const piece of pieces(data)) {
    hasher.update(piece);
  }

  assert.equal(toHex(hasher.digest()), expected, `${context} streamed`);
}

function checkXof(algorithm: pq.XofAlgorithm, data: Uint8Array, expected: string, context: string): void {
  const length = expected.length / 2;

  assert.equal(toHex(algorithm.digest(data, length)), expected, context);

  const xof = algorithm.create();

  for (const piece of pieces(data)) {
    xof.update(piece);
  }

  assert.equal(toHex(xof.read(1)) + toHex(xof.read(length - 1)), expected, `${context} streamed`);
}

// The tag one-shot and in pieces; both verifications accept it and refuse it with a bit flipped.
function checkMac(
  algorithm: pq.MacAlgorithm,
  key: Uint8Array,
  data: Uint8Array,
  expected: string,
  context: string,
): void {
  const tag = hex(expected);

  assert.equal(toHex(algorithm.digest(key, data)), expected, context);

  const mac = algorithm.create(key);

  for (const piece of pieces(data)) {
    mac.update(piece);
  }

  assert.equal(toHex(mac.digest()), expected, `${context} streamed`);

  assert.ok(mac.verify(tag) && algorithm.verify(key, data, tag), `${context} verify`);

  tag[tag.length - 1] ^= 1;

  assert.ok(!mac.verify(tag) && !algorithm.verify(key, data, tag), `${context} verify flipped`);
}

// RFC 7693, Appendix E: selftest_seq(len, seed).
function selftestSequence(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);

  let a = Math.imul(0xdead4bad, seed) >>> 0;

  let b = 1;

  for (let i = 0; i < length; i++) {
    const t = (a + b) >>> 0;

    a = b;

    b = t;

    out[i] = t >>> 24;
  }

  return out;
}

export function blake2Rfc(): number {
  let tested = 0;

  for (const [header, record] of records("rfc/blake2.txt", "out")) {
    if (header.kind === "example") {
      checkHash(BLAKE2[record.hash], hex(record.in), record.out, record.name);
    } else {
      const variant = record.hash;

      const mac = variant === "BLAKE2b" ? pq.BLAKE2B_MAC : pq.BLAKE2S_MAC;

      const grand = BLAKE2[`${variant}-256`].create();

      for (const size of record.digestLengths.split(",").map(Number)) {
        for (const length of record.inputLengths.split(",").map(Number)) {
          const data = selftestSequence(length, length);

          grand.update(BLAKE2[`${variant}-${8 * size}`].digest(data));

          grand.update(mac.configure({ length: size }).digest(selftestSequence(size, size), data));
        }
      }

      assert.equal(toHex(grand.digest()), record.out, record.name);
    }

    tested++;
  }

  assert.equal(tested, 4);

  return tested;
}

export function blake2Kats(): number {
  let tested = 0;

  for (const [name, hash, mac] of [
    ["blake2b", pq.BLAKE2B_512, pq.BLAKE2B_MAC],
    ["blake2s", pq.BLAKE2S_256, pq.BLAKE2S_MAC],
  ] as const) {
    for (const [, record] of records(`blake2/${name}.txt`, "out")) {
      const context = `${name} in ${record.in.length / 2} key ${record.key.length / 2}`;

      if (record.key === "") {
        checkHash(hash, hex(record.in), record.out, context);
      } else {
        checkMac(mac, hex(record.key), hex(record.in), record.out, context);
      }

      tested++;
    }
  }

  assert.equal(tested, 1024);

  return tested;
}

// Unkeyed lengths are those of the RFC 7693 constants; keyed ones go through the MACs' length.
export function blake2Derived(): number {
  let tested = 0;

  for (const [header, record] of records("derived/blake2.txt", "out")) {
    const size = Number(record.digestLength);

    const options = { salt: hex(record.salt), personalization: hex(record.personalization) };

    const context = `${header.hash} ${size} key ${record.key.length / 2} salt ${record.salt.length / 2}`;

    if (record.key === "") {
      checkHash(BLAKE2[`${header.hash}-${8 * size}`].configure(options), hex(record.in), record.out, context);
    } else {
      const mac = header.hash === "BLAKE2b" ? pq.BLAKE2B_MAC : pq.BLAKE2S_MAC;

      checkMac(mac.configure({ ...options, length: size }), hex(record.key), hex(record.in), record.out, context);
    }

    tested++;
  }

  assert.equal(tested, 500);

  return tested;
}

export function asconVectors(): number {
  let tested = 0;

  for (const [, record] of records("ascon/LWC_HASH_KAT_128_256.txt", "MD")) {
    checkHash(pq.ASCON_HASH256, hex(record.Msg), record.MD.toLowerCase(), `Hash256 Count = ${record.Count}`);

    tested++;
  }

  for (const [, record] of records("ascon/LWC_XOF_KAT_128_512.txt", "MD")) {
    checkXof(pq.ASCON_XOF128, hex(record.Msg), record.MD.toLowerCase(), `XOF128 Count = ${record.Count}`);

    tested++;
  }

  for (const [, record] of records("ascon/LWC_CXOF_KAT_128_512.txt", "MD")) {
    const algorithm = pq.ASCON_CXOF128.configure({ customization: hex(record.Z) });

    checkXof(algorithm, hex(record.Msg), record.MD.toLowerCase(), `CXOF128 Count = ${record.Count}`);

    tested++;
  }

  for (const [header, record] of records("acvp/Ascon.txt", "md")) {
    const context = `${header.parameterSet} tcId ${record.tcId}`;

    if (header.parameterSet === "Ascon-Hash256") {
      checkHash(pq.ASCON_HASH256, hex(record.msg), record.md, context);
    } else if (header.parameterSet === "Ascon-XOF128") {
      checkXof(pq.ASCON_XOF128, hex(record.msg), record.md, context);
    } else {
      checkXof(pq.ASCON_CXOF128.configure({ customization: hex(record.cs) }), hex(record.msg), record.md, context);
    }

    tested++;
  }

  assert.equal(tested, 1025 + 1025 + 1089 + 16);

  return tested;
}

export function cshakeVectors(): number {
  let tested = 0;

  for (const file of ["nist-examples/cSHAKE.txt", "acvp/cSHAKE.txt"]) {
    for (const [header, record] of records(file, "md")) {
      const [base, customization] = [CSHAKE[header.parameterSet], hex(record.customization)];

      const context = `${file} ${record.name ?? record.tcId}`;

      const named = hazmat.configureCshake(base, hex(record.functionName), customization);

      checkXof(named, hex(record.msg), record.md, context);

      // Without a function name, the public configure gives the same.
      if (record.functionName === "") {
        checkXof(base.configure({ customization }), hex(record.msg), record.md, `${context} configure`);
      }

      tested++;
    }
  }

  assert.equal(tested, 4 + 5);

  return tested;
}

export function kmacVectors(): number {
  let tested = 0;

  for (const file of ["nist-examples/KMAC.txt", "acvp/KMAC.txt"]) {
    for (const [header, record] of records(file, "mac")) {
      const options = {
        length: record.mac.length / 2,
        customization: hex(record.customization),
        xof: header.xof === "true",
      };

      const algorithm = KMAC[header.parameterSet].configure(options);

      const [key, data] = [hex(record.key), hex(record.msg)];

      const context = `${file} ${header.source ?? ""} ${record.name ?? record.tcId}`;

      if (record.testPassed === "false") {
        assert.notEqual(toHex(algorithm.digest(key, data)), record.mac, context);

        assert.ok(!algorithm.verify(key, data, hex(record.mac)), context);

        assert.ok(!algorithm.create(key).update(data).verify(hex(record.mac)), context);
      } else {
        checkMac(algorithm, key, data, record.mac, context);
      }

      tested++;
    }
  }

  for (const [header, record] of records("wycheproof/kmac.txt", "tag")) {
    const algorithm = KMAC[header.parameterSet].configure({ length: Number(header.tagSize) / 8 });

    const [key, data, tag] = [hex(record.key), hex(record.msg), hex(record.tag)];

    const context = `wycheproof ${header.parameterSet} tcId ${record.tcId}`;

    if (record.result === "valid") {
      checkMac(algorithm, key, data, record.tag, context);
    } else {
      assert.ok(!algorithm.verify(key, data, tag), context);

      assert.ok(!algorithm.create(key).update(data).verify(tag), context);
    }

    tested++;
  }

  assert.equal(tested, 12 + 103 + 435);

  return tested;
}

export function hkdfVectors(): number {
  let tested = 0;

  for (const [header, record] of records("rfc/hkdf.txt", "okm")) {
    const algorithm = HKDF[header.parameterSet];

    const [ikm, salt, info, length] = [hex(record.ikm), hex(record.salt), hex(record.info), Number(record.length)];

    assert.equal(toHex(algorithm.derive(ikm, length, { salt, info })), record.okm, record.name);

    assert.equal(toHex(algorithm.extract(ikm, { salt })), record.prk, record.name);

    assert.equal(toHex(algorithm.expand(hex(record.prk), length, { info })), record.okm, record.name);

    tested++;
  }

  for (const [header, record] of records("wycheproof/hkdf.txt", "okm")) {
    const algorithm = HKDF[header.parameterSet];

    const [ikm, salt, info, size] = [hex(record.ikm), hex(record.salt), hex(record.info), Number(record.size)];

    const context = `wycheproof ${header.parameterSet} tcId ${record.tcId}`;

    if (record.result === "valid") {
      assert.equal(toHex(algorithm.derive(ikm, size, { salt, info })), record.okm, context);

      assert.equal(toHex(algorithm.expand(algorithm.extract(ikm, { salt }), size, { info })), record.okm, context);
    } else {
      assert.ok(size > 255 * algorithm.prkSize, context);

      throwsCode("INVALID_LENGTH", () => algorithm.derive(ikm, size, { salt, info }), context);

      throwsCode("INVALID_LENGTH", () => algorithm.expand(algorithm.extract(ikm, { salt }), size, { info }), context);
    }

    tested++;
  }

  // A multi-expansion test extracts once and expands once per comma-separated info and okm.
  for (const [header, record] of records("acvp/KDA-HKDF.txt", "okm")) {
    const algorithm = HKDF[header.parameterSet];

    const [ikm, salt, length] = [hex(record.ikm), hex(record.salt), Number(record.length)];

    const infos = record.info.split(",");

    const okms = record.okm.split(",");

    const context = `ACVP ${header.parameterSet} ${header.revision} tcId ${record.tcId}`;

    assert.equal(infos.length, okms.length, context);

    const prk = algorithm.extract(ikm, { salt });

    infos.forEach((info, i) => {
      assert.equal(toHex(algorithm.expand(prk, length, { info: hex(info) })), okms[i], context);

      assert.equal(toHex(algorithm.derive(ikm, length, { salt, info: hex(info) })), okms[i], context);
    });

    tested++;
  }

  assert.equal(tested, 3 + 252 + 450);

  return tested;
}
