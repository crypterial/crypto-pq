import assert from "node:assert/strict";
import { test } from "node:test";

import * as pq from "../src/index.ts";
import { type Fields, hex, records, toHex } from "./vectors.ts";

const HASHES: [string, string, pq.HashAlgorithm][] = [
  ["SHA224", "SHA-224", pq.SHA_224],
  ["SHA256", "SHA-256", pq.SHA_256],
  ["SHA384", "SHA-384", pq.SHA_384],
  ["SHA512", "SHA-512", pq.SHA_512],
  ["SHA512_224", "SHA-512/224", pq.SHA_512_224],
  ["SHA512_256", "SHA-512/256", pq.SHA_512_256],
  ["SHA3_224", "SHA3-224", pq.SHA3_224],
  ["SHA3_256", "SHA3-256", pq.SHA3_256],
  ["SHA3_384", "SHA3-384", pq.SHA3_384],
  ["SHA3_512", "SHA3-512", pq.SHA3_512],
];

const XOFS: [string, pq.XofAlgorithm][] = [
  ["SHAKE128", pq.SHAKE128],
  ["SHAKE256", pq.SHAKE256],
];

// HMAC.rsp labels each group by digest length in bytes; L=20 is SHA-1, which is out of scope.
const HMACS: [string, string, pq.HmacAlgorithm][] = [
  ["28", "HMAC-SHA-224", pq.HMAC_SHA_224],
  ["32", "HMAC-SHA-256", pq.HMAC_SHA_256],
  ["48", "HMAC-SHA-384", pq.HMAC_SHA_384],
  ["64", "HMAC-SHA-512", pq.HMAC_SHA_512],
];

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
const PIECES = [0, 1, 3, 64, 7, 136, 128, 168, 0, 200];

function message(record: Fields): Uint8Array {
  const bits = Number(record.Len);

  assert.equal(bits % 8, 0, "bit-oriented message");

  return hex(record.Msg).subarray(0, bits / 8);
}

function pieces(data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];

  for (let offset = 0, index = 0; offset < data.length; index++) {
    const end = Math.min(offset + PIECES[index % PIECES.length], data.length);

    out.push(data.subarray(offset, end));

    offset = end;
  }

  return out;
}

test("hash vectors", () => {
  for (const [prefix, , algorithm] of HASHES) {
    for (const kind of ["ShortMsg", "LongMsg"]) {
      for (const [, record] of records(`cavp/${prefix}${kind}.rsp`, "MD")) {
        const data = message(record);

        const expected = record.MD.toLowerCase();

        assert.equal(toHex(algorithm.digest(data)), expected, `${prefix}${kind} Len = ${record.Len}`);

        const hasher = algorithm.create();

        for (const piece of pieces(data)) {
          hasher.update(piece);
        }

        assert.equal(toHex(hasher.digest()), expected, `${prefix}${kind} Len = ${record.Len} streamed`);
      }
    }
  }
});

// SHAVS 6.4 and SHA3VS 6.2.3: each checkpoint chains 1000 digests from the previous one.
test("hash monte carlo", () => {
  for (const [prefix, , algorithm] of HASHES) {
    const [[, first], ...checkpoints] = records(`cavp/${prefix}Monte.rsp`, "MD");

    let seed = hex(first.Seed);

    for (const [, record] of checkpoints) {
      if (prefix.startsWith("SHA3_")) {
        for (let i = 0; i < 1000; i++) {
          seed = algorithm.digest(seed);
        }
      } else {
        let md = [seed, seed, seed];

        for (let i = 0; i < 1000; i++) {
          const message = new Uint8Array(3 * seed.length);

          message.set(md[0]);

          message.set(md[1], seed.length);

          message.set(md[2], 2 * seed.length);

          md = [md[1], md[2], algorithm.digest(message)];
        }

        seed = md[2];
      }

      assert.equal(toHex(seed), record.MD.toLowerCase(), `${prefix}Monte COUNT = ${record.COUNT}`);
    }
  }
});

test("hash digest is repeatable", () => {
  const abc = new TextEncoder().encode("abc");

  const abcdef = new TextEncoder().encode("abcdef");

  for (const [, , algorithm] of HASHES) {
    const hasher = algorithm.create().update(abc);

    const first = toHex(hasher.digest());

    assert.equal(toHex(hasher.digest()), first);

    assert.equal(first, toHex(algorithm.digest(abc)));

    hasher.update(abcdef.subarray(3));

    assert.equal(toHex(hasher.digest()), toHex(algorithm.digest(abcdef)));
  }
});

test("hash properties", () => {
  for (const [, name, algorithm] of HASHES) {
    assert.equal(algorithm.name, name);

    assert.equal(algorithm.digest(new Uint8Array()).length, algorithm.digestSize);

    assert.ok(Object.isFrozen(algorithm));
  }
});

test("hash input types", () => {
  for (const wrong of ["abc", 3, null, [1, 2, 3], new ArrayBuffer(3)]) {
    assert.throws(() => pq.SHA_256.digest(wrong as unknown as Uint8Array), TypeError);
  }
});

test("xof vectors", () => {
  for (const [prefix, algorithm] of XOFS) {
    for (const kind of ["ShortMsg", "LongMsg"]) {
      for (const [header, record] of records(`cavp/${prefix}${kind}.rsp`, "Output")) {
        const data = message(record);

        const expected = record.Output.toLowerCase();

        const length = expected.length / 2;

        assert.equal(Number(header.Outputlen), 8 * length);

        assert.equal(toHex(algorithm.digest(data, length)), expected, `${prefix}${kind} Len = ${record.Len}`);

        const xof = algorithm.create();

        for (const piece of pieces(data)) {
          xof.update(piece);
        }

        assert.equal(toHex(xof.read(1)) + toHex(xof.read(length - 1)), expected, `${prefix}${kind} streamed`);
      }
    }

    for (const [, record] of records(`cavp/${prefix}VariableOut.rsp`, "Output")) {
      const expected = record.Output.toLowerCase();

      assert.equal(Number(record.Outputlen), 4 * expected.length);

      assert.equal(
        toHex(algorithm.digest(hex(record.Msg), expected.length / 2)),
        expected,
        `${prefix}VariableOut COUNT = ${record.COUNT}`,
      );
    }
  }
});

// SHA3VS 6.3.3: the next input is the first 16 output bytes, zero-padded, and the last two
// output bytes pick the next output length.
test("xof monte carlo", () => {
  for (const [prefix, algorithm] of XOFS) {
    const [[header, first], ...checkpoints] = records(`cavp/${prefix}Monte.rsp`, "Output");

    const minimum = Number(header["Minimum Output Length (bits)"]) / 8;

    const maximum = Number(header["Maximum Output Length (bits)"]) / 8;

    let output = hex(first.Msg);

    let length = maximum;

    for (const [, record] of checkpoints) {
      for (let i = 0; i < 1000; i++) {
        const message = new Uint8Array(16);

        message.set(output.subarray(0, 16));

        output = algorithm.digest(message, length);

        length = minimum + (((output[output.length - 2] << 8) | output[output.length - 1]) % (maximum - minimum + 1));
      }

      assert.equal(toHex(output), record.Output.toLowerCase(), `${prefix}Monte COUNT = ${record.COUNT}`);

      assert.equal(8 * output.length, Number(record.Outputlen));
    }
  }
});

test("xof streaming read", () => {
  const abc = new TextEncoder().encode("abc");

  for (const [, algorithm] of XOFS) {
    const xof = algorithm.create().update(abc);

    const out = [0, 1, 135, 1, 167, 200, 496].map((n) => toHex(xof.read(n))).join("");

    assert.equal(out, toHex(algorithm.digest(abc, 1000)));
  }
});

test("xof update after read", () => {
  const xof = pq.SHAKE128.create();

  xof.read(1);

  assert.throws(
    () => xof.update(new Uint8Array(1)),
    (error: unknown) => error instanceof pq.CryptoPQError && error.code === "UNSUPPORTED",
  );
});

test("xof lengths", () => {
  assert.equal(pq.SHAKE256.digest(new Uint8Array(), 0).length, 0);

  for (const wrong of [-1, 1.5, Number.NaN, Infinity, "3"]) {
    assert.throws(
      () => pq.SHAKE256.digest(new Uint8Array(), wrong as unknown as number),
      (error: unknown) => error instanceof pq.CryptoPQError && error.code === "INVALID_LENGTH",
    );
  }
});

test("xof properties", () => {
  assert.equal(pq.SHAKE128.name, "SHAKE128");

  assert.equal(pq.SHAKE256.name, "SHAKE256");
});

test("hmac vectors", () => {
  let tested = 0;

  for (const [header, record] of records("cavp/HMAC.rsp", "Mac")) {
    if (header.L === "20") {
      continue;
    }

    const entry = HMACS.find(([length]) => length === header.L);

    assert.ok(entry, `digest length ${header.L}`);

    const algorithm = entry[2];

    const key = hex(record.Key);

    const data = hex(record.Msg);

    const mac = record.Mac.toLowerCase();

    const context = `L = ${header.L} Count = ${record.Count}`;

    assert.equal(key.length, Number(record.Klen), context);

    assert.equal(mac.length / 2, Number(record.Tlen), context);

    const tag = algorithm.digest(key, data);

    assert.equal(toHex(tag).slice(0, mac.length), mac, context);

    const hmac = algorithm.create(key);

    for (const piece of pieces(data)) {
      hmac.update(piece);
    }

    assert.equal(toHex(hmac.digest()), toHex(tag), `${context} streamed`);

    assert.ok(hmac.verify(tag), context);

    assert.ok(algorithm.verify(key, data, tag), context);

    tested++;
  }

  assert.equal(tested, 1275);
});

test("hmac verify rejects", () => {
  const encoder = new TextEncoder();

  const key = encoder.encode("key");

  const data = encoder.encode("data");

  const tag = pq.HMAC_SHA_256.digest(key, data);

  assert.equal(pq.HMAC_SHA_256.verify(key, data, tag.subarray(0, tag.length - 1)), false);

  assert.equal(pq.HMAC_SHA_256.verify(key, data, Uint8Array.of(...tag, 0)), false);

  assert.equal(pq.HMAC_SHA_256.verify(encoder.encode("kez"), data, tag), false);

  for (let index = 0; index < tag.length; index++) {
    const flipped = tag.slice();

    flipped[index] ^= 0x80;

    assert.equal(pq.HMAC_SHA_256.verify(key, data, flipped), false);
  }
});

test("hmac properties", () => {
  for (const [, name, algorithm] of HMACS) {
    assert.equal(algorithm.name, name);

    assert.equal(algorithm.digest(new Uint8Array(1), new Uint8Array()).length, algorithm.digestSize);

    assert.ok(Object.isFrozen(algorithm));
  }
});
