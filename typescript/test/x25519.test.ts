import assert from "node:assert/strict";
import { test } from "node:test";

import * as pq from "../src/index.ts";
import { BASE, edwardsTable, x25519, x25519Base } from "../src/x25519.ts";
import { SLOW, hex, records, toHex } from "./vectors.ts";

test("X25519 RFC 7748", () => {
  for (const [header, record] of records("rfc/x25519.txt", "output")) {
    if (header.kind === "multiply") {
      assert.equal(toHex(x25519(hex(record.scalar), hex(record.u))), record.output);
    } else if (header.kind === "iterate") {
      const count = Number(record.iterations);

      if (count > 1000 && !SLOW) {
        continue;
      }

      let k = BASE;

      let u = BASE;

      for (let i = 0; i < count; i++) {
        [k, u] = [x25519(k, u), k];
      }

      assert.equal(toHex(k), record.output, `${count} iterations`);
    } else if (header.kind === "exchange") {
      const alice = hex(record.alicePrivate);

      const bob = hex(record.bobPrivate);

      assert.equal(toHex(x25519(alice, BASE)), record.alicePublic);

      assert.equal(toHex(x25519(bob, BASE)), record.bobPublic);

      assert.equal(toHex(x25519Base(alice)), record.alicePublic);

      assert.equal(toHex(x25519Base(bob)), record.bobPublic);

      assert.equal(toHex(x25519(alice, hex(record.bobPublic))), record.shared);

      assert.equal(toHex(x25519(bob, hex(record.alicePublic))), record.shared);
    }
  }
});

// Wycheproof marks low-order and twist points "acceptable"; X25519 itself is defined for them.
test("X25519 Wycheproof", () => {
  for (const [, record] of records("wycheproof/x25519.txt", "tcId")) {
    const shared = x25519(hex(record.private), hex(record.public));

    assert.equal(toHex(shared), record.shared.toLowerCase(), `tcId = ${record.tcId}`);
  }
});

// The fixed-base multiplication must give the ladder's result from u = 9 for every scalar: here
// repeated bytes and single bits, which give runs of extreme and zero digits, the Wycheproof private
// keys and pseudorandom scalars.
test("X25519 fixed base", () => {
  const scalars: Uint8Array[] = [];

  for (const fill of [0x00, 0xff, 0x88, 0x77, 0x80, 0x08, 0xf0, 0x0f, 0x7f, 0xf7]) {
    scalars.push(new Uint8Array(32).fill(fill));
  }

  for (let bit = 0; bit < 256; bit++) {
    const scalar = new Uint8Array(32);

    scalar[bit >> 3] = 1 << (bit & 7);

    scalars.push(scalar);
  }

  for (const [, record] of records("wycheproof/x25519.txt", "tcId")) {
    scalars.push(hex(record.private));
  }

  const stream = pq.SHAKE256.digest(new TextEncoder().encode("crypto-pq fixed-base X25519"), 32 * 2000);

  for (let i = 0; i < stream.length; i += 32) {
    scalars.push(stream.subarray(i, i + 32));
  }

  scalars.forEach((scalar, i) => {
    assert.equal(toHex(x25519Base(scalar)), toHex(x25519(scalar, BASE)), `scalar ${i}`);
  });
});

const P = 2n ** 255n - 19n;

function mod(a: bigint): bigint {
  return ((a % P) + P) % P;
}

function power(base: bigint, exponent: bigint): bigint {
  let result = 1n;

  for (let b = mod(base), e = exponent; e > 0n; e >>= 1n, b = (b * b) % P) {
    if (e & 1n) {
      result = (result * b) % P;
    }
  }

  return result;
}

// A field element of the table: sixteen 16-bit limbs, which may be slightly negative.
function limbs(table: Int32Array, offset: number): bigint {
  let value = 0n;

  for (let i = 15; i >= 0; i--) {
    value = value * 65536n + BigInt(table[offset + i]);
  }

  return mod(value);
}

// Every entry of the table against (j + 1) 256^i B in affine coordinates with BigInt, from B = (x, 4/5)
// with x the even square root of (y^2 - 1) / (d y^2 + 1) (RFC 8032, 5.1).
test("X25519 fixed-base table", () => {
  const d = mod(-121665n * power(121666n, P - 2n));

  const sum = ([x1, y1]: bigint[], [x2, y2]: bigint[]) => {
    const t = mod(d * x1 * x2 * y1 * y2);

    return [mod((x1 * y2 + y1 * x2) * power(1n + t, P - 2n)), mod((y1 * y2 + x1 * x2) * power(1n - t, P - 2n))];
  };

  const y = mod(4n * power(5n, P - 2n));

  const square = mod((y * y - 1n) * power(d * y * y + 1n, P - 2n));

  let x = power(square, (P + 3n) / 8n);

  if (mod(x * x - square) !== 0n) {
    x = mod(x * power(2n, (P - 1n) / 4n));
  }

  let row = [x & 1n ? P - x : x, y];

  const table = edwardsTable();

  for (let i = 0; i < 32; i++) {
    let multiple = row;

    for (let j = 0; j < 8; j++) {
      const [mx, my] = multiple;

      const offset = 48 * (8 * i + j);

      const entry = [limbs(table, offset), limbs(table, offset + 16), limbs(table, offset + 32)];

      assert.deepEqual(entry, [mod(my + mx), mod(my - mx), mod(2n * d * mx * my)], `entry ${i}, ${j}`);

      multiple = sum(multiple, row);
    }

    for (let n = 0; n < 8; n++) {
      row = sum(row, row);
    }
  }
});
