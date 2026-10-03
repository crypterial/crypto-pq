import assert from "node:assert/strict";
import { test } from "node:test";

import * as pq from "../src/index.ts";
import { fixedShake256, prefixedSha256, prefixedShake256 } from "../src/primitives.ts";
import { block256, block256x2, block512, block512x2 } from "../src/sha2-rounds.ts";
import { IV_256, IV_512 } from "../src/sha2.ts";
import { concat, toHex } from "./vectors.ts";

function pattern(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i * 31 + seed) & 0xff);
}

// The internal hashes of the hash-based signatures against the public hash layer, for every
// prefix and message length around the block and padding boundaries.
test("prefixed and fixed hashes", () => {
  for (const prefixLength of [0, 1, 22, 63, 64, 65, 127, 128, 136, 137]) {
    const prefix = pattern(prefixLength, 7);

    const sha256 = prefixedSha256(prefix);

    const shake256 = prefixedShake256(prefix);

    for (let length = 0; length <= 300; length++) {
      const context = `prefix ${prefixLength}, message ${length}`;

      const data = pattern(length, length);

      const parts = [data.subarray(0, length / 3), data.subarray(length / 3, length / 2), data.subarray(length / 2)];

      const whole = concat(prefix, data);

      assert.equal(toHex(sha256.digest(24, ...parts)), toHex(pq.SHA_256.digest(whole).subarray(0, 24)), context);

      assert.equal(toHex(shake256.digest(300, ...parts)), toHex(pq.SHAKE256.digest(whole, 300)), context);

      const fixed = fixedShake256(prefixLength + length, prefix);

      const expected = pq.SHAKE256.digest(whole, 200);

      fixed.message.set(pattern(length, 3), prefixLength);

      fixed.digest(new Uint8Array(expected.length));

      fixed.message.set(data, prefixLength);

      const out = new Uint8Array(expected.length);

      fixed.digest(out);

      assert.equal(toHex(out), toHex(expected), `${context}, fixed`);
    }
  }
});

// The two-lane compressions against the one-lane ones, with the state updated in place in one lane
// and read from a shared initial state in the other, as the hash-based signatures use them.
test("two-lane SHA-2 compressions", () => {
  for (let round = 0; round < 16; round++) {
    const words = Int32Array.from({ length: 128 }, (_, i) => Math.imul(i + 1, 0x9e3779b9 + round));

    const small = IV_256.slice();

    const large = IV_512.slice();

    const expected = [new Int32Array(8), new Int32Array(8), new Int32Array(16), new Int32Array(16)];

    block256(small, words, 16, expected[0]);

    block256(IV_256, words, 48, expected[1]);

    block512(large, words, 32, expected[2]);

    block512(IV_512, words, 96, expected[3]);

    const other = new Int32Array(16);

    block256x2(small, words, 16, small, IV_256, words, 48, other);

    assert.deepEqual([small, other.subarray(0, 8)], [expected[0], expected[1]], `SHA-256, round ${round}`);

    block512x2(large, words, 32, large, IV_512, words, 96, other);

    assert.deepEqual([large, other], [expected[2], expected[3]], `SHA-512, round ${round}`);
  }
});
