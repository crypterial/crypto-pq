import assert from "node:assert/strict";
import { test } from "node:test";

import * as pq from "../src/index.ts";
import { fixedSha256, fixedShake256, prefixedSha256, prefixedSha512, prefixedShake256 } from "../src/primitives.ts";
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

    const sha512 = prefixedSha512(prefix);

    const shake256 = prefixedShake256(prefix);

    for (let length = 0; length <= 300; length++) {
      const context = `prefix ${prefixLength}, message ${length}`;

      const data = pattern(length, length);

      const parts = [data.subarray(0, length / 3), data.subarray(length / 3, length / 2), data.subarray(length / 2)];

      const whole = concat(prefix, data);

      assert.equal(toHex(sha256.digest(24, ...parts)), toHex(pq.SHA_256.digest(whole).subarray(0, 24)), context);

      assert.equal(toHex(sha512.digest(64, ...parts)), toHex(pq.SHA_512.digest(whole)), context);

      assert.equal(toHex(shake256.digest(300, ...parts)), toHex(pq.SHAKE256.digest(whole, 300)), context);

      const fixed = [fixedSha256(prefixLength + length, prefix), fixedShake256(prefixLength + length, prefix)];

      const expected = [pq.SHA_256.digest(whole), pq.SHAKE256.digest(whole, 200)];

      fixed.forEach((hash, i) => {
        hash.message.set(pattern(length, 3), prefixLength);

        hash.digest(new Uint8Array(expected[i].length));

        hash.message.set(data, prefixLength);

        const out = new Uint8Array(expected[i].length);

        hash.digest(out);

        assert.equal(toHex(out), toHex(expected[i]), `${context}, fixed ${i}`);
      });
    }
  }
});
