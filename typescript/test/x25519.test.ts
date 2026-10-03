import assert from "node:assert/strict";
import { test } from "node:test";

import { BASE, x25519 } from "../src/x25519.ts";
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
