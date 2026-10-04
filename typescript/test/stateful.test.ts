import assert from "node:assert/strict";
import { test } from "node:test";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { LMS_TYPES, type LmsType, type OtsType, lmsSignatureSize, parsePublicKey } from "../src/lms.ts";
import { MerkleTree } from "../src/merkle.ts";
import { sha256 } from "../src/primitives.ts";
import { MemoryStore, SLOW, concat, hex, isCode, records, throwsCode, toHex, utf8 } from "./vectors.ts";

const SMALL: [string, string][] = [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"]];

class BrokenStore extends MemoryStore {
  override update(previous: Uint8Array | null, next: Uint8Array): boolean {
    if (previous === null) {
      return super.update(previous, next);
    }

    throw new Error("disk full");
  }
}

class CountingStore extends MemoryStore {
  writes = 0;

  override update(previous: Uint8Array | null, next: Uint8Array): boolean {
    const accepted = super.update(previous, next);

    this.writes += accepted ? 1 : 0;

    return accepted;
  }
}

function range(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => i);
}

// The next index in a state blob: it ends an HSS body and follows the XMSS object identifier.
function storedIndex(algorithm: pq.StatefulSignatureAlgorithm, state: Uint8Array | null): bigint {
  assert.ok(state !== null);

  const view = new DataView(state.buffer, state.byteOffset);

  return view.getBigUint64(algorithm === pq.HSS_LMS ? state.length - 24 : 6);
}

// The parameters of every level, read from the public key and the signed child keys.
function levelsOf(publicKey: Uint8Array, signature: Uint8Array): [LmsType, OtsType][] {
  const count = new DataView(publicKey.buffer, publicKey.byteOffset).getUint32(0);

  let key = publicKey.subarray(4);

  const levels: [LmsType, OtsType][] = [];

  let offset = 4;

  for (let level = 0; level < count; level++) {
    const parsed = parsePublicKey(key);

    assert.ok(parsed !== null);

    levels.push([parsed.lms, parsed.ots]);

    if (level + 1 < count) {
      offset += lmsSignatureSize(parsed.lms, parsed.ots);

      const child = LMS_TYPES.get(new DataView(signature.buffer, signature.byteOffset).getUint32(offset));

      assert.ok(child !== undefined);

      key = signature.subarray(offset, offset + child.publicKeySize);

      offset += child.publicKeySize;
    }
  }

  return levels;
}

function indexOf(levels: [LmsType, OtsType][], signature: Uint8Array): bigint {
  const view = new DataView(signature.buffer, signature.byteOffset);

  let offset = 4;

  let index = 0n;

  for (const [lms, ots] of levels) {
    index = (index << BigInt(lms.h)) | BigInt(view.getUint32(offset));

    offset += lmsSignatureSize(lms, ots) + lms.publicKeySize;
  }

  return index;
}

test("HSS ACVP key generation", () => {
  for (const [header, record] of records("acvp/LMS-keyGen.txt", "publicKey")) {
    const pair = hazmat.generateStatefulKeyPair(pq.HSS_LMS, concat(hex(record.i), hex(record.seed)), {
      parameters: [[header.lmsMode, header.lmOtsMode]],
      stateStore: new MemoryStore(),
    });

    const expected = `00000001${record.publicKey.toLowerCase()}`;

    assert.equal(toHex(pair.publicKey.exportKey("raw")), expected, `tcId = ${record.tcId}`);
  }
});

test("HSS ACVP verification", () => {
  for (const [header, record] of records("acvp/LMS-sigVer.txt", "signature")) {
    const publicKey = pq.HSS_LMS.importPublicKey(hex(`00000001${header.publicKey}`), "raw");

    const result = publicKey.verify(hex(`00000000${record.signature}`), hex(record.message));

    assert.equal(result, record.testPassed === "true", `tcId = ${record.tcId} (${record.reason})`);
  }
});

test("HSS RFC 8554 and RFC 9858 vectors", () => {
  for (const [, record] of records("rfc/hss.txt", "signature")) {
    const context = record.name;

    const publicKey = hex(record.publicKey);

    const message = hex(record.message);

    const signature = hex(record.signature);

    const imported = pq.HSS_LMS.importPublicKey(publicKey, "raw");

    assert.ok(imported.verify(signature, message), context);

    const tampered = signature.slice();

    tampered[tampered.length - 1] ^= 1;

    assert.ok(!imported.verify(tampered, message), context);

    assert.ok(!imported.verify(signature, concat(message, Uint8Array.of(0))), context);

    if (!("seed" in record)) {
      continue;
    }

    const levels = levelsOf(publicKey, signature);

    // RFC 9858 A.4 builds a tree of 2^20 leaves.
    if (!SLOW && levels.some(([lms]) => lms.h >= 20)) {
      continue;
    }

    const pair = hazmat.generateStatefulKeyPair(pq.HSS_LMS, concat(hex(record.i), hex(record.seed)), {
      parameters: levels.map(([lms, ots]) => [lms.name, ots.name] as const),
      stateStore: new MemoryStore(),
      index: indexOf(levels, signature),
    });

    assert.equal(toHex(pair.publicKey.exportKey("raw")), toHex(publicKey), context);

    assert.equal(toHex(pair.privateKey.sign(message)), toHex(signature), context);
  }
});

test("HSS state handling", () => {
  const store = new MemoryStore();

  const pair = pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: store });

  assert.equal(pair.privateKey.remainingSignatures(), 32n);

  const first = pair.privateKey.sign(utf8("one"));

  const second = pair.privateKey.sign(utf8("two"));

  assert.ok(pair.publicKey.verify(first, utf8("one")));

  assert.ok(pair.publicKey.verify(second, utf8("two")));

  assert.ok(!pair.publicKey.verify(first, utf8("two")));

  assert.equal(pair.privateKey.remainingSignatures(), 30n);

  const loaded = pq.HSS_LMS.loadPrivateKey(store);

  assert.ok(loaded.publicKey.equals(pair.publicKey));

  assert.equal(loaded.remainingSignatures(), 30n);

  const third = loaded.sign(utf8("three"));

  assert.equal(new DataView(third.buffer).getUint32(4), 2);

  throwsCode("STATE_CONFLICT", () => pair.privateKey.sign(utf8("stale")));

  while (loaded.remainingSignatures() > 0n) {
    loaded.sign(utf8("m"));
  }

  throwsCode("KEY_EXHAUSTED", () => loaded.sign(utf8("m")));

  throwsCode("STATE_CONFLICT", () => pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: store }));
});

test("HSS store failures", () => {
  const broken = new BrokenStore();

  const pair = pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: broken });

  assert.throws(
    () => pair.privateKey.sign(utf8("m")),
    (error: unknown) => isCode("STATE_PERSIST_FAILED")(error) && (error as Error).cause instanceof Error,
  );

  assert.equal(pair.privateKey.remainingSignatures(), 32n);

  const damaged = (broken.state as Uint8Array).slice();

  damaged[damaged.length - 20] ^= 1;

  throwsCode("INVALID_PRIVATE_KEY", () => pq.HSS_LMS.loadPrivateKey(new MemoryStore(damaged)));

  throwsCode("INVALID_PRIVATE_KEY", () => pq.HSS_LMS.loadPrivateKey(new MemoryStore()));

  throwsCode("ALGORITHM_MISMATCH", () => pq.XMSS.loadPrivateKey(new MemoryStore(broken.state)));

  const unreadable = {
    read: () => {
      throw new Error("offline");
    },
    update: () => true,
  };

  throwsCode("STATE_PERSIST_FAILED", () => pq.HSS_LMS.loadPrivateKey(unreadable));

  const refusing = { read: () => null, update: () => false };

  throwsCode("STATE_CONFLICT", () => pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: refusing }));

  const failing = {
    read: () => null,
    update: (): boolean => {
      throw new Error("disk full");
    },
  };

  throwsCode("STATE_PERSIST_FAILED", () => pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: failing }));
});

// A promise from the store would let the signature exist before its index is stored, so every
// thenable answer is refused, and the key neither signs nor moves on.
test("stateful stores answer synchronously", () => {
  const store = new MemoryStore();

  const pair = pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: store });

  const thenables: unknown[] = [
    Promise.resolve(true),
    { then: () => undefined },
    Object.assign(() => true, { then: () => undefined }),
  ];

  for (const answer of thenables) {
    const pending = { read: () => answer, update: () => answer } as unknown as pq.StateStore;

    assert.throws(() => pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: pending }), TypeError);

    assert.throws(() => pq.HSS_LMS.loadPrivateKey(pending), TypeError);

    let later = true;

    const key = pq.HSS_LMS.loadPrivateKey({
      read: () => store.read(),
      update: (previous, next) => (later ? (answer as boolean) : store.update(previous, next)),
    });

    const remaining = key.remainingSignatures();

    const stored = storedIndex(pq.HSS_LMS, store.state);

    assert.throws(() => key.sign(utf8("m")), TypeError);

    assert.equal(key.remainingSignatures(), remaining);

    assert.equal(storedIndex(pq.HSS_LMS, store.state), stored);

    later = false;

    assert.ok(pair.publicKey.verify(key.sign(utf8("m")), utf8("m")));
  }
});

// On one thread a second sign on a key can only start from inside its store; it fails at once
// instead of waiting for a call that cannot finish first.
test("a busy key refuses to sign", () => {
  const store = new MemoryStore();

  const pair = pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: store });

  const inside: [bigint, unknown][] = [];

  let reenter = true;

  let rethrow = false;

  const reentrant: pq.StateStore = {
    read: () => store.read(),
    update(previous, next) {
      if (reenter) {
        try {
          inside.push([key.remainingSignatures(), key.sign(utf8("inner"))]);
        } catch (error) {
          inside.push([key.remainingSignatures(), error]);

          if (rethrow) {
            throw error;
          }
        }
      }

      return store.update(previous, next);
    },
  };

  const key = pq.HSS_LMS.loadPrivateKey(reentrant);

  const signature = key.sign(utf8("outer"));

  assert.ok(pair.publicKey.verify(signature, utf8("outer")));

  assert.equal(new DataView(signature.buffer).getUint32(4), 0);

  assert.equal(inside.length, 1);

  assert.equal(inside[0][0], 32n);

  assert.ok(isCode("STATE_CONFLICT")(inside[0][1]));

  rethrow = true;

  assert.throws(
    () => key.sign(utf8("m")),
    (error: unknown) => isCode("STATE_PERSIST_FAILED")(error) && isCode("STATE_CONFLICT")((error as Error).cause),
  );

  assert.equal(key.remainingSignatures(), 31n);

  assert.equal(storedIndex(pq.HSS_LMS, store.state), 1n);

  reenter = false;

  assert.equal(new DataView(key.sign(utf8("m")).buffer).getUint32(4), 1);

  assert.throws(() => key.sign("message" as unknown as Uint8Array), TypeError);

  assert.equal(key.remainingSignatures(), 30n);

  assert.throws(() => pq.HSS_LMS.loadPrivateKey({} as pq.StateStore), TypeError);

  throwsCode("INVALID_OPTION", () => pq.HSS_LMS.loadPrivateKey(undefined as unknown as pq.StateStore));

  throwsCode("INVALID_OPTION", () =>
    pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: null as unknown as pq.StateStore }),
  );
});

// One update claims reserve indices, and only the first of them writes the store. The state blob
// keeps its format, holding the end of the claimed range, so a key loaded after an unclean stop
// skips what the old key never used.
test("stateful reserve", () => {
  const cases: [pq.StatefulSignatureAlgorithm, pq.StatefulParameters, number][] = [
    [pq.HSS_LMS, SMALL, 40],
    [pq.XMSS_MT, "XMSSMT-SHA2_20/4_192", 72],
  ];

  for (const [algorithm, parameters, size] of cases) {
    const reference = hazmat.generateStatefulKeyPair(algorithm, range(size), {
      parameters,
      stateStore: new MemoryStore(),
    });

    const store = new CountingStore();

    const pair = hazmat.generateStatefulKeyPair(algorithm, range(size), { parameters, stateStore: store, reserve: 4 });

    const capacity = pair.privateKey.remainingSignatures();

    assert.equal(store.writes, 1);

    assert.equal(storedIndex(algorithm, store.state), 0n);

    for (let i = 0; i < 10; i++) {
      const message = Uint8Array.of(i);

      const context = `${algorithm.name}, signature ${i}`;

      assert.deepEqual(pair.privateKey.sign(message), reference.privateKey.sign(message), context);

      assert.equal(store.writes, 2 + Math.floor(i / 4), context);

      assert.equal(storedIndex(algorithm, store.state), BigInt(4 * Math.floor(i / 4) + 4), context);

      assert.equal(pair.privateKey.remainingSignatures(), capacity - BigInt(i + 1), context);
    }

    const reloaded = algorithm.loadPrivateKey(store, { reserve: 4 });

    assert.equal(reloaded.remainingSignatures(), capacity - 12n);

    const skipped = hazmat.generateStatefulKeyPair(algorithm, range(size), {
      parameters,
      stateStore: new MemoryStore(),
      index: 12n,
    });

    assert.deepEqual(reloaded.sign(utf8("m")), skipped.privateKey.sign(utf8("m")));

    assert.equal(storedIndex(algorithm, store.state), 16n);

    // The first key still holds indices 10 and 11, which the loaded key skipped, and its next claim
    // finds the store changed.
    for (const message of [utf8("ten"), utf8("eleven")]) {
      assert.deepEqual(pair.privateKey.sign(message), reference.privateKey.sign(message));
    }

    throwsCode("STATE_CONFLICT", () => pair.privateKey.sign(utf8("m")));

    assert.equal(pair.privateKey.remainingSignatures(), capacity - 12n);

    assert.equal(storedIndex(algorithm, store.state), 16n);
  }

  const store = new CountingStore();

  const near = hazmat.generateStatefulKeyPair(pq.HSS_LMS, range(40), {
    parameters: SMALL,
    stateStore: store,
    index: 29n,
    reserve: 100n,
  });

  near.privateKey.sign(utf8("m"));

  assert.equal(storedIndex(pq.HSS_LMS, store.state), 32n);

  near.privateKey.sign(utf8("m"));

  near.privateKey.sign(utf8("m"));

  assert.equal(store.writes, 2);

  throwsCode("KEY_EXHAUSTED", () => near.privateKey.sign(utf8("m")));

  assert.equal(pq.HSS_LMS.loadPrivateKey(store).remainingSignatures(), 0n);

  const fresh = new MemoryStore();

  pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: fresh });

  for (const reserve of [Number.MAX_SAFE_INTEGER, 1n << 64n]) {
    const claimed = new MemoryStore(fresh.state);

    const key = pq.HSS_LMS.loadPrivateKey(claimed, { reserve });

    key.sign(utf8("m"));

    assert.equal(storedIndex(pq.HSS_LMS, claimed.state), 32n);

    assert.equal(key.remainingSignatures(), 31n);
  }

  const invalid: unknown[] = [0, -1, 1.5, Number.NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 0n, -3n, "2", true, null];

  for (const reserve of invalid) {
    const options = { parameters: SMALL, stateStore: new MemoryStore(), reserve: reserve as number };

    throwsCode("INVALID_OPTION", () => pq.HSS_LMS.generateKeyPair(options), String(reserve));

    throwsCode("INVALID_OPTION", () => hazmat.generateStatefulKeyPair(pq.HSS_LMS, range(40), options));

    throwsCode("INVALID_OPTION", () => pq.HSS_LMS.loadPrivateKey(fresh, { reserve: reserve as number }));
  }

  assert.throws(() => pq.HSS_LMS.loadPrivateKey(fresh, 4 as never), TypeError);
});

// A state blob holds the seed. The copy of the stored blob that update receives as previous is
// wiped once the call returns, whatever its outcome, and the key keeps its own copy intact.
test("stateful keys wipe the state copies they hand out", () => {
  const store = new MemoryStore();

  const copies: Uint8Array[] = [];

  let mode = "accept";

  const recording: pq.StateStore = {
    read: () => store.read(),
    update(previous, next) {
      if (previous !== null) {
        copies.push(previous);
      }

      if (mode === "throw") {
        throw new Error("disk full");
      }

      return mode === "accept" && store.update(previous, next);
    },
  };

  const pair = pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: recording });

  pair.privateKey.sign(utf8("one"));

  pair.privateKey.sign(utf8("two"));

  mode = "refuse";

  throwsCode("STATE_CONFLICT", () => pair.privateKey.sign(utf8("three")));

  mode = "throw";

  throwsCode("STATE_PERSIST_FAILED", () => pair.privateKey.sign(utf8("three")));

  assert.equal(copies.length, 4);

  for (const copy of copies) {
    assert.ok(copy.length > 18 && copy.every((byte) => byte === 0));
  }

  assert.equal(storedIndex(pq.HSS_LMS, store.state), 2n);

  mode = "accept";

  const signature = pair.privateKey.sign(utf8("three"));

  assert.equal(new DataView(signature.buffer).getUint32(4), 2);

  assert.ok(pair.publicKey.verify(signature, utf8("three")));
});

test("HSS parameters", () => {
  const invalid: unknown[] = [
    [],
    Array(9).fill(SMALL[0]),
    [["LMS_SHA256_M32_H5", "LMOTS_SHA256_N24_W1"]],
    [["LMS_SHA256_M24_H5", "LMOTS_SHAKE_N24_W1"]],
    "LMS_SHA256_M24_H5",
    [["LMS_SHA256_M24_H5"]],
    [["LMS_X", "LMOTS_SHA256_N24_W1"]],
    [
      ["LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"],
      ["LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"],
      ["LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8"],
    ],
  ];

  for (const parameters of invalid) {
    throwsCode(
      "INVALID_OPTION",
      () =>
        pq.HSS_LMS.generateKeyPair({ parameters: parameters as pq.StatefulParameters, stateStore: new MemoryStore() }),
      JSON.stringify(parameters),
    );
  }
});

test("HSS tree boundary", () => {
  const levels: [string, string][] = [
    ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"],
    ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"],
  ];

  const pair = hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(40), {
    parameters: levels,
    stateStore: new MemoryStore(),
    index: 31n,
  });

  const signatures = [pair.privateKey.sign(Uint8Array.of(0)), pair.privateKey.sign(Uint8Array.of(1))];

  signatures.forEach((signature, i) => assert.ok(pair.publicKey.verify(signature, Uint8Array.of(i))));

  assert.notDeepEqual(signatures[0].subarray(4, 8), signatures[1].subarray(4, 8));
});

test("HSS formats", () => {
  const pair = pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: new MemoryStore() });

  for (const format of ["raw", "der", "pem"] as const) {
    assert.ok(pq.HSS_LMS.importPublicKey(pair.publicKey.exportKey(format), format).equals(pair.publicKey));
  }

  const der = pair.publicKey.exportKey("der");

  assert.ok(toHex(der).includes("060b2a864886f70d0109100311"));

  const levels = concat(Uint8Array.of(0, 0, 0, 9), pair.publicKey.exportKey("raw").subarray(4));

  throwsCode("INVALID_PUBLIC_KEY", () => pq.HSS_LMS.importPublicKey(levels, "raw"));

  const truncated = pair.publicKey.exportKey("raw").subarray(1);

  throwsCode("INVALID_PUBLIC_KEY", () => pq.HSS_LMS.importPublicKey(truncated, "raw"));

  throwsCode("ALGORITHM_MISMATCH", () => pq.XMSS.importPublicKey(der, "der"));
});

// Computed with the Python reference: every implementation writes byte-identical state blobs.
test("stateful cross-language state", () => {
  const hssStore = new MemoryStore();

  const hss = hazmat.generateStatefulKeyPair(pq.HSS_LMS, range(40), {
    parameters: SMALL,
    stateStore: hssStore,
    index: 3n,
  });

  assert.equal(
    toHex(hssStore.state as Uint8Array),
    "0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627" +
      "000000000000000332b414e1d42dc2866aeed26f724a5be7",
  );

  assert.equal(
    toHex(hss.publicKey.exportKey("raw")),
    "000000010000000a00000005000102030405060708090a0b0c0d0e0f224f2491ed07b8b55134c2b6ea3163d0e60e423ce46b051b",
  );

  const signature = hss.privateKey.sign(utf8("crypto-pq"));

  assert.equal(
    toHex(hssStore.state as Uint8Array),
    "0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627" +
      "00000000000000047bc402dcf96640ca1c7126fe316fef60",
  );

  assert.equal(toHex(sha256(signature)), "07cb93b630cdd6b575402bcdbce2024b6a88bfdb419d9c7b920c250d7273a5a6");

  assert.ok(pq.HSS_LMS.loadPrivateKey(new MemoryStore(hssStore.state)).publicKey.equals(hss.publicKey));

  const xmssStore = new MemoryStore();

  const xmss = hazmat.generateStatefulKeyPair(pq.XMSS_MT, range(72), {
    parameters: "XMSSMT-SHAKE256_20/4_192",
    stateStore: xmssStore,
    index: 5n,
  });

  assert.equal(
    toHex(xmssStore.state as Uint8Array),
    "0103000000320000000000000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627" +
      "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647e0dc0d3f343f3dbd989a24e2ad453440",
  );

  assert.equal(
    toHex(xmss.publicKey.exportKey("raw")),
    "00000032296d594ddd9688b47a9c461c70e3d9f29e901b8cedcaaa4c303132333435363738393a3b3c3d3e3f4041424344454647",
  );

  assert.ok(pq.XMSS_MT.loadPrivateKey(new MemoryStore(xmssStore.state)).publicKey.equals(xmss.publicKey));
});

test("stateful hazmat options", () => {
  const options = { parameters: SMALL, stateStore: new MemoryStore() };

  throwsCode("INVALID_LENGTH", () => hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(39), options));

  throwsCode("INVALID_OPTION", () =>
    hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(40), { ...options, index: 33n }),
  );

  assert.throws(
    () => hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(40), { ...options, index: 3 as unknown as bigint }),
    TypeError,
  );

  const exhausted = hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(40), { ...options, index: 32n });

  assert.equal(exhausted.privateKey.remainingSignatures(), 0n);

  throwsCode("KEY_EXHAUSTED", () => exhausted.privateKey.sign(utf8("m")));

  const seed = "seed" as unknown as Uint8Array;

  assert.throws(() => hazmat.generateStatefulKeyPair(pq.XMSS, seed, options), TypeError);

  assert.throws(() => hazmat.generateStatefulKeyPair(pq.SHA_256 as never, new Uint8Array(40), options), TypeError);
});

// Above height 15 the cache keeps only the upper levels, and an authentication path rebuilds the
// subtree under the signed leaf. The tree keeps the last subtree it built, so the other leaves
// under it need no rebuild; only the RFC 9858 A.4 vector reaches this path otherwise.
test("Merkle cache", () => {
  const height = 17;

  const index32 = (value: number) => Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);

  let leaves = 0;

  const leaf = (index: number) => {
    leaves++;

    return sha256(index32(index));
  };

  const combine = (z: number, j: number, left: Uint8Array, right: Uint8Array) =>
    sha256(Uint8Array.of(z), index32(j), left, right);

  const tree = new MerkleTree(height, 32, leaf, combine);

  assert.equal(tree.low, 2);

  assert.equal(leaves, 2 ** height);

  let level = Array.from({ length: 2 ** height }, (_, index) => sha256(index32(index)));

  for (let z = 0; z < height; z++) {
    level = Array.from({ length: level.length / 2 }, (_, j) => combine(z, j, level[2 * j], level[2 * j + 1]));
  }

  assert.deepEqual(tree.root, level[0]);

  // Each leaf with the number of leaves its path recomputes: the build ends in the last subtree.
  const paths = [
    [2 ** height - 1, 0],
    [0, 4],
    [1, 0],
    [3, 0],
    [6, 4],
    [5, 0],
    [2 ** 16 + 3, 4],
    [2 ** 16, 0],
    [2 ** height - 4, 4],
    [0, 4],
  ];

  for (const [index, rebuilt] of paths) {
    leaves = 0;

    const path = tree.authPath(index);

    assert.equal(leaves, rebuilt, `leaf ${index}`);

    assert.equal(path.length, 32 * height);

    let node = sha256(index32(index));

    for (let z = 0; z < height; z++) {
      const sibling = path.subarray(32 * z, 32 * (z + 1));

      const j = index >>> (z + 1);

      node = ((index >>> z) & 1) === 0 ? combine(z, j, node, sibling) : combine(z, j, sibling, node);
    }

    assert.deepEqual(node, tree.root, `leaf ${index}`);
  }

  const small = new MerkleTree(5, 32, leaf, combine);

  leaves = 0;

  for (let index = 0; index < 32; index++) {
    small.authPath(index);
  }

  assert.equal(leaves, 0);
});
