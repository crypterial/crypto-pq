import assert from "node:assert/strict";
import { test } from "node:test";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { LMS_TYPES, type LmsType, type OtsType, lmsSignatureSize, parsePublicKey } from "../src/lms.ts";
import { MerkleTree } from "../src/merkle.ts";
import { sha256 } from "../src/primitives.ts";
import { MemoryStore, SLOW, concat, hex, isCode, records, rejectsCode, throwsCode, toHex, utf8 } from "./vectors.ts";

const SMALL: [string, string][] = [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"]];

class BrokenStore extends MemoryStore {
  override update(previous: Uint8Array | null, next: Uint8Array): boolean {
    if (previous === null) {
      return super.update(previous, next);
    }

    throw new Error("disk full");
  }
}

function range(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => i);
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

test("HSS ACVP key generation", async () => {
  for (const [header, record] of records("acvp/LMS-keyGen.txt", "publicKey")) {
    const pair = await hazmat.generateStatefulKeyPair(pq.HSS_LMS, concat(hex(record.i), hex(record.seed)), {
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

test("HSS RFC 8554 and RFC 9858 vectors", async () => {
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

    const pair = await hazmat.generateStatefulKeyPair(pq.HSS_LMS, concat(hex(record.i), hex(record.seed)), {
      parameters: levels.map(([lms, ots]) => [lms.name, ots.name] as const),
      stateStore: new MemoryStore(),
      index: indexOf(levels, signature),
    });

    assert.equal(toHex(pair.publicKey.exportKey("raw")), toHex(publicKey), context);

    assert.equal(toHex(await pair.privateKey.sign(message)), toHex(signature), context);
  }
});

test("HSS state handling", async () => {
  const store = new MemoryStore();

  const pair = await pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: store });

  assert.equal(pair.privateKey.remainingSignatures(), 32n);

  const first = await pair.privateKey.sign(utf8("one"));

  const second = await pair.privateKey.sign(utf8("two"));

  assert.ok(pair.publicKey.verify(first, utf8("one")));

  assert.ok(pair.publicKey.verify(second, utf8("two")));

  assert.ok(!pair.publicKey.verify(first, utf8("two")));

  assert.equal(pair.privateKey.remainingSignatures(), 30n);

  const loaded = await pq.HSS_LMS.loadPrivateKey(store);

  assert.ok(loaded.publicKey.equals(pair.publicKey));

  assert.equal(loaded.remainingSignatures(), 30n);

  const third = await loaded.sign(utf8("three"));

  assert.equal(new DataView(third.buffer).getUint32(4), 2);

  await rejectsCode("STATE_CONFLICT", () => pair.privateKey.sign(utf8("stale")));

  while (loaded.remainingSignatures() > 0n) {
    await loaded.sign(utf8("m"));
  }

  await rejectsCode("KEY_EXHAUSTED", () => loaded.sign(utf8("m")));

  await rejectsCode("STATE_CONFLICT", () => pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: store }));
});

test("HSS store failures", async () => {
  const broken = new BrokenStore();

  const pair = await pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: broken });

  await assert.rejects(
    pair.privateKey.sign(utf8("m")),
    (error: unknown) => isCode("STATE_PERSIST_FAILED")(error) && (error as Error).cause instanceof Error,
  );

  assert.equal(pair.privateKey.remainingSignatures(), 32n);

  const damaged = (broken.state as Uint8Array).slice();

  damaged[damaged.length - 20] ^= 1;

  await rejectsCode("INVALID_PRIVATE_KEY", () => pq.HSS_LMS.loadPrivateKey(new MemoryStore(damaged)));

  await rejectsCode("INVALID_PRIVATE_KEY", () => pq.HSS_LMS.loadPrivateKey(new MemoryStore()));

  await rejectsCode("ALGORITHM_MISMATCH", () => pq.XMSS.loadPrivateKey(new MemoryStore(broken.state)));

  const unreadable = { read: () => Promise.reject(new Error("offline")), update: () => true };

  await rejectsCode("STATE_PERSIST_FAILED", () => pq.HSS_LMS.loadPrivateKey(unreadable));

  const refusing = { read: () => null, update: () => Promise.resolve(false) };

  await rejectsCode("STATE_CONFLICT", () => pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: refusing }));

  const failing = { read: () => null, update: () => Promise.reject(new Error("disk full")) };

  await rejectsCode("STATE_PERSIST_FAILED", () =>
    pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: failing }),
  );
});

test("HSS parameters", async () => {
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
    await rejectsCode(
      "INVALID_OPTION",
      () =>
        pq.HSS_LMS.generateKeyPair({ parameters: parameters as pq.StatefulParameters, stateStore: new MemoryStore() }),
      JSON.stringify(parameters),
    );
  }
});

test("HSS tree boundary", async () => {
  const levels: [string, string][] = [
    ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"],
    ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"],
  ];

  const pair = await hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(40), {
    parameters: levels,
    stateStore: new MemoryStore(),
    index: 31n,
  });

  const signatures = [await pair.privateKey.sign(Uint8Array.of(0)), await pair.privateKey.sign(Uint8Array.of(1))];

  signatures.forEach((signature, i) => assert.ok(pair.publicKey.verify(signature, Uint8Array.of(i))));

  assert.notDeepEqual(signatures[0].subarray(4, 8), signatures[1].subarray(4, 8));
});

test("HSS formats", async () => {
  const pair = await pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: new MemoryStore() });

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
test("stateful cross-language state", async () => {
  const hssStore = new MemoryStore();

  const hss = await hazmat.generateStatefulKeyPair(pq.HSS_LMS, range(40), {
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

  const signature = await hss.privateKey.sign(utf8("crypto-pq"));

  assert.equal(
    toHex(hssStore.state as Uint8Array),
    "0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627" +
      "00000000000000047bc402dcf96640ca1c7126fe316fef60",
  );

  assert.equal(toHex(sha256(signature)), "07cb93b630cdd6b575402bcdbce2024b6a88bfdb419d9c7b920c250d7273a5a6");

  assert.ok((await pq.HSS_LMS.loadPrivateKey(new MemoryStore(hssStore.state))).publicKey.equals(hss.publicKey));

  const xmssStore = new MemoryStore();

  const xmss = await hazmat.generateStatefulKeyPair(pq.XMSS_MT, range(72), {
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

  assert.ok((await pq.XMSS_MT.loadPrivateKey(new MemoryStore(xmssStore.state))).publicKey.equals(xmss.publicKey));
});

test("stateful signing is serialized", async () => {
  const store = new MemoryStore();

  const pair = await pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: store });

  const slow: pq.StateStore = {
    read: () => store.read(),
    update: (previous, next) => new Promise((resolve) => setTimeout(() => resolve(store.update(previous, next)), 5)),
  };

  const key = await pq.HSS_LMS.loadPrivateKey(slow);

  const messages = [0, 1, 2, 3].map((i) => Uint8Array.of(i));

  const signatures = await Promise.all(messages.map((message) => key.sign(message)));

  signatures.forEach((signature, i) => {
    assert.ok(pair.publicKey.verify(signature, messages[i]));

    assert.equal(new DataView(signature.buffer).getUint32(4), i);
  });

  assert.equal(key.remainingSignatures(), 28n);

  const message = Uint8Array.of(7);

  const pending = key.sign(message);

  message[0] = 8;

  assert.ok(pair.publicKey.verify(await pending, Uint8Array.of(7)));

  await assert.rejects(key.sign("message" as unknown as Uint8Array), TypeError);

  assert.equal(key.remainingSignatures(), 27n);

  await assert.rejects(pq.HSS_LMS.loadPrivateKey({} as pq.StateStore), TypeError);

  await rejectsCode("INVALID_OPTION", () => pq.HSS_LMS.loadPrivateKey(undefined as unknown as pq.StateStore));

  await rejectsCode("INVALID_OPTION", () => pq.HSS_LMS.generateKeyPair({ parameters: SMALL, stateStore: null as unknown as pq.StateStore }));
});

test("stateful hazmat options", async () => {
  const options = { parameters: SMALL, stateStore: new MemoryStore() };

  await rejectsCode("INVALID_LENGTH", () => hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(39), options));

  await rejectsCode("INVALID_OPTION", () =>
    hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(40), { ...options, index: 33n }),
  );

  await assert.rejects(
    hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(40), { ...options, index: 3 as unknown as bigint }),
    TypeError,
  );

  const exhausted = await hazmat.generateStatefulKeyPair(pq.HSS_LMS, new Uint8Array(40), { ...options, index: 32n });

  assert.equal(exhausted.privateKey.remainingSignatures(), 0n);

  await rejectsCode("KEY_EXHAUSTED", () => exhausted.privateKey.sign(utf8("m")));

  const seed = "seed" as unknown as Uint8Array;

  await assert.rejects(hazmat.generateStatefulKeyPair(pq.XMSS, seed, options), TypeError);

  await assert.rejects(hazmat.generateStatefulKeyPair(pq.SHA_256 as never, new Uint8Array(40), options), TypeError);
});

// Above height 15 the cache keeps only the upper levels and rebuilds the subtree under the signed
// leaf; only the RFC 9858 A.4 vector reaches that path otherwise.
test("Merkle cache", () => {
  const height = 17;

  const index32 = (value: number) => Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);

  const leaf = (index: number) => sha256(index32(index));

  const combine = (z: number, j: number, left: Uint8Array, right: Uint8Array) =>
    sha256(Uint8Array.of(z), index32(j), left, right);

  const tree = new MerkleTree(height, leaf, combine);

  assert.equal(tree.low, 2);

  let level = Array.from({ length: 2 ** height }, (_, index) => leaf(index));

  for (let z = 0; z < height; z++) {
    level = Array.from({ length: level.length / 2 }, (_, j) => combine(z, j, level[2 * j], level[2 * j + 1]));
  }

  assert.deepEqual(tree.root, level[0]);

  for (const index of [0, 1, 6, 2 ** 16 + 3, 2 ** height - 1]) {
    let node = leaf(index);

    tree.authPath(index).forEach((sibling, z) => {
      const j = index >>> (z + 1);

      node = ((index >>> z) & 1) === 0 ? combine(z, j, node, sibling) : combine(z, j, sibling, node);
    });

    assert.deepEqual(node, tree.root, `leaf ${index}`);
  }
});
