import assert from "node:assert/strict";
import { test } from "node:test";

import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import { leavesComputed } from "../src/merkle.ts";
import { MemoryStore, SLOW, concat, hex, throwsCode, toHex, utf8 } from "./vectors.ts";

type Algorithm = pq.StatefulSignatureAlgorithm;

const TWO: [string, string][] = [
  ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"],
  ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2"],
];

const THREE: [string, string][] = [
  ["LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2"],
  ["LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1"],
  ["LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2"],
];

const MT = "XMSSMT-SHA2_20/4_192";

const LABEL = utf8("crypto-pq tree cache v1");

interface Tree {
  level: number;

  tree: bigint;

  low: number;

  height: number;

  n: number;

  count: number;

  nodes: Uint8Array;
}

// A tree cache taken apart, so that a test can change one field and seal it again with the key's
// seed: only then do the checks after the tag see the change. The parameters are an HSS level count
// and a pair of type codes per level, or an XMSS OID.
class Cache {
  version: number;

  kind: number;

  parameters: Uint8Array;

  publicKey: Uint8Array;

  trees: Tree[] = [];

  constructor(data: Uint8Array) {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

    const end = data[1] === 1 ? 3 + 8 * data[2] : 6;

    const size = view.getUint32(end);

    this.version = data[0];

    this.kind = data[1];

    this.parameters = data.slice(2, end);

    this.publicKey = data.slice(end + 4, end + 4 + size);

    let offset = end + 5 + size;

    for (let i = 0; i < data[end + 4 + size]; i++) {
      const n = data[offset + 11];

      const count = view.getUint32(offset + 12);

      const nodes = data.slice(offset + 16, offset + 16 + n * count);

      const tree = view.getBigUint64(offset + 1);

      this.trees.push({ level: data[offset], tree, low: data[offset + 9], height: data[offset + 10], n, count, nodes });

      offset += 16 + n * count;
    }
  }

  // Where the nodes of tree i start.
  nodesAt(i: number): number {
    const before = this.trees.slice(0, i).reduce((total, tree) => total + 16 + tree.nodes.length, 0);

    return 7 + this.parameters.length + this.publicKey.length + before + 16;
  }

  seal(seed: Uint8Array): Uint8Array {
    const parts = [Uint8Array.of(this.version, this.kind), this.parameters];

    parts.push(uint32(this.publicKey.length), this.publicKey);

    parts.push(Uint8Array.of(this.trees.length));

    for (const tree of this.trees) {
      const header = new Uint8Array(16);

      const view = new DataView(header.buffer);

      header.set([tree.level], 0);

      view.setBigUint64(1, tree.tree);

      header.set([tree.low, tree.height, tree.n], 9);

      view.setUint32(12, tree.count);

      parts.push(header, tree.nodes);
    }

    const body = concat(...parts);

    return concat(body, pq.HMAC_SHA_256.digest(pq.HMAC_SHA_256.digest(LABEL, seed), body));
  }
}

function uint32(value: number): Uint8Array {
  const out = new Uint8Array(4);

  new DataView(out.buffer).setUint32(0, value);

  return out;
}

function range(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => i);
}

function flip(data: Uint8Array, position: number, mask = 1): Uint8Array {
  const out = data.slice();

  out[position] ^= mask;

  return out;
}

function withByte(data: Uint8Array, position: number, value: number): Uint8Array {
  const out = data.slice();

  out[position] = value;

  return out;
}

interface Exported {
  readonly pair: pq.StatefulKeyPair;

  readonly state: Uint8Array;

  readonly cache: Uint8Array;
}

// A key at index that signed there, so that it holds a tree on every level, the state it stored and
// its cache.
function exported(
  algorithm: Algorithm,
  parameters: pq.StatefulParameters,
  seed: Uint8Array,
  index: bigint,
  sign = true,
): Exported {
  const store = new MemoryStore();

  const pair = hazmat.generateStatefulKeyPair(algorithm, seed, { parameters, stateStore: store, index });

  if (sign) {
    pair.privateKey.sign(utf8("first"));
  }

  return { pair, state: store.state as Uint8Array, cache: pair.privateKey.exportTreeCache() };
}

// The state of a key at index, from a key built there.
function stateAt(algorithm: Algorithm, parameters: pq.StatefulParameters, seed: Uint8Array, index: bigint): Uint8Array {
  const store = new MemoryStore();

  hazmat.generateStatefulKeyPair(algorithm, seed, { parameters, stateStore: store, index });

  return store.state as Uint8Array;
}

function load(algorithm: Algorithm, state: Uint8Array, treeCache: Uint8Array): pq.StatefulPrivateKey {
  return algorithm.loadPrivateKey(new MemoryStore(state), { treeCache });
}

// The key loaded with the cache signs as the key loaded without it.
function assertLoads(algorithm: Algorithm, state: Uint8Array, cache: Uint8Array, context: string): void {
  const loaded = load(algorithm, state, cache);

  const plain = algorithm.loadPrivateKey(new MemoryStore(state));

  assert.ok(loaded.publicKey.equals(plain.publicKey), context);

  assert.equal(loaded.remainingSignatures(), plain.remainingSignatures(), context);

  if (plain.remainingSignatures() > 0n) {
    assert.deepEqual(loaded.sign(utf8("next")), plain.sign(utf8("next")), context);
  }
}

function sealed(cache: Uint8Array, seed: Uint8Array, ...edits: ((parts: Cache) => void)[]): Uint8Array {
  const parts = new Cache(cache);

  for (const edit of edits) {
    edit(parts);
  }

  return parts.seal(seed);
}

test("tree cache round trip", () => {
  const cases: [Algorithm, pq.StatefulParameters, number, bigint][] = [
    [pq.HSS_LMS, TWO, 40, 40n],
    [pq.HSS_LMS, THREE, 48, 5000n],
    [pq.XMSS_MT, MT, 72, 0x12345n],
  ];

  for (const [algorithm, parameters, size, index] of cases) {
    const context = `${algorithm.name} at ${index}`;

    const { pair, state, cache } = exported(algorithm, parameters, range(size), index);

    const loaded = load(algorithm, state, cache);

    const plain = algorithm.loadPrivateKey(new MemoryStore(state));

    assert.ok(loaded.publicKey.equals(pair.publicKey), context);

    assert.deepEqual(loaded.exportTreeCache(), cache, context);

    for (const message of [utf8("second"), utf8("third")]) {
      const signature = loaded.sign(message);

      assert.ok(pair.publicKey.verify(signature, message), context);

      assert.deepEqual(signature, plain.sign(message), context);
    }

    assert.deepEqual(loaded.exportTreeCache(), plain.exportTreeCache(), context);
  }
});

test("tree cache format", () => {
  const seed = range(40);

  const { pair, cache } = exported(pq.HSS_LMS, TWO, seed, 40n);

  const parts = new Cache(cache);

  const publicKey = pair.publicKey.exportKey("raw");

  assert.deepEqual([parts.version, parts.kind, parts.publicKey], [1, 1, publicKey]);

  assert.equal(toHex(parts.parameters), "02" + "0000000a00000007" + "0000000a00000006");

  const shape = (tree: Tree) => [tree.level, tree.tree, tree.low, tree.height, tree.n, tree.count];

  assert.deepEqual(parts.trees.map(shape), [
    [0, 0n, 0, 5, 24, 63],
    [1, 1n, 0, 5, 24, 63],
  ]);

  assert.deepEqual(parts.trees[0].nodes.subarray(-24), publicKey.subarray(-24));

  assert.deepEqual(parts.seal(seed), cache);

  const fresh = new Cache(exported(pq.HSS_LMS, TWO, seed, 40n, false).cache);

  assert.deepEqual(fresh.trees, parts.trees.slice(0, 1));

  const mt = exported(pq.XMSS_MT, MT, range(72), 0x12345n);

  const layers = new Cache(mt.cache);

  assert.deepEqual([layers.version, layers.kind, toHex(layers.parameters)], [1, 3, "00000022"]);

  assert.deepEqual(layers.trees.map(shape), [
    [3, 0n, 0, 5, 24, 63],
    [2, 2n, 0, 5, 24, 63],
    [1, 72n, 0, 5, 24, 63],
    [0, 2330n, 0, 5, 24, 63],
  ]);

  assert.deepEqual(layers.trees[0].nodes.subarray(-24), mt.pair.publicKey.exportKey("raw").subarray(4, 28));

  assert.deepEqual(layers.seal(range(72)), mt.cache);
});

test("tree cache rejections", () => {
  const seed = range(40);

  const { state, cache } = exported(pq.HSS_LMS, TWO, seed, 40n);

  const parts = new Cache(cache);

  const invalid: [string, Uint8Array][] = [
    ["level 0 node changed", flip(cache, parts.nodesAt(0) + 5)],
    ["level 1 node changed", flip(cache, parts.nodesAt(1) + 30)],
    ["first tag byte changed", flip(cache, cache.length - 32)],
    ["last tag byte changed", flip(cache, cache.length - 1)],
    ["version 0", withByte(cache, 0, 0)],
    ["version 2", withByte(cache, 0, 2)],
    ["version 2 and kind 2", withByte(withByte(cache, 0, 2), 1, 2)],
    ["cut and kind 2", withByte(cache, 1, 2).subarray(0, -1)],
    ["cut in the parameters", cache.subarray(0, 10)],
    ["one byte appended", concat(cache, Uint8Array.of(0))],
    ["a second tag appended", concat(cache, cache.subarray(-32))],
    ["another key", exported(pq.HSS_LMS, TWO, new Uint8Array(40), 40n).cache],
  ];

  for (const [name, data] of invalid) {
    throwsCode("INVALID_ENCODING", () => load(pq.HSS_LMS, state, data), name);
  }

  for (let length = 0; length < cache.length; length++) {
    throwsCode("INVALID_ENCODING", () => load(pq.HSS_LMS, state, cache.subarray(0, length)), `cut to ${length}`);
  }

  // Another kind reads the HSS parameters with its own layout, or with none, and finds the cache
  // malformed; a cache made for another algorithm is ALGORITHM_MISMATCH.
  for (const kind of [0, 2, 3, 4]) {
    throwsCode("INVALID_ENCODING", () => load(pq.HSS_LMS, state, withByte(cache, 1, kind)), `kind ${kind}`);
  }

  const mt = exported(pq.XMSS_MT, MT, range(72), 0x12345n);

  throwsCode("ALGORITHM_MISMATCH", () => load(pq.HSS_LMS, state, mt.cache));

  throwsCode("ALGORITHM_MISMATCH", () => load(pq.XMSS_MT, mt.state, cache));

  // The same seed with another type below the top: the public key and the tag key are the same, and
  // only the parameters tell the keys apart.
  const lower: [string, string][] = [
    ["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8"],
    ["LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2"],
  ];

  for (const level of lower) {
    const other = stateAt(pq.HSS_LMS, [TWO[0], level], seed, 41n);

    throwsCode("INVALID_ENCODING", () => load(pq.HSS_LMS, other, cache), level.join(" "));
  }

  // The same I with another SEED: the public parts match, the tag does not.
  const other = stateAt(pq.HSS_LMS, TWO, concat(seed.subarray(0, 16), new Uint8Array(24)), 41n);

  throwsCode("INVALID_ENCODING", () => load(pq.HSS_LMS, other, cache));

  // The state is checked before the cache.
  throwsCode("INVALID_PRIVATE_KEY", () => load(pq.HSS_LMS, state.subarray(0, -1), cache));

  assert.equal(load(pq.HSS_LMS, stateAt(pq.HSS_LMS, TWO, seed, 1024n), cache).remainingSignatures(), 0n);

  for (const value of ["text", 7, [1], null, new Uint16Array(4)]) {
    assert.throws(() => pq.HSS_LMS.loadPrivateKey(new MemoryStore(state), { treeCache: value as never }), TypeError);
  }

  // The level-1 tree of index 40 is tree 1, which index 64 has left.
  assertLoads(pq.HSS_LMS, stateAt(pq.HSS_LMS, TWO, seed, 64n), cache, "stale level 1");

  // The key reads the cache once: changing it afterwards changes nothing.
  const copy = cache.slice();

  const key = load(pq.HSS_LMS, state, copy);

  copy.fill(0);

  assert.deepEqual(key.exportTreeCache(), cache);
});

// Changes sealed with the key's seed, which only the checks after the tag can catch.
test("tree cache sealed changes", () => {
  const seed = range(40);

  const { state, cache } = exported(pq.HSS_LMS, TWO, seed, 40n);

  const later = stateAt(pq.HSS_LMS, TWO, seed, 64n);

  // At the capacity no lower tree is needed, and the top tree is still tree 0.
  const capacity = stateAt(pq.HSS_LMS, TWO, seed, 1024n);

  const node = (i: number, position: number) => (parts: Cache) => {
    parts.trees[i].nodes = flip(parts.trees[i].nodes, position);
  };

  const number = (i: number, tree: bigint) => (parts: Cache) => {
    parts.trees[i].tree = tree;
  };

  const shape = (i: number, low: number, height: number, n: number, count: number) => (parts: Cache) => {
    const tree = parts.trees[i];

    const nodes = Uint8Array.from({ length: n * count }, (_, j) => tree.nodes[j % tree.nodes.length]);

    Object.assign(tree, { low, height, n, count, nodes });
  };

  const keep =
    (...order: number[]) =>
    (parts: Cache) => {
      parts.trees = order.map((i) => ({ ...parts.trees[i] }));
    };

  const level = (i: number, value: number) => (parts: Cache) => {
    parts.trees[i].level = value;
  };

  const key = (change: (key: Uint8Array) => Uint8Array) => (parts: Cache) => {
    parts.publicKey = change(parts.publicKey);
  };

  const section = (value: string) => (parts: Cache) => {
    parts.parameters = hex(value);
  };

  const [w4, w2, w8] = ["0000000a00000007", "0000000a00000006", "0000000a00000008"];

  const cases: [string, ((parts: Cache) => void)[], Uint8Array, pq.ErrorCode | null][] = [
    ["level 1 node changed", [node(1, 7)], state, "INVALID_ENCODING"],
    ["level 1 root changed", [node(1, 62 * 24)], state, "INVALID_ENCODING"],
    ["level 0 leaf changed", [node(0, 0)], state, "INVALID_ENCODING"],
    ["level 0 root changed", [node(0, 62 * 24 + 23)], state, "INVALID_ENCODING"],
    ["stale level 1 node changed", [node(1, 7)], later, null],
    ["level 1 claimed as tree 2", [number(1, 2n)], later, "INVALID_ENCODING"],
    ["level 1 as tree 2 for index 41", [number(1, 2n)], state, null],
    ["top tree numbered 1", [number(0, 1n)], state, null],
    ["no trees", [keep()], state, null],
    ["top tree only", [keep(0)], state, null],
    ["level 1 only", [keep(1)], state, null],
    ["levels swapped", [keep(1, 0)], state, "INVALID_ENCODING"],
    ["level 0 twice", [keep(0, 0)], state, "INVALID_ENCODING"],
    ["level 2", [level(1, 2)], state, "INVALID_ENCODING"],
    ["height 6", [shape(1, 0, 6, 24, 127)], state, "INVALID_ENCODING"],
    ["height 4", [shape(1, 0, 4, 24, 31)], state, "INVALID_ENCODING"],
    ["n 32", [shape(1, 0, 5, 32, 63)], state, "INVALID_ENCODING"],
    ["n 0", [shape(1, 0, 5, 0, 63)], state, "INVALID_ENCODING"],
    ["lowest height 1", [shape(1, 1, 5, 24, 31)], state, "INVALID_ENCODING"],
    ["one node less", [shape(1, 0, 5, 24, 62)], state, "INVALID_ENCODING"],
    ["one node more", [shape(1, 0, 5, 24, 64)], state, "INVALID_ENCODING"],
    ["public key one byte longer", [key((value) => concat(value, Uint8Array.of(0)))], state, "INVALID_ENCODING"],
    ["public key one byte shorter", [key((value) => value.subarray(0, -1))], state, "INVALID_ENCODING"],
    ["public key of three levels", [key((value) => withByte(value, 3, 3))], state, "INVALID_ENCODING"],
    ["public key root changed", [key((value) => flip(value, value.length - 1))], state, "INVALID_ENCODING"],
    ["lower level of another LM-OTS type", [section(`02${w4}${w8}`)], state, "INVALID_ENCODING"],
    ["one level", [section(`01${w4}`)], state, "INVALID_ENCODING"],
    ["levels in another order", [section(`02${w2}${w4}`)], state, "INVALID_ENCODING"],
    ["top node changed at the capacity", [node(0, 5)], capacity, "INVALID_ENCODING"],
    ["top tree 1 changed at the capacity", [number(0, 1n), node(0, 5)], capacity, null],
  ];

  for (const [name, edits, at, code] of cases) {
    const data = sealed(cache, seed, ...edits);

    if (code === null) {
      assertLoads(pq.HSS_LMS, at, data, name);
    } else {
      throwsCode(code, () => load(pq.HSS_LMS, at, data), name);
    }
  }
});

test("XMSS^MT tree cache rejections", () => {
  const seed = range(72);

  const { state, cache } = exported(pq.XMSS_MT, MT, seed, 0x12345n);

  // 0x12360 signs with the next tree of layer 0.
  const later = stateAt(pq.XMSS_MT, MT, seed, 0x12360n);

  const capacity = stateAt(pq.XMSS_MT, MT, seed, 1n << 20n);

  const parts = new Cache(cache);

  const invalid: [string, Uint8Array][] = [
    ["layer 0 node changed", flip(cache, parts.nodesAt(3) + 100)],
    ["tag changed", flip(cache, cache.length - 7)],
    ["one byte appended", concat(cache, Uint8Array.of(0))],
    ["cut", cache.subarray(0, -1)],
    ["another key", exported(pq.XMSS_MT, MT, new Uint8Array(72), 0x12345n).cache],
  ];

  for (const [name, data] of invalid) {
    throwsCode("INVALID_ENCODING", () => load(pq.XMSS_MT, state, data), name);
  }

  // XMSS shares the layout, so its kind is a mismatch; the HSS layout misreads the OID, and no
  // other kind has a layout.
  throwsCode("ALGORITHM_MISMATCH", () => load(pq.XMSS_MT, state, withByte(cache, 1, 2)));

  for (const kind of [0, 1, 4]) {
    throwsCode("INVALID_ENCODING", () => load(pq.XMSS_MT, state, withByte(cache, 1, kind)), `kind ${kind}`);
  }

  // Another parameter set from the same seed.
  throwsCode("INVALID_ENCODING", () => load(pq.XMSS_MT, stateAt(pq.XMSS_MT, "XMSSMT-SHA2_20/2_192", seed, 7n), cache));

  // The same PUB_SEED with other secret seeds: the public parts match, the tag does not.
  const other = stateAt(pq.XMSS_MT, MT, concat(new Uint8Array(48), seed.subarray(48)), 0x12346n);

  throwsCode("INVALID_ENCODING", () => load(pq.XMSS_MT, other, cache));

  const bottom = (cache: Cache) => {
    cache.trees[3].nodes = flip(cache.trees[3].nodes, 40);
  };

  const top = (cache: Cache) => {
    cache.trees[0].nodes = flip(cache.trees[0].nodes, 9);
  };

  const cases: [string, ((parts: Cache) => void)[], Uint8Array, pq.ErrorCode | null][] = [
    ["layer 0 node changed", [bottom], state, "INVALID_ENCODING"],
    ["stale layer 0 node changed", [bottom], later, null],
    ["layers swapped", [(c) => c.trees.splice(1, 2, c.trees[2], c.trees[1])], state, "INVALID_ENCODING"],
    ["layer 2 twice", [(c) => c.trees.splice(1, 0, { ...c.trees[1] })], state, "INVALID_ENCODING"],
    ["layer 4", [(c) => (c.trees[0].level = 4)], state, "INVALID_ENCODING"],
    ["top layer only", [(c) => (c.trees = c.trees.slice(0, 1))], state, null],
    ["no top layer", [(c) => (c.trees = c.trees.slice(1))], state, null],
    ["top node changed at the capacity", [top], capacity, "INVALID_ENCODING"],
    ["top tree 1 changed at the capacity", [top, (c) => (c.trees[0].tree = 1n)], capacity, null],
    ["parameters of another set", [(c) => (c.parameters = hex("00000021"))], state, "INVALID_ENCODING"],
  ];

  for (const [name, edits, at, code] of cases) {
    const data = sealed(cache, seed, ...edits);

    if (code === null) {
      assertLoads(pq.XMSS_MT, at, data, name);
    } else {
      throwsCode(code, () => load(pq.XMSS_MT, at, data), name);
    }
  }

  assertLoads(pq.XMSS_MT, later, cache, "stale layer 0");
});

// Every change of one byte gives INVALID_ENCODING and never loads: the kind byte becomes 0 or 0x81,
// no kind at all.
test("tree cache every change", () => {
  const { state, cache } = exported(pq.HSS_LMS, TWO.slice(0, 1), range(40), 5n);

  for (let position = 0; position < cache.length; position++) {
    for (const mask of [0x01, 0x80]) {
      const data = flip(cache, position, mask);

      throwsCode("INVALID_ENCODING", () => load(pq.HSS_LMS, state, data), `byte ${position}`);
    }
  }
});

// A load with the cache computes no leaf; the trees that the next index has left are built.
test("tree cache skips the build", () => {
  const cases: [Algorithm, pq.StatefulParameters, number, bigint, bigint, number][] = [
    [pq.HSS_LMS, TWO, 40, 40n, 64n, 2],
    [pq.XMSS_MT, MT, 72, 0x12345n, 0x12360n, 4],
  ];

  for (const [algorithm, parameters, size, index, later, trees] of cases) {
    const seed = range(size);

    const { state, cache } = exported(algorithm, parameters, seed, index);

    const stale = stateAt(algorithm, parameters, seed, later);

    const leaves = (sign: () => unknown) => {
      const before = leavesComputed();

      sign();

      return leavesComputed() - before;
    };

    assert.equal(leaves(() => load(algorithm, state, cache).sign(utf8("m"))), 0, algorithm.name);

    assert.equal(leaves(() => algorithm.loadPrivateKey(new MemoryStore(state)).sign(utf8("m"))), 32 * trees);

    assert.equal(leaves(() => load(algorithm, stale, cache).sign(utf8("m"))), 32, algorithm.name);
  }
});

// A sign changes the trees, so an export from inside the store fails at once.
test("tree cache export while signing", () => {
  const store = new MemoryStore();

  const seen: unknown[] = [];

  const reentrant: pq.StateStore = {
    read: () => store.read(),
    update(previous, next) {
      if (previous !== null) {
        try {
          key.exportTreeCache();
        } catch (error) {
          seen.push(error);
        }
      }

      return store.update(previous, next);
    },
  };

  const pair = pq.HSS_LMS.generateKeyPair({ parameters: TWO.slice(0, 1), stateStore: reentrant });

  const key = pair.privateKey;

  assert.ok(pair.publicKey.verify(key.sign(utf8("m")), utf8("m")));

  assert.equal(seen.length, 1);

  assert.ok(seen[0] instanceof pq.CryptoPQError && seen[0].code === "STATE_CONFLICT");

  assert.deepEqual(new Cache(key.exportTreeCache()).publicKey, pair.publicKey.exportKey("raw"));
});

// The load that the cache saves, for one tree of height 15 (20 in a slow run): every leaf against
// the parents only.
test("tree cache load time", (t) => {
  const height = SLOW ? 20 : 15;

  const parameters: [string, string][] = [[`LMS_SHA256_M24_H${height}`, "LMOTS_SHA256_N24_W2"]];

  const { state, cache } = exported(pq.HSS_LMS, parameters, new Uint8Array(40), 0n, false);

  const start = performance.now();

  const plain = pq.HSS_LMS.loadPrivateKey(new MemoryStore(state));

  const middle = performance.now();

  const cached = load(pq.HSS_LMS, state, cache);

  const end = performance.now();

  assert.ok(cached.publicKey.equals(plain.publicKey));

  const [plainTime, cachedTime] = [middle - start, end - middle].map((time) => time.toFixed(1));

  const times = `H${height}: ${plainTime} ms without the cache, ${cachedTime} ms with it`;

  t.diagnostic(times);

  assert.ok(4 * (end - middle) < middle - start, times);
});
