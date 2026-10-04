import { concat, equal, readUint32, uint32, uint64, writeUint32 } from "./bytes.ts";
import { MerkleTree } from "./merkle.ts";
import { type FixedHash, type PrefixedHash, fixedShake256, prefixedSha256, prefixedShake256 } from "./primitives.ts";
import { block256, block256x2 } from "./sha2-rounds.ts";
import { IV_256 } from "./sha2.ts";

const W = 16;

// Chain bounds of key generation: every chain from step 0 to the end, for the largest key (n = 32).
const ZEROS: readonly number[] = new Array(67).fill(0);

const TOPS: readonly number[] = new Array(67).fill(W - 1);

const OTS = 0;

const LTREE = 1;

const HASH_TREE = 2;

const F = 0;

const H = 1;

const H_MSG = 2;

const PRF = 3;

const PRF_KEYGEN = 4;

export interface Parameters {
  readonly name: string;

  readonly oid: number;

  readonly multi: boolean;

  readonly shake: boolean;

  readonly n: number;

  readonly h: number;

  readonly d: number;

  readonly padding: number;

  readonly treeHeight: number;

  readonly length: number;

  readonly indexSize: number;

  readonly publicKeySize: number;

  readonly signatureSize: number;
}

function parameters(
  name: string,
  oid: number,
  multi: boolean,
  shake: boolean,
  n: number,
  h: number,
  d: number,
): Parameters {
  const length = 2 * n + 3;

  const indexSize = multi ? Math.ceil(h / 8) : 4;

  return Object.freeze({
    name,
    oid,
    multi,
    shake,
    n,
    h,
    d,
    padding: n === 32 ? 32 : 4,
    treeHeight: h / d,
    length,
    indexSize,
    publicKeySize: 4 + 2 * n,
    signatureSize: indexSize + n + (d * length + h) * n,
  });
}

// The SP 800-208 parameter sets with their RFC 8391 and NIST code points.
export const XMSS_SETS = new Map<string, Parameters>();

export const XMSS_MT_SETS = new Map<string, Parameters>();

const FAMILIES: [string, boolean, number, string, number, number][] = [
  ["SHA2", false, 32, "256", 0x01, 0x01],
  ["SHA2", false, 24, "192", 0x0d, 0x21],
  ["SHAKE256", true, 32, "256", 0x10, 0x29],
  ["SHAKE256", true, 24, "192", 0x13, 0x31],
];

for (const [family, shake, n, bits, baseXmss, baseMt] of FAMILIES) {
  [10, 16, 20].forEach((h, j) => {
    const p = parameters(`XMSS-${family}_${h}_${bits}`, baseXmss + j, false, shake, n, h, 1);

    XMSS_SETS.set(p.name, p);
  });

  const trees = [
    [20, 2],
    [20, 4],
    [40, 2],
    [40, 4],
    [40, 8],
    [60, 3],
    [60, 6],
    [60, 12],
  ];

  trees.forEach(([h, d], j) => {
    const p = parameters(`XMSSMT-${family}_${h}/${d}_${bits}`, baseMt + j, true, shake, n, h, d);

    XMSS_MT_SETS.set(p.name, p);
  });
}

export function byOid(sets: Map<string, Parameters>, oid: number): Parameters | null {
  for (const p of sets.values()) {
    if (p.oid === oid) {
      return p;
    }
  }

  return null;
}

function toByte(value: number, length: number): Uint8Array {
  const out = new Uint8Array(length);

  writeUint32(out, length - 4, value);

  return out;
}

function prefixed(p: Parameters, prefix: Uint8Array): PrefixedHash {
  return p.shake ? prefixedShake256(prefix) : prefixedSha256(prefix);
}

function hashFunction(p: Parameters, kind: number, key: Uint8Array, ...message: Uint8Array[]): Uint8Array {
  return prefixed(p, toByte(kind, p.padding)).digest(p.n, key, ...message);
}

function address(layer: number, tree: bigint, kind: number): Uint8Array {
  const adrs = new Uint8Array(32);

  writeUint32(adrs, 0, layer);

  adrs.set(uint64(tree), 4);

  writeUint32(adrs, 12, kind);

  return adrs;
}

function setWord(adrs: Uint8Array, word: number, value: number): void {
  writeUint32(adrs, 4 * word, value);
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);

  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }

  return out;
}

// The tweakable hashes of one key: F, H and PRF keyed by PUB_SEED, and PRF_keygen keyed by SK_SEED.
abstract class Hashes {
  readonly p: Parameters;

  readonly pubSeed: Uint8Array;

  constructor(p: Parameters, pubSeed: Uint8Array) {
    this.p = p;

    this.pubSeed = pubSeed;
  }

  abstract prf(adrs: Uint8Array): Uint8Array;

  abstract h(key: Uint8Array, left: Uint8Array, right: Uint8Array): Uint8Array;

  // SP 800-208: the secret chain values of the WOTS+ key in adrs come from
  // PRF_keygen(SK_SEED, PUB_SEED || ADRS) with the hash and key-and-mask words cleared.
  abstract secrets(adrs: Uint8Array): Uint8Array[];

  // RFC 8391 chain i of the WOTS+ key in adrs, x = F(KEY, x XOR BM) with KEY and BM from
  // PRF(PUB_SEED, ADRS), from step from[i] to step to[i], starting at starts[i], for each i.
  abstract chains(adrs: Uint8Array, starts: Uint8Array[], from: readonly number[], to: readonly number[]): Uint8Array[];

  // RFC 8391 l-tree over the WOTS+ public key values, at the l-tree address in adrs.
  ltree(values: Uint8Array[], adrs: Uint8Array): Uint8Array {
    setWord(adrs, 5, 0);

    for (let height = 0; values.length > 1; height++) {
      const paired: Uint8Array[] = [];

      for (let i = 0; i < values.length >>> 1; i++) {
        setWord(adrs, 6, i);

        paired.push(randHash(this, values[2 * i], values[2 * i + 1], adrs));
      }

      if (values.length % 2 === 1) {
        paired.push(values[values.length - 1]);
      }

      values = paired;

      setWord(adrs, 5, height + 1);
    }

    return values[0];
  }

  // The root of a tree from the node at index and its authentication path.
  root(node: Uint8Array, index: number, auth: Uint8Array, layer: number, tree: bigint): Uint8Array {
    const adrs = address(layer, tree, HASH_TREE);

    const n = this.p.n;

    for (let k = 0; k < this.p.treeHeight; k++) {
      setWord(adrs, 5, k);

      setWord(adrs, 6, index >>> (k + 1));

      const sibling = auth.subarray(k * n, (k + 1) * n);

      node = ((index >>> k) & 1) === 1 ? randHash(this, sibling, node, adrs) : randHash(this, node, sibling, adrs);
    }

    return node;
  }

  // The leaf at index of a tree: the l-tree of the WOTS+ public key.
  leaf(layer: number, tree: bigint, index: number): Uint8Array {
    const ots = address(layer, tree, OTS);

    setWord(ots, 4, index);

    const values = this.chains(ots, this.secrets(ots), ZEROS, TOPS);

    const lt = address(layer, tree, LTREE);

    setWord(lt, 4, index);

    return this.ltree(values, lt);
  }
}

// The hashes on bytes, each keeping its constant prefix absorbed once; used for SHAKE256.
class ByteHashes extends Hashes {
  readonly #h: PrefixedHash;

  readonly #prf: PrefixedHash;

  readonly #keygen: PrefixedHash | null;

  readonly #chainPrf: FixedHash;

  readonly #chainF: FixedHash;

  readonly #mask: Uint8Array;

  constructor(p: Parameters, pubSeed: Uint8Array, skSeed: Uint8Array | null) {
    super(p, pubSeed);

    this.#h = prefixed(p, toByte(H, p.padding));

    this.#prf = prefixed(p, concat(toByte(PRF, p.padding), pubSeed));

    this.#keygen = skSeed === null ? null : prefixed(p, concat(toByte(PRF_KEYGEN, p.padding), skSeed));

    this.#chainPrf = fixedShake256(p.padding + p.n + 32, concat(toByte(PRF, p.padding), pubSeed));

    this.#chainF = fixedShake256(p.padding + 2 * p.n, toByte(F, p.padding));

    this.#mask = new Uint8Array(p.n);
  }

  prf(adrs: Uint8Array): Uint8Array {
    return this.#prf.digest(this.p.n, adrs);
  }

  secrets(adrs: Uint8Array): Uint8Array[] {
    const secrets: Uint8Array[] = [];

    for (let i = 0; i < this.p.length; i++) {
      setWord(adrs, 5, i);

      setWord(adrs, 6, 0);

      setWord(adrs, 7, 0);

      secrets.push((this.#keygen as PrefixedHash).digest(this.p.n, this.pubSeed, adrs));
    }

    return secrets;
  }

  h(key: Uint8Array, left: Uint8Array, right: Uint8Array): Uint8Array {
    return this.#h.digest(this.p.n, key, left, right);
  }

  chains(adrs: Uint8Array, starts: Uint8Array[], from: readonly number[], to: readonly number[]): Uint8Array[] {
    return starts.map((start, i) => {
      setWord(adrs, 5, i);

      return this.#chain(start, from[i], to[i] - from[i], adrs);
    });
  }

  // PRF writes the key straight into the F message, and F writes the new value over its own input.
  #chain(x: Uint8Array, start: number, steps: number, adrs: Uint8Array): Uint8Array {
    if (steps === 0) {
      return x;
    }

    const { n, padding } = this.p;

    const prf = this.#chainPrf;

    const f = this.#chainF;

    const mask = this.#mask;

    const at = padding + n;

    const key = f.message.subarray(padding, padding + n);

    const value = f.message.subarray(padding + n, padding + 2 * n);

    prf.message.set(adrs, at);

    value.set(x);

    for (let k = start; k < start + steps; k++) {
      writeUint32(prf.message, at + 24, k);

      writeUint32(prf.message, at + 28, 0);

      prf.digest(key);

      writeUint32(prf.message, at + 28, 1);

      prf.digest(mask);

      for (let i = 0; i < n; i++) {
        value[i] ^= mask[i];
      }

      f.digest(value);
    }

    return value.slice();
  }
}

// A SHA-256 message of whole words and fixed length, rewritten in place between digests; its constant
// leading blocks are compressed once. Every field of the XMSS hashes fills whole words.
class Message {
  readonly w: Int32Array;

  readonly #initial = IV_256.slice();

  readonly #from: number;

  constructor(prefix: Uint8Array, length: number) {
    const blocks = Math.ceil((length + 9) / 64);

    this.w = new Int32Array(16 * blocks);

    putWords(this.w, 0, prefix);

    this.w[length >>> 2] = 0x80000000;

    this.w[16 * blocks - 1] = 8 * length;

    this.#from = 16 * Math.floor(prefix.length / 64);

    for (let offset = 0; offset < this.#from; offset += 16) {
      block256(this.#initial, this.w, offset, this.#initial);
    }
  }

  // The digest into out[0 .. 8); out may be a view into another message.
  digest(out: Int32Array): void {
    block256(this.#initial, this.w, this.#from, out);

    for (let offset = this.#from + 16; offset < this.w.length; offset += 16) {
      block256(out, this.w, offset, out);
    }
  }

  // Digests a and b, two messages of the same shape, at once; with only a, digests it alone.
  static pair(a: Message, aOut: Int32Array, b: Message | null, bOut: Int32Array): void {
    if (b === null) {
      a.digest(aOut);

      return;
    }

    block256x2(a.#initial, a.w, a.#from, aOut, b.#initial, b.w, b.#from, bOut);

    for (let offset = a.#from + 16; offset < a.w.length; offset += 16) {
      block256x2(aOut, a.w, offset, aOut, bOut, b.w, offset, bOut);
    }
  }
}

function putWords(w: Int32Array, at: number, data: Uint8Array): void {
  for (let k = 0; k < data.length >>> 2; k++) {
    w[at + k] = readUint32(data, 4 * k);
  }
}

// The messages of one lane of Sha256Hashes, and a view of the place in F where PRF writes KEY.
interface Lane {
  readonly prf: Message;

  readonly f: Message;

  readonly secret: Message;

  readonly h: Message;

  readonly fKey: Int32Array;

  readonly mask: Int32Array;

  readonly mask1: Int32Array;

  readonly value: Int32Array;
}

// The SHA-256 hashes on words. Leaves, the hot path of key generation and of the trees signing
// rebuilds, run two WOTS+ chains, and then two l-tree nodes, at once through block256x2.
class Sha256Hashes extends Hashes {
  readonly #a: Lane;

  readonly #b: Lane;

  // Word offsets of ADRS in the PRF and PRF_keygen messages, and of the inputs of F and H.
  readonly #prfAt: number;

  readonly #secretAt: number;

  readonly #inputAt: number;

  readonly #values: Int32Array;

  readonly #sibling = new Int32Array(8);

  constructor(p: Parameters, pubSeed: Uint8Array, skSeed: Uint8Array | null) {
    super(p, pubSeed);

    const { n, padding } = p;

    const key = padding >>> 2;

    const lane = (): Lane => {
      const f = new Message(toByte(F, padding), padding + 2 * n);

      const h = new Message(toByte(H, padding), padding + 3 * n);

      return {
        prf: new Message(concat(toByte(PRF, padding), pubSeed), padding + n + 32),
        f,
        secret: new Message(
          concat(toByte(PRF_KEYGEN, padding), skSeed ?? new Uint8Array(n), pubSeed),
          padding + 2 * n + 32,
        ),
        h,
        fKey: f.w.subarray(key, key + 8),
        mask: new Int32Array(8),
        mask1: new Int32Array(8),
        value: new Int32Array(8),
      };
    };

    this.#a = lane();

    this.#b = lane();

    this.#prfAt = (padding + n) >>> 2;

    this.#secretAt = (padding + 2 * n) >>> 2;

    this.#inputAt = (padding + n) >>> 2;

    this.#values = new Int32Array(p.length * (n >>> 2));
  }

  prf(adrs: Uint8Array): Uint8Array {
    const lane = this.#a;

    putWords(lane.prf.w, this.#prfAt, adrs);

    lane.prf.digest(lane.mask);

    return this.#bytes(lane.mask);
  }

  h(key: Uint8Array, left: Uint8Array, right: Uint8Array): Uint8Array {
    const lane = this.#a;

    const n = this.p.n;

    putWords(lane.h.w, this.p.padding >>> 2, key);

    putWords(lane.h.w, this.#inputAt, left);

    putWords(lane.h.w, this.#inputAt + (n >>> 2), right);

    lane.h.digest(lane.value);

    return this.#bytes(lane.value);
  }

  secrets(adrs: Uint8Array): Uint8Array[] {
    const at = this.#secretAt;

    const a = this.#a;

    const b = this.#b;

    const secrets: Uint8Array[] = [];

    putWords(a.secret.w, at, adrs);

    putWords(b.secret.w, at, adrs);

    for (let c = 0; c < this.p.length; c += 2) {
      const pair = c + 1 < this.p.length ? b : null;

      for (const [lane, chain] of [
        [a, c],
        [b, c + 1],
      ] as const) {
        lane.secret.w[at + 5] = chain;

        lane.secret.w[at + 6] = 0;

        lane.secret.w[at + 7] = 0;
      }

      Message.pair(a.secret, a.value, pair && b.secret, b.value);

      secrets.push(this.#bytes(a.value));

      if (pair !== null) {
        secrets.push(this.#bytes(b.value));
      }
    }

    return secrets;
  }

  // Two lanes take the chains in turn: when the chain in one lane ends, the next waiting chain takes
  // its place, so the lanes stay busy whatever the lengths.
  chains(
    adrs: Uint8Array,
    starts: Uint8Array[],
    from: readonly number[],
    to: readonly number[],
  ): Uint8Array[] {
    const at = this.#prfAt;

    const a = this.#a;

    const b = this.#b;

    const ends = starts.slice();

    let next = 0;

    // The chain in each lane, or -1, and its next step.
    let i = -1;

    let j = 0;

    let k = -1;

    let l = 0;

    putWords(a.prf.w, at, adrs);

    putWords(b.prf.w, at, adrs);

    for (;;) {
      for (; i < 0 && next < starts.length; next++) {
        if (from[next] < to[next]) {
          i = next;

          j = from[next];

          putWords(a.value, 0, starts[i]);

          a.prf.w[at + 5] = i;
        }
      }

      for (; k < 0 && next < starts.length; next++) {
        if (from[next] < to[next]) {
          k = next;

          l = from[next];

          putWords(b.value, 0, starts[k]);

          b.prf.w[at + 5] = k;
        }
      }

      if (i < 0 && k < 0) {
        return ends;
      }

      if (i >= 0) {
        this.#step(a, j, k >= 0 ? b : null, l);
      } else {
        this.#step(b, l, null, 0);
      }

      if (i >= 0 && ++j === to[i]) {
        ends[i] = this.#bytes(a.value);

        i = -1;
      }

      if (k >= 0 && ++l === to[k]) {
        ends[k] = this.#bytes(b.value);

        k = -1;
      }
    }
  }

  override root(node: Uint8Array, index: number, auth: Uint8Array, layer: number, tree: bigint): Uint8Array {
    const n = this.p.n;

    const a = this.#a;

    const sibling = this.#sibling;

    setAddress(a.prf.w, this.#prfAt, layer, Number(tree >> 32n), Number(tree & 0xffffffffn), HASH_TREE, 0);

    putWords(a.value, 0, node);

    for (let k = 0; k < this.p.treeHeight; k++) {
      a.prf.w[this.#prfAt + 5] = k;

      a.prf.w[this.#prfAt + 6] = index >>> (k + 1);

      for (let i = 0; i < n >>> 2; i++) {
        sibling[i] = readUint32(auth, k * n + 4 * i);
      }

      if (((index >>> k) & 1) === 1) {
        this.#input(a, sibling, 0, a.value, 0);
      } else {
        this.#input(a, a.value, 0, sibling, 0);
      }

      this.#randHash(a, null);
    }

    return this.#bytes(a.value);
  }

  override ltree(values: Uint8Array[], adrs: Uint8Array): Uint8Array {
    const count = this.p.n >>> 2;

    values.forEach((value, i) => putWords(this.#values, i * count, value));

    return this.#ltree(readUint32(adrs, 0), readUint32(adrs, 4), readUint32(adrs, 8), readUint32(adrs, 16));
  }

  override leaf(layer: number, tree: bigint, index: number): Uint8Array {
    const { n, length } = this.p;

    const count = n >>> 2;

    const a = this.#a;

    const b = this.#b;

    const high = Number(tree >> 32n);

    const low = Number(tree & 0xffffffffn);

    const values = this.#values;

    for (const lane of [a, b]) {
      setAddress(lane.secret.w, this.#secretAt, layer, high, low, OTS, index);

      setAddress(lane.prf.w, this.#prfAt, layer, high, low, OTS, index);
    }

    for (let c = 0; c < length; c += 2) {
      const pair = c + 1 < length ? b : null;

      a.secret.w[this.#secretAt + 5] = c;

      b.secret.w[this.#secretAt + 5] = c + 1;

      Message.pair(a.secret, a.value, pair && b.secret, b.value);

      a.prf.w[this.#prfAt + 5] = c;

      b.prf.w[this.#prfAt + 5] = c + 1;

      for (let k = 0; k < W - 1; k++) {
        this.#step(a, k, pair, k);
      }

      values.set(a.value.subarray(0, count), c * count);

      if (pair !== null) {
        values.set(b.value.subarray(0, count), (c + 1) * count);
      }
    }

    return this.#ltree(layer, high, low, index);
  }

  // One chain step of lane a at hash address k, and of lane b, if given, at hash address l.
  #step(a: Lane, k: number, b: Lane | null, l: number): void {
    a.prf.w[this.#prfAt + 6] = k;

    if (b !== null) {
      b.prf.w[this.#prfAt + 6] = l;
    }

    this.#prfWords(a, b, 7, 0);

    Message.pair(a.prf, a.fKey, b && b.prf, (b ?? a).fKey);

    this.#prfWords(a, b, 7, 1);

    Message.pair(a.prf, a.mask, b && b.prf, (b ?? a).mask);

    this.#maskInput(a.f, a.value, a.mask);

    if (b !== null) {
      this.#maskInput(b.f, b.value, b.mask);
    }

    Message.pair(a.f, a.value, b && b.f, (b ?? a).value);
  }

  // RFC 8391 l-tree over the chain ends in #values, in place, two nodes of a level at a time.
  #ltree(layer: number, high: number, low: number, index: number): Uint8Array {
    const count = this.p.n >>> 2;

    const values = this.#values;

    const a = this.#a;

    const b = this.#b;

    setAddress(a.prf.w, this.#prfAt, layer, high, low, LTREE, index);

    setAddress(b.prf.w, this.#prfAt, layer, high, low, LTREE, index);

    for (let length = this.p.length, height = 0; length > 1; length = (length + 1) >>> 1, height++) {
      const half = length >>> 1;

      for (let i = 0; i < half; i += 2) {
        const pair = i + 1 < half ? b : null;

        this.#prfWords(a, pair, 5, height);

        a.prf.w[this.#prfAt + 6] = i;

        b.prf.w[this.#prfAt + 6] = i + 1;

        this.#input(a, values, 2 * i * count, values, (2 * i + 1) * count);

        if (pair !== null) {
          this.#input(b, values, (2 * i + 2) * count, values, (2 * i + 3) * count);
        }

        this.#randHash(a, pair);

        values.set(a.value.subarray(0, count), i * count);

        if (pair !== null) {
          values.set(b.value.subarray(0, count), (i + 1) * count);
        }
      }

      if (length % 2 === 1) {
        values.copyWithin(half * count, (length - 1) * count, length * count);
      }
    }

    return this.#bytes(values);
  }

  // RAND_HASH on the inputs in the H message of lane a, and of lane b if given, with words 0 to 6 of
  // their PRF addresses set: KEY and the two masks from PRF, the masks applied, then H.
  #randHash(a: Lane, b: Lane | null): void {
    this.#prfWords(a, b, 7, 0);

    Message.pair(a.prf, a.value, b && b.prf, (b ?? a).value);

    this.#prfWords(a, b, 7, 1);

    Message.pair(a.prf, a.mask, b && b.prf, (b ?? a).mask);

    this.#prfWords(a, b, 7, 2);

    Message.pair(a.prf, a.mask1, b && b.prf, (b ?? a).mask1);

    this.#applyMasks(a);

    if (b !== null) {
      this.#applyMasks(b);
    }

    Message.pair(a.h, a.value, b && b.h, (b ?? a).value);
  }

  // Writes KEY, held in the lane's value, into its H message and masks the two inputs.
  #applyMasks(lane: Lane): void {
    const count = this.p.n >>> 2;

    const key = this.p.padding >>> 2;

    const input = this.#inputAt;

    for (let k = 0; k < count; k++) {
      lane.h.w[key + k] = lane.value[k];

      lane.h.w[input + k] ^= lane.mask[k];

      lane.h.w[input + count + k] ^= lane.mask1[k];
    }
  }

  // Puts the left and right inputs of RAND_HASH, count words each, into the H message of lane.
  #input(lane: Lane, left: Int32Array, leftOffset: number, right: Int32Array, rightOffset: number): void {
    const count = this.p.n >>> 2;

    const input = this.#inputAt;

    for (let k = 0; k < count; k++) {
      lane.h.w[input + k] = left[leftOffset + k];

      lane.h.w[input + count + k] = right[rightOffset + k];
    }
  }

  #prfWords(a: Lane, b: Lane | null, word: number, value: number): void {
    a.prf.w[this.#prfAt + word] = value;

    if (b !== null) {
      b.prf.w[this.#prfAt + word] = value;
    }
  }

  // Writes an n-byte input of F, the words of source XOR mask.
  #maskInput(message: Message, source: Int32Array, mask: Int32Array): void {
    const at = this.#inputAt;

    for (let k = 0; k < this.p.n >>> 2; k++) {
      message.w[at + k] = source[k] ^ mask[k];
    }
  }

  #bytes(words: Int32Array): Uint8Array {
    const out = new Uint8Array(this.p.n);

    for (let k = 0; k < this.p.n >>> 2; k++) {
      writeUint32(out, 4 * k, words[k]);
    }

    return out;
  }
}

// Words 0 to 4 of ADRS at w[at]; words 5 to 7 start cleared.
function setAddress(
  w: Int32Array,
  at: number,
  layer: number,
  high: number,
  low: number,
  type: number,
  word4: number,
): void {
  w[at] = layer;

  w[at + 1] = high;

  w[at + 2] = low;

  w[at + 3] = type;

  w[at + 4] = word4;

  w[at + 5] = 0;

  w[at + 6] = 0;

  w[at + 7] = 0;
}

function createHashes(p: Parameters, pubSeed: Uint8Array, skSeed: Uint8Array | null): Hashes {
  return p.shake ? new ByteHashes(p, pubSeed, skSeed) : new Sha256Hashes(p, pubSeed, skSeed);
}

function wotsDigits(message: Uint8Array): number[] {
  const digits: number[] = [];

  for (const byte of message) {
    digits.push(byte >>> 4, byte & 0x0f);
  }

  let checksum = 0;

  for (const digit of digits) {
    checksum += W - 1 - digit;
  }

  checksum <<= 4;

  return digits.concat([(checksum >>> 12) & 0x0f, (checksum >>> 8) & 0x0f, (checksum >>> 4) & 0x0f]);
}

function wotsSign(hashes: Hashes, message: Uint8Array, adrs: Uint8Array): Uint8Array[] {
  return hashes.chains(adrs, hashes.secrets(adrs), ZEROS, wotsDigits(message));
}

function wotsPublicFromSignature(
  hashes: Hashes,
  signature: Uint8Array,
  message: Uint8Array,
  adrs: Uint8Array,
): Uint8Array[] {
  const n = hashes.p.n;

  const starts = Array.from({ length: hashes.p.length }, (_, i) => signature.subarray(i * n, (i + 1) * n));

  return hashes.chains(adrs, starts, wotsDigits(message), TOPS);
}

function randHash(hashes: Hashes, left: Uint8Array, right: Uint8Array, adrs: Uint8Array): Uint8Array {
  setWord(adrs, 7, 0);

  const key = hashes.prf(adrs);

  setWord(adrs, 7, 1);

  const mask0 = hashes.prf(adrs);

  setWord(adrs, 7, 2);

  const mask1 = hashes.prf(adrs);

  return hashes.h(key, xor(left, mask0), xor(right, mask1));
}

function subtree(hashes: Hashes, layer: number, tree: bigint): MerkleTree {
  const combine = (z: number, j: number, left: Uint8Array, right: Uint8Array) => {
    const adrs = address(layer, tree, HASH_TREE);

    setWord(adrs, 5, z);

    setWord(adrs, 6, j);

    return randHash(hashes, left, right, adrs);
  };

  return new MerkleTree(hashes.p.treeHeight, hashes.p.n, (index) => hashes.leaf(layer, tree, index), combine);
}

function messageDigest(p: Parameters, r: Uint8Array, root: Uint8Array, index: bigint, message: Uint8Array): Uint8Array {
  const indexBytes = new Uint8Array(p.n);

  indexBytes.set(uint64(index), p.n - 8);

  return hashFunction(p, H_MSG, concat(r, root, indexBytes), message);
}

function readIndex(data: Uint8Array): bigint {
  let value = 0n;

  for (const byte of data) {
    value = (value << 8n) | BigInt(byte);
  }

  return value;
}

export function verify(p: Parameters, publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const n = p.n;

  if (publicKey.length !== p.publicKeySize || signature.length !== p.signatureSize) {
    return false;
  }

  if ((((publicKey[0] << 24) | (publicKey[1] << 16) | (publicKey[2] << 8) | publicKey[3]) >>> 0) !== p.oid) {
    return false;
  }

  const root = publicKey.subarray(4, 4 + n);

  const hashes = createHashes(p, publicKey.subarray(4 + n), null);

  let index = readIndex(signature.subarray(0, p.indexSize));

  if (index >> BigInt(p.h) !== 0n) {
    return false;
  }

  const r = signature.subarray(p.indexSize, p.indexSize + n);

  let node = messageDigest(p, r, root, index, message);

  let offset = p.indexSize + n;

  const mask = (1n << BigInt(p.treeHeight)) - 1n;

  for (let layer = 0; layer < p.d; layer++) {
    const leafIndex = Number(index & mask);

    index >>= BigInt(p.treeHeight);

    const ots = address(layer, index, OTS);

    setWord(ots, 4, leafIndex);

    const values = wotsPublicFromSignature(hashes, signature.subarray(offset, offset + p.length * n), node, ots);

    offset += p.length * n;

    const lt = address(layer, index, LTREE);

    setWord(lt, 4, leafIndex);

    const auth = signature.subarray(offset, offset + p.treeHeight * n);

    node = hashes.root(hashes.ltree(values, lt), leafIndex, auth, layer, index);

    offset += p.treeHeight * n;
  }

  return equal(node, root);
}

// The signing side of an XMSS or XMSS^MT key, with one cached tree per layer.
export class Xmss {
  readonly p: Parameters;

  readonly root: Uint8Array;

  readonly #skPrf: Uint8Array;

  readonly #hashes: Hashes;

  readonly #trees = new Map<number, [bigint, MerkleTree]>();

  // The part of the signature from each layer above the bottom one, which depends only on the index
  // shifted right by layer * h' bits: it is kept until that value changes, as HSS keeps its signed
  // child keys, and signing the same root again with the same WOTS+ key gives the same bytes.
  readonly #signed = new Map<number, [bigint, Uint8Array]>();

  constructor(p: Parameters, skSeed: Uint8Array, skPrf: Uint8Array, pubSeed: Uint8Array) {
    this.p = p;

    this.#skPrf = skPrf;

    this.#hashes = createHashes(p, pubSeed, skSeed);

    this.root = this.#tree(p.d - 1, 0n).root;
  }

  get publicKey(): Uint8Array {
    return concat(uint32(this.p.oid), this.root, this.#hashes.pubSeed);
  }

  #tree(layer: number, tree: bigint): MerkleTree {
    const cached = this.#trees.get(layer);

    if (cached !== undefined && cached[0] === tree) {
      return cached[1];
    }

    const merkle = subtree(this.#hashes, layer, tree);

    this.#trees.set(layer, [tree, merkle]);

    return merkle;
  }

  sign(index: bigint, message: Uint8Array): Uint8Array {
    const p = this.p;

    const indexBytes = new Uint8Array(32);

    indexBytes.set(uint64(index), 24);

    const r = hashFunction(p, PRF, this.#skPrf, indexBytes);

    const node = messageDigest(p, r, this.root, index, message);

    const out = [uint64(index).subarray(8 - p.indexSize), r, this.#layer(0, index, node)];

    for (let layer = 1; layer < p.d; layer++) {
      out.push(this.#upper(layer, index >> BigInt(layer * p.treeHeight)));
    }

    return concat(...out);
  }

  // One layer's part of a signature: the WOTS+ signature of node by leaf (at mod 2^h') of tree
  // (at >> h') on that layer, then the authentication path of that leaf.
  #layer(layer: number, at: bigint, node: Uint8Array): Uint8Array {
    const p = this.p;

    const leafIndex = Number(at & ((1n << BigInt(p.treeHeight)) - 1n));

    const tree = at >> BigInt(p.treeHeight);

    const ots = address(layer, tree, OTS);

    setWord(ots, 4, leafIndex);

    return concat(...wotsSign(this.#hashes, node, ots), this.#tree(layer, tree).authPath(leafIndex));
  }

  // An upper layer's part, which signs the root of tree (at) on the layer below. Layers are visited
  // from the bottom up, so that tree is already cached whenever the part has to be made again.
  #upper(layer: number, at: bigint): Uint8Array {
    const cached = this.#signed.get(layer);

    if (cached !== undefined && cached[0] === at) {
      return cached[1];
    }

    const part = this.#layer(layer, at, this.#tree(layer - 1, at).root);

    this.#signed.set(layer, [at, part]);

    return part;
  }
}
