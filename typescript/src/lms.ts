import { concat, readUint32, uint32, writeUint32 } from "./bytes.ts";
import { Keccak } from "./keccak.ts";
import { type CachedLevels, type CachedTree, MerkleTree, type TreeHashes } from "./merkle.ts";
import {
  type FixedHash,
  blocks,
  copyWords,
  fixedShake256,
  loadWords,
  messageBytes,
  messageWords,
  sha256,
  shake256,
  storeWords,
} from "./primitives.ts";
import { block256, block256x2 } from "./sha2-rounds.ts";
import { IV_256, Sha256, wipeSha2Lanes } from "./sha2.ts";

// The domain separators u16(D_PBLC), u16(D_LEAF) and u16(D_INTR) as they end the 22-byte header of a
// SHA-256 message in the high half of word 5.
const D_PBLC_WORD = 0x8080 << 16;

const D_LEAF_WORD = 0x8282 << 16;

const D_INTR_WORD = 0x8383 << 16;

// Pseudorandom values derived from a tree's SEED (RFC 8554, Appendix A, and the convention of the
// hash-sigs reference used by the RFC 8554 and RFC 9858 test cases): the signature randomizer C,
// and the SEED and I of a child tree. Chain indices are below 0xFFFD.
const RANDOMIZER = 0xfffd;

const CHILD_SEED = 0xfffe;

const CHILD_I = 0xffff;

export interface OtsType {
  readonly code: number;

  readonly name: string;

  readonly shake: boolean;

  readonly n: number;

  readonly w: number;

  readonly p: number;

  readonly ls: number;

  readonly signatureSize: number;
}

export interface LmsType {
  readonly code: number;

  readonly name: string;

  readonly shake: boolean;

  readonly m: number;

  readonly h: number;

  readonly publicKeySize: number;
}

function otsType(code: number, name: string, shake: boolean, n: number, w: number): OtsType {
  const u = Math.ceil((8 * n) / w);

  const v = Math.ceil((32 - Math.clz32(((1 << w) - 1) * u)) / w);

  return Object.freeze({ code, name, shake, n, w, p: u + v, ls: 16 - v * w, signatureSize: 4 + n * (u + v + 1) });
}

const FAMILIES: [boolean, number, string, string][] = [
  [false, 32, "SHA256_N32", "SHA256_M32"],
  [false, 24, "SHA256_N24", "SHA256_M24"],
  [true, 32, "SHAKE_N32", "SHAKE_M32"],
  [true, 24, "SHAKE_N24", "SHAKE_M24"],
];

export const OTS_TYPES = new Map<number, OtsType>();

export const LMS_TYPES = new Map<number, LmsType>();

FAMILIES.forEach(([shake, n, ots, lms], index) => {
  [1, 2, 4, 8].forEach((w, j) => {
    const type = otsType(1 + 4 * index + j, `LMOTS_${ots}_W${w}`, shake, n, w);

    OTS_TYPES.set(type.code, type);
  });

  [5, 10, 15, 20, 25].forEach((h, j) => {
    const code = 5 + 5 * index + j;

    LMS_TYPES.set(code, Object.freeze({ code, name: `LMS_${lms}_H${h}`, shake, m: n, h, publicKeySize: 24 + n }));
  });
});

export const OTS_BY_NAME = new Map([...OTS_TYPES.values()].map((type) => [type.name, type]));

export const LMS_BY_NAME = new Map([...LMS_TYPES.values()].map((type) => [type.name, type]));

// Every chain's first step and, for each Winternitz parameter, its last, as many as the longest
// LM-OTS signature has chains; and the digits of a message hash, which are public.
const LONGEST = Math.max(...Array.from(OTS_TYPES.values(), (type) => type.p));

const ZEROS = new Uint8Array(LONGEST);

const TOPS = new Map([1, 2, 4, 8].map((w) => [w, new Uint8Array(LONGEST).fill((1 << w) - 1)] as const));

const DIGITS = new Uint8Array(LONGEST);

function uint16(value: number): Uint8Array {
  return Uint8Array.of(value >>> 8, value & 0xff);
}

function digest(shake: boolean, n: number, ...parts: Uint8Array[]): Uint8Array {
  return shake ? shake256(n, ...parts) : sha256(...parts).slice(0, n);
}

function derive(shake: boolean, n: number, id: Uint8Array, q: number, index: number, seed: Uint8Array): Uint8Array {
  return digest(shake, n, id, uint32(q), uint16(index), Uint8Array.of(0xff), seed);
}

// H(I || u32(q) || u16(D_MESG) || C || message), C being the n bytes at c[at]; its first n bytes are
// the message hash Q.
function messageHash(
  t: OtsType,
  id: Uint8Array,
  q: number,
  c: Uint8Array,
  at: number,
  message: Uint8Array,
): Uint8Array {
  const head = new Uint8Array(22 + t.n);

  head.set(id);

  writeUint32(head, 16, q);

  head[20] = 0x81;

  head[21] = 0x81;

  for (let i = 0; i < t.n; i++) {
    head[22 + i] = c[at + i];
  }

  if (t.shake) {
    const sponge = new Keccak(136, 0x1f);

    sponge.update(head);

    sponge.update(message);

    return sponge.read(t.n);
  }

  const engine = new Sha256(IV_256, 32);

  engine.update(head);

  engine.update(message);

  return engine.digest();
}

// The Winternitz digits of the message hash Q, then of its checksum (RFC 8554, 4.4), into out[0 .. p).
function digits(t: OtsType, qHash: Uint8Array, out: Uint8Array): void {
  const mask = (1 << t.w) - 1;

  const u = (8 * t.n) / t.w;

  let checksum = 0;

  for (let i = 0; i < u; i++) {
    const bit = i * t.w;

    out[i] = (qHash[bit >>> 3] >>> (8 - (bit & 7) - t.w)) & mask;

    checksum += mask - out[i];
  }

  const tail = (checksum << t.ls) & 0xffff;

  for (let i = u; i < t.p; i++) {
    out[i] = (tail >>> (16 - (i - u + 1) * t.w)) & mask;
  }
}

// The hashes of one tree (one I): the LM-OTS chains of one leaf at a time, and the nodes. Every hash
// writes its n bytes where the caller wants them.
interface Hashes {
  // H(I || u32(q) || u16(i) || u8(0xFF) || SEED) into out at offset: a chain start, or C.
  prf(q: number, i: number, seed: Uint8Array, out: Uint8Array, offset: number): void;

  // Sets each chain's value to its start.
  start(q: number, seed: Uint8Array): void;

  // Takes the chain values from data, n bytes each from offset on.
  load(data: Uint8Array, offset: number): void;

  // Advances chain i with x = H(I || u32(q) || u16(i) || u8(j) || x) for j from from[i] to to[i] - 1.
  run(q: number, from: ArrayLike<number>, to: ArrayLike<number>): void;

  store(out: Uint8Array, offset: number): void;

  // K = H(I || u32(q) || u16(D_PBLC) || the chain values), then the leaf node r over it,
  // H(I || u32(r) || u16(D_LEAF) || K), into out at offset.
  leaf(r: number, q: number, out: Uint8Array, offset: number): void;

  // The count interior nodes from r on, H(I || u32(r) || u16(D_INTR) || left || right), from their
  // children in order from children[from] on, into out from offset on; out may hold the children.
  combine(r: number, count: number, children: Uint8Array, from: number, out: Uint8Array, offset: number): void;
}

// Words 5 onward of a chain block: u16(i) and u8(j) in the top three bytes of prefix, then count words
// of x, which starts at byte 23 and so is shifted by three bytes, then the 0x80 padding byte.
function chainWords(w: Int32Array, prefix: number, x: Int32Array, count: number): void {
  w[5] = prefix | (x[0] >>> 24);

  for (let k = 1; k < count; k++) {
    w[5 + k] = (x[k - 1] << 8) | (x[k] >>> 24);
  }

  w[5 + count] = (x[count - 1] << 8) | 0x80;
}

// The hashes on SHA-256 words: every chain step, chain start and leaf is one block and every interior
// node two, and two chains, or two nodes, advance at once through block256x2, the next waiting chain
// taking over a lane as soon as its chain ends.
class Sha256Hashes implements Hashes {
  readonly #t: OtsType;

  readonly #a = new Int32Array(16);

  readonly #b = new Int32Array(16);

  readonly #s = new Int32Array(8);

  readonly #u = new Int32Array(8);

  readonly #seed: Int32Array;

  readonly #values: Int32Array;

  readonly #k: Int32Array;

  readonly #leaf: Int32Array;

  readonly #nodeA: Int32Array;

  readonly #nodeB: Int32Array;

  constructor(t: OtsType, id: Uint8Array) {
    const count = t.n >>> 2;

    this.#t = t;

    this.#seed = new Int32Array(count);

    this.#values = new Int32Array(t.p * count);

    this.#k = blocks(false, 0, t.p * t.n);

    this.#leaf = blocks(false, 0, t.n);

    this.#nodeA = blocks(false, 0, 2 * t.n);

    this.#nodeB = blocks(false, 0, 2 * t.n);

    for (const w of [this.#a, this.#b, this.#k, this.#leaf, this.#nodeA, this.#nodeB]) {
      loadWords(id, 0, 4, w);
    }

    this.#a[15] = 8 * (23 + t.n);

    this.#b[15] = 8 * (23 + t.n);
  }

  prf(q: number, i: number, seed: Uint8Array, out: Uint8Array, offset: number): void {
    const count = this.#t.n >>> 2;

    const a = this.#a;

    loadWords(seed, 0, count, this.#seed);

    a[4] = q;

    chainWords(a, (i << 16) | 0xff00, this.#seed, count);

    block256(IV_256, a, 0, this.#s);

    storeWords(this.#s, count, out, offset);
  }

  start(q: number, seed: Uint8Array): void {
    const { p, n } = this.#t;

    const count = n >>> 2;

    const a = this.#a;

    const b = this.#b;

    const s = this.#s;

    const u = this.#u;

    loadWords(seed, 0, count, this.#seed);

    a[4] = q;

    b[4] = q;

    for (let i = 0; i < p; i += 2) {
      chainWords(a, (i << 16) | 0xff00, this.#seed, count);

      if (i + 1 < p) {
        chainWords(b, ((i + 1) << 16) | 0xff00, this.#seed, count);

        block256x2(IV_256, a, 0, s, IV_256, b, 0, u);

        copyWords(u, 0, this.#values, (i + 1) * count, count);
      } else {
        block256(IV_256, a, 0, s);
      }

      copyWords(s, 0, this.#values, i * count, count);
    }
  }

  load(data: Uint8Array, offset: number): void {
    loadWords(data, offset, this.#values.length, this.#values);
  }

  run(q: number, from: ArrayLike<number>, to: ArrayLike<number>): void {
    const { p, n } = this.#t;

    const count = n >>> 2;

    const values = this.#values;

    const a = this.#a;

    const b = this.#b;

    const s = this.#s;

    const u = this.#u;

    let next = 0;

    // The chain in each lane, or -1, and its next step.
    let i = -1;

    let j = 0;

    let k = -1;

    let l = 0;

    a[4] = q;

    b[4] = q;

    for (;;) {
      for (; i < 0 && next < p; next++) {
        if (from[next] < to[next]) {
          i = next;

          j = from[next];

          copyWords(values, i * count, s, 0, count);
        }
      }

      for (; k < 0 && next < p; next++) {
        if (from[next] < to[next]) {
          k = next;

          l = from[next];

          copyWords(values, k * count, u, 0, count);
        }
      }

      if (i < 0 && k < 0) {
        return;
      }

      if (i >= 0) {
        chainWords(a, (i << 16) | (j << 8), s, count);
      }

      if (k >= 0) {
        chainWords(b, (k << 16) | (l << 8), u, count);
      }

      if (i >= 0 && k >= 0) {
        block256x2(IV_256, a, 0, s, IV_256, b, 0, u);
      } else if (i >= 0) {
        block256(IV_256, a, 0, s);
      } else {
        block256(IV_256, b, 0, u);
      }

      if (i >= 0 && ++j === to[i]) {
        copyWords(s, 0, values, i * count, count);

        i = -1;
      }

      if (k >= 0 && ++l === to[k]) {
        copyWords(u, 0, values, k * count, count);

        k = -1;
      }
    }
  }

  store(out: Uint8Array, offset: number): void {
    storeWords(this.#values, this.#values.length, out, offset);
  }

  leaf(r: number, q: number, out: Uint8Array, offset: number): void {
    const count = this.#t.n >>> 2;

    const k = this.#k;

    const leaf = this.#leaf;

    const s = this.#s;

    k[4] = q;

    messageWords(k, D_PBLC_WORD, this.#values, 0, this.#values.length);

    block256(IV_256, k, 0, s);

    for (let at = 16; at < k.length; at += 16) {
      block256(s, k, at, s);
    }

    leaf[4] = r;

    messageWords(leaf, D_LEAF_WORD, s, 0, count);

    block256(IV_256, leaf, 0, s);

    storeWords(s, count, out, offset);
  }

  combine(r: number, count: number, children: Uint8Array, from: number, out: Uint8Array, offset: number): void {
    const n = this.#t.n;

    const a = this.#nodeA;

    const b = this.#nodeB;

    const s = this.#s;

    const u = this.#u;

    for (let j = 0; j < count; j += 2) {
      a[4] = r + j;

      messageBytes(a, D_INTR_WORD, children, from + 2 * j * n, 2 * n);

      if (j + 1 < count) {
        b[4] = r + j + 1;

        messageBytes(b, D_INTR_WORD, children, from + 2 * (j + 1) * n, 2 * n);

        block256x2(IV_256, a, 0, s, IV_256, b, 0, u);

        block256x2(s, a, 16, s, u, b, 16, u);

        storeWords(u, n >>> 2, out, offset + (j + 1) * n);
      } else {
        block256(IV_256, a, 0, s);

        block256(s, a, 16, s);
      }

      storeWords(s, n >>> 2, out, offset + j * n);
    }
  }
}

// The hashes on SHAKE256, whose 22- or 23-byte prefixes leave the values off the lane boundaries: one
// fixed-length message per shape, rewritten in place, I absorbed once. The chain values live in the
// message of K, and K is written straight into the message of the leaf.
class ShakeHashes implements Hashes {
  readonly #t: OtsType;

  readonly #chain: FixedHash;

  readonly #k: FixedHash;

  readonly #leaf: FixedHash;

  readonly #node: FixedHash;

  // The chain value x in the chain message, K in the leaf message, and the output of a node.
  readonly #x: Uint8Array;

  readonly #key: Uint8Array;

  readonly #out: Uint8Array;

  constructor(t: OtsType, id: Uint8Array) {
    const n = t.n;

    this.#t = t;

    this.#chain = fixedShake256(23 + n, id);

    this.#k = fixedShake256(22 + t.p * n, id);

    this.#leaf = fixedShake256(22 + n, id);

    this.#node = fixedShake256(22 + 2 * n, id);

    this.#k.message.fill(0x80, 20, 22);

    this.#leaf.message.fill(0x82, 20, 22);

    this.#node.message.fill(0x83, 20, 22);

    this.#x = this.#chain.message.subarray(23);

    this.#key = this.#leaf.message.subarray(22);

    this.#out = new Uint8Array(n);
  }

  prf(q: number, i: number, seed: Uint8Array, out: Uint8Array, offset: number): void {
    const n = this.#t.n;

    const message = this.#chain.message;

    const x = this.#x;

    writeUint32(message, 16, q);

    message[20] = i >>> 8;

    message[21] = i;

    message[22] = 0xff;

    for (let k = 0; k < n; k++) {
      x[k] = seed[k];
    }

    this.#chain.digest(x);

    for (let k = 0; k < n; k++) {
      out[offset + k] = x[k];
    }
  }

  start(q: number, seed: Uint8Array): void {
    for (let i = 0; i < this.#t.p; i++) {
      this.prf(q, i, seed, this.#k.message, 22 + i * this.#t.n);
    }
  }

  load(data: Uint8Array, offset: number): void {
    const values = this.#k.message;

    for (let k = 22; k < values.length; k++) {
      values[k] = data[offset + k - 22];
    }
  }

  run(q: number, from: ArrayLike<number>, to: ArrayLike<number>): void {
    const { p, n } = this.#t;

    const message = this.#chain.message;

    const values = this.#k.message;

    const x = this.#x;

    writeUint32(message, 16, q);

    for (let i = 0; i < p; i++) {
      if (from[i] >= to[i]) {
        continue;
      }

      message[20] = i >>> 8;

      message[21] = i;

      for (let k = 0; k < n; k++) {
        x[k] = values[22 + i * n + k];
      }

      for (let j = from[i]; j < to[i]; j++) {
        message[22] = j;

        this.#chain.digest(x);
      }

      for (let k = 0; k < n; k++) {
        values[22 + i * n + k] = x[k];
      }
    }
  }

  store(out: Uint8Array, offset: number): void {
    const values = this.#k.message;

    for (let k = 22; k < values.length; k++) {
      out[offset + k - 22] = values[k];
    }
  }

  leaf(r: number, q: number, out: Uint8Array, offset: number): void {
    writeUint32(this.#k.message, 16, q);

    this.#k.digest(this.#key);

    writeUint32(this.#leaf.message, 16, r);

    this.#emit(this.#leaf, out, offset);
  }

  combine(r: number, count: number, children: Uint8Array, from: number, out: Uint8Array, offset: number): void {
    const n = this.#t.n;

    const message = this.#node.message;

    for (let j = 0; j < count; j++) {
      writeUint32(message, 16, r + j);

      for (let k = 0; k < 2 * n; k++) {
        message[22 + k] = children[from + 2 * j * n + k];
      }

      this.#emit(this.#node, out, offset + j * n);
    }
  }

  #emit(hash: FixedHash, out: Uint8Array, offset: number): void {
    hash.digest(this.#out);

    for (let k = 0; k < this.#t.n; k++) {
      out[offset + k] = this.#out[k];
    }
  }
}

function hashes(t: OtsType, id: Uint8Array): Hashes {
  return t.shake ? new ShakeHashes(t, id) : new Sha256Hashes(t, id);
}

export function lmsSignatureSize(lms: LmsType, ots: OtsType): number {
  return 8 + ots.signatureSize + lms.h * lms.m;
}

export interface LmsPublicKey {
  readonly lms: LmsType;

  readonly ots: OtsType;

  readonly id: Uint8Array;

  readonly root: Uint8Array;
}

export function parsePublicKey(data: Uint8Array): LmsPublicKey | null {
  if (data.length < 8) {
    return null;
  }

  const lms = LMS_TYPES.get(readUint32(data, 0));

  const ots = OTS_TYPES.get(readUint32(data, 4));

  if (lms === undefined || ots === undefined || lms.shake !== ots.shake || lms.m !== ots.n) {
    return null;
  }

  return data.length === lms.publicKeySize ? { lms, ots, id: data.subarray(8, 24), root: data.subarray(24) } : null;
}

// The candidate root climbs in pair, at the half its node's parity gives, the sibling from the
// signature beside it.
function lmsVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const parsed = parsePublicKey(publicKey);

  if (parsed === null || signature.length < 8) {
    return false;
  }

  const { lms, ots, id, root } = parsed;

  const q = readUint32(signature, 0);

  if (readUint32(signature, 4) !== ots.code || signature.length !== lmsSignatureSize(lms, ots)) {
    return false;
  }

  const offset = 4 + ots.signatureSize;

  if (readUint32(signature, offset) !== lms.code || q >= 2 ** lms.h) {
    return false;
  }

  const n = ots.n;

  const tree = hashes(ots, id);

  digits(ots, messageHash(ots, id, q, signature, 8, message), DIGITS);

  tree.load(signature, 8 + n);

  tree.run(q, DIGITS, TOPS.get(ots.w) as Uint8Array);

  const pair = new Uint8Array(2 * n);

  let node = 2 ** lms.h + q;

  tree.leaf(node, q, pair, (node & 1) * n);

  for (let i = 0; i < lms.h; i++) {
    const sibling = (1 - (node & 1)) * n;

    for (let k = 0; k < n; k++) {
      pair[sibling + k] = signature[offset + 4 + i * n + k];
    }

    node = Math.floor(node / 2);

    tree.combine(node, 1, pair, 0, pair, (node & 1) * n);
  }

  let difference = 0;

  for (let k = 0; k < n; k++) {
    difference |= pair[n + k] ^ root[k];
  }

  return difference === 0;
}

export function checkPublicKey(data: Uint8Array): boolean {
  if (data.length < 4) {
    return false;
  }

  const levels = readUint32(data, 0);

  return levels >= 1 && levels <= 8 && parsePublicKey(data.subarray(4)) !== null;
}

export function hssVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (!checkPublicKey(publicKey) || signature.length < 4) {
    return false;
  }

  const levels = readUint32(publicKey, 0);

  if (readUint32(signature, 0) !== levels - 1) {
    return false;
  }

  let key = publicKey.subarray(4);

  let offset = 4;

  for (let level = 0; level < levels - 1; level++) {
    const { lms, ots } = parsePublicKey(key) as LmsPublicKey;

    const end = offset + lmsSignatureSize(lms, ots);

    if (signature.length < end + 8) {
      return false;
    }

    const childLms = LMS_TYPES.get(readUint32(signature, end));

    if (childLms === undefined) {
      return false;
    }

    const child = signature.subarray(end, end + childLms.publicKeySize);

    if (parsePublicKey(child) === null || !lmsVerify(key, child, signature.subarray(offset, end))) {
      return false;
    }

    key = child;

    offset = end + child.length;
  }

  return lmsVerify(key, message, signature.subarray(offset));
}

// The I and SEED of the child tree that leaf q signs, from the I and SEED of its parent.
function childKeys(lms: LmsType, id: Uint8Array, seed: Uint8Array, q: number): [Uint8Array, Uint8Array] {
  const childId = derive(lms.shake, lms.m, id, q, CHILD_I, seed).slice(0, 16);

  return [childId, derive(lms.shake, lms.m, id, q, CHILD_SEED, seed)];
}

// One LMS tree of an HSS key: its I, SEED and the Merkle tree over its OTS public keys, built or
// taken from the levels of a tree cache, whose leaves and nodes its hashes compute.
class Tree implements TreeHashes {
  readonly lms: LmsType;

  readonly ots: OtsType;

  readonly id: Uint8Array;

  readonly seed: Uint8Array;

  readonly signatureSize: number;

  readonly merkle: MerkleTree;

  readonly publicKey: Uint8Array;

  readonly #hashes: Hashes;

  constructor(lms: LmsType, ots: OtsType, id: Uint8Array, seed: Uint8Array, levels?: readonly Uint8Array[]) {
    this.lms = lms;

    this.ots = ots;

    this.id = id;

    this.seed = seed;

    this.signatureSize = lmsSignatureSize(lms, ots);

    this.#hashes = hashes(ots, id);

    this.merkle = new MerkleTree(lms.h, lms.m, this, levels);

    this.publicKey = concat(uint32(lms.code), uint32(ots.code), id, this.merkle.root);
  }

  leaf(q: number, out: Uint8Array, offset: number): void {
    this.#hashes.start(q, this.seed);

    this.#hashes.run(q, ZEROS, TOPS.get(this.ots.w) as Uint8Array);

    this.#hashes.leaf(2 ** this.lms.h + q, q, out, offset);
  }

  combine(
    z: number,
    first: number,
    count: number,
    children: Uint8Array,
    from: number,
    out: Uint8Array,
    offset: number,
  ): void {
    this.#hashes.combine(2 ** (this.lms.h - z - 1) + first, count, children, from, out, offset);
  }

  // The LMS signature of message with leaf q into out from offset on: u32(q), the LM-OTS signature
  // (its type, C and the chain values), the LMS type and the authentication path.
  sign(q: number, message: Uint8Array, out: Uint8Array, offset: number): void {
    const { ots, lms, seed } = this;

    const tree = this.#hashes;

    writeUint32(out, offset, q);

    writeUint32(out, offset + 4, ots.code);

    tree.prf(q, RANDOMIZER, seed, out, offset + 8);

    digits(ots, messageHash(ots, this.id, q, out, offset + 8, message), DIGITS);

    tree.start(q, seed);

    tree.run(q, ZEROS, DIGITS);

    tree.store(out, offset + 8 + ots.n);

    writeUint32(out, offset + 4 + ots.signatureSize, lms.code);

    this.merkle.authPath(q, out, offset + 8 + ots.signatureSize);
  }

  child(lms: LmsType, ots: OtsType, q: number): Tree {
    const [id, seed] = childKeys(this.lms, this.id, this.seed, q);

    return new Tree(lms, ots, id, seed);
  }
}

export type Level = readonly [LmsType, OtsType];

// The signing side of an HSS key: the trees on the path to the next leaf, rebuilt when the index
// leaves a tree, and each child public key signed by its parent. `cached` holds, by level, the
// trees of a verified tree cache that the next index signs with: the top one replaces the build,
// and the lower ones wait in #restored until the first signature needs them. All are checked
// here, so a bad cache fails the load.
export class Hss {
  readonly levels: readonly Level[];

  readonly #heights: number[];

  // Entry level: the total height of the levels from level on, and the mask of one level's leaf
  // index.
  readonly #below: bigint[];

  readonly #masks: bigint[];

  readonly #trees: Tree[];

  readonly #signed: Uint8Array[] = [];

  readonly #prefixes: bigint[] = [0n];

  readonly #restored = new Map<number, [bigint, Tree]>();

  constructor(levels: readonly Level[], id: Uint8Array, seed: Uint8Array, cached?: ReadonlyMap<number, CachedLevels>) {
    this.levels = levels;

    this.#heights = levels.map(([lms]) => lms.h);

    this.#below = [...this.#heights, 0].map((_, level) =>
      BigInt(this.#heights.slice(level).reduce((total, h) => total + h, 0)),
    );

    this.#masks = this.#heights.map((h) => (1n << BigInt(h)) - 1n);

    try {
      this.#trees = [new Tree(levels[0][0], levels[0][1], id, seed, cached?.get(0)?.[1])];

      for (const [level, [prefix, nodes]] of cached ?? []) {
        if (level > 0) {
          this.#restored.set(level, [prefix, this.#pathTree(level, prefix, nodes)]);
        }
      }
    } finally {
      wipeSha2Lanes();
    }
  }

  get publicKey(): Uint8Array {
    return concat(uint32(this.levels.length), this.#trees[0].publicKey);
  }

  #leafIndex(index: bigint, level: number): number {
    return Number((index >> this.#below[level + 1]) & this.#masks[level]);
  }

  // Tree `prefix` of a lower level: the leaves that sign it on the levels above follow from its
  // number, and with them its I and SEED.
  #pathTree(level: number, prefix: bigint, nodes: readonly Uint8Array[]): Tree {
    const top = this.#trees[0];

    let [id, seed] = [top.id, top.seed];

    for (let upper = 0; upper < level; upper++) {
      const below = BigInt(this.#heights.slice(upper + 1, level).reduce((total, h) => total + h, 0));

      const q = Number((prefix >> below) & ((1n << BigInt(this.#heights[upper])) - 1n));

      [id, seed] = childKeys(top.lms, id, seed, q);
    }

    return new Tree(this.levels[level][0], this.levels[level][1], id, seed, nodes);
  }

  // Every tree the key holds, top first.
  cached(): CachedTree[] {
    const held = this.#trees.map((tree, level) => ({ level, tree: this.#prefixes[level], merkle: tree.merkle }));

    const waiting = [...this.#restored].sort(([a], [b]) => a - b);

    return [...held, ...waiting.map(([level, [prefix, tree]]) => ({ level, tree: prefix, merkle: tree.merkle }))];
  }

  // The signature, written once: u32(levels - 1), each signed child public key, then the bottom
  // tree's signature of the message.
  sign(index: bigint, message: Uint8Array): Uint8Array {
    try {
      return this.#sign(index, message);
    } finally {
      wipeSha2Lanes();
    }
  }

  #sign(index: bigint, message: Uint8Array): Uint8Array {
    const trees = this.#trees;

    for (let level = 1; level < this.levels.length; level++) {
      const prefix = index >> this.#below[level];

      if (level < trees.length && this.#prefixes[level] === prefix) {
        continue;
      }

      trees.length = level;

      this.#signed.length = level - 1;

      this.#prefixes.length = level;

      const q = this.#leafIndex(index, level - 1);

      const restored = this.#restored.get(level);

      this.#restored.delete(level);

      const tree =
        restored !== undefined && restored[0] === prefix
          ? restored[1]
          : trees[level - 1].child(this.levels[level][0], this.levels[level][1], q);

      const parent = trees[level - 1];

      const signed = new Uint8Array(parent.signatureSize + tree.publicKey.length);

      parent.sign(q, tree.publicKey, signed, 0);

      signed.set(tree.publicKey, parent.signatureSize);

      trees.push(tree);

      this.#signed.push(signed);

      this.#prefixes.push(prefix);
    }

    const bottom = trees[trees.length - 1];

    let length = 4 + bottom.signatureSize;

    for (let level = 0; level < this.#signed.length; level++) {
      length += this.#signed[level].length;
    }

    const out = new Uint8Array(length);

    writeUint32(out, 0, this.levels.length - 1);

    let offset = 4;

    for (let level = 0; level < this.#signed.length; level++) {
      out.set(this.#signed[level], offset);

      offset += this.#signed[level].length;
    }

    bottom.sign(this.#leafIndex(index, this.levels.length - 1), message, out, offset);

    return out;
  }
}
