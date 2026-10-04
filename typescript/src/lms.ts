import { concat, equal, readUint32, uint32, writeUint32 } from "./bytes.ts";
import { MerkleTree } from "./merkle.ts";
import {
  type FixedHash,
  blocks,
  fixedShake256,
  loadWords,
  messageWords,
  sha256,
  shake256,
  storeWords,
} from "./primitives.ts";
import { block256, block256x2 } from "./sha2-rounds.ts";
import { IV_256 } from "./sha2.ts";

const D_PBLC = Uint8Array.of(0x80, 0x80);

// u16(D_PBLC) as it ends the 22-byte header of K in the high half of word 5.
const D_PBLC_WORD = 0x8080 << 16;

const D_MESG = Uint8Array.of(0x81, 0x81);

const D_LEAF = Uint8Array.of(0x82, 0x82);

const D_INTR = Uint8Array.of(0x83, 0x83);

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

function uint16(value: number): Uint8Array {
  return Uint8Array.of(value >>> 8, value & 0xff);
}

function digest(shake: boolean, n: number, ...parts: Uint8Array[]): Uint8Array {
  return shake ? shake256(n, ...parts) : sha256(...parts).slice(0, n);
}

function derive(shake: boolean, n: number, id: Uint8Array, q: number, index: number, seed: Uint8Array): Uint8Array {
  return digest(shake, n, id, uint32(q), uint16(index), Uint8Array.of(0xff), seed);
}

function coefficients(t: OtsType, data: Uint8Array, count: number): number[] {
  const mask = (1 << t.w) - 1;

  const perByte = 8 / t.w;

  const out: number[] = [];

  for (let i = 0; i < count; i++) {
    out.push((data[Math.floor(i / perByte)] >>> (8 - t.w * ((i % perByte) + 1))) & mask);
  }

  return out;
}

function digits(t: OtsType, qHash: Uint8Array): number[] {
  const values = coefficients(t, qHash, (8 * t.n) / t.w);

  let checksum = 0;

  for (const value of values) {
    checksum += (1 << t.w) - 1 - value;
  }

  return coefficients(t, concat(qHash, uint16(checksum << t.ls)), t.p);
}

// The LM-OTS chains of every chain index of one leaf, for one tree (one I).
interface Chains {
  // Sets each chain's value to its start, H(I || u32(q) || u16(i) || u8(0xFF) || SEED).
  derive(q: number, seed: Uint8Array): void;

  // Takes the chain values from data, n bytes each from offset on.
  load(data: Uint8Array, offset: number): void;

  // Advances chain i with x = H(I || u32(q) || u16(i) || u8(j) || x) for j from from[i] to to[i] - 1.
  run(q: number, from: ArrayLike<number>, to: ArrayLike<number>): void;

  store(out: Uint8Array, offset: number): void;

  // K = H(I || u32(q) || u16(D_PBLC) || the chain values).
  publicKey(q: number): Uint8Array;
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

function copyWords(from: Int32Array, fromOffset: number, to: Int32Array, toOffset: number, count: number): void {
  for (let k = 0; k < count; k++) {
    to[toOffset + k] = from[fromOffset + k];
  }
}

// Chains on SHA-256 words: every step and every chain start is one block, and two chains advance at
// once through block256x2, the next waiting chain taking over a lane as soon as its chain ends.
class Sha256Chains implements Chains {
  readonly #t: OtsType;

  readonly #a = new Int32Array(16);

  readonly #b = new Int32Array(16);

  readonly #s = new Int32Array(8);

  readonly #u = new Int32Array(8);

  readonly #seed: Int32Array;

  readonly #values: Int32Array;

  readonly #k: Int32Array;

  constructor(t: OtsType, id: Uint8Array) {
    const count = t.n >>> 2;

    this.#t = t;

    for (const w of [this.#a, this.#b]) {
      loadWords(id, 0, 4, w);

      w[15] = 8 * (23 + t.n);
    }

    this.#seed = new Int32Array(count);

    this.#values = new Int32Array(t.p * count);

    this.#k = blocks(false, 0, t.p * t.n);

    loadWords(id, 0, 4, this.#k);
  }

  derive(q: number, seed: Uint8Array): void {
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

  publicKey(q: number): Uint8Array {
    const k = this.#k;

    const s = this.#s;

    k[4] = q;

    messageWords(k, D_PBLC_WORD, this.#values, 0, this.#values.length);

    block256(IV_256, k, 0, s);

    for (let offset = 16; offset < k.length; offset += 16) {
      block256(s, k, offset, s);
    }

    const out = new Uint8Array(this.#t.n);

    storeWords(s, this.#t.n >>> 2, out, 0);

    return out;
  }
}

// Chains on SHAKE256, whose 23-byte prefix leaves the values off the lane boundaries: one fixed-length
// message rewritten in place.
class ShakeChains implements Chains {
  readonly #t: OtsType;

  readonly #id: Uint8Array;

  readonly #fixed: FixedHash;

  readonly #values: Uint8Array;

  constructor(t: OtsType, id: Uint8Array) {
    this.#t = t;

    this.#id = id;

    this.#fixed = fixedShake256(23 + t.n, new Uint8Array());

    this.#values = new Uint8Array(t.p * t.n);
  }

  derive(q: number, seed: Uint8Array): void {
    const { p, n } = this.#t;

    for (let i = 0; i < p; i++) {
      this.#values.set(derive(true, n, this.#id, q, i, seed), i * n);
    }
  }

  load(data: Uint8Array, offset: number): void {
    this.#values.set(data.subarray(offset, offset + this.#values.length));
  }

  run(q: number, from: ArrayLike<number>, to: ArrayLike<number>): void {
    const { p, n } = this.#t;

    const message = this.#fixed.message;

    message.set(this.#id);

    writeUint32(message, 16, q);

    for (let i = 0; i < p; i++) {
      const value = message.subarray(23, 23 + n);

      if (from[i] >= to[i]) {
        continue;
      }

      message[20] = i >>> 8;

      message[21] = i;

      value.set(this.#values.subarray(i * n, (i + 1) * n));

      for (let j = from[i]; j < to[i]; j++) {
        message[22] = j;

        this.#fixed.digest(value);
      }

      this.#values.set(value, i * n);
    }
  }

  store(out: Uint8Array, offset: number): void {
    out.set(this.#values, offset);
  }

  publicKey(q: number): Uint8Array {
    return digest(true, this.#t.n, this.#id, uint32(q), D_PBLC, this.#values);
  }
}

function chains(t: OtsType, id: Uint8Array): Chains {
  return t.shake ? new ShakeChains(t, id) : new Sha256Chains(t, id);
}

function otsPublicKey(chains: Chains, t: OtsType, q: number, seed: Uint8Array): Uint8Array {
  chains.derive(q, seed);

  chains.run(q, new Uint8Array(t.p), new Uint8Array(t.p).fill((1 << t.w) - 1));

  return chains.publicKey(q);
}

function otsSign(
  chains: Chains,
  t: OtsType,
  id: Uint8Array,
  q: number,
  seed: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  const c = derive(t.shake, t.n, id, q, RANDOMIZER, seed);

  const qHash = digest(t.shake, t.n, id, uint32(q), D_MESG, c, message);

  chains.derive(q, seed);

  chains.run(q, new Uint8Array(t.p), digits(t, qHash));

  const out = new Uint8Array(t.signatureSize);

  writeUint32(out, 0, t.code);

  out.set(c, 4);

  chains.store(out, 4 + t.n);

  return out;
}

function otsCandidate(t: OtsType, id: Uint8Array, q: number, signature: Uint8Array, message: Uint8Array): Uint8Array {
  const n = t.n;

  const c = signature.subarray(4, 4 + n);

  const qHash = digest(t.shake, n, id, uint32(q), D_MESG, c, message);

  const otsChains = chains(t, id);

  otsChains.load(signature, 4 + n);

  otsChains.run(q, digits(t, qHash), new Uint8Array(t.p).fill((1 << t.w) - 1));

  return otsChains.publicKey(q);
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

  let node = 2 ** lms.h + q;

  const leaf = otsCandidate(ots, id, q, signature.subarray(4, offset), message);

  let candidate = digest(lms.shake, lms.m, id, uint32(node), D_LEAF, leaf);

  for (let i = 0; i < lms.h; i++) {
    const sibling = signature.subarray(offset + 4 + i * lms.m, offset + 4 + (i + 1) * lms.m);

    const odd = node % 2 === 1;

    node = Math.floor(node / 2);

    const pair = odd ? [sibling, candidate] : [candidate, sibling];

    candidate = digest(lms.shake, lms.m, id, uint32(node), D_INTR, ...pair);
  }

  return equal(candidate, root);
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

// One LMS tree of an HSS key: its I, SEED and the Merkle tree over its OTS public keys.
class Tree {
  readonly lms: LmsType;

  readonly ots: OtsType;

  readonly id: Uint8Array;

  readonly seed: Uint8Array;

  readonly merkle: MerkleTree;

  readonly publicKey: Uint8Array;

  readonly #chains: Chains;

  constructor(lms: LmsType, ots: OtsType, id: Uint8Array, seed: Uint8Array) {
    this.lms = lms;

    this.ots = ots;

    this.id = id;

    this.seed = seed;

    this.#chains = chains(ots, id);

    const leaf = (q: number) => {
      const k = otsPublicKey(this.#chains, ots, q, seed);

      return digest(lms.shake, lms.m, id, uint32(2 ** lms.h + q), D_LEAF, k);
    };

    const combine = (z: number, j: number, left: Uint8Array, right: Uint8Array) => {
      return digest(lms.shake, lms.m, id, uint32(2 ** (lms.h - z - 1) + j), D_INTR, left, right);
    };

    this.merkle = new MerkleTree(lms.h, lms.m, leaf, combine);

    this.publicKey = concat(uint32(lms.code), uint32(ots.code), id, this.merkle.root);
  }

  sign(q: number, message: Uint8Array): Uint8Array {
    const otsSignature = otsSign(this.#chains, this.ots, this.id, q, this.seed, message);

    return concat(uint32(q), otsSignature, uint32(this.lms.code), this.merkle.authPath(q));
  }

  child(lms: LmsType, ots: OtsType, q: number): Tree {
    const seed = derive(this.lms.shake, this.lms.m, this.id, q, CHILD_SEED, this.seed);

    const id = derive(this.lms.shake, this.lms.m, this.id, q, CHILD_I, this.seed).slice(0, 16);

    return new Tree(lms, ots, id, seed);
  }
}

export type Level = readonly [LmsType, OtsType];

// The signing side of an HSS key: the trees on the path to the next leaf, rebuilt when the index
// leaves a tree, and each child public key signed by its parent.
export class Hss {
  readonly levels: readonly Level[];

  readonly #heights: number[];

  readonly #trees: Tree[];

  readonly #signed: Uint8Array[] = [];

  readonly #prefixes: bigint[] = [0n];

  constructor(levels: readonly Level[], id: Uint8Array, seed: Uint8Array) {
    this.levels = levels;

    this.#heights = levels.map(([lms]) => lms.h);

    this.#trees = [new Tree(levels[0][0], levels[0][1], id, seed)];
  }

  get publicKey(): Uint8Array {
    return concat(uint32(this.levels.length), this.#trees[0].publicKey);
  }

  #below(level: number): bigint {
    return BigInt(this.#heights.slice(level).reduce((total, h) => total + h, 0));
  }

  #leafIndex(index: bigint, level: number): number {
    return Number((index >> this.#below(level + 1)) & ((1n << BigInt(this.#heights[level])) - 1n));
  }

  sign(index: bigint, message: Uint8Array): Uint8Array {
    const trees = this.#trees;

    for (let level = 1; level < this.levels.length; level++) {
      const prefix = index >> this.#below(level);

      if (level < trees.length && this.#prefixes[level] === prefix) {
        continue;
      }

      trees.length = level;

      this.#signed.length = level - 1;

      this.#prefixes.length = level;

      const q = this.#leafIndex(index, level - 1);

      const tree = trees[level - 1].child(this.levels[level][0], this.levels[level][1], q);

      trees.push(tree);

      this.#signed.push(concat(trees[level - 1].sign(q, tree.publicKey), tree.publicKey));

      this.#prefixes.push(prefix);
    }

    const bottom = trees[trees.length - 1].sign(this.#leafIndex(index, this.levels.length - 1), message);

    return concat(uint32(this.levels.length - 1), ...this.#signed, bottom);
  }
}
