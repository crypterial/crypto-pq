import { concat, equal, readUint32, uint32, writeUint32 } from "./bytes.ts";
import { MerkleTree } from "./merkle.ts";
import { type FixedHash, fixedSha256, fixedShake256, sha256, shake256 } from "./primitives.ts";

const D_PBLC = Uint8Array.of(0x80, 0x80);

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

const CHAINS = new Map<string, FixedHash>();

// x = H(I || u32(q) || u16(j) || u8(k) || x) for k from start to end - 1, the inner loop of
// LM-OTS, on a message of 23 + n bytes rewritten in place.
function chain(
  t: OtsType,
  id: Uint8Array,
  q: number,
  j: number,
  start: number,
  end: number,
  x: Uint8Array,
): Uint8Array {
  if (start >= end) {
    return x;
  }

  const key = `${t.shake} ${t.n}`;

  let fixed = CHAINS.get(key);

  if (fixed === undefined) {
    fixed = (t.shake ? fixedShake256 : fixedSha256)(23 + t.n, new Uint8Array());

    CHAINS.set(key, fixed);
  }

  const message = fixed.message;

  const value = message.subarray(23, 23 + t.n);

  message.set(id);

  writeUint32(message, 16, q);

  message[20] = j >>> 8;

  message[21] = j;

  value.set(x);

  for (let k = start; k < end; k++) {
    message[22] = k;

    fixed.digest(value);
  }

  return value.slice();
}

function otsPublicKey(t: OtsType, id: Uint8Array, q: number, seed: Uint8Array): Uint8Array {
  const top = (1 << t.w) - 1;

  const y: Uint8Array[] = [];

  for (let j = 0; j < t.p; j++) {
    y.push(chain(t, id, q, j, 0, top, derive(t.shake, t.n, id, q, j, seed)));
  }

  return digest(t.shake, t.n, id, uint32(q), D_PBLC, ...y);
}

function otsSign(t: OtsType, id: Uint8Array, q: number, seed: Uint8Array, message: Uint8Array): Uint8Array {
  const c = derive(t.shake, t.n, id, q, RANDOMIZER, seed);

  const qHash = digest(t.shake, t.n, id, uint32(q), D_MESG, c, message);

  const y = digits(t, qHash).map((a, j) => chain(t, id, q, j, 0, a, derive(t.shake, t.n, id, q, j, seed)));

  return concat(uint32(t.code), c, ...y);
}

function otsCandidate(t: OtsType, id: Uint8Array, q: number, signature: Uint8Array, message: Uint8Array): Uint8Array {
  const n = t.n;

  const c = signature.subarray(4, 4 + n);

  const qHash = digest(t.shake, n, id, uint32(q), D_MESG, c, message);

  const top = (1 << t.w) - 1;

  const z = digits(t, qHash).map((a, j) => {
    return chain(t, id, q, j, a, top, signature.subarray(4 + n * (j + 1), 4 + n * (j + 2)));
  });

  return digest(t.shake, n, id, uint32(q), D_PBLC, ...z);
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

  constructor(lms: LmsType, ots: OtsType, id: Uint8Array, seed: Uint8Array) {
    this.lms = lms;

    this.ots = ots;

    this.id = id;

    this.seed = seed;

    const leaf = (q: number) => {
      const k = otsPublicKey(ots, id, q, seed);

      return digest(lms.shake, lms.m, id, uint32(2 ** lms.h + q), D_LEAF, k);
    };

    const combine = (z: number, j: number, left: Uint8Array, right: Uint8Array) => {
      return digest(lms.shake, lms.m, id, uint32(2 ** (lms.h - z - 1) + j), D_INTR, left, right);
    };

    this.merkle = new MerkleTree(lms.h, leaf, combine);

    this.publicKey = concat(uint32(lms.code), uint32(ots.code), id, this.merkle.root);
  }

  sign(q: number, message: Uint8Array): Uint8Array {
    const otsSignature = otsSign(this.ots, this.id, q, this.seed, message);

    return concat(uint32(q), otsSignature, uint32(this.lms.code), ...this.merkle.authPath(q));
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
