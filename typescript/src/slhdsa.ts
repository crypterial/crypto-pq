import { concat, equal, writeUint32 } from "./bytes.ts";
import { HMAC_SHA_256, HMAC_SHA_512 } from "./hash.ts";
import {
  type FixedHash,
  type PrefixedHash,
  fixedSha256,
  fixedShake256,
  prefixedSha256,
  prefixedSha512,
  prefixedShake256,
  sha256,
  sha512,
  shake256,
} from "./primitives.ts";

const WOTS_HASH = 0;

const WOTS_PK = 1;

const TREE = 2;

const FORS_TREE = 3;

const FORS_ROOTS = 4;

const WOTS_PRF = 5;

const FORS_PRF = 6;

const W = 16;

const LG_W = 4;

export interface Parameters {
  readonly name: string;

  readonly shake: boolean;

  readonly n: number;

  readonly h: number;

  readonly d: number;

  readonly hp: number;

  readonly a: number;

  readonly k: number;

  readonly m: number;

  readonly length: number;

  readonly publicKeySize: number;

  readonly privateKeySize: number;

  readonly signatureSize: number;
}

function sets(family: string, shake: boolean): Parameters[] {
  const sizes: [string, number, number, number, number, number, number, number][] = [
    ["128s", 16, 63, 7, 9, 12, 14, 30],
    ["128f", 16, 66, 22, 3, 6, 33, 34],
    ["192s", 24, 63, 7, 9, 14, 17, 39],
    ["192f", 24, 66, 22, 3, 8, 33, 42],
    ["256s", 32, 64, 8, 8, 14, 22, 47],
    ["256f", 32, 68, 17, 4, 9, 35, 49],
  ];

  return sizes.map(([size, n, h, d, hp, a, k, m]) => {
    const length = 2 * n + 3;

    return Object.freeze({
      name: `SLH-DSA-${family}-${size}`,
      shake,
      n,
      h,
      d,
      hp,
      a,
      k,
      m,
      length,
      publicKeySize: 2 * n,
      privateKeySize: 4 * n,
      signatureSize: (1 + k * (1 + a) + h + d * length) * n,
    });
  });
}

export const SHA2 = sets("SHA2", false);

export const SHAKE = sets("SHAKE", true);

function setLayer(adrs: Uint8Array, value: number): void {
  writeUint32(adrs, 0, value);
}

// A hypertree address has up to 64 bits, more than a JavaScript number holds exactly, so it is
// kept as two 32-bit halves.
interface Tree {
  readonly high: number;

  readonly low: number;
}

function setTree(adrs: Uint8Array, tree: Tree): void {
  writeUint32(adrs, 4, 0);

  writeUint32(adrs, 8, tree.high);

  writeUint32(adrs, 12, tree.low);
}

// The leaf index of the tree one layer up, taken from the low bits, and the address of that tree.
function parent(tree: Tree, bits: number): [number, Tree] {
  const leaf = tree.low & ((1 << bits) - 1);

  return [leaf, { high: tree.high >>> bits, low: ((tree.low >>> bits) | (tree.high << (32 - bits))) >>> 0 }];
}

function setType(adrs: Uint8Array, value: number): void {
  writeUint32(adrs, 16, value);

  adrs.fill(0, 20, 32);
}

function setKeyPair(adrs: Uint8Array, value: number): void {
  writeUint32(adrs, 20, value);
}

function setChain(adrs: Uint8Array, value: number): void {
  writeUint32(adrs, 24, value);
}

function setHash(adrs: Uint8Array, value: number): void {
  writeUint32(adrs, 28, value);
}

function keyPair(adrs: Uint8Array): number {
  return ((adrs[20] << 24) | (adrs[21] << 16) | (adrs[22] << 8) | adrs[23]) >>> 0;
}

function treeIndex(adrs: Uint8Array): number {
  return ((adrs[28] << 24) | (adrs[29] << 16) | (adrs[30] << 8) | adrs[31]) >>> 0;
}

const setTreeHeight = setChain;

const setTreeIndex = setHash;

// FIPS 205, section 11: F, H, T and PRF bound to one public seed.
abstract class Hashes {
  readonly n: number;

  readonly #scratch = new Uint8Array(32);

  constructor(n: number) {
    this.n = n;
  }

  abstract f(adrs: Uint8Array, message: Uint8Array): Uint8Array;

  abstract h(adrs: Uint8Array, ...message: Uint8Array[]): Uint8Array;

  abstract prf(adrs: Uint8Array): Uint8Array;

  // F applied for the hash addresses start to start + steps - 1: the inner loop of WOTS+, kept
  // free of allocations because it accounts for nearly every hash call.
  abstract chain(x: Uint8Array, start: number, steps: number, adrs: Uint8Array): Uint8Array;

  // A scratch address for the secret and public-key derivations, which never nest.
  derived(adrs: Uint8Array, type: number): Uint8Array {
    const out = this.#scratch;

    out.set(adrs);

    setType(out, type);

    setKeyPair(out, keyPair(adrs));

    return out;
  }
}

// ADRSc, the 22-byte compressed address: layer, tree, type, then key pair, chain and hash.
function compressAddress(adrs: Uint8Array, out: Uint8Array, offset: number): void {
  out[offset] = adrs[3];

  for (let i = 0; i < 8; i++) {
    out[offset + 1 + i] = adrs[8 + i];
  }

  out[offset + 9] = adrs[19];

  for (let i = 0; i < 12; i++) {
    out[offset + 10 + i] = adrs[20 + i];
  }
}

// Runs F over the hash addresses start to start + steps - 1. In both chain messages the value sits
// at offset at, right after the 4-byte hash address; each step rewrites them in place.
function runChain(fixed: FixedHash, at: number, n: number, x: Uint8Array, start: number, steps: number): Uint8Array {
  const value = fixed.message.subarray(at, at + n);

  value.set(x);

  for (let j = start; j < start + steps; j++) {
    writeUint32(fixed.message, at - 4, j);

    fixed.digest(value);
  }

  return value.slice();
}

// The SHA-2 instances: the block holding PK.seed and its zero padding is hashed once and the state
// reused for every call.
class Sha2Hashes extends Hashes {
  readonly #skSeed: Uint8Array;

  readonly #small: PrefixedHash;

  readonly #large: PrefixedHash;

  readonly #compressed = new Uint8Array(22);

  readonly #chain: FixedHash;

  constructor(p: Parameters, pkSeed: Uint8Array, skSeed: Uint8Array) {
    super(p.n);

    const prefix = concat(pkSeed, new Uint8Array(64 - p.n));

    this.#skSeed = skSeed;

    this.#small = prefixedSha256(prefix);

    this.#large = p.n === 16 ? this.#small : prefixedSha512(concat(pkSeed, new Uint8Array(128 - p.n)));

    this.#chain = fixedSha256(64 + 22 + p.n, prefix);
  }

  #address(adrs: Uint8Array): Uint8Array {
    compressAddress(adrs, this.#compressed, 0);

    return this.#compressed;
  }

  f(adrs: Uint8Array, message: Uint8Array): Uint8Array {
    return this.#small.digest(this.n, this.#address(adrs), message);
  }

  h(adrs: Uint8Array, ...message: Uint8Array[]): Uint8Array {
    return this.#large.digest(this.n, this.#address(adrs), ...message);
  }

  prf(adrs: Uint8Array): Uint8Array {
    return this.#small.digest(this.n, this.#address(adrs), this.#skSeed);
  }

  chain(x: Uint8Array, start: number, steps: number, adrs: Uint8Array): Uint8Array {
    if (steps === 0) {
      return x;
    }

    compressAddress(adrs, this.#chain.message, 64);

    const out = runChain(this.#chain, 86, this.n, x, start, steps);

    setHash(adrs, start + steps - 1);

    return out;
  }
}

class ShakeHashes extends Hashes {
  readonly #skSeed: Uint8Array;

  readonly #hash: PrefixedHash;

  readonly #chain: FixedHash;

  constructor(p: Parameters, pkSeed: Uint8Array, skSeed: Uint8Array) {
    super(p.n);

    this.#skSeed = skSeed;

    this.#hash = prefixedShake256(pkSeed);

    this.#chain = fixedShake256(2 * p.n + 32, pkSeed);
  }

  f(adrs: Uint8Array, message: Uint8Array): Uint8Array {
    return this.#hash.digest(this.n, adrs, message);
  }

  h(adrs: Uint8Array, ...message: Uint8Array[]): Uint8Array {
    return this.#hash.digest(this.n, adrs, ...message);
  }

  prf(adrs: Uint8Array): Uint8Array {
    return this.#hash.digest(this.n, adrs, this.#skSeed);
  }

  chain(x: Uint8Array, start: number, steps: number, adrs: Uint8Array): Uint8Array {
    if (steps === 0) {
      return x;
    }

    this.#chain.message.set(adrs, this.n);

    const out = runChain(this.#chain, this.n + 32, this.n, x, start, steps);

    setHash(adrs, start + steps - 1);

    return out;
  }
}

function hashes(p: Parameters, pkSeed: Uint8Array, skSeed: Uint8Array): Hashes {
  return p.shake ? new ShakeHashes(p, pkSeed, skSeed) : new Sha2Hashes(p, pkSeed, skSeed);
}

function mgf1(seed: Uint8Array, length: number, hash: (...parts: Uint8Array[]) => Uint8Array): Uint8Array {
  const out = new Uint8Array(length);

  const counter = new Uint8Array(4);

  for (let offset = 0, i = 0; offset < length; i++) {
    writeUint32(counter, 0, i);

    const block = hash(seed, counter);

    out.set(block.subarray(0, Math.min(block.length, length - offset)), offset);

    offset += block.length;
  }

  return out;
}

function hMsg(p: Parameters, r: Uint8Array, pkSeed: Uint8Array, pkRoot: Uint8Array, message: Uint8Array): Uint8Array {
  if (p.shake) {
    return shake256(p.m, r, pkSeed, pkRoot, message);
  }

  const hash = p.n === 16 ? sha256 : sha512;

  return mgf1(concat(r, pkSeed, hash(r, pkSeed, pkRoot, message)), p.m, hash);
}

function prfMsg(p: Parameters, skPrf: Uint8Array, optRand: Uint8Array, message: Uint8Array): Uint8Array {
  if (p.shake) {
    return shake256(p.n, skPrf, optRand, message);
  }

  const hmac = (p.n === 16 ? HMAC_SHA_256 : HMAC_SHA_512).create(skPrf);

  return hmac.update(optRand).update(message).digest().slice(0, p.n);
}

function base2b(data: Uint8Array, b: number, count: number): number[] {
  const out: number[] = [];

  let total = 0;

  let bits = 0;

  let offset = 0;

  for (let i = 0; i < count; i++) {
    while (bits < b) {
      total = ((total << 8) | data[offset++]) & 0xffffff;

      bits += 8;
    }

    bits -= b;

    out.push((total >>> bits) & ((1 << b) - 1));
  }

  return out;
}

function wotsDigits(p: Parameters, message: Uint8Array): number[] {
  const digits = base2b(message, LG_W, 2 * p.n);

  let checksum = 0;

  for (const digit of digits) {
    checksum += W - 1 - digit;
  }

  checksum <<= 4;

  return digits.concat(base2b(Uint8Array.of(checksum >> 8, checksum & 0xff), LG_W, 3));
}

function wotsSecret(hashes: Hashes, adrs: Uint8Array, i: number): Uint8Array {
  const skAdrs = hashes.derived(adrs, WOTS_PRF);

  setChain(skAdrs, i);

  return hashes.prf(skAdrs);
}

function wotsPublic(hashes: Hashes, adrs: Uint8Array, values: Uint8Array[]): Uint8Array {
  return hashes.h(hashes.derived(adrs, WOTS_PK), ...values);
}

function wotsPkGen(p: Parameters, hashes: Hashes, adrs: Uint8Array): Uint8Array {
  const values: Uint8Array[] = [];

  for (let i = 0; i < p.length; i++) {
    const secret = wotsSecret(hashes, adrs, i);

    setChain(adrs, i);

    values.push(hashes.chain(secret, 0, W - 1, adrs));
  }

  return wotsPublic(hashes, adrs, values);
}

function wotsSign(p: Parameters, hashes: Hashes, message: Uint8Array, adrs: Uint8Array): Uint8Array[] {
  return wotsDigits(p, message).map((digit, i) => {
    const secret = wotsSecret(hashes, adrs, i);

    setChain(adrs, i);

    return hashes.chain(secret, 0, digit, adrs);
  });
}

function wotsPkFromSig(
  p: Parameters,
  hashes: Hashes,
  signature: Uint8Array,
  message: Uint8Array,
  adrs: Uint8Array,
): Uint8Array {
  const n = p.n;

  const values = wotsDigits(p, message).map((digit, i) => {
    setChain(adrs, i);

    return hashes.chain(signature.subarray(i * n, (i + 1) * n), digit, W - 1 - digit, adrs);
  });

  return wotsPublic(hashes, adrs, values);
}

function xmssNode(p: Parameters, hashes: Hashes, i: number, z: number, adrs: Uint8Array): Uint8Array {
  if (z === 0) {
    setType(adrs, WOTS_HASH);

    setKeyPair(adrs, i);

    return wotsPkGen(p, hashes, adrs);
  }

  const left = xmssNode(p, hashes, 2 * i, z - 1, adrs);

  const right = xmssNode(p, hashes, 2 * i + 1, z - 1, adrs);

  setType(adrs, TREE);

  setTreeHeight(adrs, z);

  setTreeIndex(adrs, i);

  return hashes.h(adrs, left, right);
}

function xmssSign(p: Parameters, hashes: Hashes, message: Uint8Array, index: number, adrs: Uint8Array): Uint8Array[] {
  const auth: Uint8Array[] = [];

  for (let j = 0; j < p.hp; j++) {
    auth.push(xmssNode(p, hashes, (index >>> j) ^ 1, j, adrs));
  }

  setType(adrs, WOTS_HASH);

  setKeyPair(adrs, index);

  return [...wotsSign(p, hashes, message, adrs), ...auth];
}

function xmssPkFromSig(
  p: Parameters,
  hashes: Hashes,
  index: number,
  signature: Uint8Array,
  message: Uint8Array,
  adrs: Uint8Array,
): Uint8Array {
  const n = p.n;

  setType(adrs, WOTS_HASH);

  setKeyPair(adrs, index);

  let node = wotsPkFromSig(p, hashes, signature.subarray(0, p.length * n), message, adrs);

  const auth = signature.subarray(p.length * n);

  setType(adrs, TREE);

  setTreeIndex(adrs, index);

  for (let k = 0; k < p.hp; k++) {
    setTreeHeight(adrs, k + 1);

    const sibling = auth.subarray(k * n, (k + 1) * n);

    if (((index >>> k) & 1) === 0) {
      setTreeIndex(adrs, treeIndex(adrs) >>> 1);

      node = hashes.h(adrs, node, sibling);
    } else {
      setTreeIndex(adrs, (treeIndex(adrs) - 1) >>> 1);

      node = hashes.h(adrs, sibling, node);
    }
  }

  return node;
}

function htSign(p: Parameters, hashes: Hashes, message: Uint8Array, tree: Tree, leaf: number): Uint8Array[] {
  const adrs = new Uint8Array(32);

  setTree(adrs, tree);

  let part = xmssSign(p, hashes, message, leaf, adrs);

  const out = [...part];

  let root = xmssPkFromSig(p, hashes, leaf, concat(...part), message, adrs);

  for (let j = 1; j < p.d; j++) {
    [leaf, tree] = parent(tree, p.hp);

    setLayer(adrs, j);

    setTree(adrs, tree);

    part = xmssSign(p, hashes, root, leaf, adrs);

    out.push(...part);

    if (j < p.d - 1) {
      root = xmssPkFromSig(p, hashes, leaf, concat(...part), root, adrs);
    }
  }

  return out;
}

function htVerify(
  p: Parameters,
  hashes: Hashes,
  message: Uint8Array,
  signature: Uint8Array,
  tree: Tree,
  leaf: number,
  pkRoot: Uint8Array,
): boolean {
  const size = (p.length + p.hp) * p.n;

  const adrs = new Uint8Array(32);

  setTree(adrs, tree);

  let node = xmssPkFromSig(p, hashes, leaf, signature.subarray(0, size), message, adrs);

  for (let j = 1; j < p.d; j++) {
    [leaf, tree] = parent(tree, p.hp);

    setLayer(adrs, j);

    setTree(adrs, tree);

    node = xmssPkFromSig(p, hashes, leaf, signature.subarray(j * size, (j + 1) * size), node, adrs);
  }

  return equal(node, pkRoot);
}

function forsSecret(hashes: Hashes, adrs: Uint8Array, index: number): Uint8Array {
  const skAdrs = hashes.derived(adrs, FORS_PRF);

  setTreeIndex(skAdrs, index);

  return hashes.prf(skAdrs);
}

function forsNode(p: Parameters, hashes: Hashes, i: number, z: number, adrs: Uint8Array): Uint8Array {
  if (z === 0) {
    const secret = forsSecret(hashes, adrs, i);

    setTreeHeight(adrs, 0);

    setTreeIndex(adrs, i);

    return hashes.f(adrs, secret);
  }

  const left = forsNode(p, hashes, 2 * i, z - 1, adrs);

  const right = forsNode(p, hashes, 2 * i + 1, z - 1, adrs);

  setTreeHeight(adrs, z);

  setTreeIndex(adrs, i);

  return hashes.h(adrs, left, right);
}

function forsSign(p: Parameters, hashes: Hashes, digest: Uint8Array, adrs: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];

  base2b(digest, p.a, p.k).forEach((index, i) => {
    out.push(forsSecret(hashes, adrs, (i << p.a) + index));

    for (let j = 0; j < p.a; j++) {
      out.push(forsNode(p, hashes, (i << (p.a - j)) + ((index >>> j) ^ 1), j, adrs));
    }
  });

  return out;
}

function forsPkFromSig(
  p: Parameters,
  hashes: Hashes,
  signature: Uint8Array,
  digest: Uint8Array,
  adrs: Uint8Array,
): Uint8Array {
  const n = p.n;

  const roots = base2b(digest, p.a, p.k).map((index, i) => {
    const offset = i * (p.a + 1) * n;

    setTreeHeight(adrs, 0);

    setTreeIndex(adrs, (i << p.a) + index);

    let node = hashes.f(adrs, signature.subarray(offset, offset + n));

    for (let j = 0; j < p.a; j++) {
      const sibling = signature.subarray(offset + (j + 1) * n, offset + (j + 2) * n);

      setTreeHeight(adrs, j + 1);

      if (((index >>> j) & 1) === 0) {
        setTreeIndex(adrs, treeIndex(adrs) >>> 1);

        node = hashes.h(adrs, node, sibling);
      } else {
        setTreeIndex(adrs, (treeIndex(adrs) - 1) >>> 1);

        node = hashes.h(adrs, sibling, node);
      }
    }

    return node;
  });

  return hashes.h(hashes.derived(adrs, FORS_ROOTS), ...roots);
}

export function root(p: Parameters, skSeed: Uint8Array, pkSeed: Uint8Array): Uint8Array {
  const adrs = new Uint8Array(32);

  setLayer(adrs, p.d - 1);

  return xmssNode(p, hashes(p, pkSeed, skSeed), 0, p.hp, adrs);
}

export function keygenInternal(
  skSeed: Uint8Array,
  skPrf: Uint8Array,
  pkSeed: Uint8Array,
  p: Parameters,
): [Uint8Array, Uint8Array] {
  const pkRoot = root(p, skSeed, pkSeed);

  return [concat(skSeed, skPrf, pkSeed, pkRoot), concat(pkSeed, pkRoot)];
}

// FIPS 205, Algorithm 19, lines 7 to 10: the FORS message digest, then the tree and leaf indices
// read big-endian and reduced to h - h/d and h/d bits. The tree index spans more than 32 bits in
// every parameter set.
function splitDigest(p: Parameters, digest: Uint8Array): [Uint8Array, Tree, number] {
  const mdSize = Math.ceil((p.k * p.a) / 8);

  const treeBits = p.h - p.h / p.d;

  const treeSize = Math.ceil(treeBits / 8);

  const leafBits = p.h / p.d;

  let high = 0;

  let low = 0;

  for (const byte of digest.subarray(mdSize, mdSize + treeSize)) {
    high = ((high << 8) | (low >>> 24)) >>> 0;

    low = ((low << 8) | byte) >>> 0;
  }

  let leaf = 0;

  for (const byte of digest.subarray(mdSize + treeSize, mdSize + treeSize + Math.ceil(leafBits / 8))) {
    leaf = (leaf << 8) | byte;
  }

  const tree = { high: (high & (2 ** (treeBits - 32) - 1)) >>> 0, low };

  return [digest.subarray(0, mdSize), tree, leaf & ((1 << leafBits) - 1)];
}

export function signInternal(message: Uint8Array, sk: Uint8Array, addrnd: Uint8Array, p: Parameters): Uint8Array {
  const n = p.n;

  const pkSeed = sk.subarray(2 * n, 3 * n);

  const pkRoot = sk.subarray(3 * n);

  const hashing = hashes(p, pkSeed, sk.subarray(0, n));

  const r = prfMsg(p, sk.subarray(n, 2 * n), addrnd, message);

  const [md, tree, leaf] = splitDigest(p, hMsg(p, r, pkSeed, pkRoot, message));

  const adrs = new Uint8Array(32);

  setTree(adrs, tree);

  setType(adrs, FORS_TREE);

  setKeyPair(adrs, leaf);

  const fors = forsSign(p, hashing, md, adrs);

  const pkFors = forsPkFromSig(p, hashing, concat(...fors), md, adrs);

  return concat(r, ...fors, ...htSign(p, hashing, pkFors, tree, leaf));
}

export function verifyInternal(message: Uint8Array, signature: Uint8Array, pk: Uint8Array, p: Parameters): boolean {
  const n = p.n;

  if (signature.length !== p.signatureSize || pk.length !== p.publicKeySize) {
    return false;
  }

  const pkSeed = pk.subarray(0, n);

  const pkRoot = pk.subarray(n);

  const hashing = hashes(p, pkSeed, new Uint8Array());

  const r = signature.subarray(0, n);

  const forsEnd = (1 + p.k * (1 + p.a)) * n;

  const [md, tree, leaf] = splitDigest(p, hMsg(p, r, pkSeed, pkRoot, message));

  const adrs = new Uint8Array(32);

  setTree(adrs, tree);

  setType(adrs, FORS_TREE);

  setKeyPair(adrs, leaf);

  const pkFors = forsPkFromSig(p, hashing, signature.subarray(n, forsEnd), md, adrs);

  return htVerify(p, hashing, pkFors, signature.subarray(forsEnd), tree, leaf, pkRoot);
}
