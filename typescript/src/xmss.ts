import { concat, equal, uint32, uint64, writeUint32 } from "./bytes.ts";
import { MerkleTree } from "./merkle.ts";
import {
  type FixedHash,
  type PrefixedHash,
  fixedSha256,
  fixedShake256,
  prefixedSha256,
  prefixedShake256,
} from "./primitives.ts";

const W = 16;

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

function fixed(p: Parameters, length: number, prefix: Uint8Array): FixedHash {
  return p.shake ? fixedShake256(length, prefix) : fixedSha256(length, prefix);
}

// The tweakable hashes of one key: F, H and PRF keyed by PUB_SEED, and PRF_keygen keyed by
// SK_SEED. Each keeps its constant prefix compressed once.
class Hashes {
  readonly p: Parameters;

  readonly pubSeed: Uint8Array;

  readonly #h: PrefixedHash;

  readonly #prf: PrefixedHash;

  readonly #keygen: PrefixedHash | null;

  readonly #chainPrf: FixedHash;

  readonly #chainF: FixedHash;

  readonly #mask: Uint8Array;

  constructor(p: Parameters, pubSeed: Uint8Array, skSeed: Uint8Array | null) {
    this.p = p;

    this.pubSeed = pubSeed;

    this.#h = prefixed(p, toByte(H, p.padding));

    this.#prf = prefixed(p, concat(toByte(PRF, p.padding), pubSeed));

    this.#keygen = skSeed === null ? null : prefixed(p, concat(toByte(PRF_KEYGEN, p.padding), skSeed));

    this.#chainPrf = fixed(p, p.padding + p.n + 32, concat(toByte(PRF, p.padding), pubSeed));

    this.#chainF = fixed(p, p.padding + 2 * p.n, toByte(F, p.padding));

    this.#mask = new Uint8Array(p.n);
  }

  prf(adrs: Uint8Array): Uint8Array {
    return this.#prf.digest(this.p.n, adrs);
  }

  // SP 800-208: PRF_keygen(SK_SEED, PUB_SEED || ADRS).
  keygen(adrs: Uint8Array): Uint8Array {
    return (this.#keygen as PrefixedHash).digest(this.p.n, this.pubSeed, adrs);
  }

  h(key: Uint8Array, left: Uint8Array, right: Uint8Array): Uint8Array {
    return this.#h.digest(this.p.n, key, left, right);
  }

  // RFC 8391 chain: x = F(KEY, x XOR BM) with KEY and BM from PRF(PUB_SEED, ADRS). PRF writes the
  // key straight into the F message, and F writes the new value over its own input.
  chain(x: Uint8Array, start: number, steps: number, adrs: Uint8Array): Uint8Array {
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

    setWord(adrs, 6, start + steps - 1);

    setWord(adrs, 7, 1);

    return value.slice();
  }
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

// SP 800-208: secret chain values come from PRF_keygen(SK_SEED, PUB_SEED || ADRS) with the hash
// and key-and-mask words cleared.
function wotsSecrets(hashes: Hashes, adrs: Uint8Array): Uint8Array[] {
  const secrets: Uint8Array[] = [];

  for (let i = 0; i < hashes.p.length; i++) {
    setWord(adrs, 5, i);

    setWord(adrs, 6, 0);

    setWord(adrs, 7, 0);

    secrets.push(hashes.keygen(adrs));
  }

  return secrets;
}

function wotsPublic(hashes: Hashes, adrs: Uint8Array): Uint8Array[] {
  return wotsSecrets(hashes, adrs).map((secret, i) => {
    setWord(adrs, 5, i);

    return hashes.chain(secret, 0, W - 1, adrs);
  });
}

function wotsSign(hashes: Hashes, message: Uint8Array, adrs: Uint8Array): Uint8Array[] {
  const digits = wotsDigits(message);

  return wotsSecrets(hashes, adrs).map((secret, i) => {
    setWord(adrs, 5, i);

    return hashes.chain(secret, 0, digits[i], adrs);
  });
}

function wotsPublicFromSignature(
  hashes: Hashes,
  signature: Uint8Array,
  message: Uint8Array,
  adrs: Uint8Array,
): Uint8Array[] {
  const n = hashes.p.n;

  return wotsDigits(message).map((digit, i) => {
    setWord(adrs, 5, i);

    return hashes.chain(signature.subarray(i * n, (i + 1) * n), digit, W - 1 - digit, adrs);
  });
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

function ltree(hashes: Hashes, values: Uint8Array[], adrs: Uint8Array): Uint8Array {
  setWord(adrs, 5, 0);

  for (let height = 0; values.length > 1; height++) {
    const paired: Uint8Array[] = [];

    for (let i = 0; i < values.length >>> 1; i++) {
      setWord(adrs, 6, i);

      paired.push(randHash(hashes, values[2 * i], values[2 * i + 1], adrs));
    }

    if (values.length % 2 === 1) {
      paired.push(values[values.length - 1]);
    }

    values = paired;

    setWord(adrs, 5, height + 1);
  }

  return values[0];
}

function leaf(hashes: Hashes, layer: number, tree: bigint, index: number): Uint8Array {
  const ots = address(layer, tree, OTS);

  setWord(ots, 4, index);

  const values = wotsPublic(hashes, ots);

  const lt = address(layer, tree, LTREE);

  setWord(lt, 4, index);

  return ltree(hashes, values, lt);
}

function subtree(hashes: Hashes, layer: number, tree: bigint): MerkleTree {
  const combine = (z: number, j: number, left: Uint8Array, right: Uint8Array) => {
    const adrs = address(layer, tree, HASH_TREE);

    setWord(adrs, 5, z);

    setWord(adrs, 6, j);

    return randHash(hashes, left, right, adrs);
  };

  return new MerkleTree(hashes.p.treeHeight, (index) => leaf(hashes, layer, tree, index), combine);
}

function computeRoot(
  hashes: Hashes,
  node: Uint8Array,
  index: number,
  auth: Uint8Array,
  layer: number,
  tree: bigint,
): Uint8Array {
  const adrs = address(layer, tree, HASH_TREE);

  const n = hashes.p.n;

  for (let k = 0; k < hashes.p.treeHeight; k++) {
    setWord(adrs, 5, k);

    setWord(adrs, 6, index >>> (k + 1));

    const sibling = auth.subarray(k * n, (k + 1) * n);

    node = ((index >>> k) & 1) === 1 ? randHash(hashes, sibling, node, adrs) : randHash(hashes, node, sibling, adrs);
  }

  return node;
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

  const hashes = new Hashes(p, publicKey.subarray(4 + n), null);

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

    node = computeRoot(hashes, ltree(hashes, values, lt), leafIndex, auth, layer, index);

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

  constructor(p: Parameters, skSeed: Uint8Array, skPrf: Uint8Array, pubSeed: Uint8Array) {
    this.p = p;

    this.#skPrf = skPrf;

    this.#hashes = new Hashes(p, pubSeed, skSeed);

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

    let node = messageDigest(p, r, this.root, index, message);

    const out = [uint64(index).subarray(8 - p.indexSize), r];

    const mask = (1n << BigInt(p.treeHeight)) - 1n;

    for (let layer = 0; layer < p.d; layer++) {
      const leafIndex = Number(index & mask);

      index >>= BigInt(p.treeHeight);

      const ots = address(layer, index, OTS);

      setWord(ots, 4, leafIndex);

      out.push(...wotsSign(this.#hashes, node, ots));

      const tree = this.#tree(layer, index);

      out.push(...tree.authPath(leafIndex));

      node = tree.root;
    }

    return concat(...out);
  }
}
