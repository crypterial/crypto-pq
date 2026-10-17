import { concat, wipe, writeUint32 } from "./bytes.ts";
import { permute } from "./keccak-permute.ts";
import { storeLane, xorLane } from "./keccak.ts";
import {
  blocks,
  copyWords,
  hmac,
  loadWords,
  messageBytes,
  messageWords,
  sha256,
  sha512,
  shake256,
  storeWords,
} from "./primitives.ts";
import { block256, block256x2, block512, block512x2 } from "./sha2-rounds.ts";
import { IV_256, IV_512, compress256, compress512, wipeSha2Lanes } from "./sha2.ts";

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
function setTree(adrs: Uint8Array, high: number, low: number): void {
  writeUint32(adrs, 4, 0);

  writeUint32(adrs, 8, high);

  writeUint32(adrs, 12, low);
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

type Indices = number | ArrayLike<number>;

function indexOf(base: Indices, j: number): number {
  return typeof base === "number" ? base + j : base[j];
}

// FIPS 205, section 11: F, H, T and PRF bound to one public seed, and the batched forms that the
// trees spend nearly all their time in.
abstract class Hashes {
  readonly n: number;

  readonly len: number;

  // The WOTS+ digits of the message that a layer signs.
  readonly digits: Uint8Array;

  readonly #scratch = new Uint8Array(32);

  constructor(n: number) {
    this.n = n;

    this.len = 2 * n + 3;

    this.digits = new Uint8Array(this.len);
  }

  // F of the n bytes at message[at], into out at offset.
  abstract f(adrs: Uint8Array, message: Uint8Array, at: number, out: Uint8Array, offset: number): void;

  // T of values (len or k values), into out at offset.
  abstract t(adrs: Uint8Array, values: Uint8Array, out: Uint8Array, offset: number): void;

  // PRF of SK.seed, into out at offset.
  abstract prf(adrs: Uint8Array, out: Uint8Array, offset: number): void;

  // Runs chain i of the WOTS+ key in adrs from the value inputs[at + i n ..] at step from[i] to the
  // end, into out[i n ..], for every i.
  abstract chains(adrs: Uint8Array, inputs: Uint8Array, at: number, from: ArrayLike<number>, out: Uint8Array): void;

  // The WOTS+ public key of the key pair in adrs (type WOTS_HASH), compressed by T_len, into
  // out[offset]. With digits, the chain values where they stop are the WOTS+ signature of the
  // message they encode, written to signature from at on.
  abstract wotsLeaf(
    adrs: Uint8Array,
    out: Uint8Array,
    offset: number,
    digits: ArrayLike<number> | null,
    signature: Uint8Array | null,
    at: number,
  ): void;

  // FORS leaves F(PRF(i)) of the count tree indices i from base on (adrs of type FORS_TREE), into out.
  abstract forsLeaves(adrs: Uint8Array, base: number, count: number, out: Uint8Array): void;

  // The count parents at height of the 2 count nodes from nodes[0] on, n bytes each, with the tree
  // indices from base on, or the ones listed, into out from offset on; out may be nodes, as each pair
  // of nodes is read before its parent is written.
  abstract level(
    adrs: Uint8Array,
    height: number,
    base: Indices,
    nodes: Uint8Array,
    count: number,
    out: Uint8Array,
    offset: number,
  ): void;

  // Clears the copy of SK.seed and the scratch that held secret chain values.
  abstract clear(): void;

  // A scratch address for the secret and public-key derivations, which never nest.
  derived(adrs: Uint8Array, type: number): Uint8Array {
    const out = this.#scratch;

    out.set(adrs);

    setType(out, type);

    setKeyPair(out, keyPair(adrs));

    return out;
  }
}

// After the first SHA-2 block, PK.seed and its zero padding, which is compressed once per key, a
// block starts with ADRSc, the 22-byte compressed address: words 0 to 4 and the high half of word 5.
// Every message after it is therefore shifted by two bytes against the word boundaries.
function addressWords(adrs: Uint8Array, w: Int32Array): void {
  w[0] = (adrs[3] << 24) | (adrs[8] << 16) | (adrs[9] << 8) | adrs[10];

  w[1] = (adrs[11] << 24) | (adrs[12] << 16) | (adrs[13] << 8) | adrs[14];

  w[2] = (adrs[15] << 24) | (adrs[19] << 16) | (adrs[20] << 8) | adrs[21];

  w[3] = (adrs[22] << 24) | (adrs[23] << 16) | (adrs[24] << 8) | adrs[25];

  w[4] = (adrs[26] << 24) | (adrs[27] << 16) | (adrs[28] << 8) | adrs[29];
}

// The last two address bytes, as they start word 5.
function addressTail(adrs: Uint8Array): number {
  return (adrs[30] << 24) | (adrs[31] << 16);
}

// The SHA-2 instances on words. Chains, FORS leaves and tree levels run two independent SHA-256
// computations at once (block256x2); H and T use SHA-512 when n is 24 or 32.
class Sha2Hashes extends Hashes {
  readonly #wide: boolean;

  // The bytes before the blocks of H and T: the first block of SHA-512 or SHA-256.
  readonly #prefix: number;

  readonly #seed256 = new Int32Array(8);

  readonly #seed512 = new Int32Array(16);

  readonly #sk: Int32Array;

  // Blocks of F and PRF (n-byte messages), of H (2n bytes) and of T_len, two of each for block256x2.
  readonly #fw: Int32Array;

  readonly #fx: Int32Array;

  readonly #hw: Int32Array;

  readonly #hx: Int32Array;

  readonly #tw: Int32Array;

  readonly #tk: Int32Array;

  readonly #s = new Int32Array(16);

  readonly #t = new Int32Array(16);

  readonly #values: Int32Array;

  constructor(p: Parameters, pkSeed: Uint8Array, skSeed: Uint8Array) {
    super(p.n);

    const n = p.n;

    const first = new Uint8Array(128);

    first.set(pkSeed);

    this.#wide = n > 16;

    this.#prefix = this.#wide ? 128 : 64;

    this.#seed256.set(IV_256);

    compress256(this.#seed256, first, 0);

    if (this.#wide) {
      this.#seed512.set(IV_512);

      compress512(this.#seed512, first, 0);
    }

    this.#sk = new Int32Array(n >>> 2);

    if (skSeed.length === n) {
      loadWords(skSeed, 0, n >>> 2, this.#sk);
    }

    this.#fw = blocks(false, 64, n);

    this.#fx = blocks(false, 64, n);

    this.#hw = blocks(this.#wide, this.#prefix, 2 * n);

    this.#hx = blocks(this.#wide, this.#prefix, 2 * n);

    this.#tw = blocks(this.#wide, this.#prefix, this.len * n);

    this.#tk = blocks(this.#wide, this.#prefix, p.k * n);

    this.#values = new Int32Array(this.len * (n >>> 2));
  }

  f(adrs: Uint8Array, message: Uint8Array, at: number, out: Uint8Array, offset: number): void {
    const w = this.#fw;

    addressWords(adrs, w);

    messageBytes(w, addressTail(adrs), message, at, this.n);

    storeWords(this.#run(w, false), this.n >>> 2, out, offset);
  }

  t(adrs: Uint8Array, values: Uint8Array, out: Uint8Array, offset: number): void {
    const w = values.length === this.len * this.n ? this.#tw : this.#tk;

    addressWords(adrs, w);

    messageBytes(w, addressTail(adrs), values, 0, values.length);

    storeWords(this.#run(w, this.#wide), this.n >>> 2, out, offset);
  }

  prf(adrs: Uint8Array, out: Uint8Array, offset: number): void {
    const w = this.#fw;

    addressWords(adrs, w);

    messageWords(w, addressTail(adrs), this.#sk, 0, this.n >>> 2);

    storeWords(this.#run(w, false), this.n >>> 2, out, offset);
  }

  // Two lanes take the chains in turn: when the chain in one lane ends, the next waiting chain takes
  // its place, so the lanes stay busy whatever the lengths.
  chains(adrs: Uint8Array, inputs: Uint8Array, at: number, from: ArrayLike<number>, out: Uint8Array): void {
    const n = this.n;

    const count = n >>> 2;

    const seed = this.#seed256;

    const w = this.#fw;

    const x = this.#fx;

    const s = this.#s;

    const t = this.#t;

    let next = 0;

    // The chain in each lane, or -1, and its next step.
    let i = -1;

    let j = 0;

    let k = -1;

    let l = 0;

    addressWords(adrs, w);

    copyWords(w, 0, x, 0, 4);

    for (let b = 0; b < this.len * n; b++) {
      out[b] = inputs[at + b];
    }

    for (;;) {
      for (; i < 0 && next < this.len; next++) {
        if (from[next] < W - 1) {
          i = next;

          j = from[next];

          loadWords(inputs, at + i * n, count, s);

          w[4] = i << 16;
        }
      }

      for (; k < 0 && next < this.len; next++) {
        if (from[next] < W - 1) {
          k = next;

          l = from[next];

          loadWords(inputs, at + k * n, count, t);

          x[4] = k << 16;
        }
      }

      if (i < 0 && k < 0) {
        return;
      }

      if (i >= 0) {
        messageWords(w, j << 16, s, 0, count);
      }

      if (k >= 0) {
        messageWords(x, l << 16, t, 0, count);
      }

      if (i >= 0 && k >= 0) {
        block256x2(seed, w, 0, s, seed, x, 0, t);
      } else if (i >= 0) {
        block256(seed, w, 0, s);
      } else {
        block256(seed, x, 0, t);
      }

      if (i >= 0 && ++j === W - 1) {
        storeWords(s, count, out, i * n);

        i = -1;
      }

      if (k >= 0 && ++l === W - 1) {
        storeWords(t, count, out, k * n);

        k = -1;
      }
    }
  }

  wotsLeaf(
    adrs: Uint8Array,
    out: Uint8Array,
    offset: number,
    digits: ArrayLike<number> | null,
    signature: Uint8Array | null,
    at: number,
  ): void {
    const n = this.n;

    const count = n >>> 2;

    const len = this.len;

    const seed = this.#seed256;

    const sk = this.#sk;

    const w = this.#fw;

    const x = this.#fx;

    const s = this.#s;

    const t = this.#t;

    const values = this.#values;

    addressWords(adrs, w);

    copyWords(w, 0, x, 0, 4);

    const hashType = w[2];

    const prfType = hashType | (WOTS_PRF << 16);

    for (let c = 0; c < len; c += 2) {
      const pair = c + 1 < len;

      w[2] = prfType;

      x[2] = prfType;

      w[4] = c << 16;

      x[4] = (c + 1) << 16;

      messageWords(w, 0, sk, 0, count);

      messageWords(x, 0, sk, 0, count);

      if (pair) {
        block256x2(seed, w, 0, s, seed, x, 0, t);
      } else {
        block256(seed, w, 0, s);
      }

      w[2] = hashType;

      x[2] = hashType;

      for (let j = 0; ; j++) {
        if (digits !== null) {
          if (digits[c] === j) {
            storeWords(s, count, signature as Uint8Array, at + c * n);
          }

          if (pair && digits[c + 1] === j) {
            storeWords(t, count, signature as Uint8Array, at + (c + 1) * n);
          }
        }

        if (j === W - 1) {
          break;
        }

        messageWords(w, j << 16, s, 0, count);

        if (pair) {
          messageWords(x, j << 16, t, 0, count);

          block256x2(seed, w, 0, s, seed, x, 0, t);
        } else {
          block256(seed, w, 0, s);
        }
      }

      for (let k = 0; k < count; k++) {
        values[c * count + k] = s[k];

        if (pair) {
          values[(c + 1) * count + k] = t[k];
        }
      }
    }

    const pk = this.derived(adrs, WOTS_PK);

    const tw = this.#tw;

    addressWords(pk, tw);

    messageWords(tw, addressTail(pk), values, 0, len * count);

    storeWords(this.#run(tw, this.#wide), count, out, offset);
  }

  forsLeaves(adrs: Uint8Array, base: number, count: number, out: Uint8Array): void {
    const n = this.n;

    const words = n >>> 2;

    const seed = this.#seed256;

    const sk = this.#sk;

    const w = this.#fw;

    const x = this.#fx;

    const s = this.#s;

    const t = this.#t;

    addressWords(adrs, w);

    copyWords(w, 0, x, 0, 4);

    const treeType = w[2];

    const prfType = (treeType & ~0xff0000) | (FORS_PRF << 16);

    for (let i = 0; i < count; i += 2) {
      const a = base + i;

      const b = a + 1;

      w[2] = prfType;

      x[2] = prfType;

      w[4] = a >>> 16;

      x[4] = b >>> 16;

      messageWords(w, a << 16, sk, 0, words);

      messageWords(x, b << 16, sk, 0, words);

      block256x2(seed, w, 0, s, seed, x, 0, t);

      w[2] = treeType;

      x[2] = treeType;

      messageWords(w, a << 16, s, 0, words);

      messageWords(x, b << 16, t, 0, words);

      block256x2(seed, w, 0, s, seed, x, 0, t);

      storeWords(s, words, out, i * n);

      storeWords(t, words, out, (i + 1) * n);
    }
  }

  level(
    adrs: Uint8Array,
    height: number,
    base: Indices,
    nodes: Uint8Array,
    count: number,
    out: Uint8Array,
    offset: number,
  ): void {
    const n = this.n;

    const words = n >>> 2;

    const w = this.#hw;

    const x = this.#hx;

    const s = this.#s;

    const t = this.#t;

    setTreeHeight(adrs, height);

    setTreeIndex(adrs, 0);

    addressWords(adrs, w);

    copyWords(w, 0, x, 0, 4);

    for (let j = 0; j < count; j += 2) {
      const index = indexOf(base, j);

      w[4] = (height << 16) | (index >>> 16);

      messageBytes(w, index << 16, nodes, 2 * j * n, 2 * n);

      if (j + 1 < count) {
        const next = indexOf(base, j + 1);

        x[4] = (height << 16) | (next >>> 16);

        messageBytes(x, next << 16, nodes, 2 * (j + 1) * n, 2 * n);

        if (this.#wide) {
          block512x2(this.#seed512, w, 0, s, this.#seed512, x, 0, t);
        } else {
          block256x2(this.#seed256, w, 0, s, this.#seed256, x, 0, t);
        }

        storeWords(t, words, out, offset + (j + 1) * n);
      } else if (this.#wide) {
        block512(this.#seed512, w, 0, s);
      } else {
        block256(this.#seed256, w, 0, s);
      }

      storeWords(s, words, out, offset + j * n);
    }
  }

  clear(): void {
    wipe(this.#sk, this.#fw, this.#fx, this.#hw, this.#hx, this.#tw, this.#tk, this.#s, this.#t, this.#values);

    wipeSha2Lanes();
  }

  // Compresses the blocks of w from the state after the prefix block; the state's first n bytes are
  // the hash.
  #run(w: Int32Array, wide: boolean): Int32Array {
    const s = this.#s;

    if (wide) {
      block512(this.#seed512, w, 0, s);

      for (let offset = 32; offset < w.length; offset += 32) {
        block512(s, w, offset, s);
      }
    } else {
      block256(this.#seed256, w, 0, s);

      for (let offset = 16; offset < w.length; offset += 16) {
        block256(s, w, offset, s);
      }
    }

    return s;
  }
}

const SHAKE_LANES = 17;

function swap32(value: number): number {
  return ((value & 0xff) << 24) | ((value & 0xff00) << 8) | ((value >>> 8) & 0xff00) | (value >>> 24);
}

function readLittleEndian(data: Uint8Array, offset: number): number {
  return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
}

// XORs count lanes of data, from offset on, into the state from lane `lane` on.
function xorLanes(s: Uint32Array, lane: number, data: Uint8Array, offset: number, count: number): void {
  for (let i = 0; i < count; i++) {
    xorLane(s, lane + i, readLittleEndian(data, offset + 8 * i), readLittleEndian(data, offset + 8 * i + 4));
  }
}

// The SHAKE256 instances on the bit-interleaved Keccak state: PK.seed, ADRS and every n-byte value
// fill whole lanes, so F, H and PRF are one permutation of a state built lane by lane, and a chain
// passes its value from one call to the next without converting it to bytes.
class ShakeHashes extends Hashes {
  readonly #state = new Uint32Array(50);

  // PK.seed and the padding of an F or PRF input (2n + 32 bytes), and of an H input (3n + 32 bytes).
  readonly #base = new Uint32Array(50);

  readonly #baseH = new Uint32Array(50);

  readonly #pk: Uint32Array;

  readonly #sk: Uint32Array;

  // Lanes 0 to 2 of the address: layer, tree, type and key pair.
  readonly #address = new Uint32Array(6);

  readonly #value: Uint32Array;

  readonly #values: Uint32Array;

  constructor(p: Parameters, pkSeed: Uint8Array, skSeed: Uint8Array) {
    super(p.n);

    const n = p.n;

    const lanes = n >>> 3;

    this.#pk = new Uint32Array(2 * lanes);

    this.#sk = new Uint32Array(2 * lanes);

    xorLanes(this.#pk, 0, pkSeed, 0, lanes);

    if (skSeed.length === n) {
      xorLanes(this.#sk, 0, skSeed, 0, lanes);
    }

    for (const [base, length] of [
      [this.#base, 2 * n + 32],
      [this.#baseH, 3 * n + 32],
    ] as const) {
      base.set(this.#pk);

      xorLane(base, length >>> 3, 0x1f, 0);

      xorLane(base, SHAKE_LANES - 1, 0, 0x80000000);
    }

    this.#value = new Uint32Array(2 * lanes);

    this.#values = new Uint32Array(2 * lanes * this.len);
  }

  f(adrs: Uint8Array, message: Uint8Array, at: number, out: Uint8Array, offset: number): void {
    const s = this.#start(this.#base, adrs);

    xorLanes(s, (this.n >>> 3) + 4, message, at, this.n >>> 3);

    permute(s);

    this.#store(out, offset);
  }

  // SHAKE256(PK.seed || ADRS || values), absorbed lane by lane.
  t(adrs: Uint8Array, values: Uint8Array, out: Uint8Array, offset: number): void {
    const s = this.#state;

    s.fill(0);

    s.set(this.#pk);

    let lane = this.#absorbAddress(s, this.n >>> 3, adrs);

    for (let i = 0; i < values.length; i += 8, lane++) {
      if (lane === SHAKE_LANES) {
        permute(s);

        lane = 0;
      }

      xorLane(s, lane, readLittleEndian(values, i), readLittleEndian(values, i + 4));
    }

    if (lane === SHAKE_LANES) {
      permute(s);

      lane = 0;
    }

    xorLane(s, lane, 0x1f, 0);

    xorLane(s, SHAKE_LANES - 1, 0, 0x80000000);

    permute(s);

    this.#store(out, offset);
  }

  prf(adrs: Uint8Array, out: Uint8Array, offset: number): void {
    this.#absorbWords(this.#start(this.#base, adrs), this.#sk);

    this.#store(out, offset);
  }

  chains(adrs: Uint8Array, inputs: Uint8Array, at: number, from: ArrayLike<number>, out: Uint8Array): void {
    const n = this.n;

    const lanes = n >>> 3;

    const value = this.#value;

    this.#loadAddress(adrs);

    for (let c = 0; c < this.len; c++) {
      value.fill(0);

      xorLanes(value, 0, inputs, at + c * n, lanes);

      for (let j = from[c]; j < W - 1; j++) {
        this.#step(swap32(c), swap32(j), value);

        this.#keep(value);
      }

      for (let i = 0; i < lanes; i++) {
        storeLane(value, i, out, c * n + 8 * i);
      }
    }
  }

  wotsLeaf(
    adrs: Uint8Array,
    out: Uint8Array,
    offset: number,
    digits: ArrayLike<number> | null,
    signature: Uint8Array | null,
    at: number,
  ): void {
    const n = this.n;

    const lanes = n >>> 3;

    const words = 2 * lanes;

    const address = this.#address;

    const value = this.#value;

    const values = this.#values;

    this.#loadAddress(adrs);

    const hashEven = address[4];

    const hashOdd = address[5];

    xorLane(address, 2, WOTS_PRF << 24, 0);

    const prfEven = address[4];

    const prfOdd = address[5];

    for (let c = 0; c < this.len; c++) {
      const chain = swap32(c);

      address[4] = prfEven;

      address[5] = prfOdd;

      this.#step(chain, 0, this.#sk);

      address[4] = hashEven;

      address[5] = hashOdd;

      this.#keep(value);

      for (let j = 0; ; j++) {
        if (digits !== null && digits[c] === j) {
          for (let i = 0; i < lanes; i++) {
            storeLane(value, i, signature as Uint8Array, at + c * n + 8 * i);
          }
        }

        if (j === W - 1) {
          break;
        }

        this.#step(chain, swap32(j), value);

        this.#keep(value);
      }

      values.set(value, c * words);
    }

    const s = this.#state;

    s.fill(0);

    s.set(this.#pk);

    let lane = lanes;

    lane = this.#absorbAddress(s, lane, this.derived(adrs, WOTS_PK));

    for (let i = 0; i < values.length; i += 2, lane++) {
      if (lane === SHAKE_LANES) {
        permute(s);

        lane = 0;
      }

      s[2 * lane] ^= values[i];

      s[2 * lane + 1] ^= values[i + 1];
    }

    if (lane === SHAKE_LANES) {
      permute(s);

      lane = 0;
    }

    xorLane(s, lane, 0x1f, 0);

    xorLane(s, SHAKE_LANES - 1, 0, 0x80000000);

    permute(s);

    for (let i = 0; i < lanes; i++) {
      storeLane(s, i, out, offset + 8 * i);
    }
  }

  forsLeaves(adrs: Uint8Array, base: number, count: number, out: Uint8Array): void {
    const n = this.n;

    const lanes = n >>> 3;

    const address = this.#address;

    const value = this.#value;

    this.#loadAddress(adrs);

    const treeEven = address[4];

    const treeOdd = address[5];

    xorLane(address, 2, (FORS_TREE ^ FORS_PRF) << 24, 0);

    const prfEven = address[4];

    const prfOdd = address[5];

    for (let i = 0; i < count; i++) {
      const index = swap32(base + i);

      address[4] = prfEven;

      address[5] = prfOdd;

      this.#step(0, index, this.#sk);

      this.#keep(value);

      address[4] = treeEven;

      address[5] = treeOdd;

      this.#step(0, index, value);

      for (let k = 0; k < lanes; k++) {
        storeLane(this.#state, k, out, i * n + 8 * k);
      }
    }
  }

  // H on lanes, one parent at a time.
  level(
    adrs: Uint8Array,
    height: number,
    base: Indices,
    nodes: Uint8Array,
    count: number,
    out: Uint8Array,
    offset: number,
  ): void {
    const n = this.n;

    const lanes = n >>> 3;

    setTreeHeight(adrs, height);

    for (let j = 0; j < count; j++) {
      setTreeIndex(adrs, indexOf(base, j));

      const s = this.#start(this.#baseH, adrs);

      xorLanes(s, lanes + 4, nodes, 2 * j * n, lanes);

      xorLanes(s, 2 * lanes + 4, nodes, (2 * j + 1) * n, lanes);

      permute(s);

      this.#store(out, offset + j * n);
    }
  }

  clear(): void {
    wipe(this.#sk, this.#state, this.#value, this.#values);
  }

  #loadAddress(adrs: Uint8Array): void {
    const address = this.#address;

    address.fill(0);

    xorLanes(address, 0, adrs, 0, 3);
  }

  #absorbAddress(s: Uint32Array, lane: number, adrs: Uint8Array): number {
    xorLanes(s, lane, adrs, 0, 4);

    return lane + 4;
  }

  #start(base: Uint32Array, adrs: Uint8Array): Uint32Array {
    const s = this.#state;

    s.set(base);

    this.#absorbAddress(s, this.n >>> 3, adrs);

    return s;
  }

  #absorbWords(s: Uint32Array, message: Uint32Array): void {
    const first = 2 * ((this.n >>> 3) + 4);

    for (let k = 0; k < message.length; k++) {
      s[first + k] ^= message[k];
    }

    permute(s);
  }

  // F or PRF: base, address lanes 0 to 2, lane 3 from its two little-endian words, then the message.
  #step(lo: number, hi: number, message: Uint32Array): void {
    const s = this.#state;

    const address = this.#address;

    const lane = this.n >>> 3;

    s.set(this.#base);

    for (let k = 0; k < 6; k++) {
      s[2 * lane + k] ^= address[k];
    }

    xorLane(s, lane + 3, lo, hi);

    this.#absorbWords(s, message);
  }

  // Copies the last hash, the first n bytes of the state, to value.
  #keep(value: Uint32Array): void {
    for (let k = 0; k < value.length; k++) {
      value[k] = this.#state[k];
    }
  }

  // Writes the last hash, the first n bytes of the state, into out at offset.
  #store(out: Uint8Array, offset: number): void {
    for (let i = 0; i < this.n >>> 3; i++) {
      storeLane(this.#state, i, out, offset + 8 * i);
    }
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

  return hmac(p.n === 16 ? 32 : 64, skPrf, optRand, message).slice(0, p.n);
}

// FIPS 205, Algorithm 4: the first count digits of base 2^b of data, big-endian, into out.
function base2b(data: Uint8Array, b: number, count: number, out: Int32Array | Uint8Array): void {
  let total = 0;

  let bits = 0;

  let offset = 0;

  for (let i = 0; i < count; i++) {
    while (bits < b) {
      total = ((total << 8) | data[offset++]) & 0xffffff;

      bits += 8;
    }

    bits -= b;

    out[i] = (total >>> bits) & ((1 << b) - 1);
  }
}

// The WOTS+ digits of the n-byte message at message[at], then of its checksum (FIPS 205, Algorithm
// 7), into out.
function wotsDigits(p: Parameters, message: Uint8Array, at: number, out: Uint8Array): void {
  let checksum = 0;

  for (let i = 0; i < p.n; i++) {
    out[2 * i] = message[at + i] >>> 4;

    out[2 * i + 1] = message[at + i] & 15;

    checksum += 2 * (W - 1) - out[2 * i] - out[2 * i + 1];
  }

  checksum <<= 4;

  out[2 * p.n] = (checksum >>> 12) & 15;

  out[2 * p.n + 1] = (checksum >>> 8) & 15;

  out[2 * p.n + 2] = (checksum >>> 4) & 15;
}

// Reduces the 2^height nodes from nodes[0] on, n bytes each, to their root, in place at nodes[0];
// the tree indices of the bottom level start at base. With auth, the siblings on the path of leaf
// index are copied to it from offset on.
function reduce(
  hashes: Hashes,
  adrs: Uint8Array,
  nodes: Uint8Array,
  height: number,
  base: number,
  index: number,
  auth: Uint8Array | null,
  offset: number,
): void {
  const n = hashes.n;

  for (let z = 0; z < height; z++) {
    if (auth !== null) {
      const sibling = ((index >>> z) ^ 1) * n;

      for (let i = 0; i < n; i++) {
        auth[offset + z * n + i] = nodes[sibling + i];
      }
    }

    hashes.level(adrs, z + 1, base >>> (z + 1), nodes, 1 << (height - z - 1), nodes, 0);
  }
}

// The root of the XMSS tree at the layer and tree in adrs, computed from all of its leaves in nodes,
// at nodes[0]. With a signature buffer, the WOTS+ signature of the n-byte message at message[at] by
// leaf index, then that leaf's authentication path, are written to it from offset on; the message
// may lie in nodes.
function xmssTree(
  p: Parameters,
  hashes: Hashes,
  adrs: Uint8Array,
  message: Uint8Array | null,
  at: number,
  index: number,
  signature: Uint8Array | null,
  offset: number,
  nodes: Uint8Array,
): void {
  const n = p.n;

  const digits = message === null ? null : hashes.digits;

  if (message !== null) {
    wotsDigits(p, message, at, hashes.digits);
  }

  setType(adrs, WOTS_HASH);

  for (let i = 0; i < 1 << p.hp; i++) {
    setKeyPair(adrs, i);

    hashes.wotsLeaf(adrs, nodes, i * n, i === index ? digits : null, signature, offset);
  }

  setType(adrs, TREE);

  reduce(hashes, adrs, nodes, p.hp, 0, index, signature, offset + p.length * n);
}

// The root of the XMSS tree in adrs from the signature at signature[offset] of the n-byte message at
// message[at] by leaf index, at pair[0], where it climbs beside each sibling of the path; the message
// may lie in pair.
function xmssPkFromSig(
  p: Parameters,
  hashes: Hashes,
  index: number,
  signature: Uint8Array,
  offset: number,
  message: Uint8Array,
  at: number,
  adrs: Uint8Array,
  values: Uint8Array,
  pair: Uint8Array,
): void {
  const n = p.n;

  wotsDigits(p, message, at, hashes.digits);

  setType(adrs, WOTS_HASH);

  setKeyPair(adrs, index);

  hashes.chains(adrs, signature, offset, hashes.digits, values);

  hashes.t(hashes.derived(adrs, WOTS_PK), values, pair, (index & 1) * n);

  setType(adrs, TREE);

  for (let k = 0; k < p.hp; k++) {
    const sibling = offset + (p.length + k) * n;

    const place = (1 - ((index >>> k) & 1)) * n;

    for (let i = 0; i < n; i++) {
      pair[place + i] = signature[sibling + i];
    }

    const parent = index >>> (k + 1);

    hashes.level(adrs, k + 1, parent, pair, 1, pair, (parent & 1) * n);
  }
}

// Each layer signs the root of the layer below, which the build of a tree leaves in nodes. The tree
// address is kept as its two 32-bit halves.
function htSign(
  p: Parameters,
  hashes: Hashes,
  message: Uint8Array,
  position: Position,
  out: Uint8Array,
  offset: number,
  nodes: Uint8Array,
): void {
  const size = (p.length + p.hp) * p.n;

  const adrs = new Uint8Array(32);

  let { high, low, leaf } = position;

  for (let j = 0; j < p.d; j++) {
    if (j > 0) {
      leaf = low & ((1 << p.hp) - 1);

      low = ((low >>> p.hp) | (high << (32 - p.hp))) >>> 0;

      high >>>= p.hp;
    }

    setLayer(adrs, j);

    setTree(adrs, high, low);

    xmssTree(p, hashes, adrs, j === 0 ? message : nodes, 0, leaf, out, offset + j * size, nodes);
  }
}

function htVerify(
  p: Parameters,
  hashes: Hashes,
  message: Uint8Array,
  signature: Uint8Array,
  offset: number,
  position: Position,
  pkRoot: Uint8Array,
): boolean {
  const n = p.n;

  const size = (p.length + p.hp) * n;

  const adrs = new Uint8Array(32);

  const values = new Uint8Array(p.length * n);

  const pair = new Uint8Array(2 * n);

  let { high, low, leaf } = position;

  for (let j = 0; j < p.d; j++) {
    if (j > 0) {
      leaf = low & ((1 << p.hp) - 1);

      low = ((low >>> p.hp) | (high << (32 - p.hp))) >>> 0;

      high >>>= p.hp;
    }

    setLayer(adrs, j);

    setTree(adrs, high, low);

    xmssPkFromSig(p, hashes, leaf, signature, offset + j * size, j === 0 ? message : pair, 0, adrs, values, pair);
  }

  let difference = 0;

  for (let i = 0; i < n; i++) {
    difference |= pair[i] ^ pkRoot[i];
  }

  return difference === 0;
}

// Writes the FORS signature of digest to out from offset on and returns the FORS public key, made
// from the roots of the k trees; each tree is built in nodes.
function forsSign(
  p: Parameters,
  hashes: Hashes,
  digest: Uint8Array,
  adrs: Uint8Array,
  out: Uint8Array,
  offset: number,
  nodes: Uint8Array,
): Uint8Array {
  const n = p.n;

  const indices = new Int32Array(p.k);

  const roots = new Uint8Array(p.k * n);

  base2b(digest, p.a, p.k, indices);

  for (let i = 0; i < p.k; i++) {
    const at = offset + i * (p.a + 1) * n;

    const base = i << p.a;

    const secret = hashes.derived(adrs, FORS_PRF);

    setTreeIndex(secret, base + indices[i]);

    hashes.prf(secret, out, at);

    hashes.forsLeaves(adrs, base, 1 << p.a, nodes);

    reduce(hashes, adrs, nodes, p.a, base, indices[i], out, at + n);

    for (let b = 0; b < n; b++) {
      roots[i * n + b] = nodes[b];
    }
  }

  const pkFors = new Uint8Array(n);

  hashes.t(hashes.derived(adrs, FORS_ROOTS), roots, pkFors, 0);

  return pkFors;
}

// The k trees are climbed together, one level at a time, so that the backend can hash two of their
// paths at once: each tree's node and sibling go into pairs, whose parents come back into nodes.
function forsPkFromSig(
  p: Parameters,
  hashes: Hashes,
  signature: Uint8Array,
  offset: number,
  digest: Uint8Array,
  adrs: Uint8Array,
): Uint8Array {
  const n = p.n;

  const leaves = new Int32Array(p.k);

  const parents = new Int32Array(p.k);

  const nodes = new Uint8Array(p.k * n);

  const pairs = new Uint8Array(2 * p.k * n);

  base2b(digest, p.a, p.k, leaves);

  for (let i = 0; i < p.k; i++) {
    leaves[i] += i << p.a;

    setTreeHeight(adrs, 0);

    setTreeIndex(adrs, leaves[i]);

    hashes.f(adrs, signature, offset + i * (p.a + 1) * n, nodes, i * n);
  }

  for (let j = 0; j < p.a; j++) {
    for (let i = 0; i < p.k; i++) {
      const sibling = offset + (i * (p.a + 1) + j + 1) * n;

      const left = ((leaves[i] >>> j) & 1) === 0;

      const node = 2 * i * n + (left ? 0 : n);

      const other = 2 * i * n + (left ? n : 0);

      for (let b = 0; b < n; b++) {
        pairs[node + b] = nodes[i * n + b];

        pairs[other + b] = signature[sibling + b];
      }

      parents[i] = leaves[i] >>> (j + 1);
    }

    hashes.level(adrs, j + 1, parents, pairs, p.k, nodes, 0);
  }

  const pkFors = new Uint8Array(n);

  hashes.t(hashes.derived(adrs, FORS_ROOTS), nodes, pkFors, 0);

  return pkFors;
}

export function root(p: Parameters, skSeed: Uint8Array, pkSeed: Uint8Array): Uint8Array {
  const adrs = new Uint8Array(32);

  const hashing = hashes(p, pkSeed, skSeed);

  const nodes = new Uint8Array(p.n << p.hp);

  setLayer(adrs, p.d - 1);

  try {
    xmssTree(p, hashing, adrs, null, 0, -1, null, 0, nodes);

    return nodes.slice(0, p.n);
  } finally {
    hashing.clear();
  }
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

// The tree that signs a message, as two 32-bit halves, and its leaf.
interface Position {
  readonly high: number;

  readonly low: number;

  readonly leaf: number;
}

// FIPS 205, Algorithm 19, lines 7 to 10: after the FORS message digest, the tree and leaf indices
// read big-endian and reduced to h - h/d and h/d bits. The tree index spans more than 32 bits in
// every parameter set.
function positionOf(p: Parameters, digest: Uint8Array): Position {
  const mdSize = Math.ceil((p.k * p.a) / 8);

  const treeBits = p.h - p.h / p.d;

  const treeSize = Math.ceil(treeBits / 8);

  const leafBits = p.h / p.d;

  let high = 0;

  let low = 0;

  for (let i = mdSize; i < mdSize + treeSize; i++) {
    high = ((high << 8) | (low >>> 24)) >>> 0;

    low = ((low << 8) | digest[i]) >>> 0;
  }

  let leaf = 0;

  for (let i = mdSize + treeSize; i < mdSize + treeSize + Math.ceil(leafBits / 8); i++) {
    leaf = (leaf << 8) | digest[i];
  }

  return { high: (high & (2 ** (treeBits - 32) - 1)) >>> 0, low, leaf: leaf & ((1 << leafBits) - 1) };
}

// The signature is written in place: R, the FORS signature, then the hypertree signature, whose
// trees are built in one buffer of nodes.
export function signInternal(message: Uint8Array, sk: Uint8Array, addrnd: Uint8Array, p: Parameters): Uint8Array {
  const n = p.n;

  const pkSeed = sk.subarray(2 * n, 3 * n);

  const pkRoot = sk.subarray(3 * n);

  const hashing = hashes(p, pkSeed, sk.subarray(0, n));

  const out = new Uint8Array(p.signatureSize);

  const r = prfMsg(p, sk.subarray(n, 2 * n), addrnd, message);

  out.set(r);

  const digest = hMsg(p, r, pkSeed, pkRoot, message);

  const position = positionOf(p, digest);

  const adrs = new Uint8Array(32);

  setTree(adrs, position.high, position.low);

  setType(adrs, FORS_TREE);

  setKeyPair(adrs, position.leaf);

  const nodes = new Uint8Array(n << Math.max(p.hp, p.a));

  try {
    const pkFors = forsSign(p, hashing, digest, adrs, out, n, nodes);

    htSign(p, hashing, pkFors, position, out, (1 + p.k * (1 + p.a)) * n, nodes);

    return out;
  } finally {
    hashing.clear();
  }
}

const NO_SEED = new Uint8Array(0);

export function verifyInternal(message: Uint8Array, signature: Uint8Array, pk: Uint8Array, p: Parameters): boolean {
  const n = p.n;

  if (signature.length !== p.signatureSize || pk.length !== p.publicKeySize) {
    return false;
  }

  const pkSeed = pk.subarray(0, n);

  const pkRoot = pk.subarray(n);

  const hashing = hashes(p, pkSeed, NO_SEED);

  const digest = hMsg(p, signature.subarray(0, n), pkSeed, pkRoot, message);

  const position = positionOf(p, digest);

  const adrs = new Uint8Array(32);

  setTree(adrs, position.high, position.low);

  setType(adrs, FORS_TREE);

  setKeyPair(adrs, position.leaf);

  const pkFors = forsPkFromSig(p, hashing, signature, n, digest, adrs);

  return htVerify(p, hashing, pkFors, signature, (1 + p.k * (1 + p.a)) * n, position, pkRoot);
}
