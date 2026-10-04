import { equal, wipe } from "./bytes.ts";
import { Keccak } from "./keccak.ts";
import { bitPack3, bitPack4, bitPack13, simpleBitPack10 } from "./mldsa-pack.ts";
import { shake256 } from "./primitives.ts";

const Q = 8380417;

const D = 13;

const Q_INVERSE = 1 / Q;

// 256^-1 mod q, the scaling of the inverse NTT.
const N_INVERSE = 8347681;

const GAMMA2_32 = (Q - 1) / 32;

export interface Parameters {
  readonly k: number;

  readonly l: number;

  readonly eta: number;

  readonly tau: number;

  readonly lambda: number;

  readonly gamma1: number;

  readonly gamma2: number;

  readonly omega: number;

  readonly beta: number;

  readonly etaBits: number;

  readonly gamma1Bits: number;

  readonly w1Bits: number;

  readonly publicKeySize: number;

  readonly privateKeySize: number;

  readonly signatureSize: number;
}

function bitLength(value: number): number {
  return 32 - Math.clz32(value);
}

function parameters(
  k: number,
  l: number,
  eta: number,
  tau: number,
  lambda: number,
  gamma1: number,
  gamma2: number,
  omega: number,
): Parameters {
  const etaBits = bitLength(2 * eta);

  const gamma1Bits = 1 + bitLength(gamma1 - 1);

  return Object.freeze({
    k,
    l,
    eta,
    tau,
    lambda,
    gamma1,
    gamma2,
    omega,
    beta: tau * eta,
    etaBits,
    gamma1Bits,
    w1Bits: bitLength((Q - 1) / (2 * gamma2) - 1),
    publicKeySize: 32 + 320 * k,
    privateKeySize: 128 + 32 * ((k + l) * etaBits + D * k),
    signatureSize: lambda / 4 + 32 * l * gamma1Bits + omega + k,
  });
}

export const ML_DSA_44 = parameters(4, 4, 2, 39, 128, 1 << 17, (Q - 1) / 88, 80);

export const ML_DSA_65 = parameters(6, 5, 4, 49, 192, 1 << 19, GAMMA2_32, 55);

export const ML_DSA_87 = parameters(8, 7, 2, 60, 256, 1 << 19, GAMMA2_32, 75);

// 1753^BitRev8(k) mod q, as doubles, and q minus each for the inverse transform.
const ZETAS = (() => {
  const table = new Float64Array(256);

  for (let k = 0; k < 256; k++) {
    let exponent = 0;

    for (let bit = 0; bit < 8; bit++) {
      exponent |= ((k >> bit) & 1) << (7 - bit);
    }

    let power = 1;

    for (let j = 0; j < exponent; j++) {
      power = (power * 1753) % Q;
    }

    table[k] = power;
  }

  return table;
})();

const INVERSE_ZETAS = ZETAS.map((zeta) => Q - zeta);

// A representative of a mod q in [0, 2q), for an integer |a| < 2^53. The floating-point quotient is
// never above floor(a / q) and at most one below it: 1/q rounds down, and the product's rounding
// error stays below the distance 1/q from a / q to the next integer.
function reduceLazy(a: number): number {
  return a - Math.floor(a * Q_INVERSE) * Q;
}

// Returns a mod q in [0, q) for an integer |a| < 2^53: reduceLazy and one masked subtraction.
function reduce(a: number): number {
  const r = a - Math.floor(a * Q_INVERSE) * Q - Q;

  return r + ((r >> 31) & Q);
}

function addMod(a: number, b: number): number {
  const r = a + b - Q;

  return r + ((r >> 31) & Q);
}

function subtractMod(a: number, b: number): number {
  const r = a - b;

  return r + ((r >> 31) & Q);
}

// The representative of x in [0, q), for x in (-q, q).
function canonical(x: number): number {
  return x + ((x >> 31) & Q);
}

// The representative of x in (-(q - 1) / 2, (q - 1) / 2], for x in [0, q).
function centered(x: number): number {
  return x - (Q & (((Q - 1) / 2 - x) >> 31));
}

function absolute(x: number): number {
  const sign = x >> 31;

  return (x ^ sign) - sign;
}

// 1 when some |coefficient| is at least bound, accumulated without branches.
function exceeds(values: Int32Array, bound: number, isCentered: boolean): number {
  let flag = 0;

  for (let i = 0; i < 256; i++) {
    const x = isCentered ? values[i] : centered(values[i]);

    flag |= (bound - 1 - absolute(x)) >> 31;
  }

  return flag & 1;
}

// The NTT domain is held in doubles: products of coefficients and the sums of a few of them are exact
// integers, and the reductions skip the conversions to 32-bit integers.

// The NTT in place, with lazy reductions: each layer adds at most 2q to the bound of the coefficients,
// so the products stay below 2^51; the last pass brings every coefficient into [0, 2q).
function ntt(w: Float64Array): void {
  let m = 0;

  for (let length = 128; length >= 1; length >>= 1) {
    for (let start = 0; start < 256; start += 2 * length) {
      const zeta = ZETAS[++m];

      for (let j = start; j < start + length; j++) {
        const t = reduceLazy(zeta * w[j + length]);

        const a = w[j];

        w[j + length] = a - t + 2 * Q;

        w[j] = a + t;
      }
    }
  }

  for (let j = 0; j < 256; j++) {
    w[j] = reduceLazy(w[j]);
  }
}

// The inverse NTT of w, whose coefficients lie in [0, 2q) and are overwritten, into out with
// coefficients in [0, q). The sums double at every layer, so they are reduced once halfway, after
// which they stay below 32q and the products below 2^51.
function inverseNtt(w: Float64Array, out: Int32Array): void {
  let m = 256;

  for (let length = 1; length < 256; length <<= 1) {
    for (let start = 0; start < 256; start += 2 * length) {
      const zeta = INVERSE_ZETAS[--m];

      for (let j = start; j < start + length; j++) {
        const t = w[j];

        const u = w[j + length];

        w[j] = t + u;

        w[j + length] = reduceLazy(zeta * (t - u));
      }
    }

    if (length === 8) {
      for (let j = 0; j < 256; j++) {
        w[j] = reduceLazy(w[j]);
      }
    }
  }

  for (let j = 0; j < 256; j++) {
    out[j] = reduce(w[j] * N_INVERSE);
  }
}

// NTT of a polynomial with coefficients below 2^20 in magnitude, into a new array.
function nttOf(values: Int32Array): Float64Array {
  const w = new Float64Array(values);

  ntt(w);

  return w;
}

function pointwise(f: Float64Array, g: Int32Array): Float64Array {
  const h = new Float64Array(256);

  for (let i = 0; i < 256; i++) {
    h[i] = reduceLazy(f[i] * g[i]);
  }

  return h;
}

// sum(row[i] * vector[i]) in the NTT domain; each product is below 2^48, so the sums are exact.
function dot(row: Int32Array[], vector: Float64Array[]): Float64Array {
  const total = new Float64Array(256);

  for (let i = 0; i < row.length; i++) {
    const f = row[i];

    const g = vector[i];

    for (let j = 0; j < 256; j++) {
      total[j] += f[j] * g[j];
    }
  }

  for (let j = 0; j < 256; j++) {
    total[j] = reduceLazy(total[j]);
  }

  return total;
}

// The inverse NTT of w, which it overwrites, into a new array.
function inverseOf(w: Float64Array): Int32Array {
  const out = new Int32Array(256);

  inverseNtt(w, out);

  return out;
}

// t = NTT^-1(A * NTT(s1)) + s2, with canonical coefficients.
function publicT(a: Int32Array[][], s1: Int32Array[], s2: Int32Array[]): Int32Array[] {
  const s1Hat = s1.map(nttOf);

  const t = a.map((row, i) => {
    const product = dot(row, s1Hat);

    const w = inverseOf(product);

    product.fill(0);

    for (let j = 0; j < 256; j++) {
      w[j] = addMod(w[j], canonical(s2[i][j]));
    }

    return w;
  });

  wipe(...s1Hat);

  return t;
}

function power2RoundHigh(r: number): number {
  return (r + (1 << (D - 1)) - 1) >> D;
}

function power2RoundLow(r: number): number {
  return r - (power2RoundHigh(r) << D);
}

// FIPS 204 Decompose for r in [0, q), without branches as in the Dilithium reference code.
function highBits(r: number, gamma2: number): number {
  const t = (r + 127) >> 7;

  if (gamma2 === GAMMA2_32) {
    return ((t * 1025 + (1 << 21)) >> 22) & 15;
  }

  const r1 = (t * 11275 + (1 << 23)) >> 24;

  return r1 ^ (((43 - r1) >> 31) & r1);
}

function lowBits(r: number, gamma2: number): number {
  const r0 = r - highBits(r, gamma2) * 2 * gamma2;

  return r0 - ((((Q - 1) / 2 - r0) >> 31) & Q);
}

function useHint(h: number, r: number, gamma2: number): number {
  const m = (Q - 1) / (2 * gamma2);

  const r1 = highBits(r, gamma2);

  if (h === 0) {
    return r1;
  }

  return lowBits(r, gamma2) > 0 ? (r1 + 1) % m : (r1 - 1 + m) % m;
}

function pack(values: ArrayLike<number>, bits: number, out: Uint8Array, offset: number): void {
  let buffer = 0;

  let filled = 0;

  for (let i = 0; i < 256; i++) {
    buffer |= values[i] << filled;

    filled += bits;

    while (filled >= 8) {
      out[offset++] = buffer;

      buffer >>>= 8;

      filled -= 8;
    }
  }
}

function unpack(data: Uint8Array, offset: number, bits: number): Int32Array {
  const out = new Int32Array(256);

  const mask = (1 << bits) - 1;

  let buffer = 0;

  let filled = 0;

  for (let i = 0; i < 256; i++) {
    while (filled < bits) {
      buffer |= data[offset++] << filled;

      filled += 8;
    }

    out[i] = buffer & mask;

    buffer >>>= bits;

    filled -= bits;
  }

  return out;
}

// BitPack(w, a, b) packs b - w[i]; the values here are centered.
function bitPack(w: Int32Array, b: number, bits: number, out: Uint8Array, offset: number): void {
  const values = new Int32Array(256);

  for (let i = 0; i < 256; i++) {
    values[i] = b - w[i];
  }

  pack(values, bits, out, offset);

  values.fill(0);
}

function bitUnpack(data: Uint8Array, offset: number, b: number, bits: number): Int32Array {
  const w = unpack(data, offset, bits);

  for (let i = 0; i < 256; i++) {
    w[i] = b - w[i];
  }

  return w;
}

function hintBitPack(h: Uint8Array[], p: Parameters, out: Uint8Array, offset: number): void {
  let index = 0;

  for (let i = 0; i < p.k; i++) {
    for (let j = 0; j < 256; j++) {
      if (h[i][j] !== 0) {
        out[offset + index++] = j;
      }
    }

    out[offset + p.omega + i] = index;
  }
}

// FIPS 204, Algorithm 21: the encoding must be canonical (strictly increasing indices, zero
// padding), otherwise the signature is rejected.
function hintBitUnpack(data: Uint8Array, p: Parameters): Uint8Array[] | null {
  const h: Uint8Array[] = [];

  let index = 0;

  for (let i = 0; i < p.k; i++) {
    const end = data[p.omega + i];

    if (end < index || end > p.omega) {
      return null;
    }

    const poly = new Uint8Array(256);

    const first = index;

    for (; index < end; index++) {
      if (index > first && data[index - 1] >= data[index]) {
        return null;
      }

      poly[data[index]] = 1;
    }

    h.push(poly);
  }

  for (; index < p.omega; index++) {
    if (data[index] !== 0) {
      return null;
    }
  }

  return h;
}

// The XOF streams of the samplers, reused from one polynomial to the next; reset() also clears what
// the previous seed left in them.
const XOF128 = new Keccak(168, 0x1f);

const XOF256 = new Keccak(136, 0x1f);

const MASK = new Uint8Array(640);

function rejNttPoly(seed: Uint8Array): Int32Array {
  XOF128.reset();

  XOF128.update(seed);

  const a = new Int32Array(256);

  let count = 0;

  while (count < 256) {
    const block = XOF128.readBlock();

    for (let offset = 0; offset < 168 && count < 256; offset += 3) {
      const z = block[offset] | (block[offset + 1] << 8) | ((block[offset + 2] & 0x7f) << 16);

      if (z < Q) {
        a[count++] = z;
      }
    }
  }

  return a;
}

// The sampled coefficients are secret: the reduction modulo 5 is a multiply-shift, as in the
// reference code; only the acceptance of each nibble branches.
function rejBoundedPoly(rho: Uint8Array, nonce: number, eta: number): Int32Array {
  XOF256.reset();

  XOF256.update(rho);

  XOF256.update(Uint8Array.of(nonce & 0xff, nonce >> 8));

  const a = new Int32Array(256);

  let count = 0;

  while (count < 256) {
    const block = XOF256.readBlock();

    for (let i = 0; i < 136 && count < 256; i++) {
      for (let shift = 0; shift < 8 && count < 256; shift += 4) {
        const half = (block[i] >> shift) & 0x0f;

        if (eta === 2 && half < 15) {
          a[count++] = 2 - (half - ((205 * half) >> 10) * 5);
        } else if (eta === 4 && half < 9) {
          a[count++] = 4 - half;
        }
      }
    }
  }

  XOF256.reset();

  return a;
}

// matrix[r][s] = RejNTTPoly(rho || s || r).
function expandA(rho: Uint8Array, p: Parameters): Int32Array[][] {
  const seed = new Uint8Array(34);

  seed.set(rho);

  const rows: Int32Array[][] = [];

  for (let r = 0; r < p.k; r++) {
    const row: Int32Array[] = [];

    for (let s = 0; s < p.l; s++) {
      seed[32] = s;

      seed[33] = r;

      row.push(rejNttPoly(seed));
    }

    rows.push(row);
  }

  return rows;
}

function expandS(rho: Uint8Array, p: Parameters): [Int32Array[], Int32Array[]] {
  const s: Int32Array[] = [];

  for (let r = 0; r < p.l + p.k; r++) {
    s.push(rejBoundedPoly(rho, r, p.eta));
  }

  return [s.slice(0, p.l), s.slice(p.l)];
}

// y = gamma1 - BitUnpack(H(rho' || counter)), with the 18-bit (gamma1 = 2^17) or 20-bit (2^19)
// fields read four or two at a time.
function expandMask(rho: Uint8Array, kappa: number, p: Parameters): Int32Array[] {
  const y: Int32Array[] = [];

  const data = MASK.subarray(0, 32 * p.gamma1Bits);

  const gamma1 = p.gamma1;

  for (let r = 0; r < p.l; r++) {
    const counter = kappa + r;

    XOF256.reset();

    XOF256.update(rho);

    XOF256.update(Uint8Array.of(counter & 0xff, (counter >> 8) & 0xff));

    XOF256.readInto(data);

    const poly = new Int32Array(256);

    if (p.gamma1Bits === 18) {
      for (let i = 0, at = 0; i < 256; i += 4, at += 9) {
        poly[i] = gamma1 - (data[at] | (data[at + 1] << 8) | ((data[at + 2] & 3) << 16));

        poly[i + 1] = gamma1 - ((data[at + 2] >> 2) | (data[at + 3] << 6) | ((data[at + 4] & 0x0f) << 14));

        poly[i + 2] = gamma1 - ((data[at + 4] >> 4) | (data[at + 5] << 4) | ((data[at + 6] & 0x3f) << 12));

        poly[i + 3] = gamma1 - ((data[at + 6] >> 6) | (data[at + 7] << 2) | (data[at + 8] << 10));
      }
    } else {
      for (let i = 0, at = 0; i < 256; i += 2, at += 5) {
        poly[i] = gamma1 - (data[at] | (data[at + 1] << 8) | ((data[at + 2] & 0x0f) << 16));

        poly[i + 1] = gamma1 - ((data[at + 2] >> 4) | (data[at + 3] << 4) | (data[at + 4] << 12));
      }
    }

    y.push(poly);
  }

  data.fill(0);

  XOF256.reset();

  return y;
}

// The signs are the first 64 bits of the stream, little-endian; each position j then comes from one
// byte, retried until it is at most i.
function sampleInBall(seed: Uint8Array, tau: number): Int32Array {
  XOF256.reset();

  XOF256.update(seed);

  let block = XOF256.readBlock();

  const low = block[0] | (block[1] << 8) | (block[2] << 16) | (block[3] << 24);

  const high = block[4] | (block[5] << 8) | (block[6] << 16) | (block[7] << 24);

  const c = new Int32Array(256);

  let offset = 8;

  for (let i = 256 - tau, bit = 0; i < 256; i++, bit++) {
    let j = i + 1;

    while (j > i) {
      if (offset === 136) {
        block = XOF256.readBlock();

        offset = 0;
      }

      j = block[offset++];
    }

    c[i] = c[j];

    c[j] = 1 - 2 * (((bit < 32 ? low : high) >>> (bit & 31)) & 1);
  }

  XOF256.reset();

  return c;
}

function pkEncode(rho: Uint8Array, t1: Int32Array[]): Uint8Array {
  const pk = new Uint8Array(32 + 320 * t1.length);

  pk.set(rho);

  t1.forEach((t, i) => simpleBitPack10(t, pk, 32 + 320 * i));

  return pk;
}

interface SecretKey {
  readonly rho: Uint8Array;

  readonly key: Uint8Array;

  readonly tr: Uint8Array;

  readonly s1: Int32Array[];

  readonly s2: Int32Array[];

  readonly t0: Int32Array[];
}

function skEncode(
  rho: Uint8Array,
  key: Uint8Array,
  tr: Uint8Array,
  s1: Int32Array[],
  s2: Int32Array[],
  t0: Int32Array[],
  p: Parameters,
): Uint8Array {
  const sk = new Uint8Array(p.privateKeySize);

  sk.set(rho);

  sk.set(key, 32);

  sk.set(tr, 64);

  const packS = p.eta === 2 ? bitPack3 : bitPack4;

  let offset = 128;

  for (const s of [...s1, ...s2]) {
    packS(s, p.eta, sk, offset);

    offset += 32 * p.etaBits;
  }

  for (const t of t0) {
    bitPack13(t, 1 << (D - 1), sk, offset);

    offset += 32 * D;
  }

  return sk;
}

function skDecode(sk: Uint8Array, p: Parameters): SecretKey {
  const s: Int32Array[] = [];

  let offset = 128;

  for (let i = 0; i < p.l + p.k; i++) {
    s.push(bitUnpack(sk, offset, p.eta, p.etaBits));

    offset += 32 * p.etaBits;
  }

  const t0: Int32Array[] = [];

  for (let i = 0; i < p.k; i++) {
    t0.push(bitUnpack(sk, offset, 1 << (D - 1), D));

    offset += 32 * D;
  }

  return {
    rho: sk.subarray(0, 32),
    key: sk.subarray(32, 64),
    tr: sk.subarray(64, 128),
    s1: s.slice(0, p.l),
    s2: s.slice(p.l),
    t0,
  };
}

function w1Encode(w1: Int32Array[], p: Parameters): Uint8Array {
  const out = new Uint8Array(32 * p.w1Bits * w1.length);

  w1.forEach((w, i) => pack(w, p.w1Bits, out, 32 * p.w1Bits * i));

  return out;
}

// The high (Power2Round t1) or low (t0) parts of the coefficients of each polynomial in t.
function power2Round(t: Int32Array[], high: boolean): Int32Array[] {
  return t.map((poly) => {
    const out = new Int32Array(256);

    for (let j = 0; j < 256; j++) {
      out[j] = high ? power2RoundHigh(poly[j]) : power2RoundLow(poly[j]);
    }

    return out;
  });
}

// What verification and signing derive from a public key, kept with the key object and shared by a
// private key with its public key: tr, Â in the NTT domain, entry [r][s] being
// RejNTTPoly(rho || s || r), and t̂1 = NTT(t1 2^d), which only verification reads. Each is computed on
// first use, so that a key made or imported but never used holds none of them; only tr, which a
// key's creator already has, may come with the key.
export interface PublicCache {
  tr: Uint8Array | null;

  matrix: Int32Array[][] | null;

  t1: Int32Array[] | null;
}

// ŝ1, ŝ2 and t̂0 of a private key, decoded on first use.
export interface SecretCache {
  vectors: [Int32Array[], Int32Array[], Int32Array[]] | null;
}

export function publicCache(tr: Uint8Array | null = null): PublicCache {
  return { tr, matrix: null, t1: null };
}

function t1Hat(pk: Uint8Array, p: Parameters): Int32Array[] {
  return Array.from({ length: p.k }, (_, i) => {
    const t1 = unpack(pk, 32 + 320 * i, 10);

    for (let j = 0; j < 256; j++) {
      t1[j] <<= D;
    }

    return Int32Array.from(nttOf(t1));
  });
}

// Also returns the cache of the new public key, holding tr; Â is expanded again on first use.
export function keygenInternal(xi: Uint8Array, p: Parameters): [Uint8Array, Uint8Array, PublicCache] {
  const expanded = shake256(128, xi, Uint8Array.of(p.k, p.l));

  const rho = expanded.subarray(0, 32);

  const [s1, s2] = expandS(expanded.subarray(32, 96), p);

  const a = expandA(rho, p);

  const t = publicT(a, s1, s2);

  const t0 = power2Round(t, false);

  const pk = pkEncode(rho, power2Round(t, true));

  const tr = shake256(64, pk);

  const sk = skEncode(rho, expanded.subarray(96), tr, s1, s2, t0, p);

  wipe(expanded, ...s1, ...s2, ...t, ...t0);

  return [pk, sk, publicCache(tr)];
}

// An expanded private key carries everything needed to rebuild the public key, so a key whose
// parts disagree is rejected instead of producing signatures that never verify. Also returns the
// cache of the public key, holding tr.
export function checkPrivateKey(sk: Uint8Array, p: Parameters): [Uint8Array, PublicCache] | null {
  const { rho, tr, s1, s2, t0 } = skDecode(sk, p);

  try {
    let bad = 0;

    for (const s of [...s1, ...s2]) {
      bad |= exceeds(s, p.eta + 1, true);
    }

    if (bad !== 0) {
      return null;
    }

    const a = expandA(rho, p);

    const t = publicT(a, s1, s2);

    for (let i = 0; i < p.k; i++) {
      for (let j = 0; j < 256; j++) {
        bad |= power2RoundLow(t[i][j]) ^ t0[i][j];
      }
    }

    const pk = pkEncode(rho, power2Round(t, true));

    wipe(...t);

    return bad === 0 && equal(shake256(64, pk), tr) ? [pk, publicCache(tr.slice())] : null;
  } finally {
    wipe(...s1, ...s2, ...t0);
  }
}

// NTT^-1(cHat * sHat), wiping the product left in the NTT domain.
function multiply(cHat: Float64Array, sHat: Int32Array): Int32Array {
  const product = pointwise(cHat, sHat);

  const out = inverseOf(product);

  product.fill(0);

  return out;
}

// 1 when some |LowBits(coefficient)| is at least bound, accumulated without branches.
function lowExceeds(values: Int32Array, gamma2: number, bound: number): number {
  let flag = 0;

  for (let i = 0; i < 256; i++) {
    flag |= (bound - 1 - absolute(lowBits(values[i], gamma2))) >> 31;
  }

  return flag & 1;
}

// ŝ1, ŝ2 and t̂0, the NTTs of the secret vectors of sk.
function decodeSecrets(sk: Uint8Array, p: Parameters): [Int32Array[], Int32Array[], Int32Array[]] {
  const { s1, s2, t0 } = skDecode(sk, p);

  const transform = (s: Int32Array) => {
    const w = nttOf(s);

    const out = Int32Array.from(w);

    w.fill(0);

    return out;
  };

  const vectors: [Int32Array[], Int32Array[], Int32Array[]] = [s1.map(transform), s2.map(transform), t0.map(transform)];

  wipe(...s1, ...s2, ...t0);

  return vectors;
}

// cache and secret hold what the key derives from sk.
export function signInternal(
  sk: Uint8Array,
  cache: PublicCache,
  secret: SecretCache,
  message: Uint8Array,
  rnd: Uint8Array,
  p: Parameters,
): Uint8Array {
  const [s1Hat, s2Hat, t0Hat] = (secret.vectors ??= decodeSecrets(sk, p));

  const a = (cache.matrix ??= expandA(sk.subarray(0, 32), p));

  const mu = shake256(64, sk.subarray(64, 128), message);

  const rhoPrime = shake256(64, sk.subarray(32, 64), rnd, mu);

  const w1 = Array.from({ length: p.k }, () => new Int32Array(256));

  const centeredZ = new Int32Array(256);

  const secrets: (Int32Array | Float64Array)[] = [centeredZ];

  try {
    for (let kappa = 0; ; kappa += p.l) {
      const y = expandMask(rhoPrime, kappa, p);

      const yHat = y.map(nttOf);

      const w = a.map((row) => {
        const product = dot(row, yHat);

        const out = inverseOf(product);

        product.fill(0);

        return out;
      });

      for (let i = 0; i < p.k; i++) {
        for (let j = 0; j < 256; j++) {
          w1[i][j] = highBits(w[i][j], p.gamma2);
        }
      }

      const cTilde = shake256(p.lambda / 4, mu, w1Encode(w1, p));

      const cHat = nttOf(sampleInBall(cTilde, p.tau));

      const z = s1Hat.map((s, r) => {
        const cs1 = multiply(cHat, s);

        for (let j = 0; j < 256; j++) {
          cs1[j] = addMod(canonical(y[r][j]), cs1[j]);
        }

        return cs1;
      });

      const wcs2 = s2Hat.map((s, i) => {
        const cs2 = multiply(cHat, s);

        for (let j = 0; j < 256; j++) {
          cs2[j] = subtractMod(w[i][j], cs2[j]);
        }

        return cs2;
      });

      secrets.push(...y, ...yHat, ...w, ...z, ...wcs2);

      let reject = 0;

      for (const poly of z) {
        reject |= exceeds(poly, p.gamma1 - p.beta, false);
      }

      for (const poly of wcs2) {
        reject |= lowExceeds(poly, p.gamma2, p.gamma2 - p.beta);
      }

      if (reject !== 0) {
        continue;
      }

      const h: Uint8Array[] = [];

      let ones = 0;

      for (let i = 0; i < p.k; i++) {
        const ct0 = multiply(cHat, t0Hat[i]);

        reject |= exceeds(ct0, p.gamma2, false);

        const hint = new Uint8Array(256);

        for (let j = 0; j < 256; j++) {
          const difference = highBits(addMod(wcs2[i][j], ct0[j]), p.gamma2) ^ highBits(wcs2[i][j], p.gamma2);

          hint[j] = (difference | -difference) >>> 31;

          ones += hint[j];
        }

        h.push(hint);

        secrets.push(ct0);
      }

      if (reject !== 0 || ones > p.omega) {
        continue;
      }

      const signature = new Uint8Array(p.signatureSize);

      signature.set(cTilde);

      let offset = p.lambda / 4;

      for (const poly of z) {
        for (let j = 0; j < 256; j++) {
          centeredZ[j] = centered(poly[j]);
        }

        bitPack(centeredZ, p.gamma1, p.gamma1Bits, signature, offset);

        offset += 32 * p.gamma1Bits;
      }

      hintBitPack(h, p, signature, offset);

      return signature;
    }
  } finally {
    wipe(rhoPrime, ...secrets);
  }
}

// cache holds what the key derives from pk.
export function verifyInternal(
  pk: Uint8Array,
  cache: PublicCache,
  message: Uint8Array,
  signature: Uint8Array,
  p: Parameters,
): boolean {
  if (pk.length !== p.publicKeySize || signature.length !== p.signatureSize) {
    return false;
  }

  const z: Int32Array[] = [];

  let offset = p.lambda / 4;

  for (let r = 0; r < p.l; r++) {
    z.push(bitUnpack(signature, offset, p.gamma1, p.gamma1Bits));

    offset += 32 * p.gamma1Bits;
  }

  const h = hintBitUnpack(signature.subarray(offset), p);

  if (h === null || z.some((poly) => exceeds(poly, p.gamma1 - p.beta, true) !== 0)) {
    return false;
  }

  const cTilde = signature.subarray(0, p.lambda / 4);

  const a = (cache.matrix ??= expandA(pk.subarray(0, 32), p));

  const t1 = (cache.t1 ??= t1Hat(pk, p));

  const mu = shake256(64, (cache.tr ??= shake256(64, pk)), message);

  const cHat = nttOf(sampleInBall(cTilde, p.tau));

  const zHat = z.map(nttOf);

  const w1 = a.map((row, i) => {
    const w = dot(row, zHat);

    for (let j = 0; j < 256; j++) {
      w[j] = reduceLazy(w[j] - reduceLazy(cHat[j] * t1[i][j]) + 2 * Q);
    }

    const r = inverseOf(w);

    for (let j = 0; j < 256; j++) {
      r[j] = useHint(h[i][j], r[j], p.gamma2);
    }

    return r;
  });

  return equal(shake256(p.lambda / 4, mu, w1Encode(w1, p)), cTilde);
}
