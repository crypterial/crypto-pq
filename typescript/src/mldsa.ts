import { equal, wipe } from "./bytes.ts";
import { shake128, shake256, shake256Stream } from "./primitives.ts";

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

// 1753^BitRev8(k) mod q.
const ZETAS = (() => {
  const table = new Int32Array(256);

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

// Returns a mod q in [0, q) for an integer |a| < 2^53. The floating-point quotient is never above
// floor(a / q) and at most one below it, so a single masked subtraction completes the reduction.
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

function ntt(w: Int32Array): void {
  let m = 0;

  for (let length = 128; length >= 1; length >>= 1) {
    for (let start = 0; start < 256; start += 2 * length) {
      const zeta = ZETAS[++m];

      for (let j = start; j < start + length; j++) {
        const t = reduce(zeta * w[j + length]);

        const a = w[j];

        w[j + length] = subtractMod(a, t);

        w[j] = addMod(a, t);
      }
    }
  }
}

function inverseNtt(w: Int32Array): void {
  let m = 256;

  for (let length = 1; length < 256; length <<= 1) {
    for (let start = 0; start < 256; start += 2 * length) {
      const zeta = Q - ZETAS[--m];

      for (let j = start; j < start + length; j++) {
        const t = w[j];

        w[j] = addMod(t, w[j + length]);

        w[j + length] = reduce(zeta * (t - w[j + length]));
      }
    }
  }

  for (let j = 0; j < 256; j++) {
    w[j] = reduce(w[j] * N_INVERSE);
  }
}

// NTT of a polynomial with small centered coefficients, into a new array.
function nttOf(values: Int32Array): Int32Array {
  const w = new Int32Array(256);

  for (let i = 0; i < 256; i++) {
    w[i] = canonical(values[i]);
  }

  ntt(w);

  return w;
}

function pointwise(f: Int32Array, g: Int32Array): Int32Array {
  const h = new Int32Array(256);

  for (let i = 0; i < 256; i++) {
    h[i] = reduce(f[i] * g[i]);
  }

  return h;
}

// sum(row[i] * vector[i]) in the NTT domain; each product is below 2^46, so the sums are exact.
function dot(row: Int32Array[], vector: Int32Array[]): Int32Array {
  const total = new Float64Array(256);

  for (let i = 0; i < row.length; i++) {
    const f = row[i];

    const g = vector[i];

    for (let j = 0; j < 256; j++) {
      total[j] += f[j] * g[j];
    }
  }

  const out = new Int32Array(256);

  for (let j = 0; j < 256; j++) {
    out[j] = reduce(total[j]);
  }

  total.fill(0);

  return out;
}

// t = NTT^-1(A * NTT(s1)) + s2, with canonical coefficients.
function publicT(a: Int32Array[][], s1: Int32Array[], s2: Int32Array[]): Int32Array[] {
  const s1Hat = s1.map(nttOf);

  const t = a.map((row, i) => {
    const w = dot(row, s1Hat);

    inverseNtt(w);

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

function rejNttPoly(seed: Uint8Array): Int32Array {
  const stream = shake128(seed);

  const a = new Int32Array(256);

  let count = 0;

  while (count < 256) {
    const block = stream.read(168);

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
function rejBoundedPoly(seed: Uint8Array, eta: number): Int32Array {
  const stream = shake256Stream(seed);

  const a = new Int32Array(256);

  let count = 0;

  while (count < 256) {
    const block = stream.read(136);

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

    block.fill(0);
  }

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
    s.push(rejBoundedPoly(Uint8Array.of(...rho, r & 0xff, r >> 8), p.eta));
  }

  return [s.slice(0, p.l), s.slice(p.l)];
}

function expandMask(rho: Uint8Array, kappa: number, p: Parameters): Int32Array[] {
  const y: Int32Array[] = [];

  for (let r = 0; r < p.l; r++) {
    const counter = kappa + r;

    const data = shake256(32 * p.gamma1Bits, rho, Uint8Array.of(counter & 0xff, (counter >> 8) & 0xff));

    y.push(bitUnpack(data, 0, p.gamma1, p.gamma1Bits));

    data.fill(0);
  }

  return y;
}

function sampleInBall(seed: Uint8Array, tau: number): Int32Array {
  const stream = shake256Stream(seed);

  const signs = stream.read(8);

  const c = new Int32Array(256);

  for (let i = 256 - tau, bit = 0; i < 256; i++, bit++) {
    let j = stream.read(1)[0];

    while (j > i) {
      j = stream.read(1)[0];
    }

    c[i] = c[j];

    c[j] = 1 - 2 * ((signs[bit >> 3] >> (bit & 7)) & 1);
  }

  return c;
}

function pkEncode(rho: Uint8Array, t1: Int32Array[]): Uint8Array {
  const pk = new Uint8Array(32 + 320 * t1.length);

  pk.set(rho);

  t1.forEach((t, i) => pack(t, 10, pk, 32 + 320 * i));

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

  let offset = 128;

  for (const s of [...s1, ...s2]) {
    bitPack(s, p.eta, p.etaBits, sk, offset);

    offset += 32 * p.etaBits;
  }

  for (const t of t0) {
    bitPack(t, 1 << (D - 1), D, sk, offset);

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

export function keygenInternal(xi: Uint8Array, p: Parameters): [Uint8Array, Uint8Array] {
  const expanded = shake256(128, xi, Uint8Array.of(p.k, p.l));

  const rho = expanded.subarray(0, 32);

  const [s1, s2] = expandS(expanded.subarray(32, 96), p);

  const t = publicT(expandA(rho, p), s1, s2);

  const t0 = t.map((poly) => poly.map(power2RoundLow));

  const pk = pkEncode(rho, t.map((poly) => poly.map(power2RoundHigh)));

  const sk = skEncode(rho, expanded.subarray(96), shake256(64, pk), s1, s2, t0, p);

  wipe(expanded, ...s1, ...s2, ...t, ...t0);

  return [pk, sk];
}

// An expanded private key carries everything needed to rebuild the public key, so a key whose
// parts disagree is rejected instead of producing signatures that never verify.
export function checkPrivateKey(sk: Uint8Array, p: Parameters): Uint8Array | null {
  const { rho, tr, s1, s2, t0 } = skDecode(sk, p);

  try {
    let bad = 0;

    for (const s of [...s1, ...s2]) {
      bad |= exceeds(s, p.eta + 1, true);
    }

    if (bad !== 0) {
      return null;
    }

    const t = publicT(expandA(rho, p), s1, s2);

    for (let i = 0; i < p.k; i++) {
      for (let j = 0; j < 256; j++) {
        bad |= power2RoundLow(t[i][j]) ^ t0[i][j];
      }
    }

    const pk = pkEncode(rho, t.map((poly) => poly.map(power2RoundHigh)));

    wipe(...t);

    return bad === 0 && equal(shake256(64, pk), tr) ? pk : null;
  } finally {
    wipe(...s1, ...s2, ...t0);
  }
}

export function signInternal(sk: Uint8Array, message: Uint8Array, rnd: Uint8Array, p: Parameters): Uint8Array {
  const { rho, key, tr, s1, s2, t0 } = skDecode(sk, p);

  const s1Hat = s1.map(nttOf);

  const s2Hat = s2.map(nttOf);

  const t0Hat = t0.map(nttOf);

  const a = expandA(rho, p);

  const mu = shake256(64, tr, message);

  const rhoPrime = shake256(64, key, rnd, mu);

  const secrets: Int32Array[] = [...s1, ...s2, ...t0, ...s1Hat, ...s2Hat, ...t0Hat];

  try {
    for (let kappa = 0; ; kappa += p.l) {
      const y = expandMask(rhoPrime, kappa, p);

      const yHat = y.map(nttOf);

      const w = a.map((row) => {
        const r = dot(row, yHat);

        inverseNtt(r);

        return r;
      });

      const w1 = w.map((poly) => poly.map((x) => highBits(x, p.gamma2)));

      const cTilde = shake256(p.lambda / 4, mu, w1Encode(w1, p));

      const cHat = nttOf(sampleInBall(cTilde, p.tau));

      const z = s1Hat.map((s, r) => {
        const cs1 = pointwise(cHat, s);

        inverseNtt(cs1);

        for (let j = 0; j < 256; j++) {
          cs1[j] = addMod(canonical(y[r][j]), cs1[j]);
        }

        return cs1;
      });

      const wcs2 = s2Hat.map((s, i) => {
        const cs2 = pointwise(cHat, s);

        inverseNtt(cs2);

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
        reject |= exceeds(poly.map((x) => lowBits(x, p.gamma2)), p.gamma2 - p.beta, true);
      }

      if (reject !== 0) {
        continue;
      }

      const h: Uint8Array[] = [];

      let ones = 0;

      for (let i = 0; i < p.k; i++) {
        const ct0 = pointwise(cHat, t0Hat[i]);

        inverseNtt(ct0);

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
        bitPack(poly.map(centered), p.gamma1, p.gamma1Bits, signature, offset);

        offset += 32 * p.gamma1Bits;
      }

      hintBitPack(h, p, signature, offset);

      return signature;
    }
  } finally {
    wipe(rhoPrime, ...secrets);
  }
}

export function verifyInternal(pk: Uint8Array, message: Uint8Array, signature: Uint8Array, p: Parameters): boolean {
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

  const a = expandA(pk.subarray(0, 32), p);

  const mu = shake256(64, shake256(64, pk), message);

  const cHat = nttOf(sampleInBall(cTilde, p.tau));

  const zHat = z.map(nttOf);

  const w1 = a.map((row, i) => {
    const t1 = unpack(pk, 32 + 320 * i, 10);

    for (let j = 0; j < 256; j++) {
      t1[j] <<= D;
    }

    ntt(t1);

    const product = pointwise(cHat, t1);

    const w = dot(row, zHat);

    for (let j = 0; j < 256; j++) {
      w[j] = subtractMod(w[j], product[j]);
    }

    inverseNtt(w);

    return w.map((x, j) => useHint(h[i][j], x, p.gamma2));
  });

  return equal(shake256(p.lambda / 4, mu, w1Encode(w1, p)), cTilde);
}
