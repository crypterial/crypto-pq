import { equal, wipe } from "./bytes.ts";
import { Keccak } from "./keccak.ts";
import { sha3, shake256 } from "./primitives.ts";

const Q = 3329;

// q^-1 mod 2^16, for Montgomery reduction with R = 2^16.
const Q_INVERSE = -3327;

// floor(t / q) = floor(t * 20642679 / 2^36) for every t < 2^25; the product stays below 2^53.
const DIVIDE_MULTIPLIER = 20642679;

const DIVIDE_SHIFT = 2 ** -36;

export interface Parameters {
  readonly k: number;

  readonly eta1: number;

  readonly eta2: number;

  readonly du: number;

  readonly dv: number;

  readonly encapsulationKeySize: number;

  readonly decapsulationKeySize: number;

  readonly ciphertextSize: number;
}

function parameters(k: number, eta1: number, eta2: number, du: number, dv: number): Parameters {
  return Object.freeze({
    k,
    eta1,
    eta2,
    du,
    dv,
    encapsulationKeySize: 384 * k + 32,
    decapsulationKeySize: 768 * k + 96,
    ciphertextSize: 32 * (du * k + dv),
  });
}

export const ML_KEM_512 = parameters(2, 3, 2, 10, 4);

export const ML_KEM_768 = parameters(3, 2, 2, 10, 4);

export const ML_KEM_1024 = parameters(4, 2, 2, 11, 5);

// zeta^BitRev7(i) * R mod q for zeta = 17, centered around zero.
const ZETAS = (() => {
  const table = new Int16Array(128);

  for (let i = 0; i < 128; i++) {
    let exponent = 0;

    for (let bit = 0; bit < 7; bit++) {
      exponent |= ((i >> bit) & 1) << (6 - bit);
    }

    let power = 65536 % Q;

    for (let j = 0; j < exponent; j++) {
      power = (power * 17) % Q;
    }

    table[i] = power > Q >> 1 ? power - Q : power;
  }

  return table;
})();

// Returns a value in (-q, q) congruent to a * 2^-16, for |a| < q * 2^15.
function montgomeryReduce(a: number): number {
  const t = (Math.imul(a, Q_INVERSE) << 16) >> 16;

  return (a - Math.imul(t, Q)) >> 16;
}

function fqmul(a: number, b: number): number {
  return montgomeryReduce(Math.imul(a, b));
}

// Returns the representative of a in [-(q - 1) / 2, (q - 1) / 2], for |a| < 2^15.
function barrettReduce(a: number): number {
  const t = (Math.imul(20159, a) + (1 << 25)) >> 26;

  return a - Math.imul(t, Q);
}

function canonical(a: number): number {
  return a + ((a >> 31) & Q);
}

function reduceOnce(a: number): number {
  return canonical(a - Q);
}

function ntt(r: Int16Array): void {
  let k = 1;

  for (let length = 128; length >= 2; length >>= 1) {
    for (let start = 0; start < 256; start += 2 * length) {
      const zeta = ZETAS[k++];

      for (let j = start; j < start + length; j++) {
        const t = fqmul(zeta, r[j + length]);

        r[j + length] = r[j] - t;

        r[j] = r[j] + t;
      }
    }
  }

  for (let j = 0; j < 256; j++) {
    r[j] = barrettReduce(r[j]);
  }
}

// The inverse NTT, also multiplying by R, which cancels the R^-1 left by multiplyAccumulate.
function inverseNtt(r: Int16Array): void {
  let k = 127;

  for (let length = 2; length <= 128; length <<= 1) {
    for (let start = 0; start < 256; start += 2 * length) {
      const zeta = ZETAS[k--];

      for (let j = start; j < start + length; j++) {
        const t = r[j];

        r[j] = barrettReduce(t + r[j + length]);

        r[j + length] = fqmul(zeta, r[j + length] - t);
      }
    }
  }

  for (let j = 0; j < 256; j++) {
    r[j] = fqmul(r[j], 1441);
  }
}

// A polynomial in the NTT domain prepared as the fixed factor of multiplyAccumulate: its coefficients
// with |f| < q, followed by f[4j + 1] zeta_j and -f[4j + 3] zeta_j mod q for each group of four, the
// products that the base case would otherwise reduce at every use. Key material that is multiplied
// again and again is kept in this form.
function prepare(f: Int16Array): Int16Array {
  const out = new Int16Array(384);

  out.set(f);

  for (let j = 0; j < 64; j++) {
    out[256 + 2 * j] = fqmul(f[4 * j + 1], ZETAS[64 + j]);

    out[257 + 2 * j] = fqmul(f[4 * j + 3], -ZETAS[64 + j]);
  }

  return out;
}

// Returns sum(f[i] * g[i] * R^-1) in the NTT domain for prepared factors f, with coefficients in
// (-q, q), which inverseNtt and fqmul accept. Each group of four coefficients sums plain products over
// the vector: every product is below q^2 in magnitude, so the at most eight of a sum stay below
// q * 2^15, which one Montgomery reduction accepts.
function multiplyAccumulate(f: Int16Array[], g: Int16Array[]): Int16Array {
  const r = new Int16Array(256);

  for (let j = 0; j < 64; j++) {
    const at = 4 * j;

    let r0 = 0;

    let r1 = 0;

    let r2 = 0;

    let r3 = 0;

    for (let i = 0; i < f.length; i++) {
      const a = f[i];

      const b = g[i];

      const a0 = a[at];

      const a2 = a[at + 2];

      const b0 = b[at];

      const b1 = b[at + 1];

      const b2 = b[at + 2];

      const b3 = b[at + 3];

      r0 += a0 * b0 + a[256 + 2 * j] * b1;

      r1 += a0 * b1 + a[at + 1] * b0;

      r2 += a2 * b2 + a[257 + 2 * j] * b3;

      r3 += a2 * b3 + a[at + 3] * b2;
    }

    r[at] = montgomeryReduce(r0);

    r[at + 1] = montgomeryReduce(r1);

    r[at + 2] = montgomeryReduce(r2);

    r[at + 3] = montgomeryReduce(r3);
  }

  return r;
}

// round(2^d * x / q) mod 2^d for x in [0, q), with an exact multiply-shift instead of a division.
function compress(x: number, d: number): number {
  return Math.floor(((x << d) + 1664) * DIVIDE_MULTIPLIER * DIVIDE_SHIFT) & ((1 << d) - 1);
}

function decompress(y: number, d: number): number {
  return (y * Q + (1 << (d - 1))) >> d;
}

function encode(values: ArrayLike<number>, d: number, out: Uint8Array, offset: number): void {
  let buffer = 0;

  let bits = 0;

  for (let i = 0; i < 256; i++) {
    buffer |= values[i] << bits;

    bits += d;

    while (bits >= 8) {
      out[offset++] = buffer;

      buffer >>>= 8;

      bits -= 8;
    }
  }
}

function decode(data: Uint8Array, offset: number, d: number): Int16Array {
  const out = new Int16Array(256);

  const mask = (1 << d) - 1;

  let buffer = 0;

  let bits = 0;

  for (let i = 0; i < 256; i++) {
    while (bits < d) {
      buffer |= data[offset++] << bits;

      bits += 8;
    }

    out[i] = buffer & mask;

    buffer >>>= d;

    bits -= d;
  }

  return out;
}

// ByteEncode12 of a polynomial whose coefficients lie in (-q, q).
function encode12(f: Int16Array, out: Uint8Array, offset: number): void {
  const values = new Int16Array(256);

  for (let i = 0; i < 256; i++) {
    values[i] = canonical(f[i]);
  }

  encode(values, 12, out, offset);

  values.fill(0);
}

// ByteDecode12 followed by a reduction modulo q, as FIPS 203 specifies for decapsulation keys.
function decode12(data: Uint8Array, offset: number): Int16Array {
  const f = decode(data, offset, 12);

  for (let i = 0; i < 256; i++) {
    f[i] = reduceOnce(f[i]);
  }

  return f;
}

function compressPolynomial(f: Int16Array, d: number, out: Uint8Array, offset: number): void {
  const values = new Int16Array(256);

  for (let i = 0; i < 256; i++) {
    values[i] = compress(canonical(f[i]), d);
  }

  encode(values, d, out, offset);

  values.fill(0);
}

function decompressPolynomial(data: Uint8Array, offset: number, d: number): Int16Array {
  const f = decode(data, offset, d);

  for (let i = 0; i < 256; i++) {
    f[i] = decompress(f[i], d);
  }

  return f;
}

// The XOF streams of the samplers, reused from one polynomial to the next; reset() also clears what
// the previous seed left in them.
const XOF128 = new Keccak(168, 0x1f);

const XOF256 = new Keccak(136, 0x1f);

const NOISE = new Uint8Array(192);

function sampleNtt(seed: Uint8Array): Int16Array {
  XOF128.reset();

  XOF128.update(seed);

  const a = new Int16Array(256);

  let count = 0;

  while (count < 256) {
    const block = XOF128.readBlock();

    for (let offset = 0; offset < 168 && count < 256; offset += 3) {
      const d1 = block[offset] | ((block[offset + 1] & 0x0f) << 8);

      const d2 = (block[offset + 1] >> 4) | (block[offset + 2] << 4);

      if (d1 < Q) {
        a[count++] = d1;
      }

      if (d2 < Q && count < 256) {
        a[count++] = d2;
      }
    }
  }

  return a;
}

// SamplePolyCBD: each coefficient is the difference of two eta-bit popcounts, computed with
// masks and additions so that no branch or index depends on the secret bits.
function sampleCbd(data: Uint8Array, eta: number): Int16Array {
  const f = new Int16Array(256);

  if (eta === 2) {
    for (let i = 0; i < 32; i++) {
      const t = data[4 * i] | (data[4 * i + 1] << 8) | (data[4 * i + 2] << 16) | (data[4 * i + 3] << 24);

      const d = (t & 0x55555555) + ((t >>> 1) & 0x55555555);

      for (let j = 0; j < 8; j++) {
        f[8 * i + j] = ((d >>> (4 * j)) & 3) - ((d >>> (4 * j + 2)) & 3);
      }
    }
  } else {
    for (let i = 0; i < 64; i++) {
      const t = data[3 * i] | (data[3 * i + 1] << 8) | (data[3 * i + 2] << 16);

      const d = (t & 0x249249) + ((t >>> 1) & 0x249249) + ((t >>> 2) & 0x249249);

      for (let j = 0; j < 4; j++) {
        f[4 * i + j] = ((d >>> (6 * j)) & 7) - ((d >>> (6 * j + 3)) & 7);
      }
    }
  }

  return f;
}

function noise(seed: Uint8Array, nonce: number, eta: number): Int16Array {
  const data = NOISE.subarray(0, 64 * eta);

  XOF256.reset();

  XOF256.update(seed);

  XOF256.update(Uint8Array.of(nonce));

  XOF256.readInto(data);

  const f = sampleCbd(data, eta);

  data.fill(0);

  XOF256.reset();

  return f;
}

// matrix[i][j] = SampleNTT(rho || j || i).
function matrix(rho: Uint8Array, k: number): Int16Array[][] {
  const seed = new Uint8Array(34);

  seed.set(rho);

  const rows: Int16Array[][] = [];

  for (let i = 0; i < k; i++) {
    const row: Int16Array[] = [];

    for (let j = 0; j < k; j++) {
      seed[32] = j;

      seed[33] = i;

      row.push(sampleNtt(seed));
    }

    rows.push(row);
  }

  return rows;
}

function pkeKeygen(d: Uint8Array, p: Parameters): [Uint8Array, Uint8Array] {
  const k = p.k;

  const g = sha3(64, d, Uint8Array.of(k));

  const rho = g.subarray(0, 32);

  const sigma = g.subarray(32);

  const a = matrix(rho, k);

  const s: Int16Array[] = [];

  const e: Int16Array[] = [];

  for (let i = 0; i < k; i++) {
    s.push(noise(sigma, i, p.eta1));

    ntt(s[i]);
  }

  for (let i = 0; i < k; i++) {
    e.push(noise(sigma, k + i, p.eta1));

    ntt(e[i]);
  }

  const sHat = s.map(prepare);

  const ek = new Uint8Array(p.encapsulationKeySize);

  const dk = new Uint8Array(384 * k);

  for (let i = 0; i < k; i++) {
    const t = multiplyAccumulate(sHat, a[i]);

    for (let j = 0; j < 256; j++) {
      t[j] = barrettReduce(fqmul(t[j], 1353) + e[i][j]);
    }

    encode12(t, ek, 384 * i);

    encode12(s[i], dk, 384 * i);
  }

  ek.set(rho, 384 * k);

  wipe(g, ...s, ...sHat, ...e);

  return [ek, dk];
}

// What encryption derives from an encapsulation key, kept with the key object and shared by a private
// key with its public key: H(ek), and Â in the NTT domain with the decoded vector t̂, both prepared.
// Each part is computed on first use unless the key's creator supplies it.
export interface PublicCache {
  digest: Uint8Array | null;

  matrix: Int16Array[][] | null;

  t: Int16Array[] | null;
}

// ŝ of a private key, decoded and prepared on first use.
export interface SecretCache {
  s: Int16Array[] | null;
}

export function publicCache(digest: Uint8Array | null = null): PublicCache {
  return { digest, matrix: null, t: null };
}

// ByteDecode12 of the first k encoded polynomials of a key, prepared.
function decodeVector(key: Uint8Array, k: number): Int16Array[] {
  return Array.from({ length: k }, (_, i) => {
    const f = decode12(key, 384 * i);

    const prepared = prepare(f);

    f.fill(0);

    return prepared;
  });
}

function pkeEncrypt(ek: Uint8Array, cache: PublicCache, m: Uint8Array, r: Uint8Array, p: Parameters): Uint8Array {
  const k = p.k;

  const a = (cache.matrix ??= matrix(ek.subarray(384 * k), k).map((row) => row.map(prepare)));

  const t = (cache.t ??= decodeVector(ek, k));

  const y: Int16Array[] = [];

  for (let i = 0; i < k; i++) {
    y.push(noise(r, i, p.eta1));

    ntt(y[i]);
  }

  const c = new Uint8Array(p.ciphertextSize);

  for (let i = 0; i < k; i++) {
    const column: Int16Array[] = [];

    for (let j = 0; j < k; j++) {
      column.push(a[j][i]);
    }

    const u = multiplyAccumulate(column, y);

    const e1 = noise(r, k + i, p.eta2);

    inverseNtt(u);

    for (let j = 0; j < 256; j++) {
      u[j] = barrettReduce(u[j] + e1[j]);
    }

    compressPolynomial(u, p.du, c, 32 * p.du * i);

    wipe(u, e1);
  }

  const v = multiplyAccumulate(t, y);

  const e2 = noise(r, 2 * k, p.eta2);

  inverseNtt(v);

  for (let j = 0; j < 256; j++) {
    v[j] = barrettReduce(v[j] + e2[j] + (-((m[j >> 3] >> (j & 7)) & 1) & 1665));
  }

  compressPolynomial(v, p.dv, c, 32 * p.du * k);

  wipe(v, e2, ...y);

  return c;
}

function pkeDecrypt(s: Int16Array[], c: Uint8Array, p: Parameters): Uint8Array {
  const k = p.k;

  const u: Int16Array[] = [];

  for (let i = 0; i < k; i++) {
    u.push(decompressPolynomial(c, 32 * p.du * i, p.du));

    ntt(u[i]);
  }

  const w = multiplyAccumulate(s, u);

  const v = decompressPolynomial(c, 32 * p.du * k, p.dv);

  inverseNtt(w);

  const m = new Uint8Array(32);

  for (let j = 0; j < 256; j++) {
    m[j >> 3] |= compress(canonical(barrettReduce(v[j] - w[j])), 1) << (j & 7);
  }

  wipe(w);

  return m;
}

export function keygenInternal(d: Uint8Array, z: Uint8Array, p: Parameters): [Uint8Array, Uint8Array] {
  const [ek, dkPke] = pkeKeygen(d, p);

  const dk = new Uint8Array(p.decapsulationKeySize);

  dk.set(dkPke);

  dk.set(ek, 384 * p.k);

  dk.set(sha3(32, ek), 768 * p.k + 32);

  dk.set(z, 768 * p.k + 64);

  dkPke.fill(0);

  return [ek, dk];
}

export function encapsInternal(
  ek: Uint8Array,
  cache: PublicCache,
  m: Uint8Array,
  p: Parameters,
): [Uint8Array, Uint8Array] {
  const g = sha3(64, m, (cache.digest ??= sha3(32, ek)));

  const ciphertext = pkeEncrypt(ek, cache, m, g.subarray(32), p);

  const sharedSecret = g.slice(0, 32);

  g.fill(0);

  return [sharedSecret, ciphertext];
}

// Implicit rejection: a ciphertext that does not re-encrypt to itself yields J(z || c). The
// comparison and the choice between the two secrets use masks, not branches. secret and cache hold
// what the key derives from dk.
export function decapsInternal(
  dk: Uint8Array,
  secret: SecretCache,
  cache: PublicCache,
  c: Uint8Array,
  p: Parameters,
): Uint8Array {
  const k = p.k;

  const m = pkeDecrypt((secret.s ??= decodeVector(dk, k)), c, p);

  const g = sha3(64, m, dk.subarray(768 * k + 32, 768 * k + 64));

  const rejected = shake256(32, dk.subarray(768 * k + 64), c);

  const reencrypted = pkeEncrypt(dk.subarray(384 * k, 768 * k + 32), cache, m, g.subarray(32), p);

  let difference = 0;

  for (let i = 0; i < c.length; i++) {
    difference |= c[i] ^ reencrypted[i];
  }

  const mask = -((difference | -difference) >>> 31);

  const sharedSecret = new Uint8Array(32);

  for (let i = 0; i < 32; i++) {
    sharedSecret[i] = g[i] ^ (mask & (g[i] ^ rejected[i]));
  }

  wipe(m, g, rejected, reencrypted);

  return sharedSecret;
}

// FIPS 203, 7.2: every coefficient of the encoded vector must already be reduced modulo q.
export function checkEncapsulationKey(ek: Uint8Array, p: Parameters): boolean {
  if (ek.length !== p.encapsulationKeySize) {
    return false;
  }

  for (let i = 0; i < 384 * p.k; i += 3) {
    if ((ek[i] | ((ek[i + 1] & 0x0f) << 8)) >= Q || ((ek[i + 1] >> 4) | (ek[i + 2] << 4)) >= Q) {
      return false;
    }
  }

  return true;
}

export function checkDecapsulationKey(dk: Uint8Array, p: Parameters): boolean {
  const k = p.k;

  if (dk.length !== p.decapsulationKeySize) {
    return false;
  }

  const ek = dk.subarray(384 * k, 768 * k + 32);

  return checkEncapsulationKey(ek, p) && equal(sha3(32, ek), dk.subarray(768 * k + 32, 768 * k + 64));
}

export function publicKeyOf(dk: Uint8Array, p: Parameters): Uint8Array {
  return dk.slice(384 * p.k, 768 * p.k + 32);
}

// H(ek), which a decapsulation key holds.
export function digestOf(dk: Uint8Array, p: Parameters): Uint8Array {
  return dk.slice(768 * p.k + 32, 768 * p.k + 64);
}
