import { equal, wipe } from "./bytes.ts";
import { Keccak, absorbBytes, squeezeBytes } from "./keccak.ts";
import { sha3 } from "./primitives.ts";

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
function multiplyAccumulate(f: Int16Array[], g: Int16Array[], r: Int16Array): void {
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

function decode(data: Uint8Array, offset: number, d: number, out: Int16Array): Int16Array {
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

// ByteEncode12 of a polynomial whose coefficients lie in (-q, q), which it leaves canonical.
function encode12(f: Int16Array, out: Uint8Array, offset: number): void {
  for (let i = 0; i < 256; i++) {
    f[i] = canonical(f[i]);
  }

  encode(f, 12, out, offset);
}

// ByteDecode12 followed by a reduction modulo q, as FIPS 203 specifies for decapsulation keys.
function decode12(data: Uint8Array, offset: number): Int16Array {
  const f = decode(data, offset, 12, new Int16Array(256));

  for (let i = 0; i < 256; i++) {
    f[i] = reduceOnce(f[i]);
  }

  return f;
}

// Compress_d, then ByteEncode_d, of a polynomial with coefficients in (-q, q), which it overwrites.
function compressPolynomial(f: Int16Array, d: number, out: Uint8Array, offset: number): void {
  for (let i = 0; i < 256; i++) {
    f[i] = compress(canonical(f[i]), d);
  }

  encode(f, d, out, offset);
}

function decompressPolynomial(data: Uint8Array, offset: number, d: number, out: Int16Array): Int16Array {
  const f = decode(data, offset, d, out);

  for (let i = 0; i < 256; i++) {
    f[i] = decompress(f[i], d);
  }

  return f;
}

// The XOF streams of the samplers, reused from one polynomial to the next; reset() also clears what
// the previous seed left in them.
const XOF128 = new Keccak(168, 0x1f);

const XOF256 = new Keccak(136, 0x1f);

// The noise stream of eta = 3 and of eta = 2, and the one-byte nonce.
const NOISE = new Uint8Array(192);

const NOISE2 = NOISE.subarray(0, 128);

const NONCE = new Uint8Array(1);

// The scratch of one encryption or decryption, which never nest: polynomials of a vector (y or u)
// and two more, G's output (K, then the noise seed r), J's output, the message and a ciphertext. Each
// is wiped after use.
const VECTOR = Array.from({ length: 4 }, () => new Int16Array(256));

const POLY = new Int16Array(256);

const ERROR = new Int16Array(256);

const G_OUT = new Uint8Array(64);

const R = G_OUT.subarray(32);

const REJECTED = new Uint8Array(32);

const MESSAGE = new Uint8Array(32);

const CIPHERTEXT = new Uint8Array(1568);

// The state of G and J, which read their inputs where they are. Each absorbs into it from zero, so it
// is cleared after every use, also one that an exception such as a stack overflow ends.
const SPONGE = new Uint32Array(50);

// G(a || b), SHA3-512 of the 32 bytes of a and the 32 from b[from], into G_OUT.
function hashG(a: Uint8Array, b: Uint8Array, from: number): void {
  try {
    const position = absorbBytes(SPONGE, 72, absorbBytes(SPONGE, 72, 0, a, 0, 32), b, from, from + 32);

    squeezeBytes(SPONGE, 72, position, 0x06, G_OUT);
  } finally {
    SPONGE.fill(0);
  }
}

// J(z || c), SHAKE256 to 32 bytes of the 32 bytes from z[from] and of c, into REJECTED.
function hashJ(z: Uint8Array, from: number, c: Uint8Array): void {
  try {
    const position = absorbBytes(SPONGE, 136, absorbBytes(SPONGE, 136, 0, z, from, from + 32), c, 0, c.length);

    squeezeBytes(SPONGE, 136, position, 0x1f, REJECTED);
  } finally {
    SPONGE.fill(0);
  }
}

function sampleNtt(seed: Uint8Array, a: Int16Array = new Int16Array(256)): Int16Array {
  XOF128.reset();

  XOF128.update(seed);

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

// SamplePolyCBD into f: each coefficient is the difference of two eta-bit popcounts, computed with
// masks and additions so that no branch or index depends on the secret bits.
function sampleCbd(data: Uint8Array, eta: number, f: Int16Array): Int16Array {
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

function noise(seed: Uint8Array, nonce: number, eta: number, f: Int16Array = new Int16Array(256)): Int16Array {
  const data = eta === 2 ? NOISE2 : NOISE;

  XOF256.reset();

  XOF256.update(seed);

  NONCE[0] = nonce;

  XOF256.update(NONCE);

  XOF256.readInto(data);

  sampleCbd(data, eta, f);

  data.fill(0);

  XOF256.reset();

  return f;
}

// Row i of A, entry j being SampleNTT(rho || j || i), into row; or of A transposed, entry j being
// A[j][i] = SampleNTT(rho || i || j).
function matrixRow(rho: Uint8Array, k: number, i: number, transposed: boolean, row: Int16Array[]): void {
  const seed = new Uint8Array(34);

  seed.set(rho);

  for (let j = 0; j < k; j++) {
    seed[32] = transposed ? i : j;

    seed[33] = transposed ? j : i;

    sampleNtt(seed, row[j]);
  }
}

// Each row of A is sampled in turn into the scratch, as t needs it.
function pkeKeygen(d: Uint8Array, p: Parameters): [Uint8Array, Uint8Array] {
  const k = p.k;

  const g = sha3(64, d, Uint8Array.of(k));

  const rho = g.subarray(0, 32);

  const sigma = g.subarray(32);

  const s: Int16Array[] = [];

  for (let i = 0; i < k; i++) {
    s.push(noise(sigma, i, p.eta1));

    ntt(s[i]);
  }

  const sHat = s.map(prepare);

  const ek = new Uint8Array(p.encapsulationKeySize);

  const dk = new Uint8Array(384 * k);

  for (let i = 0; i < k; i++) {
    matrixRow(rho, k, i, false, VECTOR);

    multiplyAccumulate(sHat, VECTOR, POLY);

    noise(sigma, k + i, p.eta1, ERROR);

    ntt(ERROR);

    for (let j = 0; j < 256; j++) {
      POLY[j] = barrettReduce(fqmul(POLY[j], 1353) + ERROR[j]);
    }

    encode12(POLY, ek, 384 * i);
  }

  for (let i = 0; i < k; i++) {
    encode12(s[i], dk, 384 * i);
  }

  ek.set(rho, 384 * k);

  wipe(g, ...s, ...sHat, POLY, ERROR);

  return [ek, dk];
}

// What encryption derives from an encapsulation key, kept with the key object and shared by a private
// key with its public key: H(ek), and Â transposed in the NTT domain with the decoded vector t̂, both
// prepared. Each part is computed on first use unless the key's creator supplies it.
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

// ByteDecode12 of the first k encoded polynomials from key[at], prepared.
function decodeVector(key: Uint8Array, k: number, at = 0): Int16Array[] {
  return Array.from({ length: k }, (_, i) => {
    const f = decode12(key, at + 384 * i);

    const prepared = prepare(f);

    f.fill(0);

    return prepared;
  });
}

function transposed(rho: Uint8Array, k: number): Int16Array[][] {
  return Array.from({ length: k }, (_, i) => {
    const row = Array.from({ length: k }, () => new Int16Array(256));

    matrixRow(rho, k, i, true, row);

    return row.map(prepare);
  });
}

// Writes the ciphertext to c, whose first ciphertextSize bytes it fills, for the encapsulation key at
// key[at], which only fills an empty cache; y lives in the scratch vector.
function pkeEncrypt(
  key: Uint8Array,
  at: number,
  cache: PublicCache,
  m: Uint8Array,
  r: Uint8Array,
  p: Parameters,
  c: Uint8Array,
): void {
  const k = p.k;

  const a = (cache.matrix ??= transposed(key.subarray(at + 384 * k, at + 384 * k + 32), k));

  const t = (cache.t ??= decodeVector(key, k, at));

  for (let i = 0; i < k; i++) {
    noise(r, i, p.eta1, VECTOR[i]);

    ntt(VECTOR[i]);
  }

  for (let i = 0; i < k; i++) {
    multiplyAccumulate(a[i], VECTOR, POLY);

    noise(r, k + i, p.eta2, ERROR);

    inverseNtt(POLY);

    for (let j = 0; j < 256; j++) {
      POLY[j] = barrettReduce(POLY[j] + ERROR[j]);
    }

    compressPolynomial(POLY, p.du, c, 32 * p.du * i);
  }

  multiplyAccumulate(t, VECTOR, POLY);

  noise(r, 2 * k, p.eta2, ERROR);

  inverseNtt(POLY);

  for (let j = 0; j < 256; j++) {
    POLY[j] = barrettReduce(POLY[j] + ERROR[j] + (-((m[j >> 3] >> (j & 7)) & 1) & 1665));
  }

  compressPolynomial(POLY, p.dv, c, 32 * p.du * k);

  wipe(POLY, ERROR, ...VECTOR);
}

// Writes the message to m; u lives in the scratch vector.
function pkeDecrypt(s: Int16Array[], c: Uint8Array, p: Parameters, m: Uint8Array): void {
  const k = p.k;

  for (let i = 0; i < k; i++) {
    decompressPolynomial(c, 32 * p.du * i, p.du, VECTOR[i]);

    ntt(VECTOR[i]);
  }

  multiplyAccumulate(s, VECTOR, POLY);

  const v = decompressPolynomial(c, 32 * p.du * k, p.dv, ERROR);

  inverseNtt(POLY);

  m.fill(0);

  for (let j = 0; j < 256; j++) {
    m[j >> 3] |= compress(canonical(barrettReduce(v[j] - POLY[j])), 1) << (j & 7);
  }

  POLY.fill(0);
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

// (K, r) = G(m || H(ek)) in the scratch, r being the noise seed of the encryption, from m read once
// into the scratch. The ciphertext fills the first ciphertextSize bytes of the array given, or a new
// one.
export function encapsInternal(
  ek: Uint8Array,
  cache: PublicCache,
  m: Uint8Array,
  p: Parameters,
  ciphertext: Uint8Array = new Uint8Array(p.ciphertextSize),
): [Uint8Array, Uint8Array] {
  for (let i = 0; i < 32; i++) {
    MESSAGE[i] = m[i];
  }

  hashG(MESSAGE, (cache.digest ??= sha3(32, ek)), 0);

  pkeEncrypt(ek, 0, cache, MESSAGE, R, p, ciphertext);

  const sharedSecret = G_OUT.slice(0, 32);

  wipe(G_OUT, MESSAGE);

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

  pkeDecrypt((secret.s ??= decodeVector(dk, k)), c, p, MESSAGE);

  hashG(MESSAGE, dk, 768 * k + 32);

  hashJ(dk, 768 * k + 64, c);

  pkeEncrypt(dk, 384 * k, cache, MESSAGE, R, p, CIPHERTEXT);

  let difference = 0;

  for (let i = 0; i < c.length; i++) {
    difference |= c[i] ^ CIPHERTEXT[i];
  }

  const mask = -((difference | -difference) >>> 31);

  const sharedSecret = new Uint8Array(32);

  for (let i = 0; i < 32; i++) {
    sharedSecret[i] = G_OUT[i] ^ (mask & (G_OUT[i] ^ REJECTED[i]));
  }

  wipe(MESSAGE, G_OUT, REJECTED, CIPHERTEXT);

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
