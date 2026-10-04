import { wipe } from "./bytes.ts";
import { multiply, square } from "./x25519-field.ts";

// GF(2^255 - 19) with sixteen 16-bit limbs held in doubles. Limb products and their sums stay
// below 2^53, so every operation is exact, and no branch or index depends on a value.
type Field = Float64Array;

const LIMB = 65536;

const LIMB_INVERSE = 2 ** -16;

export const BASE = Uint8Array.of(9, ...new Uint8Array(31));

function field(value = 0): Field {
  const out = new Float64Array(16);

  out[0] = value;

  return out;
}

// Brings every limb into [0, 2^16), folding the carry out of the top limb back as 2^256 = 38.
function carry(o: Field): void {
  for (let i = 0; i < 16; i++) {
    const c = Math.floor(o[i] * LIMB_INVERSE);

    o[i] -= c * LIMB;

    if (i < 15) {
      o[i + 1] += c;
    } else {
      o[0] += 38 * c;
    }
  }
}

function add(o: Field, a: Field, b: Field): void {
  for (let i = 0; i < 16; i++) {
    o[i] = a[i] + b[i];
  }
}

function subtract(o: Field, a: Field, b: Field): void {
  for (let i = 0; i < 16; i++) {
    o[i] = a[i] - b[i];
  }
}

// a * 121665, the constant (A - 2) / 4 of the Montgomery ladder.
function multiplyA24(o: Field, a: Field): void {
  for (let i = 0; i < 16; i++) {
    o[i] = 121665 * a[i];
  }

  carry(o);

  carry(o);
}

// Swaps p and q when bit is 1, with a mask instead of a branch.
function swap(p: Field, q: Field, bit: number): void {
  const mask = -bit;

  for (let i = 0; i < 16; i++) {
    const t = mask & (p[i] ^ q[i]);

    p[i] ^= t;

    q[i] ^= t;
  }
}

function squares(o: Field, a: Field, count: number): void {
  square(o, a);

  for (let i = 1; i < count; i++) {
    square(o, o);
  }
}

// a^(p - 2) = a^-1 by the fixed addition chain of 254 squarings and 11 multiplications in ref10.
function invert(o: Field, a: Field): void {
  const t0 = field();

  const t1 = field();

  const t2 = field();

  const t3 = field();

  square(t0, a);

  squares(t1, t0, 2);

  multiply(t1, a, t1);

  multiply(t0, t0, t1);

  square(t2, t0);

  multiply(t1, t1, t2);

  squares(t2, t1, 5);

  multiply(t1, t2, t1);

  squares(t2, t1, 10);

  multiply(t2, t2, t1);

  squares(t3, t2, 20);

  multiply(t2, t3, t2);

  squares(t2, t2, 10);

  multiply(t1, t2, t1);

  squares(t2, t1, 50);

  multiply(t2, t2, t1);

  squares(t3, t2, 100);

  multiply(t2, t3, t2);

  squares(t2, t2, 50);

  multiply(t1, t2, t1);

  squares(t1, t1, 5);

  multiply(o, t1, t0);

  wipe(t0, t1, t2, t3);
}

function unpack(data: Uint8Array): Field {
  const o = field();

  for (let i = 0; i < 16; i++) {
    o[i] = data[2 * i] + (data[2 * i + 1] << 8);
  }

  o[15] &= 0x7fff;

  return o;
}

// The canonical encoding: p is subtracted twice, each result kept only when it did not borrow.
function pack(n: Field): Uint8Array {
  const t = n.slice();

  const m = field();

  carry(t);

  carry(t);

  carry(t);

  for (let round = 0; round < 2; round++) {
    m[0] = t[0] - 0xffed;

    for (let i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);

      m[i - 1] &= 0xffff;
    }

    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);

    const borrow = (m[15] >> 16) & 1;

    m[14] &= 0xffff;

    swap(t, m, 1 - borrow);
  }

  const out = new Uint8Array(32);

  for (let i = 0; i < 16; i++) {
    out[2 * i] = t[i];

    out[2 * i + 1] = t[i] >> 8;
  }

  wipe(t, m);

  return out;
}

// RFC 7748, section 5: the Montgomery ladder over u-coordinates with a masked conditional swap.
export function x25519(scalar: Uint8Array, u: Uint8Array): Uint8Array {
  const k = scalar.slice();

  k[0] &= 248;

  k[31] &= 127;

  k[31] |= 64;

  const x1 = unpack(u);

  const x2 = field(1);

  const z2 = field();

  const x3 = x1.slice();

  const z3 = field(1);

  const a = field();

  const aa = field();

  const b = field();

  const bb = field();

  const e = field();

  const c = field();

  const d = field();

  const da = field();

  const cb = field();

  let swapped = 0;

  for (let t = 254; t >= 0; t--) {
    const bit = (k[t >>> 3] >>> (t & 7)) & 1;

    swapped ^= bit;

    swap(x2, x3, swapped);

    swap(z2, z3, swapped);

    swapped = bit;

    add(a, x2, z2);

    square(aa, a);

    subtract(b, x2, z2);

    square(bb, b);

    subtract(e, aa, bb);

    add(c, x3, z3);

    subtract(d, x3, z3);

    multiply(da, d, a);

    multiply(cb, c, b);

    add(x3, da, cb);

    square(x3, x3);

    subtract(z3, da, cb);

    square(z3, z3);

    multiply(z3, z3, x1);

    multiply(x2, aa, bb);

    multiplyA24(a, e);

    add(a, a, aa);

    multiply(z2, e, a);
  }

  swap(x2, x3, swapped);

  swap(z2, z3, swapped);

  invert(z2, z2);

  multiply(x2, x2, z2);

  const out = pack(x2);

  wipe(k, x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb);

  return out;
}

// Fixed-base X25519 for public keys, as in ref10 and libsodium: [k]B on the Edwards form of the curve
// (RFC 7748, 4.1), whose u-coordinate (1 + y) / (1 - y) = (Z + Y) / (Z - Y) is what the ladder gives for
// the same scalar. [k]B sums one multiple of 16^i B per signed radix-16 digit of k, taken from a table of
// the multiples 1 to 8 of 256^i B: the odd digits first, then a multiplication by 16, then the even
// digits. A digit only steers masked moves over all eight entries of its table row.

// A point (X : Y : Z : T) on -x^2 + y^2 = 1 + d x^2 y^2, with x = X / Z, y = Y / Z and xy = T / Z.
interface Point {
  readonly x: Field;

  readonly y: Field;

  readonly z: Field;

  readonly t: Field;
}

// An affine point as y + x, y - x and 2dxy, the form that mixed addition reads.
interface Affine {
  readonly yPlusX: Field;

  readonly yMinusX: Field;

  readonly xy2d: Field;
}

// The x-coordinate of the base point B = (x, 4/5), the even one of the two roots (RFC 8032, 5.1),
// little-endian.
const BASE_X = Uint8Array.of(
  0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
  0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
);

// The temporaries of the point formulas, shared since JavaScript runs one call at a time; x25519Base
// clears them.
const SCRATCH = Array.from({ length: 9 }, () => field());

const [TA, TB, TC, TD, TE, TF, TG, TH, NEGATED] = SCRATCH;

// The identity, (0 : 1 : 1 : 0).
function point(): Point {
  return { x: field(), y: field(1), z: field(1), t: field() };
}

// The identity in affine form.
function affine(): Affine {
  return { yPlusX: field(1), yMinusX: field(1), xy2d: field() };
}

// v = p + q for an affine q (add-2008-hwcd-3 with k = 2d and Z2 = 1); v may be p. Every product input
// is a sum of at most three products, as the limb bound of multiply allows.
function addAffine(v: Point, p: Point, q: Affine): void {
  add(TA, p.y, p.x);

  subtract(TB, p.y, p.x);

  multiply(TC, TB, q.yMinusX);

  multiply(TD, TA, q.yPlusX);

  multiply(TE, p.t, q.xy2d);

  add(TF, p.z, p.z);

  subtract(TA, TD, TC);

  add(TB, TD, TC);

  subtract(TG, TF, TE);

  add(TH, TF, TE);

  multiply(v.x, TA, TG);

  multiply(v.y, TH, TB);

  multiply(v.z, TG, TH);

  multiply(v.t, TA, TB);
}

// v = 2p (dbl-2008-hwcd with a = -1) with every coordinate negated, which is the same point; v may be p.
// The largest product input is a sum of four products.
function double(v: Point, p: Point): void {
  square(TA, p.x);

  square(TB, p.y);

  square(TC, p.z);

  add(TC, TC, TC);

  add(TD, p.x, p.y);

  square(TE, TD);

  add(TD, TA, TB);

  subtract(TF, TB, TA);

  subtract(TE, TE, TD);

  subtract(TG, TC, TF);

  multiply(v.x, TE, TG);

  multiply(v.y, TF, TD);

  multiply(v.z, TG, TF);

  multiply(v.t, TE, TD);
}

// The points in affine form, with one inversion for all of them: the running products of the Z
// coordinates are inverted once and then unwound (Montgomery's trick).
function toAffine(points: Point[], d2: Field): Affine[] {
  const products: Field[] = [];

  let product = field(1);

  for (const p of points) {
    products.push(product);

    const next = field();

    multiply(next, product, p.z);

    product = next;
  }

  const inverse = field();

  invert(inverse, product);

  const out: Affine[] = [];

  for (let i = points.length - 1; i >= 0; i--) {
    const zInverse = field();

    multiply(zInverse, inverse, products[i]);

    multiply(inverse, inverse, points[i].z);

    const x = field();

    const y = field();

    multiply(x, points[i].x, zInverse);

    multiply(y, points[i].y, zInverse);

    const entry = affine();

    add(entry.yPlusX, y, x);

    subtract(entry.yMinusX, y, x);

    multiply(x, x, y);

    multiply(entry.xy2d, x, d2);

    out[i] = entry;
  }

  return out;
}

let TABLE: Int32Array | null = null;

// The table of x25519Base: entry 8i + j is (j + 1) 256^i B as y + x, y - x and 2dxy, sixteen limbs each,
// computed from B on first use. d is -121665 / 121666 (RFC 7748, 4.1).
export function edwardsTable(): Int32Array {
  const d2 = field();

  invert(d2, field(121666));

  const minus = field();

  subtract(minus, field(), field(121665));

  multiply(d2, minus, d2);

  add(d2, d2, d2);

  const base = point();

  base.x.set(unpack(BASE_X));

  invert(minus, field(5));

  multiply(base.y, field(4), minus);

  multiply(base.t, base.x, base.y);

  const rows = [base];

  for (let i = 1; i < 32; i++) {
    const p = point();

    double(p, rows[i - 1]);

    for (let n = 1; n < 8; n++) {
      double(p, p);
    }

    rows.push(p);
  }

  const firsts = toAffine(rows, d2);

  const multiples: Point[] = [];

  for (let i = 0; i < 32; i++) {
    let previous = rows[i];

    for (let j = 1; j < 8; j++) {
      const next = point();

      addAffine(next, previous, firsts[i]);

      multiples.push(next);

      previous = next;
    }
  }

  const rest = toAffine(multiples, d2);

  const table = new Int32Array(32 * 8 * 48);

  for (let i = 0; i < 32 * 8; i++) {
    const entry = i % 8 === 0 ? firsts[i / 8] : rest[i - 1 - Math.floor(i / 8)];

    table.set(entry.yPlusX, 48 * i);

    table.set(entry.yMinusX, 48 * i + 16);

    table.set(entry.xy2d, 48 * i + 32);
  }

  return table;
}

// Sets out to the multiple digit of row's base point, for |digit| <= 8. Masked moves read all eight
// entries; a negative digit then swaps y + x with y - x and negates 2dxy, which negates the point.
function select(out: Affine, table: Int32Array, row: number, digit: number): void {
  const sign = digit >> 31;

  const magnitude = (digit ^ sign) - sign;

  out.yPlusX.fill(0);

  out.yMinusX.fill(0);

  out.xy2d.fill(0);

  out.yPlusX[0] = 1;

  out.yMinusX[0] = 1;

  for (let j = 0; j < 8; j++) {
    const mask = -(((magnitude ^ (j + 1)) - 1) >>> 31);

    const offset = 48 * (8 * row + j);

    for (let i = 0; i < 16; i++) {
      out.yPlusX[i] ^= mask & (out.yPlusX[i] ^ table[offset + i]);

      out.yMinusX[i] ^= mask & (out.yMinusX[i] ^ table[offset + 16 + i]);

      out.xy2d[i] ^= mask & (out.xy2d[i] ^ table[offset + 32 + i]);
    }
  }

  swap(out.yPlusX, out.yMinusX, -sign);

  for (let i = 0; i < 16; i++) {
    NEGATED[i] = -out.xy2d[i];
  }

  swap(out.xy2d, NEGATED, -sign);
}

// X25519(scalar, 9): the u-coordinate of [k]B for the clamped scalar k.
export function x25519Base(scalar: Uint8Array): Uint8Array {
  const k = scalar.slice();

  k[0] &= 248;

  k[31] &= 127;

  k[31] |= 64;

  // k = sum of digits[i] 16^i with every digit in [-8, 8]: each nibble above 7 becomes the nibble minus 16
  // and carries one into the next. The top digit stays at most 8 since bit 255 is clear.
  const digits = new Int8Array(64);

  for (let i = 0; i < 32; i++) {
    digits[2 * i] = k[i] & 15;

    digits[2 * i + 1] = k[i] >> 4;
  }

  let up = 0;

  for (let i = 0; i < 63; i++) {
    digits[i] += up;

    up = (digits[i] + 8) >> 4;

    digits[i] -= up << 4;
  }

  digits[63] += up;

  const table = (TABLE ??= edwardsTable());

  const h = point();

  const entry = affine();

  for (let i = 1; i < 64; i += 2) {
    select(entry, table, i >> 1, digits[i]);

    addAffine(h, h, entry);
  }

  for (let n = 0; n < 4; n++) {
    double(h, h);
  }

  for (let i = 0; i < 64; i += 2) {
    select(entry, table, i >> 1, digits[i]);

    addAffine(h, h, entry);
  }

  const numerator = field();

  const denominator = field();

  add(numerator, h.z, h.y);

  subtract(denominator, h.z, h.y);

  invert(denominator, denominator);

  multiply(numerator, numerator, denominator);

  const out = pack(numerator);

  wipe(k, digits, h.x, h.y, h.z, h.t, entry.yPlusX, entry.yMinusX, entry.xy2d, numerator, denominator, ...SCRATCH);

  return out;
}
