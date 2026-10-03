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
