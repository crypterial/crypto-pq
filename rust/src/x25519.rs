use core::hint::black_box;

use crate::wipe::wipe;

// Field elements modulo p = 2^255 - 19 in five 51-bit limbs. mul, square and mul_small carry
// their results to limbs just above 2^51; add and sub do not carry, and their limbs stay below
// 2^54, which mul and square accept: their 128-bit sums of products stay below 2^115.
type Fe = [u64; 5];

const MASK: u64 = (1 << 51) - 1;

const ZERO: Fe = [0; 5];

const ONE: Fe = [1, 0, 0, 0, 0];

// 2p, added before subtracting so that no limb underflows.
const TWO_P: Fe = [
    0xF_FFFF_FFFF_FFDA,
    0xF_FFFF_FFFF_FFFE,
    0xF_FFFF_FFFF_FFFE,
    0xF_FFFF_FFFF_FFFE,
    0xF_FFFF_FFFF_FFFE,
];

const A24: u64 = 121665;

fn load64(bytes: &[u8; 32], offset: usize) -> u64 {
    let mut word = [0; 8];

    word.copy_from_slice(&bytes[offset..offset + 8]);

    u64::from_le_bytes(word)
}

// The top bit of u is ignored (RFC 7748, section 5).
fn decode(bytes: &[u8; 32]) -> Fe {
    [
        load64(bytes, 0) & MASK,
        (load64(bytes, 6) >> 3) & MASK,
        (load64(bytes, 12) >> 6) & MASK,
        (load64(bytes, 19) >> 1) & MASK,
        (load64(bytes, 24) >> 12) & MASK,
    ]
}

// The field arithmetic is const so that the table of multiples of the base point is computed
// at compile time from its definition, with the same code that runs.
const fn carry(mut wide: [u128; 5]) -> Fe {
    let mut h = [0; 5];

    let mut i = 0;

    while i < 4 {
        wide[i + 1] += wide[i] >> 51;

        h[i] = wide[i] as u64 & MASK;

        i += 1;
    }

    h[4] = wide[4] as u64 & MASK;

    h[0] += 19 * (wide[4] >> 51) as u64;

    h[1] += h[0] >> 51;

    h[0] &= MASK;

    h
}

const fn add(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ]
}

// b must be carried, so that adding 2p first keeps every limb from going below zero.
const fn sub(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + TWO_P[0] - b[0],
        a[1] + TWO_P[1] - b[1],
        a[2] + TWO_P[2] - b[2],
        a[3] + TWO_P[3] - b[3],
        a[4] + TWO_P[4] - b[4],
    ]
}

fn mul_small(a: &Fe, k: u64) -> Fe {
    carry(a.map(|limb| u128::from(limb) * u128::from(k)))
}

const fn wide(x: u64, y: u64) -> u128 {
    x as u128 * y as u128
}

const fn mul(a: &Fe, b: &Fe) -> Fe {
    let [a0, a1, a2, a3, a4] = *a;

    let [b0, b1, b2, b3, b4] = *b;

    let (b1_19, b2_19, b3_19, b4_19) = (19 * b1, 19 * b2, 19 * b3, 19 * b4);

    carry([
        wide(a0, b0) + wide(a1, b4_19) + wide(a2, b3_19) + wide(a3, b2_19) + wide(a4, b1_19),
        wide(a0, b1) + wide(a1, b0) + wide(a2, b4_19) + wide(a3, b3_19) + wide(a4, b2_19),
        wide(a0, b2) + wide(a1, b1) + wide(a2, b0) + wide(a3, b4_19) + wide(a4, b3_19),
        wide(a0, b3) + wide(a1, b2) + wide(a2, b1) + wide(a3, b0) + wide(a4, b4_19),
        wide(a0, b4) + wide(a1, b3) + wide(a2, b2) + wide(a3, b1) + wide(a4, b0),
    ])
}

// mul(a, a) with the symmetric products counted once and doubled.
const fn square(a: &Fe) -> Fe {
    let [a0, a1, a2, a3, a4] = *a;

    let (a3_19, a4_19) = (19 * a3, 19 * a4);

    carry([
        wide(a0, a0) + wide(2 * a1, a4_19) + wide(2 * a2, a3_19),
        wide(2 * a0, a1) + wide(2 * a2, a4_19) + wide(a3, a3_19),
        wide(2 * a0, a2) + wide(a1, a1) + wide(2 * a3, a4_19),
        wide(2 * a0, a3) + wide(2 * a1, a2) + wide(a4, a4_19),
        wide(2 * a0, a4) + wide(2 * a1, a3) + wide(a2, a2),
    ])
}

const fn square_times(a: &Fe, count: usize) -> Fe {
    let mut x = *a;

    let mut i = 0;

    while i < count {
        x = square(&x);

        i += 1;
    }

    x
}

// z^(2^250 - 1) and z^11, through the usual chain shared by inversion and square roots.
const fn power_2_250_1(z: &Fe) -> (Fe, Fe) {
    let z2 = square(z);

    let z9 = mul(&square_times(&z2, 2), z);

    let z11 = mul(&z9, &z2);

    let z_5_0 = mul(&square(&z11), &z9);

    let z_10_0 = mul(&square_times(&z_5_0, 5), &z_5_0);

    let z_20_0 = mul(&square_times(&z_10_0, 10), &z_10_0);

    let z_40_0 = mul(&square_times(&z_20_0, 20), &z_20_0);

    let z_50_0 = mul(&square_times(&z_40_0, 10), &z_10_0);

    let z_100_0 = mul(&square_times(&z_50_0, 50), &z_50_0);

    let z_200_0 = mul(&square_times(&z_100_0, 100), &z_100_0);

    (mul(&square_times(&z_200_0, 50), &z_50_0), z11)
}

// z^(p - 2) = z^(2^255 - 21): 254 squarings and 11 multiplications.
const fn invert(z: &Fe) -> Fe {
    let (z_250_0, z11) = power_2_250_1(z);

    mul(&square_times(&z_250_0, 5), &z11)
}

// z^((p - 5) / 8) = z^(2^252 - 3), the exponent of RFC 8032's square roots.
const fn power_p58(z: &Fe) -> Fe {
    let (z_250_0, _) = power_2_250_1(z);

    mul(&square_times(&z_250_0, 2), z)
}

// The canonical representative, below p.
const fn freeze(h: &Fe) -> Fe {
    let mut h = *h;

    let mut i = 0;

    while i < 4 {
        h[i + 1] += h[i] >> 51;

        h[i] &= MASK;

        i += 1;
    }

    h[0] += 19 * (h[4] >> 51);

    h[4] &= MASK;

    // Now h < 2p, so one conditional subtraction of p is enough; q = 1 exactly when h >= p.
    let mut q = (h[0] + 19) >> 51;

    let mut i = 1;

    while i < 5 {
        q = (h[i] + q) >> 51;

        i += 1;
    }

    h[0] += 19 * q;

    let mut i = 0;

    while i < 4 {
        h[i + 1] += h[i] >> 51;

        h[i] &= MASK;

        i += 1;
    }

    h[4] &= MASK;

    h
}

fn encode(h: &Fe) -> [u8; 32] {
    let h = freeze(h);

    let words = [
        h[0] | (h[1] << 51),
        (h[1] >> 13) | (h[2] << 38),
        (h[2] >> 26) | (h[3] << 25),
        (h[3] >> 39) | (h[4] << 12),
    ];

    let mut out = [0; 32];

    for (bytes, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }

    out
}

fn swap(bit: u64, a: &mut Fe, b: &mut Fe) {
    let mask = black_box(0u64.wrapping_sub(bit));

    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = mask & (*x ^ *y);

        *x ^= t;

        *y ^= t;
    }
}

fn clamp(scalar: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];

    k.copy_from_slice(scalar);

    k[0] &= 248;

    k[31] &= 127;

    k[31] |= 64;

    k
}

// RFC 7748, section 5: the Montgomery ladder over u-coordinates with a masked swap.
pub(crate) fn x25519(scalar: &[u8], u: &[u8]) -> [u8; 32] {
    let mut k = clamp(scalar);

    let mut point = [0u8; 32];

    point.copy_from_slice(u);

    let x1 = decode(&point);

    let (mut x2, mut z2, mut x3, mut z3) = (ONE, ZERO, x1, ONE);

    let mut swapped = 0;

    for t in (0..255).rev() {
        let bit = u64::from((k[t / 8] >> (t % 8)) & 1);

        swapped ^= bit;

        swap(swapped, &mut x2, &mut x3);

        swap(swapped, &mut z2, &mut z3);

        swapped = bit;

        let a = add(&x2, &z2);

        let aa = square(&a);

        let b = sub(&x2, &z2);

        let bb = square(&b);

        let e = sub(&aa, &bb);

        let c = add(&x3, &z3);

        let d = sub(&x3, &z3);

        let da = mul(&d, &a);

        let cb = mul(&c, &b);

        x3 = square(&add(&da, &cb));

        z3 = mul(&x1, &square(&sub(&da, &cb)));

        x2 = mul(&aa, &bb);

        z2 = mul(&e, &add(&aa, &mul_small(&e, A24)));
    }

    swap(swapped, &mut x2, &mut x3);

    swap(swapped, &mut z2, &mut z3);

    let out = encode(&mul(&x2, &invert(&z2)));

    wipe(&mut k);

    for value in [&mut x2, &mut z2, &mut x3, &mut z3] {
        wipe(value);
    }

    out
}

// A point of edwards25519, -x^2 + y^2 = 1 + d x^2 y^2, in extended coordinates: x = X/Z,
// y = Y/Z and XY = ZT.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

const IDENTITY: Point = Point {
    x: ZERO,
    y: ONE,
    z: ONE,
    t: ZERO,
};

// An affine point as y + x, y - x and 2dxy, the form in which the table holds the multiples of
// the base point (ref10's ge_precomp).
type Precomputed = [Fe; 3];

// The formulas of ref10's ge_p2_dbl and ge_p1p1_to_p3, reordered so that every subtrahend is
// carried: x = 2XY / (Y^2 - X^2) and y = (Y^2 + X^2) / (2Z^2 + X^2 - Y^2). The inputs of the
// last four multiplications stay below 2^53.4.
const fn double(p: &Point) -> Point {
    let xx = square(&p.x);

    let yy = square(&p.y);

    let zz = square(&p.z);

    let e = sub(&sub(&square(&add(&p.x, &p.y)), &xx), &yy);

    let g = sub(&yy, &xx);

    let h = add(&yy, &xx);

    let f = sub(&add(&add(&zz, &zz), &xx), &yy);

    Point {
        x: mul(&e, &f),
        y: mul(&h, &g),
        z: mul(&g, &f),
        t: mul(&e, &h),
    }
}

// p + q for q in the table's form, as ref10's ge_madd and ge_p1p1_to_p3; the inputs of the
// last four multiplications stay below 2^53.
fn add_precomputed(p: &Point, q: &Precomputed) -> Point {
    let [plus, minus, xy2d] = q;

    let a = mul(&add(&p.y, &p.x), plus);

    let b = mul(&sub(&p.y, &p.x), minus);

    let c = mul(xy2d, &p.t);

    let d = add(&p.z, &p.z);

    let e = sub(&a, &b);

    let f = sub(&d, &c);

    let g = add(&d, &c);

    let h = add(&a, &b);

    Point {
        x: mul(&e, &f),
        y: mul(&h, &g),
        z: mul(&g, &f),
        t: mul(&e, &h),
    }
}

// What follows defines the table: the curve constant, the base point and the multiples
// j * 256^i * B for i < 32 and 1 <= j <= 8, all derived here from their definitions.

const fn small(value: u64) -> Fe {
    [value, 0, 0, 0, 0]
}

const fn same(a: &Fe, b: &Fe) -> bool {
    let (a, b) = (freeze(a), freeze(b));

    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4]
}

// d = -121665 / 121666.
const D: Fe = mul(&sub(&ZERO, &small(121665)), &invert(&small(121666)));

const D2: Fe = add(&D, &D);

// 2^((p - 1) / 4), a square root of -1 because 2 is not a square modulo p.
const SQRT_M1: Fe = mul(&square(&power_p58(&small(2))), &small(2));

// p + q for two points in extended coordinates (Hisil, Wong, Carter and Dawson, 2008, for
// a = -1); only the table is built with it.
const fn add_points(p: &Point, q: &Point) -> Point {
    let a = mul(&sub(&p.y, &p.x), &sub(&q.y, &q.x));

    let b = mul(&add(&p.y, &p.x), &add(&q.y, &q.x));

    let c = mul(&mul(&p.t, &q.t), &D2);

    let d = mul(&p.z, &add(&q.z, &q.z));

    let e = sub(&b, &a);

    let f = sub(&d, &c);

    let g = add(&d, &c);

    let h = add(&b, &a);

    Point {
        x: mul(&e, &f),
        y: mul(&g, &h),
        z: mul(&f, &g),
        t: mul(&e, &h),
    }
}

// B = (x, 4/5) with x even (RFC 8032, section 5.1). x^2 = (y^2 - 1) / (d y^2 + 1), and the root
// is taken as in RFC 8032, section 5.1.3: x = u v^3 (u v^7)^((p - 5) / 8), times sqrt(-1) when
// v x^2 = -u.
const BASE_POINT: Point = {
    let y = mul(&small(4), &invert(&small(5)));

    let yy = square(&y);

    let u = sub(&yy, &ONE);

    let v = add(&mul(&D, &yy), &ONE);

    let v3 = mul(&square(&v), &v);

    let v7 = mul(&square(&v3), &v);

    let mut x = mul(&mul(&u, &v3), &power_p58(&mul(&u, &v7)));

    if !same(&mul(&v, &square(&x)), &u) {
        x = mul(&x, &SQRT_M1);
    }

    assert!(same(&mul(&v, &square(&x)), &u), "x^2 has no square root");

    x = freeze(&x);

    if x[0] & 1 == 1 {
        x = freeze(&sub(&ZERO, &x));
    }

    let point = Point {
        x,
        y: freeze(&y),
        z: ONE,
        t: mul(&x, &y),
    };

    // On the curve, and mapped to u = 9 by u = (1 + y) / (1 - y): it is X25519's base point.
    let xx = square(&point.x);

    assert!(
        same(&sub(&yy, &xx), &add(&ONE, &mul(&D, &mul(&xx, &yy)))),
        "B is not on the curve"
    );

    assert!(
        same(&mul(&add(&ONE, &y), &invert(&sub(&ONE, &y))), &small(9)),
        "B does not map to u = 9"
    );

    point
};

// The multiples in extended coordinates, then all brought to Z = 1 with one inversion
// (Montgomery's trick) and written as y + x, y - x and 2dxy.
const fn table() -> [[Precomputed; 8]; 32] {
    let mut points = [[IDENTITY; 8]; 32];

    let mut base = BASE_POINT;

    let mut i = 0;

    while i < 32 {
        points[i][0] = base;

        let mut j = 1;

        while j < 8 {
            points[i][j] = add_points(&points[i][j - 1], &base);

            j += 1;
        }

        let mut n = 0;

        while n < 8 {
            base = double(&base);

            n += 1;
        }

        i += 1;
    }

    let mut prefixes = [[ONE; 8]; 32];

    let mut product = ONE;

    let mut n = 0;

    while n < 256 {
        prefixes[n / 8][n % 8] = product;

        product = mul(&product, &points[n / 8][n % 8].z);

        n += 1;
    }

    let mut inverse = invert(&product);

    let mut table = [[[ZERO; 3]; 8]; 32];

    let mut n = 256;

    while n > 0 {
        n -= 1;

        let point = &points[n / 8][n % 8];

        let z_inverse = mul(&inverse, &prefixes[n / 8][n % 8]);

        inverse = mul(&inverse, &point.z);

        let x = mul(&point.x, &z_inverse);

        let y = mul(&point.y, &z_inverse);

        table[n / 8][n % 8] = [
            freeze(&add(&y, &x)),
            freeze(&sub(&y, &x)),
            freeze(&mul(&mul(&x, &y), &D2)),
        ];
    }

    table
}

static TABLE: [[Precomputed; 8]; 32] = table();

// 1 when a == b, 0 otherwise, for a and b below 2^31.
fn equal(a: u64, b: u64) -> u64 {
    ((a ^ b) as u32).wrapping_sub(1) as u64 >> 31
}

// |digit| * 256^position * B, negated when the digit is negative, as ref10's select: every entry
// of the row is read and kept or dropped by a mask, so neither a branch nor an index depends on
// the digit.
fn select(position: usize, digit: i8) -> Precomputed {
    let sign = digit >> 7;

    let magnitude = ((digit ^ sign) - sign) as u64;

    let mut t = [ONE, ONE, ZERO];

    for (j, entry) in (1..).zip(&TABLE[position]) {
        let mask = black_box(0u64.wrapping_sub(equal(magnitude, j)));

        for (x, y) in t.as_flattened_mut().iter_mut().zip(entry.as_flattened()) {
            *x ^= mask & (*x ^ *y);
        }
    }

    // -(x, y) = (-x, y): y + x and y - x trade places and 2dxy changes sign.
    let negative = black_box(i64::from(sign) as u64);

    let [plus, minus, xy2d] = &mut t;

    for (x, y) in plus.iter_mut().zip(minus.iter_mut()) {
        let difference = negative & (*x ^ *y);

        *x ^= difference;

        *y ^= difference;
    }

    let negated = sub(&ZERO, xy2d);

    for (x, y) in xy2d.iter_mut().zip(negated) {
        *x ^= negative & (*x ^ y);
    }

    t
}

// The clamped scalar as 64 signed radix-16 digits in [-8, 8], as ref10's ge_scalarmult_base: its
// top bit is clear, so the last digit takes the final carry without overflowing.
fn digits(k: &[u8; 32]) -> [i8; 64] {
    let mut e = [0i8; 64];

    for (pair, byte) in e.as_chunks_mut::<2>().0.iter_mut().zip(k) {
        *pair = [(byte & 15) as i8, (byte >> 4) as i8];
    }

    let mut carry = 0;

    for digit in &mut e[..63] {
        *digit += carry;

        carry = (*digit + 8) >> 4;

        *digit -= carry << 4;
    }

    e[63] += carry;

    e
}

// X25519(k, 9) for public keys: k * B on edwards25519 from the table, as ref10's
// ge_scalarmult_base, sums the multiples of the odd digits, multiplies by 16 and adds those of
// the even ones. u = (1 + y) / (1 - y) = (Z + Y) / (Z - Y) maps the result to the u-coordinate
// that the ladder computes: the map takes B to the point with u = 9 and preserves the group law.
pub(crate) fn x25519_base(scalar: &[u8]) -> [u8; 32] {
    let mut k = clamp(scalar);

    let mut e = digits(&k);

    let mut h = IDENTITY;

    for (position, pair) in e.as_chunks::<2>().0.iter().enumerate() {
        h = add_precomputed(&h, &select(position, pair[1]));
    }

    for _ in 0..4 {
        h = double(&h);
    }

    for (position, pair) in e.as_chunks::<2>().0.iter().enumerate() {
        h = add_precomputed(&h, &select(position, pair[0]));
    }

    let out = encode(&mul(&add(&h.z, &h.y), &invert(&sub(&h.z, &h.y))));

    wipe(&mut k);

    wipe(&mut e);

    for value in [&mut h.x, &mut h.y, &mut h.z, &mut h.t] {
        wipe(value);
    }

    out
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::collections::HashMap;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use super::{x25519, x25519_base};
    use crate::primitives::shake256;

    type Fields = HashMap<String, String>;

    const BASE: [u8; 32] = {
        let mut base = [0; 32];

        base[0] = 9;

        base
    };

    // The shared vector format: [key = value] headers persist, blank lines end records.
    fn records(name: &str, field: &str) -> Vec<(Fields, Fields)> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../vectors")
            .join(name);

        let text = std::fs::read_to_string(&path).expect("vector file");

        let mut header = Fields::new();

        let mut record = Fields::new();

        let mut found = Vec::new();

        for line in text.lines().chain([""]) {
            let line = line.trim();

            if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let (key, value) = inner.split_once('=').unwrap_or((inner, ""));

                header.insert(key.trim().to_string(), value.trim().to_string());
            } else if let Some((key, value)) =
                line.split_once('=').filter(|_| !line.starts_with('#'))
            {
                record.insert(key.trim().to_string(), value.trim().to_string());
            } else if !record.is_empty() {
                found.push((header.clone(), std::mem::take(&mut record)));
            }
        }

        let prefix = std::format!("{field} =");

        let expected = text.lines().filter(|l| l.starts_with(&prefix)).count();

        let parsed = found.iter().filter(|(_, r)| r.contains_key(field)).count();

        assert!(
            expected > 0 && parsed == expected,
            "{name}: {parsed} of {expected}"
        );

        found
    }

    fn unhex(text: &str) -> [u8; 32] {
        let mut out = [0; 32];

        assert_eq!(text.len(), 64);

        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex");
        }

        out
    }

    #[test]
    fn rfc7748() {
        let slow = std::env::var_os("CRYPTO_PQ_SLOW").is_some_and(|value| !value.is_empty());

        let mut iterations_run = 0;

        let mut exchanges = 0;

        for (header, record) in records("rfc/x25519.txt", "output") {
            match header["kind"].as_str() {
                "multiply" => {
                    let result = x25519(&unhex(&record["scalar"]), &unhex(&record["u"]));

                    assert_eq!(result, unhex(&record["output"]));
                }
                "iterate" => {
                    let count: usize = record["iterations"].parse().expect("count");

                    if count > 1000 && !slow {
                        continue;
                    }

                    let (mut k, mut u) = (BASE, BASE);

                    for _ in 0..count {
                        (k, u) = (x25519(&k, &u), k);
                    }

                    assert_eq!(k, unhex(&record["output"]), "{count} iterations");

                    iterations_run += 1;
                }
                "exchange" => {
                    let alice = unhex(&record["alicePrivate"]);

                    let bob = unhex(&record["bobPrivate"]);

                    let alice_public = unhex(&record["alicePublic"]);

                    let bob_public = unhex(&record["bobPublic"]);

                    assert_eq!(x25519(&alice, &BASE), alice_public);

                    assert_eq!(x25519(&bob, &BASE), bob_public);

                    assert_eq!(x25519_base(&alice), alice_public);

                    assert_eq!(x25519_base(&bob), bob_public);

                    assert_eq!(x25519(&alice, &bob_public), unhex(&record["shared"]));

                    assert_eq!(x25519(&bob, &alice_public), unhex(&record["shared"]));

                    exchanges += 1;
                }
                kind => panic!("unknown kind {kind}"),
            }
        }

        assert_eq!(iterations_run, if slow { 3 } else { 2 });

        assert_eq!(exchanges, 1);
    }

    // Wycheproof marks low-order and twist points "acceptable"; X25519 itself is defined for them.
    #[test]
    fn wycheproof() {
        let found = records("wycheproof/x25519.txt", "tcId");

        for (_, record) in &found {
            let shared = x25519(&unhex(&record["private"]), &unhex(&record["public"]));

            assert_eq!(shared, unhex(&record["shared"]), "tcId {}", record["tcId"]);
        }

        assert_eq!(found.len(), 518);
    }

    // The table path must give the ladder's result for every scalar: many from a fixed SHAKE256
    // stream, and edge scalars whose digits reach -8, 0 and 8 with every carry pattern.
    #[test]
    fn base_matches_ladder() {
        let mut stream = shake256(&[b"crypto-pq x25519 base"]);

        for _ in 0..10_000 {
            let mut k = [0; 32];

            stream.read(&mut k);

            assert_eq!(x25519_base(&k), x25519(&k, &BASE), "{k:02x?}");
        }

        let values = [
            0x00, 0x01, 0x07, 0x08, 0x0F, 0x10, 0x70, 0x77, 0x78, 0x7F, 0x80, 0x87, 0x88, 0x8F,
            0xF0, 0xF7, 0xF8, 0xFF,
        ];

        for background in [0x00, 0x88, 0xFF] {
            for position in 0..32 {
                for value in values {
                    let mut k = [background; 32];

                    k[position] = value;

                    assert_eq!(x25519_base(&k), x25519(&k, &BASE), "{k:02x?}");
                }
            }
        }
    }
}
