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

pub(crate) const BASE: [u8; 32] = {
    let mut base = [0; 32];

    base[0] = 9;

    base
};

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

fn carry(mut wide: [u128; 5]) -> Fe {
    for i in 0..4 {
        wide[i + 1] += wide[i] >> 51;

        wide[i] &= u128::from(MASK);
    }

    let mut h = wide.map(|limb| (limb & u128::from(MASK)) as u64);

    h[0] += 19 * (wide[4] >> 51) as u64;

    h[1] += h[0] >> 51;

    h[0] &= MASK;

    h
}

fn add(a: &Fe, b: &Fe) -> Fe {
    core::array::from_fn(|i| a[i] + b[i])
}

// b must be carried, so that adding 2p first keeps every limb from going below zero.
fn sub(a: &Fe, b: &Fe) -> Fe {
    core::array::from_fn(|i| a[i] + TWO_P[i] - b[i])
}

fn mul_small(a: &Fe, k: u64) -> Fe {
    carry(a.map(|limb| u128::from(limb) * u128::from(k)))
}

fn mul(a: &Fe, b: &Fe) -> Fe {
    let m = |x: u64, y: u64| u128::from(x) * u128::from(y);

    let [a0, a1, a2, a3, a4] = *a;

    let [b0, b1, b2, b3, b4] = *b;

    let (b1_19, b2_19, b3_19, b4_19) = (19 * b1, 19 * b2, 19 * b3, 19 * b4);

    carry([
        m(a0, b0) + m(a1, b4_19) + m(a2, b3_19) + m(a3, b2_19) + m(a4, b1_19),
        m(a0, b1) + m(a1, b0) + m(a2, b4_19) + m(a3, b3_19) + m(a4, b2_19),
        m(a0, b2) + m(a1, b1) + m(a2, b0) + m(a3, b4_19) + m(a4, b3_19),
        m(a0, b3) + m(a1, b2) + m(a2, b1) + m(a3, b0) + m(a4, b4_19),
        m(a0, b4) + m(a1, b3) + m(a2, b2) + m(a3, b1) + m(a4, b0),
    ])
}

// mul(a, a) with the symmetric products counted once and doubled.
fn square(a: &Fe) -> Fe {
    let m = |x: u64, y: u64| u128::from(x) * u128::from(y);

    let [a0, a1, a2, a3, a4] = *a;

    let (a3_19, a4_19) = (19 * a3, 19 * a4);

    carry([
        m(a0, a0) + m(2 * a1, a4_19) + m(2 * a2, a3_19),
        m(2 * a0, a1) + m(2 * a2, a4_19) + m(a3, a3_19),
        m(2 * a0, a2) + m(a1, a1) + m(2 * a3, a4_19),
        m(2 * a0, a3) + m(2 * a1, a2) + m(a4, a4_19),
        m(2 * a0, a4) + m(2 * a1, a3) + m(a2, a2),
    ])
}

fn square_times(a: &Fe, count: usize) -> Fe {
    (0..count).fold(*a, |x, _| square(&x))
}

// z^(p - 2) = z^(2^255 - 21) through the usual chain of 254 squarings and 11 multiplications.
fn invert(z: &Fe) -> Fe {
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

    let z_250_0 = mul(&square_times(&z_200_0, 50), &z_50_0);

    mul(&square_times(&z_250_0, 5), &z11)
}

fn encode(h: &Fe) -> [u8; 32] {
    let mut h = *h;

    for i in 0..4 {
        h[i + 1] += h[i] >> 51;

        h[i] &= MASK;
    }

    h[0] += 19 * (h[4] >> 51);

    h[4] &= MASK;

    // Now h < 2p, so one conditional subtraction of p is enough; q = 1 exactly when h >= p.
    let q = h[1..]
        .iter()
        .fold((h[0] + 19) >> 51, |q, limb| (limb + q) >> 51);

    h[0] += 19 * q;

    for i in 0..4 {
        h[i + 1] += h[i] >> 51;

        h[i] &= MASK;
    }

    h[4] &= MASK;

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

// RFC 7748, section 5: the Montgomery ladder over u-coordinates with a masked swap.
pub(crate) fn x25519(scalar: &[u8], u: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];

    k.copy_from_slice(scalar);

    k[0] &= 248;

    k[31] &= 127;

    k[31] |= 64;

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

#[cfg(test)]
mod tests {
    extern crate std;

    use std::collections::HashMap;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use super::{BASE, x25519};

    type Fields = HashMap<String, String>;

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
}
