//! Arithmetic modulo q = 3329 and the number-theoretic transform (FIPS 203, section 4.3).
//!
//! Every coefficient is kept fully reduced in `[0, q)`. Reductions use a
//! multiply-and-shift Barrett step followed by a masked conditional
//! subtraction, so no secret value reaches a division or a branch.

pub(crate) const Q: u16 = 3329;
pub(crate) const N: usize = 256;

/// A polynomial in R_q or T_q, coefficients in `[0, q)`.
pub(crate) type Poly = [u16; N];

const fn bitrev7(x: usize) -> usize {
    let mut r = 0;
    let mut i = 0;
    while i < 7 {
        r |= ((x >> i) & 1) << (6 - i);
        i += 1;
    }
    r
}

const fn pow_mod(mut base: u32, mut exp: u32) -> u16 {
    let mut acc: u32 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % Q as u32;
        }
        base = base * base % Q as u32;
        exp >>= 1;
    }
    acc as u16
}

const fn zeta_table(scale: u32, offset: u32) -> [u16; 128] {
    let mut t = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = pow_mod(17, scale * bitrev7(i) as u32 + offset);
        i += 1;
    }
    t
}

/// ZETAS[i] = 17^BitRev7(i) mod q, used by NTT and NTT^-1.
pub(crate) const ZETAS: [u16; 128] = zeta_table(1, 0);

/// GAMMAS[i] = 17^(2 BitRev7(i) + 1) mod q, used by MultiplyNTTs.
pub(crate) const GAMMAS: [u16; 128] = zeta_table(2, 1);

/// Reduces `x` in `[0, 2q)` to `[0, q)`.
#[inline(always)]
pub(crate) fn csub(x: u16) -> u16 {
    let t = x as i32 - Q as i32;
    let mask = t >> 31;
    (t + (mask & Q as i32)) as u16
}

/// Reduces `x < 2^26` to `[0, q)`. 20158 = floor(2^26 / q), which leaves the
/// remainder below 2q for the whole input range (checked exhaustively in tests).
#[inline(always)]
pub(crate) fn barrett(x: u32) -> u16 {
    debug_assert!(x < 1 << 26);
    let t = ((x as u64 * 20158) >> 26) as u32;
    csub((x - t * Q as u32) as u16)
}

#[inline(always)]
pub(crate) fn add(a: u16, b: u16) -> u16 {
    csub(a + b)
}

#[inline(always)]
pub(crate) fn sub(a: u16, b: u16) -> u16 {
    csub(a + Q - b)
}

#[inline(always)]
pub(crate) fn mul(a: u16, b: u16) -> u16 {
    barrett(a as u32 * b as u32)
}

/// NTT (FIPS 203, algorithm 9), in place.
pub(crate) fn ntt(f: &mut Poly) {
    let mut i = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i];
            i += 1;
            for j in start..start + len {
                let t = mul(zeta, f[j + len]);
                f[j + len] = sub(f[j], t);
                f[j] = add(f[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// NTT^-1 (FIPS 203, algorithm 10), in place.
pub(crate) fn intt(f: &mut Poly) {
    let mut i = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i];
            i -= 1;
            for j in start..start + len {
                let t = f[j];
                f[j] = add(t, f[j + len]);
                f[j + len] = mul(zeta, sub(f[j + len], t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for x in f.iter_mut() {
        *x = mul(*x, 3303);
    }
}

/// MultiplyNTTs (FIPS 203, algorithms 11 and 12).
pub(crate) fn mul_ntt(f: &Poly, g: &Poly) -> Poly {
    let mut h = [0u16; N];
    for i in 0..128 {
        let (a0, a1) = (f[2 * i], f[2 * i + 1]);
        let (b0, b1) = (g[2 * i], g[2 * i + 1]);
        h[2 * i] = add(mul(a0, b0), mul(mul(a1, b1), GAMMAS[i]));
        h[2 * i + 1] = add(mul(a0, b1), mul(a1, b0));
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrett_is_exact_over_its_whole_input_range() {
        for x in 0u32..(1 << 26) {
            assert_eq!(barrett(x) as u32, x % Q as u32, "x = {x}");
        }
    }

    #[test]
    fn csub_is_exact() {
        for x in 0u16..2 * Q {
            assert_eq!(csub(x), x % Q);
        }
    }

    #[test]
    fn zeta_is_a_primitive_256th_root_of_unity() {
        assert_eq!(ZETAS[0], 1);
        assert_eq!(GAMMAS[0], 17);
        assert_eq!(pow_mod(17, 128), Q - 1);
        assert_eq!(pow_mod(17, 256), 1);
        assert_eq!(mul(ZETAS[1], ZETAS[1]), Q - 1);
        assert_eq!(mul(128, 3303), 1);
    }

    fn pseudo_random_poly(seed: u32) -> Poly {
        let mut state = seed;
        let mut f = [0u16; N];
        for x in f.iter_mut() {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *x = (state >> 8) as u16 % Q;
        }
        f
    }

    #[test]
    fn ntt_roundtrip() {
        for seed in 1..8 {
            let f = pseudo_random_poly(seed);
            let mut g = f;
            ntt(&mut g);
            intt(&mut g);
            assert_eq!(f, g);
        }
    }

    #[test]
    fn mul_ntt_matches_negacyclic_schoolbook_product() {
        for seed in 1..4 {
            let a = pseudo_random_poly(seed);
            let b = pseudo_random_poly(seed + 100);
            let mut expected = [0u16; N];
            for i in 0..N {
                for j in 0..N {
                    let p = mul(a[i], b[j]);
                    if i + j < N {
                        expected[i + j] = add(expected[i + j], p);
                    } else {
                        expected[i + j - N] = sub(expected[i + j - N], p);
                    }
                }
            }
            let (mut ah, mut bh) = (a, b);
            ntt(&mut ah);
            ntt(&mut bh);
            let mut c = mul_ntt(&ah, &bh);
            intt(&mut c);
            assert_eq!(c, expected);
        }
    }
}
