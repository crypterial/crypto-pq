// The number-theoretic transforms and products of ML-KEM and ML-DSA with four 32-bit
// coefficients per NEON vector, value for value what the portable code computes, and ML-KEM's
// transforms on 16-bit lanes, which give the same canonical results. The portable Montgomery
// product high(a, b) - high(m, q), with m = a * b_qinv mod 2^32, is SQDMULH(a, b) - SQDMULH(m, q)
// halved by SHSUB: SQDMULH is the high half of the doubled product, a * b and m * q agree in
// their low 32 bits, so the difference of the doubled high halves is even and halving it is
// exact. SQDMULH saturates only for -2^31 * -2^31, which no operand here reaches.
//
// The layers run in two passes over registers instead of one pass over memory each: first the
// three layers that pair coefficients 128, 64 and 32 apart, on eight vectors 32 coefficients
// apart, then the others on 32 consecutive coefficients. For the layers that pair coefficients
// 2 and 1 apart, two vectors are transposed so that partners sit in the same lane.
//
// All of these are data-processing instructions on Arm's data-independent-timing list, with no
// branch or address that depends on a coefficient.

use core::arch::aarch64::*;

use crate::cpu::{Field, Field16, Prepare};

#[allow(unsafe_code)]
pub(crate) fn ntt(w: &mut [i32; 256], field: &Field) -> bool {
    // SAFETY: NEON is part of every target this module is built for.
    unsafe { forward(w, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn inverse_ntt(w: &mut [i32; 256], field: &Field) -> bool {
    // SAFETY: as in ntt.
    unsafe { inverse(w, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn multiply(
    out: &mut [i32; 256],
    f: &[i32; 256],
    g: &[i32; 256],
    field: &Field,
) -> bool {
    // SAFETY: as in ntt.
    unsafe { products::<false>(out, f, g, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn multiply_add(
    acc: &mut [i32; 256],
    f: &[i32; 256],
    g: &[i32; 256],
    field: &Field,
) -> bool {
    // SAFETY: as in ntt.
    unsafe { products::<true>(acc, f, g, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn base_multiply_add(
    acc: &mut [i32; 256],
    f: &[u16; 256],
    g: &[u16; 256],
    gammas: &[i32; 128],
    field: &Field,
) -> bool {
    // SAFETY: as in ntt.
    unsafe { base_products(acc, f, g, gammas, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn ntt16(f: &mut [u16; 256], field: &Field16) -> bool {
    // SAFETY: as in ntt.
    unsafe { forward16(f, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn inverse_ntt16(acc: &[i32; 256], out: &mut [u16; 256], field: &Field16) -> bool {
    // SAFETY: as in ntt.
    unsafe { inverse16(acc, out, field) };

    true
}

// A factor and its product by q^-1, the same in every lane or one per lane.
#[derive(Clone, Copy)]
struct Twiddle {
    zeta: int32x4_t,
    qinv: int32x4_t,
}

const fn pack(low: i32, high: i32) -> u64 {
    (low as u32 as u64) | ((high as u32 as u64) << 32)
}

#[target_feature(enable = "neon")]
#[inline]
fn load(values: &[i32; 4]) -> int32x4_t {
    let low = vcreate_u64(pack(values[0], values[1]));

    let high = vcreate_u64(pack(values[2], values[3]));

    vreinterpretq_s32_u64(vcombine_u64(low, high))
}

#[target_feature(enable = "neon")]
#[inline]
fn store(vector: int32x4_t, out: &mut [i32; 4]) {
    let halves = vreinterpretq_u64_s32(vector);

    let (low, high) = (vgetq_lane_u64::<0>(halves), vgetq_lane_u64::<1>(halves));

    *out = [
        low as i32,
        (low >> 32) as i32,
        high as i32,
        (high >> 32) as i32,
    ];
}

#[target_feature(enable = "neon")]
#[inline]
fn constant(zeta: i32, qinv: i32) -> Twiddle {
    Twiddle {
        zeta: vdupq_n_s32(zeta),
        qinv: vdupq_n_s32(zeta.wrapping_mul(qinv)),
    }
}

#[target_feature(enable = "neon")]
#[inline]
fn broadcast(zetas: &[i32; 256], products: &[i32; 256], m: usize) -> Twiddle {
    Twiddle {
        zeta: vdupq_n_s32(zetas[m]),
        qinv: vdupq_n_s32(products[m]),
    }
}

// Factors m and m + 1 of a table, each in two adjacent lanes, for an even m.
#[target_feature(enable = "neon")]
#[inline]
fn pairs(zetas: &[i32; 256], products: &[i32; 256], m: usize) -> Twiddle {
    let twice = |table: &[i32; 256]| {
        let [first, second] = table.as_chunks::<2>().0[m / 2];

        let two = vreinterpret_s32_u64(vcreate_u64(pack(first, second)));

        vcombine_s32(vzip1_s32(two, two), vzip2_s32(two, two))
    };

    Twiddle {
        zeta: twice(zetas),
        qinv: twice(products),
    }
}

// Factors m to m + 3 of a table, one per lane, for m a multiple of 4.
#[target_feature(enable = "neon")]
#[inline]
fn quads(zetas: &[i32; 256], products: &[i32; 256], m: usize) -> Twiddle {
    Twiddle {
        zeta: load(&zetas.as_chunks::<4>().0[m / 4]),
        qinv: load(&products.as_chunks::<4>().0[m / 4]),
    }
}

#[target_feature(enable = "neon")]
#[inline]
fn montgomery(a: int32x4_t, t: Twiddle, q: int32x4_t) -> int32x4_t {
    vhsubq_s32(
        vqdmulhq_s32(a, t.zeta),
        vqdmulhq_s32(vmulq_s32(a, t.qinv), q),
    )
}

// (-q, q) to [0, q): x + (q & (x >> 31)).
#[target_feature(enable = "neon")]
#[inline]
fn freeze(x: int32x4_t, q: int32x4_t) -> int32x4_t {
    vaddq_s32(x, vandq_s32(q, vshrq_n_s32::<31>(x)))
}

// Cooley-Tukey: (a + b zeta, a - b zeta).
#[target_feature(enable = "neon")]
#[inline]
fn forward_butterfly(
    a: int32x4_t,
    b: int32x4_t,
    t: Twiddle,
    q: int32x4_t,
) -> (int32x4_t, int32x4_t) {
    let product = montgomery(b, t, q);

    (vaddq_s32(a, product), vsubq_s32(a, product))
}

// Gentleman-Sande: (a + b, (b - a) zeta).
#[target_feature(enable = "neon")]
#[inline]
fn inverse_butterfly(
    a: int32x4_t,
    b: int32x4_t,
    t: Twiddle,
    q: int32x4_t,
) -> (int32x4_t, int32x4_t) {
    (vaddq_s32(a, b), montgomery(vsubq_s32(b, a), t, q))
}

// The low halves of x and y, then their high halves; applied twice it gives x and y back.
#[target_feature(enable = "neon")]
#[inline]
fn halves(x: int32x4_t, y: int32x4_t) -> (int32x4_t, int32x4_t) {
    let (x, y) = (vreinterpretq_s64_s32(x), vreinterpretq_s64_s32(y));

    (
        vreinterpretq_s32_s64(vtrn1q_s64(x, y)),
        vreinterpretq_s32_s64(vtrn2q_s64(x, y)),
    )
}

// The even lanes of x and y interleaved, then the odd ones; also its own inverse.
#[target_feature(enable = "neon")]
#[inline]
fn words(x: int32x4_t, y: int32x4_t) -> (int32x4_t, int32x4_t) {
    (vtrn1q_s32(x, y), vtrn2q_s32(x, y))
}

// The forward layers. With the table's group m counted from 1, the layer that pairs
// coefficients d apart uses groups 128 / d to 256 / d - 1, one per 2d coefficients.
#[target_feature(enable = "neon")]
fn forward(w: &mut [i32; 256], field: &Field) {
    let q = vdupq_n_s32(field.q);

    let (z, zq) = (&field.forward, &field.forward_qinv);

    let chunks = w.as_chunks_mut::<4>().0;

    let t128 = broadcast(z, zq, 1);

    let t64 = [broadcast(z, zq, 2), broadcast(z, zq, 3)];

    let t32 = [4, 5, 6, 7].map(|m| broadcast(z, zq, m));

    for j in 0..8 {
        let mut x = [vdupq_n_s32(0); 8];

        for (m, x) in x.iter_mut().enumerate() {
            *x = load(&chunks[j + 8 * m]);
        }

        for (i, k) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
            (x[i], x[k]) = forward_butterfly(x[i], x[k], t128, q);
        }

        for (i, k, t) in [(0, 2, 0), (1, 3, 0), (4, 6, 1), (5, 7, 1)] {
            (x[i], x[k]) = forward_butterfly(x[i], x[k], t64[t], q);
        }

        for (g, i) in [0, 2, 4, 6].into_iter().enumerate() {
            (x[i], x[i + 1]) = forward_butterfly(x[i], x[i + 1], t32[g], q);
        }

        for (m, x) in x.iter().enumerate() {
            store(*x, &mut chunks[j + 8 * m]);
        }
    }

    let scale = field.forward_scale.map(|scale| constant(scale, field.qinv));

    for (b, block) in chunks.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let mut x = [vdupq_n_s32(0); 8];

        for (x, chunk) in x.iter_mut().zip(block.iter()) {
            *x = load(chunk);
        }

        let t16 = broadcast(z, zq, 8 + b);

        for (i, k) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
            (x[i], x[k]) = forward_butterfly(x[i], x[k], t16, q);
        }

        let t8 = [broadcast(z, zq, 16 + 2 * b), broadcast(z, zq, 17 + 2 * b)];

        for (i, k, t) in [(0, 2, 0), (1, 3, 0), (4, 6, 1), (5, 7, 1)] {
            (x[i], x[k]) = forward_butterfly(x[i], x[k], t8[t], q);
        }

        for (g, i) in [0, 2, 4, 6].into_iter().enumerate() {
            let t4 = broadcast(z, zq, 32 + 4 * b + g);

            (x[i], x[i + 1]) = forward_butterfly(x[i], x[i + 1], t4, q);
        }

        for (i, pair) in x.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            let (low, high) = halves(pair[0], pair[1]);

            let (mut low, mut high) =
                forward_butterfly(low, high, pairs(z, zq, 64 + 8 * b + 2 * i), q);

            if field.layers == 8 {
                let (even, odd) = words(low, high);

                let t1 = quads(z, zq, 128 + 16 * b + 4 * i);

                let (even, odd) = forward_butterfly(even, odd, t1, q);

                (low, high) = words(even, odd);
            }

            (pair[0], pair[1]) = halves(low, high);
        }

        if let Some(scale) = scale {
            for x in &mut x {
                *x = freeze(montgomery(*x, scale, q), q);
            }
        }

        for (x, chunk) in x.iter().zip(block.iter_mut()) {
            store(*x, chunk);
        }
    }
}

// The inverse layers, which take the groups in the reverse order: the table is the forward one
// reversed, and the layer that pairs coefficients d apart uses its groups from 256 - 256 / d on.
#[target_feature(enable = "neon")]
fn inverse(w: &mut [i32; 256], field: &Field) {
    let q = vdupq_n_s32(field.q);

    let (z, zq) = (&field.inverse, &field.inverse_qinv);

    let chunks = w.as_chunks_mut::<4>().0;

    let reduce = vdupq_n_s32(1 << 22);

    let montgomery_scale = match field.prepare {
        Prepare::Reduce => None,
        Prepare::Montgomery(factor) => Some(constant(factor, field.qinv)),
    };

    for (b, block) in chunks.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let mut x = [vdupq_n_s32(0); 8];

        for (x, chunk) in x.iter_mut().zip(block.iter()) {
            let value = load(chunk);

            *x = match montgomery_scale {
                None => vmlsq_s32(value, vshrq_n_s32::<23>(vaddq_s32(value, reduce)), q),
                Some(scale) => montgomery(value, scale, q),
            };
        }

        for (i, pair) in x.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            let (mut low, mut high) = halves(pair[0], pair[1]);

            if field.layers == 8 {
                let (even, odd) = words(low, high);

                let (even, odd) = inverse_butterfly(even, odd, quads(z, zq, 16 * b + 4 * i), q);

                (low, high) = words(even, odd);
            }

            let (low, high) = inverse_butterfly(low, high, pairs(z, zq, 128 + 8 * b + 2 * i), q);

            (pair[0], pair[1]) = halves(low, high);
        }

        for (g, i) in [0, 2, 4, 6].into_iter().enumerate() {
            let t4 = broadcast(z, zq, 192 + 4 * b + g);

            (x[i], x[i + 1]) = inverse_butterfly(x[i], x[i + 1], t4, q);
        }

        let t8 = [broadcast(z, zq, 224 + 2 * b), broadcast(z, zq, 225 + 2 * b)];

        for (i, k, t) in [(0, 2, 0), (1, 3, 0), (4, 6, 1), (5, 7, 1)] {
            (x[i], x[k]) = inverse_butterfly(x[i], x[k], t8[t], q);
        }

        let t16 = broadcast(z, zq, 240 + b);

        for (i, k) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
            (x[i], x[k]) = inverse_butterfly(x[i], x[k], t16, q);
        }

        for (x, chunk) in x.iter().zip(block.iter_mut()) {
            store(*x, chunk);
        }
    }

    let t32 = [248, 249, 250, 251].map(|m| broadcast(z, zq, m));

    let t64 = [broadcast(z, zq, 252), broadcast(z, zq, 253)];

    let t128 = broadcast(z, zq, 254);

    let scale = constant(field.inverse_scale, field.qinv);

    for j in 0..8 {
        let mut x = [vdupq_n_s32(0); 8];

        for (m, x) in x.iter_mut().enumerate() {
            *x = load(&chunks[j + 8 * m]);
        }

        for (g, i) in [0, 2, 4, 6].into_iter().enumerate() {
            (x[i], x[i + 1]) = inverse_butterfly(x[i], x[i + 1], t32[g], q);
        }

        for (i, k, t) in [(0, 2, 0), (1, 3, 0), (4, 6, 1), (5, 7, 1)] {
            (x[i], x[k]) = inverse_butterfly(x[i], x[k], t64[t], q);
        }

        for (i, k) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
            (x[i], x[k]) = inverse_butterfly(x[i], x[k], t128, q);
        }

        for (m, x) in x.iter().enumerate() {
            store(freeze(montgomery(*x, scale, q), q), &mut chunks[j + 8 * m]);
        }
    }
}

// out = f * g, or out += f * g, coefficient by coefficient (ML-DSA).
#[target_feature(enable = "neon")]
fn products<const ADD: bool>(out: &mut [i32; 256], f: &[i32; 256], g: &[i32; 256], field: &Field) {
    let (q, qinv) = (vdupq_n_s32(field.q), vdupq_n_s32(field.qinv));

    let factors = f.as_chunks::<4>().0.iter().zip(g.as_chunks::<4>().0);

    for (out, (f, g)) in out.as_chunks_mut::<4>().0.iter_mut().zip(factors) {
        let b = load(g);

        let t = Twiddle {
            zeta: b,
            qinv: vmulq_s32(b, qinv),
        };

        let product = montgomery(load(f), t, q);

        store(
            if ADD {
                vaddq_s32(load(out), product)
            } else {
                product
            },
            out,
        );
    }
}

// The even and the odd coefficients of eight, as 32-bit lanes.
#[target_feature(enable = "neon")]
#[inline]
fn split(values: &[u16; 8]) -> (int32x4_t, int32x4_t) {
    let pack16 = |v: &[u16]| {
        u64::from(v[0])
            | (u64::from(v[1]) << 16)
            | (u64::from(v[2]) << 32)
            | (u64::from(v[3]) << 48)
    };

    let pairs = vcombine_u64(
        vcreate_u64(pack16(&values[..4])),
        vcreate_u64(pack16(&values[4..])),
    );

    let pairs = vreinterpretq_u32_u64(pairs);

    (
        vreinterpretq_s32_u32(vandq_u32(pairs, vdupq_n_u32(0xFFFF))),
        vreinterpretq_s32_u32(vshrq_n_u32::<16>(pairs)),
    )
}

// acc += f * g in ML-KEM's NTT domain, four pairs at a time: (a0 b0 + (a1 b1) gamma, a0 b1 + a1 b0)
// with a1 b1 a Montgomery product.
#[target_feature(enable = "neon")]
fn base_products(
    acc: &mut [i32; 256],
    f: &[u16; 256],
    g: &[u16; 256],
    gammas: &[i32; 128],
    field: &Field,
) {
    let (q, qinv) = (vdupq_n_s32(field.q), vdupq_n_s32(field.qinv));

    let factors = f.as_chunks::<8>().0.iter().zip(g.as_chunks::<8>().0);

    let groups = factors.zip(gammas.as_chunks::<4>().0);

    for (acc, ((f, g), gamma)) in acc.as_chunks_mut::<8>().0.iter_mut().zip(groups) {
        let ((a0, a1), (b0, b1)) = (split(f), split(g));

        let t = Twiddle {
            zeta: b1,
            qinv: vmulq_s32(b1, qinv),
        };

        let even = vmlaq_s32(vmulq_s32(a0, b0), montgomery(a1, t, q), load(gamma));

        let odd = vmlaq_s32(vmulq_s32(a0, b1), a1, b0);

        let [low, high] = acc.as_chunks_mut::<4>().0 else {
            unreachable!("eight values are two groups of four")
        };

        store(vaddq_s32(load(low), vzip1q_s32(even, odd)), low);

        store(vaddq_s32(load(high), vzip2q_s32(even, odd)), high);
    }
}

// ML-KEM on eight 16-bit lanes per vector. The Montgomery product modulo 2^16 is exact for the
// same reason as above, and stays in (-q, q) while |a b| < 2^15 q. The forward sums stay below
// 8q < 2^15 without a reduction; the inverse sums double with every layer, so a Barrett
// reduction brings them back below q after the third and the sixth layer.
#[derive(Clone, Copy)]
struct Twiddle16 {
    zeta: int16x8_t,
    qinv: int16x8_t,
}

const fn pack16(values: &[u16]) -> u64 {
    (values[0] as u64)
        | ((values[1] as u64) << 16)
        | ((values[2] as u64) << 32)
        | ((values[3] as u64) << 48)
}

#[target_feature(enable = "neon")]
#[inline]
fn load16(values: &[u16; 8]) -> int16x8_t {
    let (low, high) = values.split_at(4);

    vreinterpretq_s16_u64(vcombine_u64(
        vcreate_u64(pack16(low)),
        vcreate_u64(pack16(high)),
    ))
}

#[target_feature(enable = "neon")]
#[inline]
fn store16(vector: int16x8_t, out: &mut [u16; 8]) {
    let halves = vreinterpretq_u64_s16(vector);

    let words = [vgetq_lane_u64::<0>(halves), vgetq_lane_u64::<1>(halves)];

    *out = core::array::from_fn(|i| (words[i / 4] >> (16 * (i % 4))) as u16);
}

#[target_feature(enable = "neon")]
#[inline]
fn constant16(zeta: i16, qinv: i16) -> Twiddle16 {
    Twiddle16 {
        zeta: vdupq_n_s16(zeta),
        qinv: vdupq_n_s16(zeta.wrapping_mul(qinv)),
    }
}

#[target_feature(enable = "neon")]
#[inline]
fn broadcast16(zetas: &[i16; 128], products: &[i16; 128], m: usize) -> Twiddle16 {
    Twiddle16 {
        zeta: vdupq_n_s16(zetas[m]),
        qinv: vdupq_n_s16(products[m]),
    }
}

// Vector p of a per-lane table: tables k and k + 1 hold the factors and their products.
#[target_feature(enable = "neon")]
#[inline]
fn lanes16(tables: &[[[i16; 8]; 16]; 4], k: usize, p: usize) -> Twiddle16 {
    let load = |values: &[i16; 8]| load16(&values.map(|x| x as u16));

    Twiddle16 {
        zeta: load(&tables[k][p]),
        qinv: load(&tables[k + 1][p]),
    }
}

#[target_feature(enable = "neon")]
#[inline]
fn montgomery16(a: int16x8_t, t: Twiddle16, q: int16x8_t) -> int16x8_t {
    vhsubq_s16(
        vqdmulhq_s16(a, t.zeta),
        vqdmulhq_s16(vmulq_s16(a, t.qinv), q),
    )
}

#[target_feature(enable = "neon")]
#[inline]
fn freeze16(x: int16x8_t, q: int16x8_t) -> int16x8_t {
    vaddq_s16(x, vandq_s16(q, vshrq_n_s16::<15>(x)))
}

// x - round(x / q) q, with round(x / q) estimated as round(x * round(2^26 / q) / 2^26): SQDMULH
// and a rounding shift by 11. The estimate is off by at most one where x / q is within 2^-11 of
// a half, so the result stays below q in absolute value.
#[target_feature(enable = "neon")]
#[inline]
fn barrett16(x: int16x8_t, barrett: int16x8_t, q: int16x8_t) -> int16x8_t {
    vmlsq_s16(x, vrshrq_n_s16::<11>(vqdmulhq_s16(x, barrett)), q)
}

#[target_feature(enable = "neon")]
#[inline]
fn forward_butterfly16(
    a: int16x8_t,
    b: int16x8_t,
    t: Twiddle16,
    q: int16x8_t,
) -> (int16x8_t, int16x8_t) {
    let product = montgomery16(b, t, q);

    (vaddq_s16(a, product), vsubq_s16(a, product))
}

#[target_feature(enable = "neon")]
#[inline]
fn inverse_butterfly16(
    a: int16x8_t,
    b: int16x8_t,
    t: Twiddle16,
    q: int16x8_t,
) -> (int16x8_t, int16x8_t) {
    (vaddq_s16(a, b), montgomery16(vsubq_s16(b, a), t, q))
}

// The 64-bit halves and the 32-bit pairs of lanes, as halves and words do for 32-bit lanes.
#[target_feature(enable = "neon")]
#[inline]
fn halves16(x: int16x8_t, y: int16x8_t) -> (int16x8_t, int16x8_t) {
    let (x, y) = (vreinterpretq_s64_s16(x), vreinterpretq_s64_s16(y));

    (
        vreinterpretq_s16_s64(vtrn1q_s64(x, y)),
        vreinterpretq_s16_s64(vtrn2q_s64(x, y)),
    )
}

#[target_feature(enable = "neon")]
#[inline]
fn pairs16(x: int16x8_t, y: int16x8_t) -> (int16x8_t, int16x8_t) {
    let (x, y) = (vreinterpretq_s32_s16(x), vreinterpretq_s32_s16(y));

    (
        vreinterpretq_s16_s32(vtrn1q_s32(x, y)),
        vreinterpretq_s16_s32(vtrn2q_s32(x, y)),
    )
}

// The seven forward layers on canonical coefficients, which end in canonical form. Each pass
// keeps eight or four vectors in registers, like the 32-bit transform.
#[target_feature(enable = "neon")]
fn forward16(f: &mut [u16; 256], field: &Field16) {
    let q = vdupq_n_s16(field.q);

    let (z, zq) = (&field.forward, &field.forward_qinv);

    let chunks = f.as_chunks_mut::<8>().0;

    let t128 = broadcast16(z, zq, 1);

    let t64 = [broadcast16(z, zq, 2), broadcast16(z, zq, 3)];

    let t32 = [4, 5, 6, 7].map(|m| broadcast16(z, zq, m));

    for j in 0..4 {
        let mut x = [vdupq_n_s16(0); 8];

        for (m, x) in x.iter_mut().enumerate() {
            *x = load16(&chunks[j + 4 * m]);
        }

        for (i, k) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
            (x[i], x[k]) = forward_butterfly16(x[i], x[k], t128, q);
        }

        for (i, k, t) in [(0, 2, 0), (1, 3, 0), (4, 6, 1), (5, 7, 1)] {
            (x[i], x[k]) = forward_butterfly16(x[i], x[k], t64[t], q);
        }

        for (g, i) in [0, 2, 4, 6].into_iter().enumerate() {
            (x[i], x[i + 1]) = forward_butterfly16(x[i], x[i + 1], t32[g], q);
        }

        for (m, x) in x.iter().enumerate() {
            store16(*x, &mut chunks[j + 4 * m]);
        }
    }

    let canonical = constant16(field.canonical, field.qinv);

    for (b, block) in chunks.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let mut x = [vdupq_n_s16(0); 4];

        for (x, chunk) in x.iter_mut().zip(block.iter()) {
            *x = load16(chunk);
        }

        let t16 = broadcast16(z, zq, 8 + b);

        for (i, k) in [(0, 2), (1, 3)] {
            (x[i], x[k]) = forward_butterfly16(x[i], x[k], t16, q);
        }

        let t8 = [
            broadcast16(z, zq, 16 + 2 * b),
            broadcast16(z, zq, 17 + 2 * b),
        ];

        for (g, i) in [0, 2].into_iter().enumerate() {
            (x[i], x[i + 1]) = forward_butterfly16(x[i], x[i + 1], t8[g], q);
        }

        for (pair, xs) in x.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            let p = 2 * b + pair;

            let (low, high) = halves16(xs[0], xs[1]);

            let (low, high) =
                forward_butterfly16(low, high, lanes16(&field.forward_lanes, 0, p), q);

            let (even, odd) = pairs16(low, high);

            let (even, odd) =
                forward_butterfly16(even, odd, lanes16(&field.forward_lanes, 2, p), q);

            let (low, high) = pairs16(even, odd);

            (xs[0], xs[1]) = halves16(low, high);
        }

        for x in &mut x {
            *x = freeze16(montgomery16(*x, canonical, q), q);
        }

        for (x, chunk) in x.iter().zip(block.iter_mut()) {
            store16(*x, chunk);
        }
    }
}

// The seven inverse layers on the 32-bit sums of the base multiplication, first brought below q
// by a 32-bit Montgomery product, into canonical coefficients.
#[target_feature(enable = "neon")]
fn inverse16(acc: &[i32; 256], out: &mut [u16; 256], field: &Field16) {
    let q = vdupq_n_s16(field.q);

    let barrett = vdupq_n_s16(field.barrett);

    let (q32, reduce) = (
        vdupq_n_s32(i32::from(field.q)),
        constant(field.reduce32, field.qinv32),
    );

    let (z, zq) = (&field.inverse, &field.inverse_qinv);

    let sums = acc.as_chunks::<8>().0;

    let chunks = out.as_chunks_mut::<8>().0;

    let blocks = chunks.as_chunks_mut::<4>().0.iter_mut();

    for (b, (block, sums)) in blocks.zip(sums.as_chunks::<4>().0).enumerate() {
        let mut x = [vdupq_n_s16(0); 4];

        for (x, sum) in x.iter_mut().zip(sums) {
            let [low, high] = sum.as_chunks::<4>().0 else {
                unreachable!("eight values are two groups of four")
            };

            let low = vmovn_s32(montgomery(load(low), reduce, q32));

            let high = vmovn_s32(montgomery(load(high), reduce, q32));

            *x = vcombine_s16(low, high);
        }

        for (pair, xs) in x.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            let p = 2 * b + pair;

            let (low, high) = halves16(xs[0], xs[1]);

            let (even, odd) = pairs16(low, high);

            let (even, odd) =
                inverse_butterfly16(even, odd, lanes16(&field.inverse_lanes, 2, p), q);

            let (low, high) = pairs16(even, odd);

            let (low, high) =
                inverse_butterfly16(low, high, lanes16(&field.inverse_lanes, 0, p), q);

            (xs[0], xs[1]) = halves16(low, high);
        }

        let t8 = [
            broadcast16(z, zq, 96 + 2 * b),
            broadcast16(z, zq, 97 + 2 * b),
        ];

        for (g, i) in [0, 2].into_iter().enumerate() {
            (x[i], x[i + 1]) = inverse_butterfly16(x[i], x[i + 1], t8[g], q);
        }

        for x in &mut x {
            *x = barrett16(*x, barrett, q);
        }

        let t16 = broadcast16(z, zq, 112 + b);

        for (i, k) in [(0, 2), (1, 3)] {
            (x[i], x[k]) = inverse_butterfly16(x[i], x[k], t16, q);
        }

        for (x, chunk) in x.iter().zip(block.iter_mut()) {
            store16(*x, chunk);
        }
    }

    let t32 = [120, 121, 122, 123].map(|m| broadcast16(z, zq, m));

    let t64 = [broadcast16(z, zq, 124), broadcast16(z, zq, 125)];

    let t128 = broadcast16(z, zq, 126);

    let scale = constant16(field.inverse_scale, field.qinv);

    for j in 0..4 {
        let mut x = [vdupq_n_s16(0); 8];

        for (m, x) in x.iter_mut().enumerate() {
            *x = load16(&chunks[j + 4 * m]);
        }

        for (g, i) in [0, 2, 4, 6].into_iter().enumerate() {
            (x[i], x[i + 1]) = inverse_butterfly16(x[i], x[i + 1], t32[g], q);
        }

        for (i, k, t) in [(0, 2, 0), (1, 3, 0), (4, 6, 1), (5, 7, 1)] {
            (x[i], x[k]) = inverse_butterfly16(x[i], x[k], t64[t], q);
        }

        for x in &mut x {
            *x = barrett16(*x, barrett, q);
        }

        for (i, k) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
            (x[i], x[k]) = inverse_butterfly16(x[i], x[k], t128, q);
        }

        for (m, x) in x.iter().enumerate() {
            store16(
                freeze16(montgomery16(*x, scale, q), q),
                &mut chunks[j + 4 * m],
            );
        }
    }
}
