// The number-theoretic transforms and products of ML-DSA and ML-KEM on eight 32-bit coefficients
// per AVX2 vector, value for value what the portable code computes. The portable Montgomery product
// high(a, b) - high(m, q), with m = a * b_qinv mod 2^32, comes from 64-bit products of the even
// lanes and of the odd lanes moved down: their high halves are subtracted lane by lane, which is
// exact whatever the low halves hold, and the odd lanes' results are blended back.
//
// The layers run in two passes over registers: first the three layers that pair coefficients 128,
// 64 and 32 apart, on eight vectors 32 coefficients apart, then the others on blocks of 32
// consecutive coefficients. For the layers that pair coefficients 4, 2 and 1 apart, two vectors
// are transposed by halves, 64-bit and 32-bit groups so that partners share a lane; the factors
// of those layers are spread over the lanes by a permutation of four or eight table entries.
//
// All of these are data-processing instructions on Intel's data-operand-independent timing list,
// with no branch or address that depends on a coefficient.

use core::arch::x86_64::*;

#[cfg(not(crypto_pq_optimized))]
use super::memory::words_of;
use super::memory::{clear, load128, load256, store256};
use crate::cpu::{Field, Prepare};
use crate::wipe::wipe_unless_optimized;

// A factor and its product by q^-1 in the even lanes, and the same for the odd lanes moved down.
#[derive(Clone, Copy)]
struct Twiddle {
    zeta: __m256i,
    qinv: __m256i,
    zeta_odd: __m256i,
    qinv_odd: __m256i,
}

#[target_feature(enable = "avx2")]
#[inline]
fn odd(x: __m256i) -> __m256i {
    _mm256_shuffle_epi32::<0xF5>(x)
}

#[target_feature(enable = "avx2")]
#[inline]
fn spread(zeta: __m256i, qinv: __m256i) -> Twiddle {
    Twiddle {
        zeta,
        qinv,
        zeta_odd: odd(zeta),
        qinv_odd: odd(qinv),
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn constant(zeta: i32, qinv: i32) -> Twiddle {
    let (zeta, qinv) = (_mm256_set1_epi32(zeta), _mm256_set1_epi32(qinv));

    Twiddle {
        zeta,
        qinv,
        zeta_odd: zeta,
        qinv_odd: qinv,
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn broadcast(zetas: &[i32; 256], products: &[i32; 256], m: usize) -> Twiddle {
    constant(zetas[m], products[m])
}

// Entries m to m + COUNT - 1 of a table, each repeated over 8 / COUNT lanes.
#[target_feature(enable = "avx2")]
#[inline]
fn entries<const COUNT: usize>(zetas: &[i32; 256], products: &[i32; 256], m: usize) -> Twiddle {
    let load = |table: &[i32; 256]| match COUNT {
        2 => {
            let pair = i64::from(table[m] as u32) | i64::from(table[m + 1] as u32) << 32;

            _mm256_castsi128_si256(_mm_cvtsi64_si128(pair))
        }
        4 => {
            let four: &[i32; 4] = table[m..m + 4].try_into().expect("four entries");

            _mm256_castsi128_si256(load128(four))
        }
        _ => {
            let eight: &[i32; 8] = table[m..m + 8].try_into().expect("eight entries");

            load256(eight)
        }
    };

    let (zeta, qinv) = (load(zetas), load(products));

    if COUNT == 8 {
        return spread(zeta, qinv);
    }

    let order = if COUNT == 2 {
        _mm256_setr_epi32(0, 0, 0, 0, 1, 1, 1, 1)
    } else {
        _mm256_setr_epi32(0, 0, 1, 1, 2, 2, 3, 3)
    };

    spread(
        _mm256_permutevar8x32_epi32(zeta, order),
        _mm256_permutevar8x32_epi32(qinv, order),
    )
}

#[target_feature(enable = "avx2")]
#[inline]
fn montgomery(a: __m256i, t: Twiddle, q: __m256i) -> __m256i {
    let a_odd = odd(a);

    let m_even = _mm256_mul_epi32(a, t.qinv);

    let m_odd = _mm256_mul_epi32(a_odd, t.qinv_odd);

    let even = _mm256_sub_epi32(_mm256_mul_epi32(a, t.zeta), _mm256_mul_epi32(m_even, q));

    let odd_lanes = _mm256_sub_epi32(
        _mm256_mul_epi32(a_odd, t.zeta_odd),
        _mm256_mul_epi32(m_odd, q),
    );

    _mm256_blend_epi32::<0xAA>(odd(even), odd_lanes)
}

// The Montgomery product of a and b coefficient by coefficient, m from the low half of a b.
#[target_feature(enable = "avx2")]
#[inline]
fn product(a: __m256i, b: __m256i, qinv: __m256i, q: __m256i) -> __m256i {
    let (a_odd, b_odd) = (odd(a), odd(b));

    let (even, odd_lanes) = (_mm256_mul_epi32(a, b), _mm256_mul_epi32(a_odd, b_odd));

    let m_even = _mm256_mul_epi32(even, qinv);

    let m_odd = _mm256_mul_epi32(odd_lanes, qinv);

    let even = _mm256_sub_epi32(even, _mm256_mul_epi32(m_even, q));

    let odd_lanes = _mm256_sub_epi32(odd_lanes, _mm256_mul_epi32(m_odd, q));

    _mm256_blend_epi32::<0xAA>(odd(even), odd_lanes)
}

// (-q, q) to [0, q).
#[target_feature(enable = "avx2")]
#[inline]
fn freeze(x: __m256i, q: __m256i) -> __m256i {
    _mm256_add_epi32(x, _mm256_and_si256(q, _mm256_srai_epi32::<31>(x)))
}

// Cooley-Tukey: (a + b zeta, a - b zeta).
#[target_feature(enable = "avx2")]
#[inline]
fn forward_butterfly(a: __m256i, b: __m256i, t: Twiddle, q: __m256i) -> (__m256i, __m256i) {
    let product = montgomery(b, t, q);

    (_mm256_add_epi32(a, product), _mm256_sub_epi32(a, product))
}

// Gentleman-Sande: (a + b, (b - a) zeta).
#[target_feature(enable = "avx2")]
#[inline]
fn inverse_butterfly(a: __m256i, b: __m256i, t: Twiddle, q: __m256i) -> (__m256i, __m256i) {
    (
        _mm256_add_epi32(a, b),
        montgomery(_mm256_sub_epi32(b, a), t, q),
    )
}

// The low halves of x and y, then the high halves; the 64-bit groups; the 32-bit lanes. Each of
// these transpositions is its own inverse.
#[target_feature(enable = "avx2")]
#[inline]
fn halves(x: __m256i, y: __m256i) -> (__m256i, __m256i) {
    (
        _mm256_permute2x128_si256::<0x20>(x, y),
        _mm256_permute2x128_si256::<0x31>(x, y),
    )
}

#[target_feature(enable = "avx2")]
#[inline]
fn quarters(x: __m256i, y: __m256i) -> (__m256i, __m256i) {
    (_mm256_unpacklo_epi64(x, y), _mm256_unpackhi_epi64(x, y))
}

#[target_feature(enable = "avx2")]
#[inline]
fn words(x: __m256i, y: __m256i) -> (__m256i, __m256i) {
    (
        _mm256_blend_epi32::<0xAA>(x, _mm256_slli_epi64::<32>(y)),
        _mm256_blend_epi32::<0xAA>(_mm256_srli_epi64::<32>(x), y),
    )
}

// The layers that pair coefficients 4, 2 and 1 apart on two vectors, the p-th pair of block b.
// With the table's group m counted from 1, the layer that pairs coefficients d apart uses groups
// 128 / d to 256 / d - 1.
#[target_feature(enable = "avx2")]
#[inline]
fn forward_tail(
    x: __m256i,
    y: __m256i,
    field: &Field,
    group: usize,
    q: __m256i,
) -> (__m256i, __m256i) {
    let (z, zq) = (&field.forward, &field.forward_qinv);

    let (x, y) = halves(x, y);

    let (x, y) = forward_butterfly(x, y, entries::<2>(z, zq, 32 + 2 * group), q);

    let (x, y) = quarters(x, y);

    let (mut x, mut y) = forward_butterfly(x, y, entries::<4>(z, zq, 64 + 4 * group), q);

    if field.layers == 8 {
        let (even, odd) = words(x, y);

        let (even, odd) = forward_butterfly(even, odd, entries::<8>(z, zq, 128 + 8 * group), q);

        (x, y) = words(even, odd);
    }

    let (x, y) = quarters(x, y);

    halves(x, y)
}

// The forward layers. ML-KEM's seven layers end with freeze(montgomery(x, forward_scale)).
#[target_feature(enable = "avx2")]
pub(super) fn forward(w: &mut [i32; 256], field: &Field) {
    let q = _mm256_set1_epi32(field.q);

    let (z, zq) = (&field.forward, &field.forward_qinv);

    let vectors = w.as_chunks_mut::<8>().0;

    let t128 = broadcast(z, zq, 1);

    let t64 = [broadcast(z, zq, 2), broadcast(z, zq, 3)];

    let t32 = [4, 5, 6, 7].map(|m| broadcast(z, zq, m));

    // The working vectors, which the loops index through memory, are cleared at the end.
    let zero = _mm256_setzero_si256();

    let (mut x8, mut x4) = ([zero; 8], [zero; 4]);

    for j in 0..4 {
        let x = &mut x8;

        for (m, x) in x.iter_mut().enumerate() {
            *x = load256(&vectors[j + 4 * m]);
        }

        for i in 0..4 {
            (x[i], x[i + 4]) = forward_butterfly(x[i], x[i + 4], t128, q);
        }

        for (i, k, t) in [(0, 2, 0), (1, 3, 0), (4, 6, 1), (5, 7, 1)] {
            (x[i], x[k]) = forward_butterfly(x[i], x[k], t64[t], q);
        }

        for (g, i) in [0, 2, 4, 6].into_iter().enumerate() {
            (x[i], x[i + 1]) = forward_butterfly(x[i], x[i + 1], t32[g], q);
        }

        for (m, x) in x.iter().enumerate() {
            store256(*x, &mut vectors[j + 4 * m]);
        }
    }

    let scale = field
        .forward_scale
        .map(|scale| constant(scale, scale.wrapping_mul(field.qinv)));

    for (b, block) in vectors.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let x = &mut x4;

        for (x, chunk) in x.iter_mut().zip(block.iter()) {
            *x = load256(chunk);
        }

        let t16 = broadcast(z, zq, 8 + b);

        for (i, k) in [(0, 2), (1, 3)] {
            (x[i], x[k]) = forward_butterfly(x[i], x[k], t16, q);
        }

        for (g, i) in [0, 2].into_iter().enumerate() {
            let t8 = broadcast(z, zq, 16 + 2 * b + g);

            (x[i], x[i + 1]) = forward_butterfly(x[i], x[i + 1], t8, q);
        }

        for (p, i) in [0, 2].into_iter().enumerate() {
            (x[i], x[i + 1]) = forward_tail(x[i], x[i + 1], field, 2 * b + p, q);
        }

        if let Some(scale) = scale {
            for x in x.iter_mut() {
                *x = freeze(montgomery(*x, scale, q), q);
            }
        }

        for (x, chunk) in x.iter().zip(block.iter_mut()) {
            store256(*x, chunk);
        }
    }

    clear(&mut x8, zero);

    clear(&mut x4, zero);
}

// The inverse layers that pair coefficients 1, 2 and 4 apart, mirroring forward_tail with the
// reversed table, whose layer d uses its groups from 256 - 256 / d on.
#[target_feature(enable = "avx2")]
#[inline]
fn inverse_head(
    x: __m256i,
    y: __m256i,
    field: &Field,
    group: usize,
    q: __m256i,
) -> (__m256i, __m256i) {
    let (z, zq) = (&field.inverse, &field.inverse_qinv);

    let (x, y) = halves(x, y);

    let (mut x, mut y) = quarters(x, y);

    if field.layers == 8 {
        let (even, odd) = words(x, y);

        let (even, odd) = inverse_butterfly(even, odd, entries::<8>(z, zq, 8 * group), q);

        (x, y) = words(even, odd);
    }

    let (x, y) = inverse_butterfly(x, y, entries::<4>(z, zq, 128 + 4 * group), q);

    let (x, y) = quarters(x, y);

    let (x, y) = inverse_butterfly(x, y, entries::<2>(z, zq, 192 + 2 * group), q);

    halves(x, y)
}

// The inverse layers on the reversed table, after the first step of Prepare, and the final
// freeze(montgomery(x, inverse_scale)).
#[target_feature(enable = "avx2")]
pub(super) fn inverse(w: &mut [i32; 256], field: &Field) {
    let q = _mm256_set1_epi32(field.q);

    let (z, zq) = (&field.inverse, &field.inverse_qinv);

    let vectors = w.as_chunks_mut::<8>().0;

    let prepare = |x: __m256i| match field.prepare {
        Prepare::Reduce => {
            let quotient = _mm256_srai_epi32::<23>(_mm256_add_epi32(x, _mm256_set1_epi32(1 << 22)));

            _mm256_sub_epi32(x, _mm256_mullo_epi32(quotient, q))
        }
        Prepare::Montgomery(factor) => {
            montgomery(x, constant(factor, factor.wrapping_mul(field.qinv)), q)
        }
    };

    // The working vectors, which the loops index through memory, are cleared at the end.
    let zero = _mm256_setzero_si256();

    let (mut x4, mut x8) = ([zero; 4], [zero; 8]);

    for (b, block) in vectors.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let x = &mut x4;

        for (x, chunk) in x.iter_mut().zip(block.iter()) {
            *x = prepare(load256(chunk));
        }

        for (p, i) in [0, 2].into_iter().enumerate() {
            (x[i], x[i + 1]) = inverse_head(x[i], x[i + 1], field, 2 * b + p, q);
        }

        for (g, i) in [0, 2].into_iter().enumerate() {
            let t8 = broadcast(z, zq, 224 + 2 * b + g);

            (x[i], x[i + 1]) = inverse_butterfly(x[i], x[i + 1], t8, q);
        }

        let t16 = broadcast(z, zq, 240 + b);

        for (i, k) in [(0, 2), (1, 3)] {
            (x[i], x[k]) = inverse_butterfly(x[i], x[k], t16, q);
        }

        for (x, chunk) in x.iter().zip(block.iter_mut()) {
            store256(*x, chunk);
        }
    }

    let t32 = [248, 249, 250, 251].map(|m| broadcast(z, zq, m));

    let t64 = [broadcast(z, zq, 252), broadcast(z, zq, 253)];

    let t128 = broadcast(z, zq, 254);

    let scale = constant(
        field.inverse_scale,
        field.inverse_scale.wrapping_mul(field.qinv),
    );

    for j in 0..4 {
        let x = &mut x8;

        for (m, x) in x.iter_mut().enumerate() {
            *x = load256(&vectors[j + 4 * m]);
        }

        for (g, i) in [0, 2, 4, 6].into_iter().enumerate() {
            (x[i], x[i + 1]) = inverse_butterfly(x[i], x[i + 1], t32[g], q);
        }

        for (i, k, t) in [(0, 2, 0), (1, 3, 0), (4, 6, 1), (5, 7, 1)] {
            (x[i], x[k]) = inverse_butterfly(x[i], x[k], t64[t], q);
        }

        for i in 0..4 {
            (x[i], x[i + 4]) = inverse_butterfly(x[i], x[i + 4], t128, q);
        }

        for (m, x) in x.iter().enumerate() {
            store256(freeze(montgomery(*x, scale, q), q), &mut vectors[j + 4 * m]);
        }
    }

    clear(&mut x4, zero);

    clear(&mut x8, zero);
}

// out = f * g coefficient by coefficient.
#[target_feature(enable = "avx2")]
pub(super) fn products(out: &mut [i32; 256], f: &[i32; 256], g: &[i32; 256], field: &Field) {
    let (q, qinv) = (_mm256_set1_epi32(field.q), _mm256_set1_epi32(field.qinv));

    let factors = f.as_chunks::<8>().0.iter().zip(g.as_chunks::<8>().0);

    for (out, (f, g)) in out.as_chunks_mut::<8>().0.iter_mut().zip(factors) {
        store256(product(load256(f), load256(g), qinv, q), out);
    }
}

// acc += f[j] * g[j] summed over j, coefficient by coefficient: sixteen coefficients of acc stay
// in registers while every product is added. The sums are exact, so their order does not matter.
#[target_feature(enable = "avx2")]
pub(super) fn products_add(
    acc: &mut [i32; 256],
    f: &[[i32; 256]],
    g: &[[i32; 256]],
    field: &Field,
) {
    let (q, qinv) = (_mm256_set1_epi32(field.q), _mm256_set1_epi32(field.qinv));

    for (chunk, acc) in acc.as_chunks_mut::<16>().0.iter_mut().enumerate() {
        let [low, high] = acc.as_chunks_mut::<8>().0 else {
            unreachable!("sixteen values are two groups of eight")
        };

        let mut sums = [load256(low), load256(high)];

        for (f, g) in f.iter().zip(g) {
            let factors = f.as_chunks::<16>().0[chunk].as_chunks::<8>().0;

            let others = g.as_chunks::<16>().0[chunk].as_chunks::<8>().0;

            for ((sum, f), g) in sums.iter_mut().zip(factors).zip(others) {
                *sum = _mm256_add_epi32(*sum, product(load256(f), load256(g), qinv, q));
            }
        }

        store256(sums[0], low);

        store256(sums[1], high);

        wipe_unless_optimized!(words_of(&mut sums));
    }
}
