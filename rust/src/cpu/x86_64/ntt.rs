// The number-theoretic transforms and products of ML-DSA and ML-KEM on eight 32-bit coefficients
// per AVX2 vector, value for value what the portable code computes. The portable Montgomery product
// high(a, b) - high(m, q), with m = a * b_qinv mod 2^32, comes from 64-bit products of the even
// lanes and of the odd lanes moved down: their high halves are subtracted lane by lane, which is
// exact whatever the low halves hold, and the odd lanes' results are blended back.
//
// The layers run in two passes over eight registers: first the three layers that pair coefficients
// 128, 64 and 32 apart, on vectors 32 coefficients apart, then the others on 64 consecutive
// coefficients, so that each layer has four independent butterflies. For the layers that pair
// coefficients 4, 2 and 1 apart, pairs of vectors are transposed by halves, 64-bit and 32-bit
// groups so that partners share a lane; the factors of those layers come from broadcasts, a
// widening load or a load of eight table entries.
//
// All of these are data-processing instructions on Intel's data-operand-independent timing list,
// with no branch or address that depends on a coefficient.

use core::arch::x86_64::*;

#[cfg(not(crypto_pq_optimized))]
use super::memory::words_of;
use super::memory::{load128, load256, store256};
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

// The factors of the layer that pairs coefficients 4 apart: entries m and m + 1 of a table, each
// over four lanes, from two broadcasts; adjacent lanes share their factor, so the odd lanes' form
// is the same vector.
#[target_feature(enable = "avx2")]
#[inline]
fn fours(zetas: &[i32; 256], products: &[i32; 256], m: usize) -> Twiddle {
    let two = |table: &[i32; 256]| {
        _mm256_blend_epi32::<0xF0>(_mm256_set1_epi32(table[m]), _mm256_set1_epi32(table[m + 1]))
    };

    let (zeta, qinv) = (two(zetas), two(products));

    Twiddle {
        zeta,
        qinv,
        zeta_odd: zeta,
        qinv_odd: qinv,
    }
}

// The factors of the layer that pairs coefficients 2 apart: entries m to m + 3, each over two
// adjacent lanes. The products read only the low half of each 64-bit lane, so entry i widened to
// 64 bits serves both of its lanes, even and odd.
#[target_feature(enable = "avx2")]
#[inline]
fn twos(zetas: &[i32; 256], products: &[i32; 256], m: usize) -> Twiddle {
    let four = |table: &[i32; 256]| {
        let four: &[i32; 4] = table[m..m + 4].try_into().expect("four entries");

        _mm256_cvtepu32_epi64(load128(four))
    };

    let (zeta, qinv) = (four(zetas), four(products));

    Twiddle {
        zeta,
        qinv,
        zeta_odd: zeta,
        qinv_odd: qinv,
    }
}

// The factors of the layer that pairs neighbours: entries m to m + 7, one per lane.
#[target_feature(enable = "avx2")]
#[inline]
fn ones(zetas: &[i32; 256], products: &[i32; 256], m: usize) -> Twiddle {
    let eight = |table: &[i32; 256]| {
        let eight: &[i32; 8] = table[m..m + 8].try_into().expect("eight entries");

        load256(eight)
    };

    spread(eight(zetas), eight(products))
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

// The body once for each value of the index, as a constant: LLVM kept loops over these few
// vectors rolled, with the vectors on the stack and one butterfly at a time, which left the
// multiplier waiting on each product's latency.
macro_rules! unroll {
    ($index:ident in [$($value:literal),+] $body:block) => {
        $({
            const $index: usize = $value;

            $body
        })+
    };
}

// The layers that pair coefficients 4, 2 and 1 apart on four pairs of vectors, pair p in x[2p]
// and x[2p + 1], sixteen consecutive coefficients that are group first + p. With the table's group
// m counted from 1, the layer that pairs coefficients d apart uses groups 128 / d to 256 / d - 1.
#[target_feature(enable = "avx2")]
#[inline]
fn forward_tail(x: &mut [__m256i; 8], field: &Field, first: usize, q: __m256i) {
    let (z, zq) = (&field.forward, &field.forward_qinv);

    unroll!(P in [0, 1, 2, 3] {
        let (x0, x1) = halves(x[2 * P], x[2 * P + 1]);

        (x[2 * P], x[2 * P + 1]) = forward_butterfly(x0, x1, fours(z, zq, 32 + 2 * (first + P)), q);
    });

    unroll!(P in [0, 1, 2, 3] {
        let (x0, x1) = quarters(x[2 * P], x[2 * P + 1]);

        (x[2 * P], x[2 * P + 1]) = forward_butterfly(x0, x1, twos(z, zq, 64 + 4 * (first + P)), q);
    });

    if field.layers == 8 {
        unroll!(P in [0, 1, 2, 3] {
            let (even, odd) = words(x[2 * P], x[2 * P + 1]);

            let (even, odd) = forward_butterfly(even, odd, ones(z, zq, 128 + 8 * (first + P)), q);

            (x[2 * P], x[2 * P + 1]) = words(even, odd);
        });
    }

    unroll!(P in [0, 1, 2, 3] {
        let (x0, x1) = quarters(x[2 * P], x[2 * P + 1]);

        (x[2 * P], x[2 * P + 1]) = halves(x0, x1);
    });
}

// The forward layers in two passes over registers: the layers that pair coefficients 128, 64 and
// 32 apart on eight vectors 32 coefficients apart, then the others on 64 consecutive coefficients,
// two blocks of 32, so that every layer has four independent butterflies. ML-KEM's seven layers
// end with freeze(montgomery(x, forward_scale)).
#[target_feature(enable = "avx2")]
pub(super) fn forward(w: &mut [i32; 256], field: &Field) {
    let q = _mm256_set1_epi32(field.q);

    let (z, zq) = (&field.forward, &field.forward_qinv);

    let vectors = w.as_chunks_mut::<8>().0;

    let t128 = broadcast(z, zq, 1);

    let t64 = [broadcast(z, zq, 2), broadcast(z, zq, 3)];

    let t32 = [4, 5, 6, 7].map(|m| broadcast(z, zq, m));

    // The working vectors of both passes, indexed with constants only: registers (D-76).
    let zero = _mm256_setzero_si256();

    let mut x = [zero; 8];

    for j in 0..4 {
        unroll!(M in [0, 1, 2, 3, 4, 5, 6, 7] {
            x[M] = load256(&vectors[j + 4 * M]);
        });

        unroll!(I in [0, 1, 2, 3] {
            (x[I], x[I + 4]) = forward_butterfly(x[I], x[I + 4], t128, q);
        });

        unroll!(I in [0, 1, 4, 5] {
            (x[I], x[I + 2]) = forward_butterfly(x[I], x[I + 2], t64[I / 4], q);
        });

        unroll!(G in [0, 1, 2, 3] {
            (x[2 * G], x[2 * G + 1]) = forward_butterfly(x[2 * G], x[2 * G + 1], t32[G], q);
        });

        unroll!(M in [0, 1, 2, 3, 4, 5, 6, 7] {
            store256(x[M], &mut vectors[j + 4 * M]);
        });
    }

    let scale = field
        .forward_scale
        .map(|scale| constant(scale, scale.wrapping_mul(field.qinv)));

    // Blocks 2c and 2c + 1 of 32 coefficients in x[0..4] and x[4..8].
    for (c, blocks) in vectors.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        unroll!(M in [0, 1, 2, 3, 4, 5, 6, 7] {
            x[M] = load256(&blocks[M]);
        });

        unroll!(H in [0, 1] {
            let t16 = broadcast(z, zq, 8 + 2 * c + H);

            unroll!(I in [0, 1] {
                (x[4 * H + I], x[4 * H + I + 2]) =
                    forward_butterfly(x[4 * H + I], x[4 * H + I + 2], t16, q);
            });
        });

        unroll!(H in [0, 1] {
            unroll!(G in [0, 1] {
                let t8 = broadcast(z, zq, 16 + 2 * (2 * c + H) + G);

                (x[4 * H + 2 * G], x[4 * H + 2 * G + 1]) =
                    forward_butterfly(x[4 * H + 2 * G], x[4 * H + 2 * G + 1], t8, q);
            });
        });

        forward_tail(&mut x, field, 4 * c, q);

        if let Some(scale) = scale {
            unroll!(M in [0, 1, 2, 3, 4, 5, 6, 7] {
                x[M] = freeze(montgomery(x[M], scale, q), q);
            });
        }

        unroll!(M in [0, 1, 2, 3, 4, 5, 6, 7] {
            store256(x[M], &mut blocks[M]);
        });
    }

    wipe_unless_optimized!(words_of(&mut x));
}

// The inverse layers that pair coefficients 1, 2 and 4 apart, mirroring forward_tail with the
// reversed table, whose layer d uses its groups from 256 - 256 / d on.
#[target_feature(enable = "avx2")]
#[inline]
fn inverse_head(x: &mut [__m256i; 8], field: &Field, first: usize, q: __m256i) {
    let (z, zq) = (&field.inverse, &field.inverse_qinv);

    unroll!(P in [0, 1, 2, 3] {
        let (x0, x1) = halves(x[2 * P], x[2 * P + 1]);

        (x[2 * P], x[2 * P + 1]) = quarters(x0, x1);
    });

    if field.layers == 8 {
        unroll!(P in [0, 1, 2, 3] {
            let (even, odd) = words(x[2 * P], x[2 * P + 1]);

            let (even, odd) = inverse_butterfly(even, odd, ones(z, zq, 8 * (first + P)), q);

            (x[2 * P], x[2 * P + 1]) = words(even, odd);
        });
    }

    unroll!(P in [0, 1, 2, 3] {
        let t = twos(z, zq, 128 + 4 * (first + P));

        let (x0, x1) = inverse_butterfly(x[2 * P], x[2 * P + 1], t, q);

        (x[2 * P], x[2 * P + 1]) = quarters(x0, x1);
    });

    unroll!(P in [0, 1, 2, 3] {
        let t = fours(z, zq, 192 + 2 * (first + P));

        let (x0, x1) = inverse_butterfly(x[2 * P], x[2 * P + 1], t, q);

        (x[2 * P], x[2 * P + 1]) = halves(x0, x1);
    });
}

// The inverse layers on the reversed table, after the first step of Prepare, in the two passes of
// forward in the reverse order. The last layer takes the final freeze(montgomery(x, inverse_scale))
// with it: its sums are multiplied by the scale and its differences by the factor premultiplied by
// it, which gives the same canonical coefficients with one product fewer per pair.
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

    // The working vectors of both passes, indexed with constants only: registers (D-76).
    let zero = _mm256_setzero_si256();

    let mut x = [zero; 8];

    for (c, blocks) in vectors.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        unroll!(M in [0, 1, 2, 3, 4, 5, 6, 7] {
            x[M] = prepare(load256(&blocks[M]));
        });

        inverse_head(&mut x, field, 4 * c, q);

        unroll!(H in [0, 1] {
            unroll!(G in [0, 1] {
                let t8 = broadcast(z, zq, 224 + 2 * (2 * c + H) + G);

                (x[4 * H + 2 * G], x[4 * H + 2 * G + 1]) =
                    inverse_butterfly(x[4 * H + 2 * G], x[4 * H + 2 * G + 1], t8, q);
            });
        });

        unroll!(H in [0, 1] {
            let t16 = broadcast(z, zq, 240 + 2 * c + H);

            unroll!(I in [0, 1] {
                (x[4 * H + I], x[4 * H + I + 2]) =
                    inverse_butterfly(x[4 * H + I], x[4 * H + I + 2], t16, q);
            });
        });

        unroll!(M in [0, 1, 2, 3, 4, 5, 6, 7] {
            store256(x[M], &mut blocks[M]);
        });
    }

    let t32 = [248, 249, 250, 251].map(|m| broadcast(z, zq, m));

    let t64 = [broadcast(z, zq, 252), broadcast(z, zq, 253)];

    let (s, zeta) = (field.inverse_scale, z[254]);

    let product = i64::from(zeta) * i64::from(s);

    let m = (product as i32).wrapping_mul(field.qinv);

    let scaled = ((product - i64::from(m) * i64::from(field.q)) >> 32) as i32;

    let scale = constant(s, s.wrapping_mul(field.qinv));

    let t128 = constant(scaled, scaled.wrapping_mul(field.qinv));

    for j in 0..4 {
        unroll!(M in [0, 1, 2, 3, 4, 5, 6, 7] {
            x[M] = load256(&vectors[j + 4 * M]);
        });

        unroll!(G in [0, 1, 2, 3] {
            (x[2 * G], x[2 * G + 1]) = inverse_butterfly(x[2 * G], x[2 * G + 1], t32[G], q);
        });

        unroll!(I in [0, 1, 4, 5] {
            (x[I], x[I + 2]) = inverse_butterfly(x[I], x[I + 2], t64[I / 4], q);
        });

        unroll!(I in [0, 1, 2, 3] {
            let sum = _mm256_add_epi32(x[I], x[I + 4]);

            let difference = _mm256_sub_epi32(x[I + 4], x[I]);

            x[I] = freeze(montgomery(sum, scale, q), q);

            x[I + 4] = freeze(montgomery(difference, t128, q), q);
        });

        unroll!(M in [0, 1, 2, 3, 4, 5, 6, 7] {
            store256(x[M], &mut vectors[j + 4 * M]);
        });
    }

    wipe_unless_optimized!(words_of(&mut x));
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

// The Montgomery reduction of 64-bit sums, the even lanes' in even and the odd lanes' in odd:
// sum - m q with m = sum q^-1 mod 2^32 has its result in the high half, and the even lanes' are
// moved down and blended with the odd lanes'.
#[target_feature(enable = "avx2")]
#[inline]
fn reduce_wide(even: __m256i, odd_lanes: __m256i, qinv: __m256i, q: __m256i) -> __m256i {
    let even = _mm256_sub_epi64(even, _mm256_mul_epi32(_mm256_mul_epi32(even, qinv), q));

    let odd_lanes = _mm256_sub_epi64(
        odd_lanes,
        _mm256_mul_epi32(_mm256_mul_epi32(odd_lanes, qinv), q),
    );

    _mm256_blend_epi32::<0xAA>(odd(even), odd_lanes)
}

// acc += (f[0] g[0] + f[1] g[1] + ...) * 2^-32 coefficient by coefficient: the products of
// sixteen coefficients are summed exactly in 64-bit lanes, even and odd lanes apart, and reduced
// once, as the portable code does.
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

        let mut even = [_mm256_setzero_si256(); 2];

        let mut odd_lanes = [_mm256_setzero_si256(); 2];

        for (f, g) in f.iter().zip(g) {
            let factors = f.as_chunks::<16>().0[chunk].as_chunks::<8>().0;

            let others = g.as_chunks::<16>().0[chunk].as_chunks::<8>().0;

            for v in 0..2 {
                let (a, b) = (load256(&factors[v]), load256(&others[v]));

                even[v] = _mm256_add_epi64(even[v], _mm256_mul_epi32(a, b));

                odd_lanes[v] = _mm256_add_epi64(odd_lanes[v], _mm256_mul_epi32(odd(a), odd(b)));
            }
        }

        store256(
            _mm256_add_epi32(load256(low), reduce_wide(even[0], odd_lanes[0], qinv, q)),
            low,
        );

        store256(
            _mm256_add_epi32(load256(high), reduce_wide(even[1], odd_lanes[1], qinv, q)),
            high,
        );

        // Sums of products with the secret s1 (D-76).
        wipe_unless_optimized!(words_of(&mut even));

        wipe_unless_optimized!(words_of(&mut odd_lanes));
    }
}
