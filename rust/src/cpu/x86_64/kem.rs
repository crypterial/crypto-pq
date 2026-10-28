// ML-KEM with AVX2 on sixteen 16-bit lanes per vector, the x86-64 twin of the NEON kernels: the
// transforms, the base multiplication, the reductions, the encodings, compression, the noise and
// the rejection sampling of the matrix. They give exactly what the portable code gives: the
// transforms and reductions the same canonical coefficients, the others the same values.
//
// The Montgomery product modulo 2^16 is high(a b) - high(m q) with m = a (b q^-1) mod 2^16: a b and
// m q agree in their low halves, so the difference of the high halves is exact, and it lies in
// (-q, q) while |a b| < 2^15 q. The transforms keep 32 coefficients in two vectors; for the layers
// that pair coefficients 8, 4 and 2 apart they transpose the halves, the 64-bit and the 32-bit
// groups of the two vectors so that partners share a lane, and transpose them back afterwards.
//
// Everything that touches secret coefficients is a data-processing instruction on Intel's list of
// data-operand-independent timing instructions, with no branch or address that depends on the
// data. The rejection sampler serves the public matrix, so its accept patterns index tables.

use core::arch::x86_64::*;

use super::ACCEPTED;
#[cfg(not(crypto_pq_optimized))]
use super::memory::words_of;
use super::memory::{load128, load256, store128, store256};
use crate::cpu::Field16;
use crate::wipe::wipe_unless_optimized;

// A factor and its product by q^-1, the same in every lane or one per lane.
#[derive(Clone, Copy)]
struct Twiddle {
    zeta: __m256i,
    qinv: __m256i,
}

#[target_feature(enable = "avx2")]
#[inline]
fn broadcast(zeta: i16, qinv: i16) -> Twiddle {
    Twiddle {
        zeta: _mm256_set1_epi16(zeta),
        qinv: _mm256_set1_epi16(qinv),
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn lanes(table: &[[[i16; 16]; 8]; 6], layer: usize, block: usize) -> Twiddle {
    Twiddle {
        zeta: load256(&table[2 * layer][block]),
        qinv: load256(&table[2 * layer + 1][block]),
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn montgomery(a: __m256i, t: Twiddle, q: __m256i) -> __m256i {
    let high = _mm256_mulhi_epi16(a, t.zeta);

    let m = _mm256_mullo_epi16(a, t.qinv);

    _mm256_sub_epi16(high, _mm256_mulhi_epi16(m, q))
}

// Cooley-Tukey: (a + b zeta, a - b zeta).
#[target_feature(enable = "avx2")]
#[inline]
fn forward_butterfly(a: __m256i, b: __m256i, t: Twiddle, q: __m256i) -> (__m256i, __m256i) {
    let product = montgomery(b, t, q);

    (_mm256_add_epi16(a, product), _mm256_sub_epi16(a, product))
}

// Gentleman-Sande: (a + b, (b - a) zeta).
#[target_feature(enable = "avx2")]
#[inline]
fn inverse_butterfly(a: __m256i, b: __m256i, t: Twiddle, q: __m256i) -> (__m256i, __m256i) {
    (
        _mm256_add_epi16(a, b),
        montgomery(_mm256_sub_epi16(b, a), t, q),
    )
}

// x - round(x / q) q for any 16-bit x, the quotient estimated as round(x round(2^26 / q) / 2^26)
// from the high half of the product: off by at most one where x / q is within 2^-9 of a half,
// so the result stays within q / 2 + 4 of zero.
#[target_feature(enable = "avx2")]
#[inline]
fn barrett(x: __m256i, v: __m256i, q: __m256i) -> __m256i {
    let estimate = _mm256_mulhi_epi16(x, v);

    let quotient = _mm256_srai_epi16::<10>(_mm256_add_epi16(estimate, _mm256_set1_epi16(512)));

    _mm256_sub_epi16(x, _mm256_mullo_epi16(quotient, q))
}

// (-q, q) to [0, q).
#[target_feature(enable = "avx2")]
#[inline]
fn freeze(x: __m256i, q: __m256i) -> __m256i {
    _mm256_add_epi16(x, _mm256_and_si256(q, _mm256_srai_epi16::<15>(x)))
}

// [0, 2q) to [0, q): the smaller of x and x - q as unsigned values.
#[target_feature(enable = "avx2")]
#[inline]
fn subtract_q(x: __m256i, q: __m256i) -> __m256i {
    _mm256_min_epu16(x, _mm256_sub_epi16(x, q))
}

// The low halves of x and y, then their high halves; each of these transpositions is its own
// inverse.
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
fn pairs(x: __m256i, y: __m256i) -> (__m256i, __m256i) {
    (
        _mm256_blend_epi32::<0xAA>(x, _mm256_slli_epi64::<32>(y)),
        _mm256_blend_epi32::<0xAA>(_mm256_srli_epi64::<32>(x), y),
    )
}

// The seven forward layers on canonical coefficients, which end in canonical form: first the
// layers 128, 64 and 32 apart on eight vectors 32 coefficients apart, then the others on blocks
// of 32 consecutive coefficients. The sums stay below 8q < 2^15.
#[target_feature(enable = "avx2")]
pub(super) fn ntt(f: &mut [u16; 256], field: &Field16) {
    let q = _mm256_set1_epi16(field.q);

    let v = _mm256_set1_epi16(field.barrett);

    let (z, zq) = (&field.forward, &field.forward_qinv);

    let vectors = f.as_chunks_mut::<16>().0;

    let t128 = broadcast(z[1], zq[1]);

    let t64 = [broadcast(z[2], zq[2]), broadcast(z[3], zq[3])];

    let t32 = [4, 5, 6, 7].map(|m| broadcast(z[m], zq[m]));

    for j in 0..2 {
        let mut x = [_mm256_setzero_si256(); 8];

        for (m, x) in x.iter_mut().enumerate() {
            *x = load256(&vectors[j + 2 * m]);
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
            store256(*x, &mut vectors[j + 2 * m]);
        }

        wipe_unless_optimized!(words_of(&mut x));
    }

    for (b, block) in vectors.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        let (a, c) = (load256(&block[0]), load256(&block[1]));

        let (a, c) = forward_butterfly(a, c, broadcast(z[8 + b], zq[8 + b]), q);

        let (x, y) = halves(a, c);

        let (x, y) = forward_butterfly(x, y, lanes(&field.forward_x86, 0, b), q);

        let (x, y) = quarters(x, y);

        let (x, y) = forward_butterfly(x, y, lanes(&field.forward_x86, 1, b), q);

        let (x, y) = pairs(x, y);

        let (x, y) = forward_butterfly(x, y, lanes(&field.forward_x86, 2, b), q);

        let (x, y) = (freeze(barrett(x, v, q), q), freeze(barrett(y, v, q), q));

        let (x, y) = pairs(x, y);

        let (x, y) = quarters(x, y);

        let (a, c) = halves(x, y);

        store256(a, &mut block[0]);

        store256(c, &mut block[1]);
    }
}

// Sixteen 32-bit sums, any values, to sixteen 16-bit lanes congruent to them times 2^-16 and
// within q + 4 of zero: the high halves of the sums are brought within q / 2 + 4 of zero, which
// changes the sums by multiples of q 2^16, and a Montgomery reduction divides by 2^16.
#[target_feature(enable = "avx2")]
#[inline]
fn reduce_sums(
    first: &[i32; 8],
    second: &[i32; 8],
    qinv: __m256i,
    v: __m256i,
    q: __m256i,
) -> __m256i {
    let (x, y) = (load256(first), load256(second));

    let mask = _mm256_set1_epi32(0xFFFF);

    let low = _mm256_packus_epi32(_mm256_and_si256(x, mask), _mm256_and_si256(y, mask));

    let high = _mm256_packs_epi32(_mm256_srai_epi32::<16>(x), _mm256_srai_epi32::<16>(y));

    let m = _mm256_mullo_epi16(low, qinv);

    let reduced = _mm256_sub_epi16(barrett(high, v, q), _mm256_mulhi_epi16(m, q));

    // The packs kept each 128-bit half: first's words 0 to 3, second's 0 to 3, then 4 to 7 of each.
    _mm256_permute4x64_epi64::<0xD8>(reduced)
}

// The seven inverse layers into canonical coefficients, from 16-bit values within 2^11 + q of zero
// that load gives for each block of 32 coefficients, congruent to the inputs times 2^-16, which the
// final factor takes back. Barrett reductions after the layers 8 and 64 apart keep the sums below
// 8 (2^11 + q) < 2^15.
#[target_feature(enable = "avx2")]
#[inline]
fn inverse_layers(
    out: &mut [u16; 256],
    field: &Field16,
    mut load: impl FnMut(usize) -> (__m256i, __m256i),
) {
    let q = _mm256_set1_epi16(field.q);

    let v = _mm256_set1_epi16(field.barrett);

    let (z, zq) = (&field.inverse, &field.inverse_qinv);

    let vectors = out.as_chunks_mut::<16>().0;

    for (b, block) in vectors.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        let (a, c) = load(b);

        let (x, y) = halves(a, c);

        let (x, y) = quarters(x, y);

        let (x, y) = pairs(x, y);

        let (x, y) = inverse_butterfly(x, y, lanes(&field.inverse_x86, 2, b), q);

        let (x, y) = pairs(x, y);

        let (x, y) = inverse_butterfly(x, y, lanes(&field.inverse_x86, 1, b), q);

        let (x, y) = quarters(x, y);

        let (x, y) = inverse_butterfly(x, y, lanes(&field.inverse_x86, 0, b), q);

        let (a, c) = halves(x, y);

        let (a, c) = (barrett(a, v, q), barrett(c, v, q));

        let (a, c) = inverse_butterfly(a, c, broadcast(z[112 + b], zq[112 + b]), q);

        store256(a, &mut block[0]);

        store256(c, &mut block[1]);
    }

    let t32 = [120, 121, 122, 123].map(|m| broadcast(z[m], zq[m]));

    let t64 = [broadcast(z[124], zq[124]), broadcast(z[125], zq[125])];

    let t128 = broadcast(z[126], zq[126]);

    let scale = field.inverse_scale_x86;

    let scale = broadcast(scale, scale.wrapping_mul(field.qinv));

    for j in 0..2 {
        let mut x = [_mm256_setzero_si256(); 8];

        for (m, x) in x.iter_mut().enumerate() {
            *x = load256(&vectors[j + 2 * m]);
        }

        for (g, i) in [0, 2, 4, 6].into_iter().enumerate() {
            (x[i], x[i + 1]) = inverse_butterfly(x[i], x[i + 1], t32[g], q);
        }

        for (i, k, t) in [(0, 2, 0), (1, 3, 0), (4, 6, 1), (5, 7, 1)] {
            (x[i], x[k]) = inverse_butterfly(x[i], x[k], t64[t], q);
        }

        for x in &mut x {
            *x = barrett(*x, v, q);
        }

        for i in 0..4 {
            (x[i], x[i + 4]) = inverse_butterfly(x[i], x[i + 4], t128, q);
        }

        for (m, x) in x.iter().enumerate() {
            store256(freeze(montgomery(*x, scale, q), q), &mut vectors[j + 2 * m]);
        }

        wipe_unless_optimized!(words_of(&mut x));
    }
}

// The seven inverse layers on the 32-bit sums of the base multiplication, any values, into
// canonical coefficients.
#[target_feature(enable = "avx2")]
pub(super) fn inverse_ntt(acc: &[i32; 256], out: &mut [u16; 256], field: &Field16) {
    let q = _mm256_set1_epi16(field.q);

    let v = _mm256_set1_epi16(field.barrett);

    let qinv = _mm256_set1_epi16(field.qinv);

    let sums = acc.as_chunks::<8>().0;

    inverse_layers(out, field, |b| {
        (
            reduce_sums(&sums[4 * b], &sums[4 * b + 1], qinv, v, q),
            reduce_sums(&sums[4 * b + 2], &sums[4 * b + 3], qinv, v, q),
        )
    });
}

// InvNTT of the sum of the products a[j] * b[j] in ML-KEM's NTT domain, with the caches of the
// b[j], into canonical coefficients: the even and odd sums of each sixteen coefficients stay in
// registers over every product and go straight into the first inverse layers. At most four
// products of canonical values keep the sums below 2^27.
#[target_feature(enable = "avx2")]
pub(super) fn inner_product(
    out: &mut [u16; 256],
    a: &[&[u16; 256]],
    b: &[[u16; 256]],
    caches: &[[u16; 128]],
    field: &Field16,
) {
    let c = Constants {
        q: _mm256_set1_epi16(field.q),
        qinv: field.qinv,
        v: _mm256_set1_epi16(field.barrett),
    };

    let chunk = |i: usize| {
        let (mut even, mut odd) = (_mm256_setzero_si256(), _mm256_setzero_si256());

        for ((a, b), cache) in a.iter().zip(b).zip(caches) {
            let (e, o) = pair_products(
                &a.as_chunks::<16>().0[i],
                &b.as_chunks::<16>().0[i],
                &cache.as_chunks::<8>().0[i],
            );

            even = _mm256_add_epi32(even, e);

            odd = _mm256_add_epi32(odd, o);
        }

        interleave_pairs(reduce_pairs(even, odd, c))
    };

    inverse_layers(out, field, |b| (chunk(2 * b), chunk(2 * b + 1)));
}

// The products a * b of sixteen coefficients in ML-KEM's NTT domain, with b's cache of b1 gamma:
// the even sums a0 b0 + a1 c and the odd ones a0 b1 + a1 b0, each a multiply-add of 16-bit pairs
// into 32 bits. Every product of canonical values, and the sum of two, fits in 25 bits.
#[target_feature(enable = "avx2")]
#[inline]
fn pair_products(a: &[u16; 16], b: &[u16; 16], c: &[u16; 8]) -> (__m256i, __m256i) {
    let swap = _mm256_setr_epi8(
        2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9,
        14, 15, 12, 13,
    );

    let (a, b) = (load256(a), load256(b));

    let c = _mm256_slli_epi32::<16>(_mm256_cvtepu16_epi32(load128(c)));

    let even = _mm256_madd_epi16(a, _mm256_blend_epi16::<0xAA>(b, c));

    let odd = _mm256_madd_epi16(a, _mm256_shuffle_epi8(b, swap));

    (even, odd)
}

// The even and odd sums of eight pairs, in coefficient order, as two vectors of eight sums.
#[target_feature(enable = "avx2")]
#[inline]
fn interleave_sums(even: __m256i, odd: __m256i) -> (__m256i, __m256i) {
    let (low, high) = (
        _mm256_unpacklo_epi32(even, odd),
        _mm256_unpackhi_epi32(even, odd),
    );

    halves(low, high)
}

// acc += a * b in ML-KEM's NTT domain, sixteen coefficients at a time.
#[target_feature(enable = "avx2")]
pub(super) fn base_multiply_add(
    acc: &mut [i32; 256],
    a: &[u16; 256],
    b: &[u16; 256],
    cache: &[u16; 128],
) {
    let factors = a.as_chunks::<16>().0.iter().zip(b.as_chunks::<16>().0);

    let groups = factors.zip(cache.as_chunks::<8>().0);

    for (acc, ((a, b), c)) in acc.as_chunks_mut::<16>().0.iter_mut().zip(groups) {
        let (even, odd) = pair_products(a, b, c);

        let (first, second) = interleave_sums(even, odd);

        let [low, high] = acc.as_chunks_mut::<8>().0 else {
            unreachable!("sixteen sums are two groups of eight")
        };

        store256(_mm256_add_epi32(load256(low), first), low);

        store256(_mm256_add_epi32(load256(high), second), high);
    }
}

// The 16-bit constants of a field given by q alone: q^-1 mod 2^16 by Newton's iteration, and
// round(2^26 / q) for the Barrett reduction.
#[derive(Clone, Copy)]
struct Constants {
    q: __m256i,
    qinv: i16,
    v: __m256i,
}

#[target_feature(enable = "avx2")]
#[inline]
fn constants(q: i16) -> Constants {
    let mut qinv = 1i16;

    for _ in 0..4 {
        qinv = qinv.wrapping_mul(2i16.wrapping_sub(q.wrapping_mul(qinv)));
    }

    Constants {
        q: _mm256_set1_epi16(q),
        qinv,
        v: _mm256_set1_epi16((((1 << 26) + i32::from(q) / 2) / i32::from(q)) as i16),
    }
}

// x mod q in (-q / 2, q / 2], for a factor of a Montgomery product.
const fn centered(x: i64, q: i16) -> i16 {
    let x = x.rem_euclid(q as i64) as i16;

    if x > q / 2 { x - q } else { x }
}

// The even and odd sums of eight pairs, below 2^27, reduced to 16 bits: congruent to the sums
// times 2^-16 and within 2^11 + q of zero, in the order even sums 0 to 3, odd sums 0 to 3, then
// 4 to 7 of each, in the two halves.
#[target_feature(enable = "avx2")]
#[inline]
fn reduce_pairs(even: __m256i, odd: __m256i, c: Constants) -> __m256i {
    let mask = _mm256_set1_epi32(0xFFFF);

    let low = _mm256_packus_epi32(_mm256_and_si256(even, mask), _mm256_and_si256(odd, mask));

    let high = _mm256_packs_epi32(_mm256_srai_epi32::<16>(even), _mm256_srai_epi32::<16>(odd));

    let m = _mm256_mullo_epi16(low, _mm256_set1_epi16(c.qinv));

    _mm256_sub_epi16(high, _mm256_mulhi_epi16(m, c.q))
}

// The order of reduce_pairs to coefficient order, in each half.
#[target_feature(enable = "avx2")]
#[inline]
fn interleave_pairs(x: __m256i) -> __m256i {
    let order = _mm256_setr_epi8(
        0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15, 0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12,
        13, 6, 7, 14, 15,
    );

    _mm256_shuffle_epi8(x, order)
}

// Rows of t = A * s + e of key generation, all canonical, each row's sums kept in registers
// sixteen coefficients at a time. The sums of at most four products of canonical values are
// below 2^27; reduce_pairs leaves them times 2^-16, which a product by 2^32 mod q takes back.
#[target_feature(enable = "avx2")]
pub(super) fn matrix_vector(
    t: &mut [[u16; 256]],
    a: &[[u16; 256]],
    s: &[[u16; 256]],
    caches: &[[u16; 128]],
    e: &[[u16; 256]],
    q: u16,
) {
    let c = constants(q as i16);

    let r2 = centered(1 << 32, q as i16);

    let r2 = broadcast(r2, r2.wrapping_mul(c.qinv));

    for ((t, row), e) in t.iter_mut().zip(a.chunks_exact(s.len())).zip(e) {
        let outputs = t.as_chunks_mut::<16>().0.iter_mut();

        for (chunk, (out, e)) in outputs.zip(e.as_chunks::<16>().0).enumerate() {
            let (mut even, mut odd) = (_mm256_setzero_si256(), _mm256_setzero_si256());

            for ((a, b), cache) in row.iter().zip(s).zip(caches) {
                let (e, o) = pair_products(
                    &a.as_chunks::<16>().0[chunk],
                    &b.as_chunks::<16>().0[chunk],
                    &cache.as_chunks::<8>().0[chunk],
                );

                even = _mm256_add_epi32(even, e);

                odd = _mm256_add_epi32(odd, o);
            }

            let x = freeze(montgomery(reduce_pairs(even, odd, c), r2, c.q), c.q);

            let x = _mm256_add_epi16(interleave_pairs(x), load256(e));

            store256(subtract_q(x, c.q), out);
        }
    }
}

// freeze(montgomery(x, factor)) of the 32-bit Montgomery product of every sum, which is x factor
// 2^-32 mod q: the sums reduced as for the inverse transform, times 2^-16, then a 16-bit product
// by factor mod q. The low half of q^-1 mod 2^32 is q^-1 mod 2^16.
#[target_feature(enable = "avx2")]
pub(super) fn reduce(w: &[i32; 256], factor: i32, q: i32, qinv: i32, out: &mut [u16; 256]) {
    let c = constants(q as i16);

    let qinv = _mm256_set1_epi16(qinv as i16);

    let f = centered(i64::from(factor), q as i16);

    let f = broadcast(f, f.wrapping_mul(c.qinv));

    let sums = w.as_chunks::<8>().0;

    for (i, out) in out.as_chunks_mut::<16>().0.iter_mut().enumerate() {
        let x = reduce_sums(&sums[2 * i], &sums[2 * i + 1], qinv, c.v, c.q);

        store256(freeze(montgomery(x, f, c.q), c.q), out);
    }
}

// Twelve bytes of a 24-byte group, in each 128-bit half: bytes 0 to 11 in the low half and 12
// to 23 in the high half, at its offset 4.
#[target_feature(enable = "avx2")]
#[inline]
fn load24(bytes: &[u8; 24]) -> __m256i {
    let low: &[u8; 16] = bytes[..16].try_into().expect("sixteen bytes");

    let high: &[u8; 16] = bytes[8..].try_into().expect("sixteen bytes");

    _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(load128(low)), load128(high))
}

// Sixteen 12-bit values from 24 bytes: the pairs (x, y) of every three bytes.
#[target_feature(enable = "avx2")]
#[inline]
fn unpack12(bytes: &[u8; 24]) -> __m256i {
    let spread = _mm256_setr_epi8(
        0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11, 4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11, 12,
        13, 14, 14, 15,
    );

    let words = _mm256_shuffle_epi8(load24(bytes), spread);

    _mm256_blend_epi16::<0xAA>(
        _mm256_and_si256(words, _mm256_set1_epi16(0x0FFF)),
        _mm256_srli_epi16::<4>(words),
    )
}

// Stores the low 24 bytes of a vector.
#[target_feature(enable = "avx2")]
#[inline]
fn store24(vector: __m256i, out: &mut [u8; 24]) {
    let (low, high) = out.split_at_mut(16);

    let low: &mut [u8; 16] = low.try_into().expect("sixteen bytes");

    store128(_mm256_castsi256_si128(vector), low);

    let rest = _mm_cvtsi128_si64(_mm256_extracti128_si256::<1>(vector)) as u64;

    high.copy_from_slice(&rest.to_le_bytes());
}

// Sixteen coefficients of 12 bits into 24 bytes: x + 4096 y of each pair is three bytes.
#[target_feature(enable = "avx2")]
pub(super) fn encode12(f: &[u16; 256], out: &mut [u8; 384]) {
    let gather = _mm256_setr_epi8(
        0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, -1, -1, -1, -1, 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13,
        14, -1, -1, -1, -1,
    );

    let together = _mm256_setr_epi32(0, 1, 2, 4, 5, 6, 3, 7);

    let pairs = _mm256_set1_epi32(0x1000_0001);

    for (out, f) in out
        .as_chunks_mut::<24>()
        .0
        .iter_mut()
        .zip(f.as_chunks::<16>().0)
    {
        let words = _mm256_madd_epi16(load256(f), pairs);

        let bytes = _mm256_shuffle_epi8(words, gather);

        store24(_mm256_permutevar8x32_epi32(bytes, together), out);
    }
}

// ByteDecode_12 followed by the reduction of every value modulo q.
#[target_feature(enable = "avx2")]
pub(super) fn decode12(data: &[u8; 384], q: u16, out: &mut [u16; 256]) {
    let q = _mm256_set1_epi16(q as i16);

    for (out, bytes) in out
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(data.as_chunks::<24>().0)
    {
        store256(subtract_q(unpack12(bytes), q), out);
    }
}

// Compress_d of canonical values: round(2^d x / q) mod 2^d. The estimate x round(2^(16 + d) / q)
// / 2^16 is at most one away from it, and the remainder 2^d x + (q - 1) / 2 - estimate q, which
// lies in [-q, 2q) and so is exact in 16-bit arithmetic, says which way.
#[target_feature(enable = "avx2")]
#[inline]
fn compress_values<const D: i32>(x: __m256i, q: i16) -> __m256i {
    let m = (((1i64 << (16 + D)) + i64::from(q) / 2) / i64::from(q)) as u16 as i16;

    let estimate = _mm256_mulhi_epu16(x, _mm256_set1_epi16(m));

    let remainder = _mm256_sub_epi16(
        _mm256_add_epi16(_mm256_slli_epi16::<D>(x), _mm256_set1_epi16((q - 1) / 2)),
        _mm256_mullo_epi16(estimate, _mm256_set1_epi16(q)),
    );

    let above = _mm256_cmpgt_epi16(remainder, _mm256_set1_epi16(q - 1));

    let below = _mm256_cmpgt_epi16(_mm256_setzero_si256(), remainder);

    let v = _mm256_add_epi16(_mm256_sub_epi16(estimate, above), below);

    _mm256_and_si256(v, _mm256_set1_epi16((1 << D) - 1))
}

// All lanes set where bit i of the sixteen message bits is set, for lane i.
#[target_feature(enable = "avx2")]
#[inline]
fn message_lanes(bits: u16) -> __m256i {
    let lanes = _mm256_setr_epi16(
        1,
        2,
        4,
        8,
        16,
        32,
        64,
        128,
        256,
        512,
        1024,
        2048,
        4096,
        8192,
        16384,
        i16::MIN,
    );

    _mm256_cmpeq_epi16(
        _mm256_and_si256(_mm256_set1_epi16(bits as i16), lanes),
        lanes,
    )
}

// Chunk i of f + e, plus Decompress_1 of the message bits if there are any, compressed.
#[target_feature(enable = "avx2")]
#[inline]
fn compressed<const D: i32>(
    f: &[u16; 256],
    e: &[u16; 256],
    message: Option<&[u8; 32]>,
    i: usize,
    q: i16,
) -> __m256i {
    let qv = _mm256_set1_epi16(q);

    let sum = _mm256_add_epi16(
        load256(&f.as_chunks::<16>().0[i]),
        load256(&e.as_chunks::<16>().0[i]),
    );

    let mut x = subtract_q(sum, qv);

    if let Some(message) = message {
        let bits = u16::from_le_bytes([message[2 * i], message[2 * i + 1]]);

        let half = _mm256_and_si256(message_lanes(bits), _mm256_set1_epi16((q + 1) / 2));

        x = subtract_q(_mm256_add_epi16(x, half), qv);
    }

    compress_values::<D>(x, q)
}

// Sixteen values of D bits, D = 5, 10 or 11, as 2D bytes at the start of out, overwriting bytes
// after them up to the 27th. Pairs of values become words of 2D bits, pairs of words 4D bits in
// each 64-bit lane, and the two lanes of each half are joined into 8D bits.
#[target_feature(enable = "avx2")]
#[inline]
fn pack<const D: i32>(v: __m256i, out: &mut [u8; 32]) {
    let words = _mm256_madd_epi16(v, _mm256_set1_epi32(1 | 1 << (16 + D)));

    let low = _mm256_set1_epi64x((1 << (2 * D)) - 1);

    let lanes = _mm256_or_si256(
        _mm256_and_si256(words, low),
        _mm256_andnot_si256(low, _mm256_srl_epi64(words, _mm_cvtsi32_si128(32 - 2 * D))),
    );

    // 4D bits in each 64-bit lane: the second lane's bits follow the first's.
    let joined = _mm256_or_si256(
        lanes,
        _mm256_sll_epi64(_mm256_bsrli_epi128::<8>(lanes), _mm_cvtsi32_si128(4 * D)),
    );

    let halves = if 8 * D > 64 {
        _mm256_blend_epi32::<0xCC>(
            joined,
            _mm256_srl_epi64(lanes, _mm_cvtsi32_si128(64 - 4 * D)),
        )
    } else {
        joined
    };

    let first: &mut [u8; 16] = (&mut out[..16]).try_into().expect("sixteen bytes");

    store128(_mm256_castsi256_si128(halves), first);

    let start = D as usize;

    let second: &mut [u8; 16] = (&mut out[start..start + 16])
        .try_into()
        .expect("sixteen bytes");

    store128(_mm256_extracti128_si256::<1>(halves), second);
}

// ByteEncode_d(Compress_d(f + e)), with Decompress_1 of a message added first if there is one,
// for f and e canonical and d one of 1, 4, 5, 10 and 11.
#[target_feature(enable = "avx2")]
pub(super) fn compress(
    f: &[u16; 256],
    e: &[u16; 256],
    message: Option<&[u8; 32]>,
    d: u32,
    q: u16,
    out: &mut [u8],
) {
    let q = q as i16;

    match d {
        1 => {
            for (i, out) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let first = compressed::<1>(f, e, message, 2 * i, q);

                let second = compressed::<1>(f, e, message, 2 * i + 1, q);

                *out = message_bits(first, second).to_le_bytes();
            }
        }
        4 => {
            let nibbles = _mm256_set1_epi16(0x1001);

            let order = _mm256_setr_epi32(0, 4, 1, 5, 2, 6, 3, 7);

            for (i, out) in out.as_chunks_mut::<32>().0.iter_mut().enumerate() {
                #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
                let mut v: [__m256i; 4] =
                    core::array::from_fn(|j| compressed::<4>(f, e, message, 4 * i + j, q));

                #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
                let mut pairs = [
                    _mm256_maddubs_epi16(_mm256_packus_epi16(v[0], v[1]), nibbles),
                    _mm256_maddubs_epi16(_mm256_packus_epi16(v[2], v[3]), nibbles),
                ];

                let bytes = _mm256_packus_epi16(pairs[0], pairs[1]);

                store256(_mm256_permutevar8x32_epi32(bytes, order), out);

                wipe_unless_optimized!(words_of(&mut v));

                wipe_unless_optimized!(words_of(&mut pairs));
            }
        }
        5 => compress_packed::<5>(f, e, message, q, out),
        10 => compress_packed::<10>(f, e, message, q, out),
        11 => compress_packed::<11>(f, e, message, q, out),
        _ => unreachable!("no ML-KEM encoding uses {d} bits"),
    }
}

// The sixteen values of each of two vectors, 0 or 1, as the 32 bits of a word.
#[target_feature(enable = "avx2")]
#[inline]
fn message_bits(first: __m256i, second: __m256i) -> u32 {
    let bytes = _mm256_packs_epi16(
        _mm256_slli_epi16::<15>(first),
        _mm256_slli_epi16::<15>(second),
    );

    _mm256_movemask_epi8(_mm256_permute4x64_epi64::<0xD8>(bytes)) as u32
}

// The buffer is wiped: in decapsulation it holds the re-encryption, which stays secret.
#[target_feature(enable = "avx2")]
#[inline]
fn compress_packed<const D: i32>(
    f: &[u16; 256],
    e: &[u16; 256],
    message: Option<&[u8; 32]>,
    q: i16,
    out: &mut [u8],
) {
    let size = 2 * D as usize;

    let mut buffer = [0u8; 32 * 11 + 32];

    for i in 0..16 {
        let v = compressed::<D>(f, e, message, i, q);

        let window = (&mut buffer[size * i..size * i + 32])
            .try_into()
            .expect("32 bytes");

        pack::<D>(v, window);
    }

    out.copy_from_slice(&buffer[..16 * size]);

    crate::wipe::wipe(&mut buffer);
}

// Sixteen values of D bits, D = 4, 5, 10 or 11, from the start of bytes, which reaches at least
// 32 bytes past it.
#[target_feature(enable = "avx2")]
#[inline]
fn unpack<const D: i32>(bytes: &[u8; 32]) -> __m256i {
    match D {
        4 => {
            let spread = _mm256_setr_epi8(
                0, -1, 0, -1, 1, -1, 1, -1, 2, -1, 2, -1, 3, -1, 3, -1, 4, -1, 4, -1, 5, -1, 5, -1,
                6, -1, 6, -1, 7, -1, 7, -1,
            );

            let all = _mm256_set1_epi64x(i64::from_le_bytes(
                *bytes.first_chunk().expect("eight bytes"),
            ));

            let words = _mm256_shuffle_epi8(all, spread);

            _mm256_blend_epi16::<0xAA>(
                _mm256_and_si256(words, _mm256_set1_epi16(0x0F)),
                _mm256_srli_epi16::<4>(words),
            )
        }
        5 | 10 => {
            let (spread, scale) = if D == 5 {
                (
                    _mm_setr_epi8(0, 1, 0, 1, 1, 2, 1, 2, 2, 3, 3, 4, 3, 4, 4, 5),
                    _mm256_setr_epi16(
                        2048, 64, 512, 16, 128, 1024, 32, 256, 2048, 64, 512, 16, 128, 1024, 32,
                        256,
                    ),
                )
            } else {
                (
                    _mm_setr_epi8(0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9),
                    _mm256_setr_epi16(64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1),
                )
            };

            let half = D as usize;

            let low: &[u8; 16] = bytes[..16].try_into().expect("sixteen bytes");

            let high: &[u8; 16] = bytes[half..half + 16].try_into().expect("sixteen bytes");

            let (low, high) = (load128(low), load128(high));

            let words = _mm256_shuffle_epi8(
                _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(low), high),
                _mm256_broadcastsi128_si256(spread),
            );

            // Each value's bits moved to the top of its word, then down.
            _mm256_srl_epi16(_mm256_mullo_epi16(words, scale), _mm_cvtsi32_si128(16 - D))
        }
        _ => {
            let low: &[u8; 16] = bytes[..16].try_into().expect("sixteen bytes");

            let high: &[u8; 16] = bytes[11..27].try_into().expect("sixteen bytes");

            let (low, high) = (load128(low), load128(high));

            let both = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(low), high);

            let first = _mm256_shuffle_epi8(
                both,
                _mm256_setr_epi8(
                    0, 1, 2, 3, 1, 2, 3, 4, 2, 3, 4, 5, 4, 5, 6, 7, 0, 1, 2, 3, 1, 2, 3, 4, 2, 3,
                    4, 5, 4, 5, 6, 7,
                ),
            );

            let second = _mm256_shuffle_epi8(
                both,
                _mm256_setr_epi8(
                    5, 6, 7, 8, 6, 7, 8, 9, 8, 9, 10, 11, 9, 10, 11, 12, 5, 6, 7, 8, 6, 7, 8, 9, 8,
                    9, 10, 11, 9, 10, 11, 12,
                ),
            );

            let mask = _mm256_set1_epi32(0x7FF);

            let first = _mm256_and_si256(
                _mm256_srlv_epi32(first, _mm256_setr_epi32(0, 3, 6, 1, 0, 3, 6, 1)),
                mask,
            );

            let second = _mm256_and_si256(
                _mm256_srlv_epi32(second, _mm256_setr_epi32(4, 7, 2, 5, 4, 7, 2, 5)),
                mask,
            );

            _mm256_packs_epi32(first, second)
        }
    }
}

// Decompress_d(ByteDecode_d(data)) for d one of 4, 5, 10 and 11: round(q y / 2^d), which is the
// rounding high half of (y 2^(15 - d)) q.
#[target_feature(enable = "avx2")]
pub(super) fn decompress(data: &[u8], d: u32, q: u16, out: &mut [u16; 256]) {
    match d {
        4 => decompress_packed::<4>(data, q, out),
        5 => decompress_packed::<5>(data, q, out),
        10 => decompress_packed::<10>(data, q, out),
        11 => decompress_packed::<11>(data, q, out),
        _ => unreachable!("no ML-KEM ciphertext uses {d} bits"),
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn decompress_packed<const D: i32>(data: &[u8], q: u16, out: &mut [u16; 256]) {
    let size = 2 * D as usize;

    let mut buffer = [0u8; 32 * 11 + 32];

    buffer[..16 * size].copy_from_slice(data);

    let q = _mm256_set1_epi16(q as i16);

    for (i, out) in out.as_chunks_mut::<16>().0.iter_mut().enumerate() {
        let window = buffer[size * i..size * i + 32]
            .try_into()
            .expect("32 bytes");

        let v = unpack::<D>(window);

        let scaled = _mm256_sll_epi16(v, _mm_cvtsi32_si128(15 - D));

        store256(_mm256_mulhrs_epi16(scaled, q), out);
    }
}

// ByteEncode_1(Compress_1(v - w)) for canonical v and w: a bit is set where the difference lies
// between q / 4 and 3q / 4, the values that round to q / 2.
#[target_feature(enable = "avx2")]
pub(super) fn message(v: &[u16; 256], w: &[u16; 256], q: u16, out: &mut [u8; 32]) {
    let qv = _mm256_set1_epi16(q as i16);

    let (low, high) = (
        _mm256_set1_epi16(q as i16 / 4),
        _mm256_set1_epi16(3 * q as i16 / 4 + 1),
    );

    let bit = |i: usize| {
        let x = freeze(
            _mm256_sub_epi16(
                load256(&v.as_chunks::<16>().0[i]),
                load256(&w.as_chunks::<16>().0[i]),
            ),
            qv,
        );

        _mm256_srli_epi16::<15>(_mm256_and_si256(
            _mm256_cmpgt_epi16(x, low),
            _mm256_cmpgt_epi16(high, x),
        ))
    };

    for (i, out) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        *out = message_bits(bit(2 * i), bit(2 * i + 1)).to_le_bytes();
    }
}

// x + q where x is negative: [-3, 3] to [0, q).
#[target_feature(enable = "avx2")]
#[inline]
fn noise_canonical(x: __m256i, q: __m256i) -> __m256i {
    _mm256_add_epi16(x, _mm256_and_si256(q, _mm256_srai_epi16::<15>(x)))
}

// Two vectors of sixteen signed bytes, each half of each vector widened to sixteen words.
#[target_feature(enable = "avx2")]
#[inline]
fn store_noise(bytes: [__m256i; 2], q: __m256i, out: &mut [[u16; 16]]) {
    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut halves = [
        _mm256_castsi256_si128(bytes[0]),
        _mm256_castsi256_si128(bytes[1]),
        _mm256_extracti128_si256::<1>(bytes[0]),
        _mm256_extracti128_si256::<1>(bytes[1]),
    ];

    for (half, out) in halves.into_iter().zip(out) {
        store256(noise_canonical(_mm256_cvtepi8_epi16(half), q), out);
    }

    wipe_unless_optimized!(words_of(&mut halves));
}

// ML-KEM's centered binomial distribution (FIPS 203, Algorithm 8) from the PRF output, given as
// the 64-bit lanes of the sponges in stream order. For eta = 2 each byte gives two coefficients,
// the bit count of its first two bits minus that of the next two, for each half; for eta = 3
// every three bytes give four, from six bits each.
#[target_feature(enable = "avx2")]
pub(super) fn binomial(eta: usize, lanes: &[u64], q: u16, out: &mut [u16; 256]) {
    let q = _mm256_set1_epi16(q as i16);

    let outputs = out.as_chunks_mut::<16>().0;

    if eta == 2 {
        let (alternate, nibble, pair) = (
            _mm256_set1_epi8(0x55),
            _mm256_set1_epi8(0x0F),
            _mm256_set1_epi8(0x03),
        );

        for (chunk, out) in lanes.as_chunks::<4>().0.iter().zip(outputs.chunks_mut(4)) {
            let v = load256(chunk);

            let sums = _mm256_add_epi8(
                _mm256_and_si256(v, alternate),
                _mm256_and_si256(_mm256_srli_epi16::<1>(v), alternate),
            );

            // Each nibble holds a, the count of its low bit pair, and b, that of its high pair.
            let difference = |half: __m256i| {
                _mm256_sub_epi8(
                    _mm256_and_si256(half, pair),
                    _mm256_and_si256(_mm256_srli_epi16::<2>(half), pair),
                )
            };

            let even = difference(_mm256_and_si256(sums, nibble));

            let odd = difference(_mm256_and_si256(_mm256_srli_epi16::<4>(sums), nibble));

            #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
            let mut bytes = [
                _mm256_unpacklo_epi8(even, odd),
                _mm256_unpackhi_epi8(even, odd),
            ];

            store_noise(bytes, q, out);

            wipe_unless_optimized!(words_of(&mut bytes));
        }

        return;
    }

    let spread = _mm256_setr_epi8(
        0, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8, -1, 9, 10, 11, -1, 4, 5, 6, -1, 7, 8, 9, -1, 10, 11, 12,
        -1, 13, 14, 15, -1,
    );

    let ones = _mm256_set1_epi32(0x0024_9249);

    let (three, six) = (_mm256_set1_epi8(0x07), _mm256_set1_epi32(0x3F));

    let mut bytes = [0u8; 192];

    for (bytes, lane) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(lanes) {
        *bytes = lane.to_le_bytes();
    }

    for (group, out) in bytes.as_chunks::<24>().0.iter().zip(outputs.chunks_mut(2)) {
        let x = _mm256_shuffle_epi8(load24(group), spread);

        // Each three-bit field of the 24 bits counts the set bits of that field.
        let counts = _mm256_add_epi32(
            _mm256_add_epi32(
                _mm256_and_si256(x, ones),
                _mm256_and_si256(_mm256_srli_epi32::<1>(x), ones),
            ),
            _mm256_and_si256(_mm256_srli_epi32::<2>(x), ones),
        );

        // The four six-bit fields to the four bytes of each word.
        let fields = _mm256_or_si256(
            _mm256_or_si256(
                _mm256_and_si256(counts, six),
                _mm256_and_si256(_mm256_slli_epi32::<2>(counts), _mm256_slli_epi32::<8>(six)),
            ),
            _mm256_or_si256(
                _mm256_and_si256(_mm256_slli_epi32::<4>(counts), _mm256_slli_epi32::<16>(six)),
                _mm256_and_si256(_mm256_slli_epi32::<6>(counts), _mm256_slli_epi32::<24>(six)),
            ),
        );

        let coefficients = _mm256_sub_epi8(
            _mm256_and_si256(fields, three),
            _mm256_and_si256(_mm256_srli_epi16::<3>(fields), three),
        );

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut halves = [
            _mm256_castsi256_si128(coefficients),
            _mm256_extracti128_si256::<1>(coefficients),
        ];

        for (half, out) in halves.into_iter().zip(out) {
            store256(noise_canonical(_mm256_cvtepi8_epi16(half), q), out);
        }

        wipe_unless_optimized!(words_of(&mut halves));
    }

    crate::wipe::wipe(&mut bytes);
}

// Shuffle indices that bring the accepted lanes of eight 16-bit lanes to the start in order, for
// every pattern of accepted lanes; 0xFF selects zero for the rest.
const fn compaction() -> [[u8; 16]; 256] {
    let mut table = [[0xFF; 16]; 256];

    let mut pattern = 0;

    while pattern < 256 {
        let mut next = 0;

        let mut lane = 0;

        while lane < 8 {
            if pattern & (1 << lane) != 0 {
                table[pattern][2 * next] = 2 * lane as u8;

                table[pattern][2 * next + 1] = 2 * lane as u8 + 1;

                next += 1;
            }

            lane += 1;
        }

        pattern += 1;
    }

    table
}

static COMPACT: [[u8; 16]; 256] = compaction();

// ML-KEM's rejection sampling of the public matrix (FIPS 203, Algorithm 7) on a block of XOF
// output given as the lanes of the Keccak state: sixteen candidates of twelve bits from every 24
// bytes, compared with q side by side; the accepted ones of each half move together through a
// shuffle chosen by their pattern and are stored at the count of values so far, which may write
// slots past it that later values or the end replace. Near the end the candidates go one at a
// time, as in the portable code.
#[target_feature(enable = "avx2")]
pub(super) fn uniform12(lanes: &[u64; 21], q: u16, a: &mut [u16; 256], count: &mut usize) {
    let mut bytes = [0u8; 168];

    for (bytes, lane) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(lanes) {
        *bytes = lane.to_le_bytes();
    }

    let groups = bytes.as_chunks::<24>().0;

    let bound = _mm256_set1_epi16(q as i16);

    let (mut step, mut filled) = (0, *count);

    while step < groups.len() && filled <= 256 - 16 {
        let candidates = unpack12(&groups[step]);

        let accepted = _mm256_cmpgt_epi16(bound, candidates);

        let mask =
            _mm256_movemask_epi8(_mm256_packs_epi16(accepted, _mm256_setzero_si256())) as u32;

        let halves = [
            (_mm256_castsi256_si128(candidates), mask & 0xFF),
            (
                _mm256_extracti128_si256::<1>(candidates),
                (mask >> 16) & 0xFF,
            ),
        ];

        for (values, pattern) in halves {
            let packed = _mm_shuffle_epi8(values, load128(&COMPACT[pattern as usize]));

            let out: &mut [u16; 8] = (&mut a[filled..filled + 8]).try_into().expect("eight");

            store128(packed, out);

            filled += usize::from(ACCEPTED[pattern as usize]);
        }

        step += 1;
    }

    *count = filled;

    for chunk in groups[step..].as_flattened().as_chunks::<3>().0 {
        let d1 = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0F) << 8);

        let d2 = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);

        for candidate in [d1, d2] {
            if *count == 256 {
                return;
            }

            a[*count] = candidate;

            *count += usize::from(candidate < q);
        }
    }
}

// The cache of b for the base multiplication: b[2i + 1] gamma_i mod q, canonical, sixteen at a
// time, the odd coefficients of 32 taken from the high halves of their 32-bit pairs.
#[target_feature(enable = "avx2")]
pub(super) fn multiply_cache(b: &[u16; 256], gammas: &[i16; 128], q: u16, cache: &mut [u16; 128]) {
    let c = constants(q as i16);

    let qinv = _mm256_set1_epi16(c.qinv);

    let pairs = b.as_chunks::<16>().0.as_chunks::<2>().0;

    let groups = gammas.as_chunks::<16>().0;

    for ((out, pair), gammas) in cache
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(pairs)
        .zip(groups)
    {
        let (low, high) = (load256(&pair[0]), load256(&pair[1]));

        let odd = _mm256_packus_epi32(_mm256_srli_epi32::<16>(low), _mm256_srli_epi32::<16>(high));

        let odd = _mm256_permute4x64_epi64::<0xD8>(odd);

        let zeta = load256(gammas);

        let t = Twiddle {
            zeta,
            qinv: _mm256_mullo_epi16(zeta, qinv),
        };

        store256(freeze(montgomery(odd, t, c.q), c.q), out);
    }
}
