// FrodoKEM's products of eight rows of the public matrix A with the secret matrices, with AVX2.
// Arithmetic is modulo 2^16, the wrapping arithmetic of 16-bit lanes, so the kernels compute
// exactly what the portable code computes, with VPMULLW, VPADDW and VPHADDW and loads from
// addresses that depend only on n.

use core::arch::x86_64::*;

use super::memory::{load128, load256, store128, store256};

// Rows r and r + 1 of acc += the products of those rows of A with the n̄ rows of S^T, which the
// private key holds as little-endian 16-bit values: sixteen products per row of S^T at a time,
// summed lane by lane and the lanes at the end. Two rows of A share each load of S^T, and four
// rows of S^T at a time keep the sums in registers.
#[target_feature(enable = "avx2")]
pub(super) fn mul_add_as(acc: &mut [[u16; 8]; 8], rows: &[u16], st: &[u8], n: usize) {
    let blocks = n / 16;

    let (rows, _) = rows.as_chunks::<16>();

    let (st, _) = st.as_chunks::<32>();

    let st: [&[[u8; 32]]; 8] = core::array::from_fn(|k| &st[k * blocks..(k + 1) * blocks]);

    for (acc, rows) in acc
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(rows.chunks_exact(2 * blocks))
    {
        let (first, second) = rows.split_at(blocks);

        let mut halves = [[_mm_setzero_si128(); 2]; 2];

        for (h, st) in st.as_chunks::<4>().0.iter().enumerate() {
            let mut sums = [[_mm256_setzero_si256(); 4]; 2];

            for (b, (x, y)) in first.iter().zip(second).enumerate() {
                let a = [load256(x), load256(y)];

                for (k, st) in st.iter().enumerate() {
                    let s = load256(&st[b]);

                    for (sums, a) in sums.iter_mut().zip(a) {
                        sums[k] = _mm256_add_epi16(sums[k], _mm256_mullo_epi16(a, s));
                    }
                }
            }

            for (half, sums) in halves.iter_mut().zip(sums) {
                half[h] = total4(sums);
            }
        }

        for (acc, half) in acc.iter_mut().zip(halves) {
            let total = _mm_unpacklo_epi64(half[0], half[1]);

            store128(_mm_add_epi16(load128(acc), total), acc);
        }
    }
}

// The sums of the sixteen lanes of each of four vectors, in lanes 0 to 3: pairs, fours and eights
// of lanes in each half, then the two halves.
#[target_feature(enable = "avx2")]
#[inline]
fn total4(sums: [__m256i; 4]) -> __m128i {
    let pairs = [
        _mm256_hadd_epi16(sums[0], sums[1]),
        _mm256_hadd_epi16(sums[2], sums[3]),
    ];

    let fours = _mm256_hadd_epi16(pairs[0], pairs[1]);

    let eights = _mm256_hadd_epi16(fours, fours);

    _mm_add_epi16(
        _mm256_castsi256_si128(eights),
        _mm256_extracti128_si256::<1>(eights),
    )
}

// Rows k and k + 1 of acc += sum over r of S'[k][i0 + r] A[i0 + r], sixteen entries at a time,
// over four rows of A at a time: eight broadcast factors, and each load of A serves two rows of
// acc.
#[target_feature(enable = "avx2")]
pub(super) fn mul_add_sa(acc: &mut [u16], rows: &[u16], column: &[[u16; 8]; 8], n: usize) {
    let blocks = n / 16;

    let (rows, _) = rows.as_chunks::<16>();

    let rows: [&[[u16; 16]]; 8] = core::array::from_fn(|r| &rows[r * blocks..(r + 1) * blocks]);

    let (acc, _) = acc.as_chunks_mut::<16>();

    for (p, acc) in acc.chunks_exact_mut(2 * blocks).enumerate() {
        let (first, second) = acc.split_at_mut(blocks);

        for (h, rows) in rows.as_chunks::<4>().0.iter().enumerate() {
            let c: [[__m256i; 4]; 2] = core::array::from_fn(|i| {
                core::array::from_fn(|r| _mm256_set1_epi16(column[4 * h + r][2 * p + i] as i16))
            });

            for (b, (x, y)) in first.iter_mut().zip(second.iter_mut()).enumerate() {
                let a: [__m256i; 4] = core::array::from_fn(|r| load256(&rows[r][b]));

                let sum = |c: &[__m256i; 4]| {
                    _mm256_add_epi16(
                        _mm256_add_epi16(
                            _mm256_mullo_epi16(c[0], a[0]),
                            _mm256_mullo_epi16(c[1], a[1]),
                        ),
                        _mm256_add_epi16(
                            _mm256_mullo_epi16(c[2], a[2]),
                            _mm256_mullo_epi16(c[3], a[3]),
                        ),
                    )
                };

                store256(_mm256_add_epi16(load256(x), sum(&c[0])), x);

                store256(_mm256_add_epi16(load256(y), sum(&c[1])), y);
            }
        }
    }
}
