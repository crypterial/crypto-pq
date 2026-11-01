// FrodoKEM's products of eight rows of the public matrix A with the secret matrices, with NEON.
// Arithmetic is modulo 2^16, the wrapping arithmetic of 16-bit lanes, so the kernels compute
// exactly what the portable code computes, with multiply-accumulates by a vector lane and loads
// from addresses that depend only on n.

use core::arch::aarch64::*;

use super::memory::{load_u16, store_u16};
#[cfg(not(crypto_pq_optimized))]
use super::vector_lanes;
use crate::wipe::wipe_unless_optimized;

#[allow(unsafe_code)]
pub(crate) fn mul_add_as(acc: &mut [[u16; 8]; 8], rows: &[u16], s: &[u16], n: usize) -> bool {
    if !n.is_multiple_of(8) || rows.len() != 8 * n || s.len() != 8 * n {
        return false;
    }

    // SAFETY: NEON is part of every target this module is built for.
    unsafe { mul_add_as_neon(acc, rows, s, n) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn mul_add_sa(acc: &mut [u16], rows: &[u16], column: &[[u16; 8]; 8], n: usize) -> bool {
    if !n.is_multiple_of(8) || rows.len() != 8 * n || acc.len() != 8 * n {
        return false;
    }

    // SAFETY: as in mul_add_as.
    unsafe { mul_add_sa_neon(acc, rows, column, n) };

    true
}

// Row r of acc += sum over j of A[r][j] S[j]: S[j] is a vector of n̄ entries, and A[r][j] a lane
// of the vector of eight entries of row r. Each row keeps two sums, of the even and of the odd
// columns, so that sixteen chains of multiply-accumulates run side by side.
#[target_feature(enable = "neon")]
fn mul_add_as_neon(acc: &mut [[u16; 8]; 8], rows: &[u16], s: &[u16], n: usize) {
    let blocks = n / 8;

    let (rows, _) = rows.as_chunks::<8>();

    let rows: [&[[u16; 8]]; 8] = core::array::from_fn(|r| &rows[r * blocks..(r + 1) * blocks]);

    let (s, _) = s.as_chunks::<8>();

    let (s, _) = s.as_chunks::<8>();

    let mut even = [vdupq_n_u16(0); 8];

    let mut odd = [vdupq_n_u16(0); 8];

    for (b, s) in s.iter().enumerate() {
        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut s: [uint16x8_t; 8] = core::array::from_fn(|m| load_u16(&s[m]));

        for r in 0..8 {
            let a = load_u16(&rows[r][b]);

            even[r] = vmlaq_laneq_u16::<0>(even[r], s[0], a);

            odd[r] = vmlaq_laneq_u16::<1>(odd[r], s[1], a);

            even[r] = vmlaq_laneq_u16::<2>(even[r], s[2], a);

            odd[r] = vmlaq_laneq_u16::<3>(odd[r], s[3], a);

            even[r] = vmlaq_laneq_u16::<4>(even[r], s[4], a);

            odd[r] = vmlaq_laneq_u16::<5>(odd[r], s[5], a);

            even[r] = vmlaq_laneq_u16::<6>(even[r], s[6], a);

            odd[r] = vmlaq_laneq_u16::<7>(odd[r], s[7], a);
        }

        wipe_unless_optimized!(vector_lanes(&mut s));
    }

    for (r, acc) in acc.iter_mut().enumerate() {
        store_u16(vaddq_u16(load_u16(acc), vaddq_u16(even[r], odd[r])), acc);
    }

    wipe_unless_optimized!(vector_lanes(&mut odd));

    wipe_unless_optimized!(vector_lanes(&mut even));
}

// Row k of acc += sum over r of S'[k][i0 + r] A[i0 + r]: the n̄ entries of S'^T for row r of A are
// one vector, and S'[k][i0 + r] is its lane k. Eight entries of each of the eight rows of A are
// loaded once and serve the eight rows of acc.
#[target_feature(enable = "neon")]
fn mul_add_sa_neon(acc: &mut [u16], rows: &[u16], column: &[[u16; 8]; 8], n: usize) {
    let blocks = n / 8;

    let (rows, _) = rows.as_chunks::<8>();

    let rows: [&[[u16; 8]]; 8] = core::array::from_fn(|r| &rows[r * blocks..(r + 1) * blocks]);

    let (acc, _) = acc.as_chunks_mut::<8>();

    let mut acc = acc.chunks_exact_mut(blocks);

    let out: [&mut [[u16; 8]]; 8] =
        core::array::from_fn(|_| acc.next().expect("n̄ rows of n entries"));

    let c: [uint16x8_t; 8] = core::array::from_fn(|r| load_u16(&column[r]));

    for b in 0..blocks {
        let a: [uint16x8_t; 8] = core::array::from_fn(|r| load_u16(&rows[r][b]));

        accumulate::<0>(&mut out[0][b], &a, &c);

        accumulate::<1>(&mut out[1][b], &a, &c);

        accumulate::<2>(&mut out[2][b], &a, &c);

        accumulate::<3>(&mut out[3][b], &a, &c);

        accumulate::<4>(&mut out[4][b], &a, &c);

        accumulate::<5>(&mut out[5][b], &a, &c);

        accumulate::<6>(&mut out[6][b], &a, &c);

        accumulate::<7>(&mut out[7][b], &a, &c);
    }
}

// out += sum over r of c[r][K] a[r], in two chains of four.
#[target_feature(enable = "neon")]
#[inline]
fn accumulate<const K: i32>(out: &mut [u16; 8], a: &[uint16x8_t; 8], c: &[uint16x8_t; 8]) {
    let mut x = load_u16(out);

    let mut y = vmulq_laneq_u16::<K>(a[1], c[1]);

    x = vmlaq_laneq_u16::<K>(x, a[0], c[0]);

    x = vmlaq_laneq_u16::<K>(x, a[2], c[2]);

    y = vmlaq_laneq_u16::<K>(y, a[3], c[3]);

    x = vmlaq_laneq_u16::<K>(x, a[4], c[4]);

    y = vmlaq_laneq_u16::<K>(y, a[5], c[5]);

    x = vmlaq_laneq_u16::<K>(x, a[6], c[6]);

    y = vmlaq_laneq_u16::<K>(y, a[7], c[7]);

    store_u16(vaddq_u16(x, y), out);
}
