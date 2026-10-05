// ML-KEM's centered binomial distribution (FIPS 203, Algorithm 8). For eta = 2 each byte gives two
// coefficients, the bit count of its first two bits minus that of the next two, for each half;
// for eta = 3 every three bytes give four, from six bits each. The noise is secret; every step is
// a data-processing instruction on Arm's data-independent-timing list, with no branch or address
// that depends on it.

use core::arch::aarch64::*;

use super::memory::{load_u64, load3_u8, store_u16};

// The PRF output is given as the 64-bit lanes of the sponges, in stream order.
#[allow(unsafe_code)]
pub(crate) fn binomial(eta: usize, lanes: &[u64], q: u16, out: &mut [u16; 256]) -> bool {
    match (eta, lanes.len()) {
        // SAFETY: NEON is part of every target this module is built for.
        (2, 16) => unsafe { binomial2(lanes.try_into().expect("16 lanes"), q, out) },
        // SAFETY: as above.
        (3, 24) => unsafe { binomial3(lanes.try_into().expect("24 lanes"), q, out) },
        _ => return false,
    }

    true
}

#[target_feature(enable = "neon")]
fn binomial2(lanes: &[u64; 16], q: u16, out: &mut [u16; 256]) {
    let (alternate, nibble, pair) = (vdupq_n_u8(0x55), vdupq_n_u8(0x0F), vdupq_n_u8(0x03));

    let q = vdupq_n_s16(q as i16);

    for (chunk, out) in lanes
        .as_chunks::<2>()
        .0
        .iter()
        .zip(out.as_chunks_mut::<32>().0)
    {
        let v = vreinterpretq_u8_u64(load_u64(chunk));

        // Two-bit sums of adjacent bits: each nibble holds a, the count of its low bit pair, and
        // b, that of its high pair; the coefficient is a - b.
        let sums = vaddq_u8(
            vandq_u8(v, alternate),
            vandq_u8(vshrq_n_u8::<1>(v), alternate),
        );

        let difference = |half: uint8x16_t| {
            vsubq_s8(
                vreinterpretq_s8_u8(vandq_u8(half, pair)),
                vreinterpretq_s8_u8(vshrq_n_u8::<2>(half)),
            )
        };

        let even = difference(vandq_u8(sums, nibble));

        let odd = difference(vshrq_n_u8::<4>(sums));

        let (first, second) = (vzip1q_s8(even, odd), vzip2q_s8(even, odd));

        let wide = [
            vmovl_s8(vget_low_s8(first)),
            vmovl_high_s8(first),
            vmovl_s8(vget_low_s8(second)),
            vmovl_high_s8(second),
        ];

        for (x, out) in wide.into_iter().zip(out.as_chunks_mut::<8>().0) {
            // [-2, 2] to [0, q): q is added to the negative ones.
            let canonical = vaddq_s16(x, vandq_s16(q, vshrq_n_s16::<15>(x)));

            store_u16(vreinterpretq_u16_s16(canonical), out);
        }
    }
}

// Sixteen groups of three bytes at a time, deinterleaved by the load into the first, second and
// third bytes of every group: the four six-bit fields of a group are its coefficients, each the
// bit count of its low three bits minus that of its high three.
#[target_feature(enable = "neon")]
fn binomial3(lanes: &[u64; 24], q: u16, out: &mut [u16; 256]) {
    let q = vdupq_n_s16(q as i16);

    let (low, six) = (vdupq_n_u8(7), vdupq_n_u8(0x3F));

    for (chunk, out) in lanes
        .as_chunks::<6>()
        .0
        .iter()
        .zip(out.as_chunks_mut::<64>().0)
    {
        let uint8x16x3_t(b0, b1, b2) = load3_u8(chunk);

        let fields = [
            vandq_u8(b0, six),
            vorrq_u8(
                vshrq_n_u8::<6>(b0),
                vshlq_n_u8::<2>(vandq_u8(b1, vdupq_n_u8(0x0F))),
            ),
            vorrq_u8(
                vshrq_n_u8::<4>(b1),
                vshlq_n_u8::<4>(vandq_u8(b2, vdupq_n_u8(0x03))),
            ),
            vshrq_n_u8::<2>(b2),
        ];

        let [c0, c1, c2, c3] = fields.map(|field| {
            vsubq_s8(
                vreinterpretq_s8_u8(vcntq_u8(vandq_u8(field, low))),
                vreinterpretq_s8_u8(vcntq_u8(vshrq_n_u8::<3>(field))),
            )
        });

        // Coefficient 4k + i is field i of group k.
        let (first, second) = (vzip1q_s8(c0, c1), vzip2q_s8(c0, c1));

        let (third, fourth) = (vzip1q_s8(c2, c3), vzip2q_s8(c2, c3));

        let pairs = |x: int8x16_t, y: int8x16_t| {
            let (x, y) = (vreinterpretq_s16_s8(x), vreinterpretq_s16_s8(y));

            (
                vreinterpretq_s8_s16(vzip1q_s16(x, y)),
                vreinterpretq_s8_s16(vzip2q_s16(x, y)),
            )
        };

        let (g0, g1) = pairs(first, third);

        let (g2, g3) = pairs(second, fourth);

        for (group, out) in [g0, g1, g2, g3]
            .into_iter()
            .zip(out.as_chunks_mut::<16>().0)
        {
            let [low_out, high_out] = out.as_chunks_mut::<8>().0 else {
                unreachable!("sixteen values are two groups of eight")
            };

            for (x, out) in [vmovl_s8(vget_low_s8(group)), vmovl_high_s8(group)]
                .into_iter()
                .zip([low_out, high_out])
            {
                // [-3, 3] to [0, q): q is added to the negative ones.
                let canonical = vaddq_s16(x, vandq_s16(q, vshrq_n_s16::<15>(x)));

                store_u16(vreinterpretq_u16_s16(canonical), out);
            }
        }
    }
}
