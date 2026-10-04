// ML-KEM's centered binomial distribution for eta = 2 (FIPS 203, Algorithm 8) on sixteen bytes at
// a time: each byte gives two coefficients, the bit count of its first two bits minus that of the
// next two, for each half. The noise is secret; every step is a data-processing instruction on
// Arm's data-independent-timing list, with no branch or address that depends on it. eta = 3
// stays with the portable code.

use core::arch::aarch64::*;

#[allow(unsafe_code)]
pub(crate) fn binomial(eta: usize, bytes: &[u8], q: u16, out: &mut [u16; 256]) -> bool {
    let Ok(bytes) = <&[u8; 128]>::try_from(bytes) else {
        return false;
    };

    if eta != 2 {
        return false;
    }

    // SAFETY: NEON is part of every target this module is built for.
    unsafe { binomial2(bytes, q, out) };

    true
}

#[target_feature(enable = "neon")]
fn binomial2(bytes: &[u8; 128], q: u16, out: &mut [u16; 256]) {
    let (alternate, nibble, pair) = (vdupq_n_u8(0x55), vdupq_n_u8(0x0F), vdupq_n_u8(0x03));

    let q = vdupq_n_s16(q as i16);

    for (chunk, out) in bytes
        .as_chunks::<16>()
        .0
        .iter()
        .zip(out.as_chunks_mut::<32>().0)
    {
        let [low, high] = chunk.as_chunks::<8>().0 else {
            unreachable!("sixteen bytes are two groups of eight")
        };

        let v = vcombine_u8(
            vcreate_u8(u64::from_le_bytes(*low)),
            vcreate_u8(u64::from_le_bytes(*high)),
        );

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
            let canonical = vreinterpretq_u64_s16(vaddq_s16(x, vandq_s16(q, vshrq_n_s16::<15>(x))));

            let words = [
                vgetq_lane_u64::<0>(canonical),
                vgetq_lane_u64::<1>(canonical),
            ];

            *out = core::array::from_fn(|i| (words[i / 4] >> (16 * (i % 4))) as u16);
        }
    }
}
