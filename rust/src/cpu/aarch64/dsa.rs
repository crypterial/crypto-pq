// ML-DSA's coefficient-wise steps of signing with NEON, value for value what the portable code
// computes: sums and differences modulo q, the norm checks, the hints, Decompose with the
// encoding of w1, and the expansion of the mask. All of them work on secret values with
// data-processing instructions only; the checks return their outcome as a mask, which the caller
// declassifies only as the decision to restart.

use core::arch::aarch64::*;

use super::memory::{load_i32, load_u8, store_i32, store_u8};
#[cfg(not(crypto_pq_optimized))]
use super::vector_lanes;
use crate::wipe::wipe_unless_optimized;

#[allow(unsafe_code)]
pub(crate) fn add(out: &mut [i32; 256], a: &[i32; 256], b: &[i32; 256], q: i32) -> bool {
    // SAFETY: NEON is part of every target this module is built for.
    unsafe { combine::<true>(out, a, b, q) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn sub(out: &mut [i32; 256], a: &[i32; 256], b: &[i32; 256], q: i32) -> bool {
    // SAFETY: as in add.
    unsafe { combine::<false>(out, a, b, q) };

    true
}

// -1 when some value reaches the bound in absolute value: the centered coefficients, or with
// gamma2 the low bits of Decompose; 0 otherwise.
#[allow(unsafe_code)]
pub(crate) fn norm(values: &[i32; 256], bound: i32, gamma2: Option<i32>, q: i32) -> Option<i32> {
    // SAFETY: as in add.
    Some(unsafe { norm_neon(values, bound, gamma2, q) })
}

// The hints of r and ct0 (FIPS 204, Algorithm 39 on r + ct0 and r), one per coefficient, and how
// many are set.
#[allow(unsafe_code)]
pub(crate) fn hints(
    h: &mut [i32; 256],
    r: &[i32; 256],
    ct0: &[i32; 256],
    gamma2: i32,
    q: i32,
) -> Option<i32> {
    // SAFETY: as in add.
    Some(unsafe { hints_neon(h, r, ct0, gamma2, q) })
}

// HighBits of every coefficient packed in four bits, for gamma2 = (q - 1) / 32; with hints, the
// values UseHint gives.
#[allow(unsafe_code)]
pub(crate) fn encode_w1(
    out: &mut [u8],
    w: &[i32; 256],
    hints: Option<&[bool; 256]>,
    gamma2: i32,
    q: i32,
) -> bool {
    let Ok(out) = <&mut [u8; 128]>::try_from(out) else {
        return false;
    };

    if gamma2 != (q - 1) / 32 {
        return false;
    }

    // SAFETY: as in add.
    unsafe {
        match hints {
            Some(hints) => encode_w1_neon::<true>(out, w, hints, gamma2, q),
            None => encode_w1_neon::<false>(out, w, &[false; 256], gamma2, q),
        }
    }

    true
}

// gamma1 - x modulo q for the mask's values x of 18 or 20 bits.
#[allow(unsafe_code)]
pub(crate) fn unpack_mask(
    out: &mut [i32; 256],
    bytes: &[u8],
    bits: u32,
    gamma1: i32,
    q: i32,
) -> bool {
    match (bits, bytes.len()) {
        (18, 576) => {
            // SAFETY: as in add.
            unsafe { unpack_mask_neon::<18, 9>(out, bytes, gamma1, q) };
        }
        (20, 640) => {
            // SAFETY: as in add.
            unsafe { unpack_mask_neon::<20, 10>(out, bytes, gamma1, q) };
        }
        _ => return false,
    }

    true
}

// (-q, q) to [0, q).
#[target_feature(enable = "neon")]
#[inline]
fn freeze(x: int32x4_t, q: int32x4_t) -> int32x4_t {
    vaddq_s32(x, vandq_s32(q, vshrq_n_s32::<31>(x)))
}

#[target_feature(enable = "neon")]
fn combine<const ADD: bool>(out: &mut [i32; 256], a: &[i32; 256], b: &[i32; 256], q: i32) {
    let q = vdupq_n_s32(q);

    let operands = a.as_chunks::<4>().0.iter().zip(b.as_chunks::<4>().0);

    for (out, (a, b)) in out.as_chunks_mut::<4>().0.iter_mut().zip(operands) {
        let (a, b) = (load_i32(a), load_i32(b));

        let x = if ADD {
            vsubq_s32(vaddq_s32(a, b), q)
        } else {
            vsubq_s32(a, b)
        };

        store_i32(freeze(x, q), out);
    }
}

// FIPS 204, Algorithm 36, branch-free as decompose in mldsa.rs: (r1, r0) for r in [0, q).
#[target_feature(enable = "neon")]
#[inline]
fn decompose(r: int32x4_t, gamma2: i32, q: i32) -> (int32x4_t, int32x4_t) {
    let r1 = vshrq_n_s32::<7>(vaddq_s32(r, vdupq_n_s32(127)));

    let r1 = if gamma2 == (q - 1) / 32 {
        let r1 = vmlaq_s32(vdupq_n_s32(1 << 21), r1, vdupq_n_s32(1025));

        vandq_s32(vshrq_n_s32::<22>(r1), vdupq_n_s32(15))
    } else {
        let r1 = vshrq_n_s32::<24>(vmlaq_s32(vdupq_n_s32(1 << 23), r1, vdupq_n_s32(11275)));

        veorq_s32(
            r1,
            vandq_s32(vshrq_n_s32::<31>(vsubq_s32(vdupq_n_s32(43), r1)), r1),
        )
    };

    let r0 = vmlsq_s32(r, r1, vdupq_n_s32(2 * gamma2));

    let wrap = vshrq_n_s32::<31>(vsubq_s32(vdupq_n_s32((q - 1) / 2), r0));

    (r1, vsubq_s32(r0, vandq_s32(wrap, vdupq_n_s32(q))))
}

#[target_feature(enable = "neon")]
fn norm_neon(values: &[i32; 256], bound: i32, gamma2: Option<i32>, q: i32) -> i32 {
    let (limit, qv, half) = (
        vdupq_n_s32(bound - 1),
        vdupq_n_s32(q),
        vdupq_n_s32((q - 1) / 2),
    );

    let mut flags = vdupq_n_s32(0);

    for values in values.as_chunks::<4>().0 {
        let x = load_i32(values);

        let value = match gamma2 {
            Some(gamma2) => decompose(x, gamma2, q).1,
            None => vsubq_s32(x, vandq_s32(qv, vshrq_n_s32::<31>(vsubq_s32(half, x)))),
        };

        let reached = vshrq_n_s32::<31>(vsubq_s32(limit, vabsq_s32(value)));

        flags = vorrq_s32(flags, reached);
    }

    vminvq_s32(flags)
}

#[target_feature(enable = "neon")]
fn hints_neon(h: &mut [i32; 256], r: &[i32; 256], ct0: &[i32; 256], gamma2: i32, q: i32) -> i32 {
    let qv = vdupq_n_s32(q);

    let mut count = vdupq_n_s32(0);

    let operands = r.as_chunks::<4>().0.iter().zip(ct0.as_chunks::<4>().0);

    for (h, (r, c)) in h.as_chunks_mut::<4>().0.iter_mut().zip(operands) {
        let (x, c) = (load_i32(r), load_i32(c));

        let sum = freeze(vsubq_s32(vaddq_s32(x, c), qv), qv);

        let same = vceqq_s32(decompose(sum, gamma2, q).0, decompose(x, gamma2, q).0);

        let bits = vreinterpretq_s32_u32(vshrq_n_u32::<31>(vmvnq_u32(same)));

        store_i32(bits, h);

        count = vaddq_s32(count, bits);
    }

    vaddvq_s32(count)
}

// UseHint (FIPS 204 Algorithm 40) for gamma2 = (q - 1) / 32, from HighBits r1, LowBits r0 and
// hints h of 0 or 1: r1 + 1 where h is set and r0 > 0, r1 - 1 where it is set and r0 <= 0, modulo
// 16. Only verification gives hints, and its values are public.
#[target_feature(enable = "neon")]
#[inline]
fn hinted(r1: int32x4_t, r0: int32x4_t, h: int32x4_t) -> int32x4_t {
    // -1 where r0 <= 0: h ^ -1 minus -1 is -h.
    let down = vreinterpretq_s32_u32(vclezq_s32(r0));

    let delta = vsubq_s32(veorq_s32(h, down), down);

    vandq_s32(vaddq_s32(r1, delta), vdupq_n_s32(15))
}

// Thirty-two values of four bits into sixteen bytes, the first of each pair in the low half; with
// HINT, the values UseHint gives.
#[target_feature(enable = "neon")]
fn encode_w1_neon<const HINT: bool>(
    out: &mut [u8; 128],
    w: &[i32; 256],
    hints: &[bool; 256],
    gamma2: i32,
    q: i32,
) {
    let groups = w.as_chunks::<32>().0.iter().zip(hints.as_chunks::<32>().0);

    for (out, (w, h)) in out.as_chunks_mut::<16>().0.iter_mut().zip(groups) {
        let mut narrow = [vdupq_n_u8(0); 2];

        let halves = w.as_chunks::<16>().0.iter().zip(h.as_chunks::<16>().0);

        for (narrow, (w, h)) in narrow.iter_mut().zip(halves) {
            let [a, b, c, d] = w.as_chunks::<4>().0 else {
                unreachable!("sixteen values are four groups of four")
            };

            // The sixteen hints in 32-bit lanes, four per vector.
            let h = load_u8(&h.map(u8::from));

            let h = [vmovl_u8(vget_low_u8(h)), vmovl_u8(vget_high_u8(h))];

            #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
            let mut h = [
                vmovl_u16(vget_low_u16(h[0])),
                vmovl_u16(vget_high_u16(h[0])),
                vmovl_u16(vget_low_u16(h[1])),
                vmovl_u16(vget_high_u16(h[1])),
            ];

            let values = [a, b, c, d];

            let r1 = |i: usize| {
                let (r1, r0) = decompose(load_i32(values[i]), gamma2, q);

                let r1 = if HINT {
                    hinted(r1, r0, vreinterpretq_s32_u32(h[i]))
                } else {
                    r1
                };

                vreinterpretq_u32_s32(r1)
            };

            // Built and indexed with constants only, so that no array helper holds them (D-76).
            #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
            let mut high = [r1(0), r1(1), r1(2), r1(3)];

            #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
            let mut halves = [
                vcombine_u16(vmovn_u32(high[0]), vmovn_u32(high[1])),
                vcombine_u16(vmovn_u32(high[2]), vmovn_u32(high[3])),
            ];

            *narrow = vcombine_u8(vmovn_u16(halves[0]), vmovn_u16(halves[1]));

            wipe_unless_optimized!(vector_lanes(&mut halves));

            wipe_unless_optimized!(vector_lanes(&mut high));

            wipe_unless_optimized!(vector_lanes(&mut h));
        }

        // Each 16-bit lane holds a value x in its low byte and y in its high byte, both below 16:
        // x | y << 4 is the lane ORed with itself shifted right by four, in its low byte.
        let pair = |bytes: uint8x16_t| {
            let lanes = vreinterpretq_u16_u8(bytes);

            vmovn_u16(vorrq_u16(lanes, vshrq_n_u16::<4>(lanes)))
        };

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut pairs = [pair(narrow[0]), pair(narrow[1])];

        store_u8(vcombine_u8(pairs[0], pairs[1]), out);

        wipe_unless_optimized!(vector_lanes(&mut pairs));

        wipe_unless_optimized!(vector_lanes(&mut narrow));
    }
}

// Four values of BITS bits from each BYTES bytes: a shuffle gives each value the three bytes it
// spans, a shift by (BITS * i) % 8 and a mask take its bits. Every sixteen-byte load covers
// two groups; the last one starts early enough to stay in the input and shifts its indices.
#[target_feature(enable = "neon")]
fn unpack_mask_neon<const BITS: usize, const BYTES: usize>(
    out: &mut [i32; 256],
    bytes: &[u8],
    gamma1: i32,
    q: i32,
) {
    let mut indices = [0u8; 16];

    let mut shifts = [0i32; 4];

    for i in 0..4 {
        let first = BITS * i / 8;

        for j in 0..3 {
            indices[4 * i + j] = (first + j) as u8;
        }

        indices[4 * i + 3] = 0xFF;

        shifts[i] = -((BITS * i % 8) as i32);
    }

    let last = bytes.len() - 16;

    let late = (BYTES * 63 - last) as u8;

    let indices = [
        load_u8(&indices),
        load_u8(&indices.map(|i| i.saturating_add(late))),
    ];

    let (shifts, mask) = (load_i32(&shifts), vdupq_n_u32((1 << BITS) - 1));

    let (gamma1, qv) = (vdupq_n_s32(gamma1), vdupq_n_s32(q));

    for (group, out) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let start = (BYTES * group).min(last);

        let window = load_u8(bytes[start..start + 16].try_into().expect("sixteen bytes"));

        let picked = vqtbl1q_u8(window, indices[usize::from(start == last)]);

        let values = vandq_u32(vshlq_u32(vreinterpretq_u32_u8(picked), shifts), mask);

        let x = vsubq_s32(gamma1, vreinterpretq_s32_u32(values));

        store_i32(freeze(x, qv), out);
    }
}
