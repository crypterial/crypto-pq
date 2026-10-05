// ML-DSA's coefficient-wise steps of signing with NEON, value for value what the portable code
// computes: sums and differences modulo q, the norm checks, the hints, Decompose with the
// encoding of w1, and the expansion of the mask. All of them work on secret values with
// data-processing instructions only; the checks return their outcome as a mask, which the caller
// declassifies only as the decision to restart.

use core::arch::aarch64::*;

use super::memory::{load_i32, load_u8, store_i32, store_u8};

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

// HighBits of every coefficient packed in four bits, for gamma2 = (q - 1) / 32.
#[allow(unsafe_code)]
pub(crate) fn encode_w1(out: &mut [u8], w: &[i32; 256], gamma2: i32, q: i32) -> bool {
    let Ok(out) = <&mut [u8; 128]>::try_from(out) else {
        return false;
    };

    if gamma2 != (q - 1) / 32 {
        return false;
    }

    // SAFETY: as in add.
    unsafe { encode_w1_neon(out, w, gamma2, q) };

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

// Thirty-two values of four bits into sixteen bytes, the first of each pair in the low half.
#[target_feature(enable = "neon")]
fn encode_w1_neon(out: &mut [u8; 128], w: &[i32; 256], gamma2: i32, q: i32) {
    for (out, w) in out
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(w.as_chunks::<32>().0)
    {
        let mut narrow = [vdupq_n_u8(0); 2];

        for (narrow, w) in narrow.iter_mut().zip(w.as_chunks::<16>().0) {
            let [a, b, c, d] = w.as_chunks::<4>().0 else {
                unreachable!("sixteen values are four groups of four")
            };

            let high = [a, b, c, d]
                .map(|values| vreinterpretq_u32_s32(decompose(load_i32(values), gamma2, q).0));

            let halves = [
                vcombine_u16(vmovn_u32(high[0]), vmovn_u32(high[1])),
                vcombine_u16(vmovn_u32(high[2]), vmovn_u32(high[3])),
            ];

            *narrow = vcombine_u8(vmovn_u16(halves[0]), vmovn_u16(halves[1]));
        }

        // Each 16-bit lane holds a value x in its low byte and y in its high byte, both below 16:
        // x | y << 4 is the lane ORed with itself shifted right by four, in its low byte.
        let pairs = narrow.map(|bytes| {
            let lanes = vreinterpretq_u16_u8(bytes);

            vmovn_u16(vorrq_u16(lanes, vshrq_n_u16::<4>(lanes)))
        });

        store_u8(vcombine_u8(pairs[0], pairs[1]), out);
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
