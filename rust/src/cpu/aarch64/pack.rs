// ML-KEM's reduction of the sums of products to canonical coefficients and its 12-bit encoding,
// with NEON. Both compute exactly what the portable code computes, with data-processing
// instructions only.

use core::arch::aarch64::*;

use super::memory::{load_i32, load_u16, store_u16, store3_u8};
use crate::cpu::Field;

#[allow(unsafe_code)]
pub(crate) fn reduce(w: &[i32; 256], factor: i32, field: &Field, out: &mut [u16; 256]) -> bool {
    // SAFETY: NEON is part of every target this module is built for.
    unsafe { reduce_neon(w, factor, field, out) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn encode12(f: &[u16; 256], out: &mut [u8; 384]) -> bool {
    // SAFETY: as in reduce.
    unsafe { encode12_neon(f, out) };

    true
}

// freeze(montgomery(x, factor)) on 32-bit lanes, as the portable Montgomery product with the
// halving subtraction of the transforms, narrowed to 16 bits.
#[target_feature(enable = "neon")]
fn reduce_neon(w: &[i32; 256], factor: i32, field: &Field, out: &mut [u16; 256]) {
    let (zeta, zeta_qinv) = (
        vdupq_n_s32(factor),
        vdupq_n_s32(factor.wrapping_mul(field.qinv)),
    );

    let q = vdupq_n_s32(field.q);

    for (out, w) in out
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(w.as_chunks::<8>().0)
    {
        let [low, high] = w.as_chunks::<4>().0 else {
            unreachable!("eight values are two groups of four")
        };

        let reduced = [low, high].map(|values| {
            let x = load_i32(values);

            let product = vhsubq_s32(
                vqdmulhq_s32(x, zeta),
                vqdmulhq_s32(vmulq_s32(x, zeta_qinv), q),
            );

            vaddq_s32(product, vandq_s32(q, vshrq_n_s32::<31>(product)))
        });

        let narrow = vcombine_s16(vmovn_s32(reduced[0]), vmovn_s32(reduced[1]));

        store_u16(vreinterpretq_u16_s16(narrow), out);
    }
}

// Sixteen coefficients of 12 bits into 24 bytes: the pairs (x, y) make the bytes x, x >> 8 | y << 4
// and y >> 4, which the interleaving store puts in order.
#[target_feature(enable = "neon")]
fn encode12_neon(f: &[u16; 256], out: &mut [u8; 384]) {
    for (out, f) in out
        .as_chunks_mut::<24>()
        .0
        .iter_mut()
        .zip(f.as_chunks::<16>().0)
    {
        let [low, high] = f.as_chunks::<8>().0 else {
            unreachable!("sixteen values are two groups of eight")
        };

        let (low, high) = (load_u16(low), load_u16(high));

        let (x, y) = (vuzp1q_u16(low, high), vuzp2q_u16(low, high));

        let bytes = uint8x8x3_t(
            vmovn_u16(x),
            vmovn_u16(vorrq_u16(vshrq_n_u16::<8>(x), vshlq_n_u16::<4>(y))),
            vmovn_u16(vshrq_n_u16::<4>(y)),
        );

        store3_u8(bytes, out);
    }
}
