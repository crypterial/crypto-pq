// ML-KEM's reduction of the sums of products to canonical coefficients and its 12-bit encoding and
// decoding, with NEON. All compute exactly what the portable code computes, with data-processing
// instructions only.

use core::arch::aarch64::*;

use super::memory::{load_i32, load_u16, load3_bytes, store_u16, store2_u16, store3_u8};
#[cfg(not(crypto_pq_optimized))]
use super::vector_lanes;
use crate::cpu::Field;
use crate::wipe::wipe_unless_optimized;

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

#[allow(unsafe_code)]
pub(crate) fn decode12(data: &[u8; 384], q: u16, out: &mut [u16; 256]) -> bool {
    // SAFETY: as in reduce.
    unsafe { decode12_neon(data, q, out) };

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

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut reduced = [low, high].map(|values| {
            let x = load_i32(values);

            let product = vhsubq_s32(
                vqdmulhq_s32(x, zeta),
                vqdmulhq_s32(vmulq_s32(x, zeta_qinv), q),
            );

            vaddq_s32(product, vandq_s32(q, vshrq_n_s32::<31>(product)))
        });

        let narrow = vcombine_s16(vmovn_s32(reduced[0]), vmovn_s32(reduced[1]));

        store_u16(vreinterpretq_u16_s16(narrow), out);

        wipe_unless_optimized!(vector_lanes(&mut reduced));
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

// ByteDecode_12 followed by the reduction of every value modulo q, sixteen pairs (x, y) at a time:
// the deinterleaving load splits their bytes a, b and c, of which x = a | (b & 15) << 8 and
// y = (b | c << 8) >> 4, and the interleaving store puts each x before its y.
#[target_feature(enable = "neon")]
fn decode12_neon(data: &[u8; 384], q: u16, out: &mut [u16; 256]) {
    let (q, nibble) = (vdupq_n_u16(q), vdupq_n_u8(0x0F));

    // A value of 12 bits is below 2q, so one subtraction reduces it.
    let x = |bytes: uint8x16_t| {
        let x = vreinterpretq_u16_u8(bytes);

        vminq_u16(x, vsubq_u16(x, q))
    };

    let y = |bytes: uint8x16_t| {
        let y = vshrq_n_u16::<4>(vreinterpretq_u16_u8(bytes));

        vminq_u16(y, vsubq_u16(y, q))
    };

    for (out, bytes) in out
        .as_chunks_mut::<32>()
        .0
        .iter_mut()
        .zip(data.as_chunks::<48>().0)
    {
        let [first, second] = out.as_chunks_mut::<16>().0 else {
            unreachable!("32 values are two groups of 16")
        };

        let uint8x16x3_t(a, b, c) = load3_bytes(bytes);

        let low = vandq_u8(b, nibble);

        store2_u16(
            uint16x8x2_t(x(vzip1q_u8(a, low)), y(vzip1q_u8(b, c))),
            first,
        );

        store2_u16(
            uint16x8x2_t(x(vzip2q_u8(a, low)), y(vzip2q_u8(b, c))),
            second,
        );
    }
}
