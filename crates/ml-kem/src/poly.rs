//! Polynomial helpers: vector arithmetic, Compress/Decompress and ByteEncode/ByteDecode
//! (FIPS 203, sections 4.2.1 and 4.2.2).

use crate::field::{add, csub, sub, Poly, N, Q};

pub(crate) fn add_assign(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a[i] = add(a[i], b[i]);
    }
}

pub(crate) fn sub_assign(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a[i] = sub(a[i], b[i]);
    }
}

/// floor(t / q) for t < 2^25, as a multiply and a shift. 41285358 = ceil(2^37 / q); the
/// rounding error stays below 1/q over the whole range (checked exhaustively in tests).
#[inline(always)]
fn div_q(t: u32) -> u32 {
    debug_assert!(t < 1 << 25);
    ((t as u64 * 41285358) >> 37) as u32
}

/// Compress_d(x) = round(2^d x / q) mod 2^d, for x in [0, q) and 1 <= d <= 11.
#[inline(always)]
pub(crate) fn compress(d: usize, x: u16) -> u16 {
    let t = ((x as u32) << d) + (Q as u32 - 1) / 2;
    (div_q(t) & ((1 << d) - 1)) as u16
}

/// Decompress_d(y) = round(q y / 2^d), for y < 2^d.
#[inline(always)]
pub(crate) fn decompress(d: usize, y: u16) -> u16 {
    (((y as u32) * Q as u32 + (1 << (d - 1))) >> d) as u16
}

/// ByteEncode_d: packs 256 d-bit values little-endian into 32 d bytes.
pub(crate) fn byte_encode(d: usize, f: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d);
    let mask = (1u32 << d) - 1;
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut idx = 0;
    for &c in f.iter() {
        acc |= (c as u32 & mask) << bits;
        bits += d;
        while bits >= 8 {
            out[idx] = acc as u8;
            idx += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// ByteDecode_d: the inverse of `byte_encode`. For d = 12 the values are reduced
/// modulo q as the standard requires; callers that need the modulus check re-encode
/// and compare.
pub(crate) fn byte_decode(d: usize, bytes: &[u8], f: &mut Poly) {
    debug_assert_eq!(bytes.len(), 32 * d);
    let mask = (1u32 << d) - 1;
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut idx = 0;
    for c in f.iter_mut() {
        while bits < d {
            acc |= (bytes[idx] as u32) << bits;
            idx += 1;
            bits += 8;
        }
        *c = (acc & mask) as u16;
        acc >>= d;
        bits -= d;
    }
    if d == 12 {
        for c in f.iter_mut() {
            *c = csub(*c);
        }
    }
}

/// ByteEncode_d(Compress_d(f)).
pub(crate) fn compress_encode(d: usize, f: &Poly, out: &mut [u8]) {
    let mut t = [0u16; N];
    for i in 0..N {
        t[i] = compress(d, f[i]);
    }
    byte_encode(d, &t, out);
}

/// Decompress_d(ByteDecode_d(bytes)).
pub(crate) fn decode_decompress(d: usize, bytes: &[u8], f: &mut Poly) {
    byte_decode(d, bytes, f);
    for c in f.iter_mut() {
        *c = decompress(d, *c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn div_q_is_exact_over_its_whole_input_range() {
        for t in 0u32..(1 << 25) {
            assert_eq!(div_q(t), t / Q as u32, "t = {t}");
        }
    }

    #[test]
    fn compress_matches_the_definition() {
        for d in 1..=11 {
            for x in 0..Q {
                let expected = ((((x as u32) << d) + 1664) / Q as u32) & ((1 << d) - 1);
                assert_eq!(compress(d, x) as u32, expected, "d = {d}, x = {x}");
            }
        }
    }

    #[test]
    fn decompress_then_compress_is_identity() {
        for d in 1..=11 {
            for y in 0..(1u16 << d) {
                let x = decompress(d, y);
                assert!(x < Q);
                assert_eq!(compress(d, x), y, "d = {d}, y = {y}");
            }
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        for d in 1..=12usize {
            let modulus = if d == 12 { Q as u32 } else { 1 << d };
            let mut f = [0u16; N];
            let mut state = 7u32;
            for x in f.iter_mut() {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                *x = ((state >> 8) % modulus) as u16;
            }
            let mut bytes = [0u8; 32 * 12];
            byte_encode(d, &f, &mut bytes[..32 * d]);
            let mut g = [0u16; N];
            byte_decode(d, &bytes[..32 * d], &mut g);
            assert_eq!(f, g, "d = {d}");
        }
    }

    #[test]
    fn decode12_reduces_out_of_range_values() {
        let mut bytes = [0u8; 384];
        bytes[0] = 0x01;
        bytes[1] = 0x0d;
        let mut f = [0u16; N];
        byte_decode(12, &bytes, &mut f);
        assert_eq!(f[0], 0);
    }
}
