// Loads and stores between arrays and NEON registers, one instruction each. Every array has the
// size of the vector, so an access never leaves the reference it is given, and the element types
// set the only alignment that the instructions need. Apart from the round constants that the
// Keccak assembly reads, these are the NEON kernels' only accesses through pointers; built from
// scalars instead, each vector costs two loads and an insert.

use core::arch::aarch64::*;

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn load_i32(values: &[i32; 4]) -> int32x4_t {
    // SAFETY: values is readable for the sixteen bytes that the load reads.
    unsafe { vld1q_s32(values.as_ptr()) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store_i32(vector: int32x4_t, out: &mut [i32; 4]) {
    // SAFETY: out is writable for the sixteen bytes that the store writes.
    unsafe { vst1q_s32(out.as_mut_ptr(), vector) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn load_u32(values: &[u32; 4]) -> uint32x4_t {
    // SAFETY: as in load_i32.
    unsafe { vld1q_u32(values.as_ptr()) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store_u32(vector: uint32x4_t, out: &mut [u32; 4]) {
    // SAFETY: as in store_i32.
    unsafe { vst1q_u32(out.as_mut_ptr(), vector) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn load_i16(values: &[i16; 8]) -> int16x8_t {
    // SAFETY: as in load_i32.
    unsafe { vld1q_s16(values.as_ptr()) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn load_u16(values: &[u16; 8]) -> uint16x8_t {
    // SAFETY: as in load_i32.
    unsafe { vld1q_u16(values.as_ptr()) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store_u16(vector: uint16x8_t, out: &mut [u16; 8]) {
    // SAFETY: as in store_i32.
    unsafe { vst1q_u16(out.as_mut_ptr(), vector) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn load_u8(values: &[u8; 16]) -> uint8x16_t {
    // SAFETY: as in load_i32.
    unsafe { vld1q_u8(values.as_ptr()) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn load_u64(values: &[u64; 2]) -> uint64x2_t {
    // SAFETY: as in load_i32.
    unsafe { vld1q_u64(values.as_ptr()) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store_u64(vector: uint64x2_t, out: &mut [u64; 2]) {
    // SAFETY: as in store_i32.
    unsafe { vst1q_u64(out.as_mut_ptr(), vector) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store3_u8(vectors: uint8x8x3_t, out: &mut [u8; 24]) {
    // SAFETY: out is writable for the 24 bytes that the interleaving store writes.
    unsafe { vst3_u8(out.as_mut_ptr(), vectors) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store_u8(vector: uint8x16_t, out: &mut [u8; 16]) {
    // SAFETY: as in store_i32.
    unsafe { vst1q_u8(out.as_mut_ptr(), vector) }
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn load3_u8(values: &[u64; 6]) -> uint8x16x3_t {
    // SAFETY: values is readable for the 48 bytes that the deinterleaving load reads, which are
    // its lanes in memory order.
    unsafe { vld3q_u8(values.as_ptr().cast()) }
}
