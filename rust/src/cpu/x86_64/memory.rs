// Loads and stores between arrays of 16 or 32 bytes and vector registers, one instruction each,
// without an alignment requirement. Every array has the size of the vector, which a constant
// assertion checks, so an access never leaves the reference it is given. These are the kernels'
// only accesses through pointers; built from scalars instead, each vector costs a load and an
// insert per element.

use core::arch::x86_64::*;
use core::mem::MaybeUninit;

// The element types of the arrays: integers, of which every bit pattern is a value.
pub(super) trait Plain: Copy {}

impl Plain for u8 {}

impl Plain for u16 {}

impl Plain for i16 {}

impl Plain for u32 {}

impl Plain for i32 {}

impl Plain for u64 {}

#[target_feature(enable = "sse2")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn load128<T: Plain, const N: usize>(values: &[T; N]) -> __m128i {
    const { assert!(size_of::<[T; N]>() == 16) };

    // SAFETY: values is readable for the sixteen bytes that the load reads.
    unsafe { _mm_loadu_si128(values.as_ptr().cast()) }
}

#[target_feature(enable = "sse2")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store128<T: Plain, const N: usize>(vector: __m128i, out: &mut [T; N]) {
    const { assert!(size_of::<[T; N]>() == 16) };

    // SAFETY: out is writable for the sixteen bytes that the store writes, and every bit pattern
    // is a value of its element type.
    unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), vector) }
}

#[target_feature(enable = "avx")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn load256<T: Plain, const N: usize>(values: &[T; N]) -> __m256i {
    const { assert!(size_of::<[T; N]>() == 32) };

    // SAFETY: values is readable for the 32 bytes that the load reads.
    unsafe { _mm256_loadu_si256(values.as_ptr().cast()) }
}

#[target_feature(enable = "avx")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store256<T: Plain, const N: usize>(vector: __m256i, out: &mut [T; N]) {
    const { assert!(size_of::<[T; N]>() == 32) };

    // SAFETY: as in store128, for 32 bytes.
    unsafe { _mm256_storeu_si256(out.as_mut_ptr().cast(), vector) }
}

// store256 into element i of an array that may not hold values yet, such as a buffer that is not
// zeroed before use because every element is written before it is read. The index is checked.
#[target_feature(enable = "avx")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store256_at<T: Plain, const N: usize, const M: usize>(
    vector: __m256i,
    out: &mut MaybeUninit<[[T; N]; M]>,
    i: usize,
) {
    const { assert!(size_of::<[T; N]>() == 32) };

    assert!(i < M, "element {i} of {M}");

    // SAFETY: element i < M of out is writable for the 32 bytes that the store writes; they then
    // hold a value, as every bit pattern of the element type is one.
    unsafe { _mm256_storeu_si256(out.as_mut_ptr().cast::<[T; N]>().add(i).cast(), vector) }
}
