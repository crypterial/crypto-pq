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

// A vector into element i of an array of vectors that may not hold values yet, as store256_at
// does for arrays of words. The index is checked.
#[target_feature(enable = "avx")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn store_vector_at<const M: usize>(
    vector: __m256i,
    out: &mut MaybeUninit<[__m256i; M]>,
    i: usize,
) {
    assert!(i < M, "vector {i} of {M}");

    // SAFETY: element i < M of out is writable and aligned for a vector, which then holds a
    // value.
    unsafe { out.as_mut_ptr().cast::<__m256i>().add(i).write(vector) }
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

/// Values made of vectors alone, which take any bits: seen as words, they can be wiped.
///
/// # Safety
///
/// The type has no padding, which words_of relies on.
#[cfg(not(crypto_pq_optimized))]
#[allow(unsafe_code)]
pub(super) unsafe trait Vectors: Copy {}

// SAFETY: one vector, sixteen bytes of any bits.
#[cfg(not(crypto_pq_optimized))]
#[allow(unsafe_code)]
unsafe impl Vectors for __m128i {}

// SAFETY: one vector, thirty-two bytes of any bits.
#[cfg(not(crypto_pq_optimized))]
#[allow(unsafe_code)]
unsafe impl Vectors for __m256i {}

// SAFETY: an array has no padding between its elements.
#[cfg(not(crypto_pq_optimized))]
#[allow(unsafe_code)]
unsafe impl<T: Vectors, const N: usize> Vectors for [T; N] {}

// The 64-bit words of such a value, for wiping it.
#[cfg(not(crypto_pq_optimized))]
#[inline(always)]
#[allow(unsafe_code)]
pub(super) fn words_of<T: Vectors>(value: &mut T) -> &mut [u64] {
    // SAFETY: a Vectors value is 16- or 32-byte vectors with no padding between them, so it is
    // size_of::<T>() / 8 words aligned for u64, and every bit pattern is a value of either type;
    // the borrow of value covers the result.
    unsafe {
        core::slice::from_raw_parts_mut(core::ptr::from_mut(value).cast(), size_of::<T>() / 8)
    }
}

// The words of an array of vectors, for wiping it.
#[inline]
#[allow(unsafe_code)]
pub(super) fn vector_words<const M: usize>(vectors: &mut [__m256i; M]) -> &mut [[u64; 4]; M] {
    // SAFETY: four words take the 32 bytes of a vector and need less alignment, and every bit
    // pattern is a value of both types; the borrow of vectors covers the result.
    unsafe { &mut *vectors.as_mut_ptr().cast() }
}

// Zeros over vectors or words that held secrets, which the compiler must keep: volatile stores,
// one per value.
#[inline]
#[allow(unsafe_code)]
pub(super) fn clear<T: Copy>(values: &mut [T], zero: T) {
    for value in values {
        // SAFETY: value comes from a mutable slice, so it is valid, aligned and exclusive.
        unsafe { core::ptr::write_volatile(value, zero) };
    }

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
