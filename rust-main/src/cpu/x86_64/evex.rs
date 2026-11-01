// EVEX rotations and the two-table permutation of AVX-512VL, on registers of at most 256 bits, as
// inline assembly in AVX2 code: with avx512f enabled, the compiler copied and cleared 64-byte
// arrays with 512-bit moves. The callers run them only on a CPU with the AVX-512 tier (D-44).
use core::arch::asm;
use core::arch::x86_64::*;

/// x rotated right by R in each 32-bit lane: one VPRORD on a register.
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL, and the operating system saves their registers.
#[target_feature(enable = "avx2")]
#[inline]
#[allow(unsafe_code)]
pub(super) unsafe fn ror32<const R: u32>(x: __m128i) -> __m128i {
    let out;

    // SAFETY: one VPRORD on a register, which the caller's CPU has (AVX512F and AVX512VL); it
    // reads and writes no memory, stack or flags.
    unsafe {
        asm!(
            "vprord {x}, {x}, {r}",
            x = inout(xmm_reg) x => out,
            r = const R,
            options(pure, nomem, nostack, preserves_flags),
        );
    }

    out
}

/// x rotated right by R in each 64-bit lane: one VPRORQ on a register.
///
/// # Safety
///
/// As for ror32.
#[cfg(feature = "blake2")]
#[target_feature(enable = "avx2")]
#[inline]
#[allow(unsafe_code)]
pub(super) unsafe fn ror64<const R: u32>(x: __m256i) -> __m256i {
    let out;

    // SAFETY: as in ror32, a VPRORQ.
    unsafe {
        asm!(
            "vprorq {x}, {x}, {r}",
            x = inout(ymm_reg) x => out,
            r = const R,
            options(pure, nomem, nostack, preserves_flags),
        );
    }

    out
}

/// The words of a and b that index selects, as _mm256_permutex2var_epi32(a, index, b).
///
/// # Safety
///
/// As for ror32.
#[cfg(feature = "blake3")]
#[target_feature(enable = "avx2")]
#[inline]
#[allow(unsafe_code)]
pub(super) unsafe fn permute2(a: __m256i, index: __m256i, b: __m256i) -> __m256i {
    let out;

    // SAFETY: as in ror32, a VPERMT2D.
    unsafe {
        asm!(
            "vpermt2d {a}, {index}, {b}",
            a = inout(ymm_reg) a => out,
            index = in(ymm_reg) index,
            b = in(ymm_reg) b,
            options(pure, nomem, nostack, preserves_flags),
        );
    }

    out
}
