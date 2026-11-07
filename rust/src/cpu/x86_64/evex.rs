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
#[cfg(any(feature = "blake2", feature = "blake3"))]
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

/// A sigma function of SHA-512 in each 64-bit lane: x rotated right by R0 and by R1, xored with x
/// shifted right by S.
///
/// # Safety
///
/// As for ror32.
#[target_feature(enable = "avx2")]
#[inline]
#[allow(unsafe_code)]
pub(super) unsafe fn sigma64<const R0: u32, const R1: u32, const S: u32>(x: __m256i) -> __m256i {
    let out;

    // SAFETY: as in ror32: two VPRORQ, a VPSRLQ and a VPTERNLOGQ, on registers.
    unsafe {
        asm!(
            "vprorq {out}, {x}, {r0}",
            "vprorq {a}, {x}, {r1}",
            "vpsrlq {b}, {x}, {s}",
            "vpternlogq {out}, {a}, {b}, 0x96",
            out = out(ymm_reg) out,
            a = out(ymm_reg) _,
            b = out(ymm_reg) _,
            x = in(ymm_reg) x,
            r0 = const R0,
            r1 = const R1,
            s = const S,
            options(pure, nomem, nostack, preserves_flags),
        );
    }

    out
}
