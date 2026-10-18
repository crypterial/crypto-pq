// SHA-256 with the SHA extensions (SHA256RNDS2, SHA256MSG1, SHA256MSG2); with AVX2, BMI1 and BMI2
// (the AVX2 tier): the SHA-256 lanes, SHA-256 without the SHA extensions and SHA-512,
// Keccak-f[1600] on four states and on one, BLAKE2b and BLAKE2s, Ascon, and the ML-KEM and ML-DSA
// arithmetic, sampling and encodings; BLAKE2b and BLAKE2s without AVX2 with SSE4.1. Every
// instruction used is on Intel's list of data-operand-independent timing instructions, and the code
// around them has no branch or address that depends on secret data. The kernels are safe code
// inside #[target_feature] functions, apart from the loads and stores of memory.rs and the assembly
// of the SHA-2 rounds and of single shuffles and blends; what is unsafe is calling one once its
// feature is known to be there, and CPUID with XGETBV.

use core::arch::x86_64::*;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};

// A function of one AVX2 instruction in assembly, for shuffles that must stay as written: as
// intrinsics, LLVM's shuffle combining rewrote them into other shuffles, in BLAKE2 a rotation by
// 16 into two of them on both of its operands, which doubled the work of the one port that runs
// shuffles on Intel cores, and in SHA-512 a lane-crossing pair into a permutation that takes two
// operations and twice the latency on AMD cores. An instruction in assembly is opaque to it.
macro_rules! instruction {
    ($name:ident, $vector:ty, $class:ident, $template:literal, $($input:ident),+) => {
        #[target_feature(enable = "avx2")]
        #[inline]
        #[allow(unsafe_code)]
        fn $name($($input: $vector),+) -> $vector {
            let out: $vector;

            // SAFETY: one AVX2 instruction on registers, which this function's target feature
            // provides; it reads and writes no memory, stack or flags.
            unsafe {
                core::arch::asm!(
                    $template,
                    out = lateout($class) out,
                    $($input = in($class) $input),+,
                    options(pure, nomem, nostack, preserves_flags),
                );
            }

            out
        }
    };
}

mod aes;

mod ascon;

mod blake2;

mod dsa;

mod keccak;

mod kem;

mod memory;

mod ntt;

mod sha2;

use crate::cpu::{Field, Field16, Pack};
use crate::sha2::{K256, compress256_lanes_portable};
use crate::wipe::wipe;

// The SHA extensions together with the SSSE3 and SSE4.1 shuffles that the kernel needs.
const SHA: u32 = 1;

// AVX2 with ymm state that the operating system saves, together with BMI1 and BMI2, as Go's
// standard library also requires them: every CPU with AVX2 has them, and the kernels that the
// flag selects use either.
const AVX2: u32 = 1 << 1;

// SSSE3 and SSE4.1.
const SSE41: u32 = 1 << 2;

// AES-NI, with SSE4.1 as on every CPU that has it.
const AES: u32 = 1 << 3;

const READY: u32 = 1 << 31;

// What the build guarantees needs no detection, and its check folds away.
const fn guaranteed(feature: u32) -> bool {
    if cfg!(crypto_pq_ct) {
        return false;
    }

    match feature {
        SHA => cfg!(all(
            target_feature = "sha",
            target_feature = "ssse3",
            target_feature = "sse4.1"
        )),
        AVX2 => cfg!(all(
            target_feature = "avx2",
            target_feature = "bmi1",
            target_feature = "bmi2"
        )),
        SSE41 => cfg!(all(target_feature = "ssse3", target_feature = "sse4.1")),
        AES => cfg!(all(target_feature = "aes", target_feature = "sse4.1")),
        _ => false,
    }
}

// The constant-time check runs under valgrind, which cannot execute the SHA extensions, so its
// build leaves them out and checks the AVX2, SSE4.1 and AES-NI paths.
const fn usable(feature: u32) -> bool {
    if cfg!(crypto_pq_ct) {
        return feature != SHA;
    }

    true
}

static FEATURES: AtomicU32 = AtomicU32::new(0);

// Every thread that finds the cache empty computes the same value, so a relaxed store suffices.
#[inline]
fn has(feature: u32) -> bool {
    if !usable(feature) {
        return false;
    }

    if guaranteed(feature) {
        return true;
    }

    let mut found = FEATURES.load(Ordering::Relaxed);

    if found == 0 {
        found = probe() | READY;

        FEATURES.store(found, Ordering::Relaxed);
    }

    found & feature != 0
}

// CPUID leaf 1 ECX: SSSE3 bit 9, SSE4.1 bit 19, AES bit 25, OSXSAVE bit 27, AVX
// bit 28; leaf 7 EBX: BMI1 bit 3, AVX2 bit 5, BMI2 bit 8, SHA bit 29. Newer Rust makes __cpuid
// safe, hence unused_unsafe.
// Out of line, as CPUID's registers made every kernel's caller save six, for the first call only.
#[cold]
#[inline(never)]
#[allow(unsafe_code, unused_unsafe)]
fn probe() -> u32 {
    // SAFETY: every x86-64 CPU has CPUID; the one environment where it faults, an SGX enclave,
    // compiles this module out.
    let (max, leaf1) = unsafe { (__cpuid(0).eax, __cpuid(1)) };

    let mut found = 0;

    if leaf1.ecx & (1 << 9) != 0 && leaf1.ecx & (1 << 19) != 0 {
        found |= SSE41;

        if leaf1.ecx & (1 << 25) != 0 {
            found |= AES;
        }
    }

    if max < 7 {
        return found;
    }

    // SAFETY: as above; leaf 7 exists because the highest leaf is at least 7.
    let leaf7 = unsafe { __cpuid_count(7, 0) };

    if found & SSE41 != 0 && leaf7.ebx & (1 << 29) != 0 {
        found |= SHA;
    }

    let bmi = leaf7.ebx & (1 << 3) != 0 && leaf7.ebx & (1 << 8) != 0;

    let avx = bmi && leaf7.ebx & (1 << 5) != 0 && leaf1.ecx & (1 << 28) != 0;

    // XGETBV exists once the operating system has enabled XSAVE (OSXSAVE); bits 1 and 2 of XCR0
    // say that it saves the SSE and AVX registers on a context switch.
    //
    // SAFETY: XGETBV is only executed with OSXSAVE set, and reading XCR0 has no side effects.
    if avx && leaf1.ecx & (1 << 27) != 0 && unsafe { _xgetbv(0) } & 6 == 6 {
        found |= AVX2;
    }

    found
}

#[allow(unsafe_code)]
pub(crate) fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]], more: &[[u8; 64]]) -> bool {
    if has(SHA) {
        // SAFETY: the CPU has the SHA extensions, SSSE3 and SSE4.1, all that the kernel needs.
        unsafe { compress256_sha(state, blocks, more) };

        return true;
    }

    if has(AVX2) {
        // SAFETY: the CPU has AVX2, BMI1 and BMI2, and the operating system saves the registers.
        unsafe { sha2::compress256(state, blocks, more) };

        return true;
    }

    false
}

// SHA-NI two lanes at a time where it exists; otherwise the portable lanes compiled for AVX2,
// eight lanes per vector instead of SSE2's four.
#[allow(unsafe_code)]
pub(crate) fn compress256_lanes<const LANES: usize>(
    states: &mut [[u32; LANES]; 8],
    w: &mut [[u32; LANES]; 16],
) -> bool {
    if has(SHA) {
        // SAFETY: as in compress256.
        unsafe { compress256_lanes_sha(states, w) };

        return true;
    }

    if has(AVX2) {
        // SAFETY: the CPU has AVX2 and the operating system saves its registers.
        unsafe { compress256_lanes_avx2(states, w) };

        return true;
    }

    false
}

// The one-shot hashes build their padding in memory, as the portable code does; with the SHA
// extensions, the portable code calls compress256 for the blocks.
#[allow(unsafe_code)]
pub(crate) fn finish256(state: &mut [u32; 8], data: &[u8], bits: u64) -> bool {
    if has(SHA) || !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::finish256(state, data, bits) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn finish512(state: &mut [u64; 8], data: &[u8], bits: u128) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::finish512(state, data, bits) };

    true
}

// HMAC in one call on the AVX2 path; with the SHA extensions the generic code calls compress256.
#[allow(unsafe_code)]
pub(crate) fn hmac256(iv: &[u32; 8], key: &[u8], data: &[u8], tag: &mut [u8]) -> bool {
    if has(SHA) || !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::hmac256(iv, key, data, tag) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn hmac512(iv: &[u64; 8], key: &[u8], data: &[u8], tag: &mut [u8]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::hmac512(iv, key, data, tag) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn hmac256_keyed(keyed: &[[u32; 8]; 2], data: &[u8], tag: &mut [u8]) -> bool {
    if has(SHA) || !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::hmac256_keyed(keyed, data, tag) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn hmac512_keyed(keyed: &[[u64; 8]; 2], data: &[u8], tag: &mut [u8]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::hmac512_keyed(keyed, data, tag) };

    true
}

// With the SHA extensions the pair goes through compress256_lanes, two streams side by side.
#[allow(unsafe_code)]
pub(crate) fn compress256_pair(states: &mut [[u32; 8]; 2], blocks: &[[u8; 64]; 2]) -> bool {
    if has(SHA) || !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::compress256_pair(states, blocks) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn compress512(state: &mut [u64; 8], blocks: &[[u8; 128]], more: &[[u8; 128]]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::compress512(state, blocks, more) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn compress512_pair(states: &mut [[u64; 8]; 2], blocks: &[[u8; 128]; 2]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::compress512_pair(states, blocks) };

    true
}

// The transforms and products of ML-DSA, and of ML-KEM where the 16-bit kernels are not used.
#[allow(unsafe_code)]
pub(crate) fn ntt(w: &mut [i32; 256], field: &Field) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: the CPU has AVX2 and the operating system saves its registers.
    unsafe { ntt::forward(w, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn inverse_ntt(w: &mut [i32; 256], field: &Field) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { ntt::inverse(w, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn multiply(
    out: &mut [i32; 256],
    f: &[i32; 256],
    g: &[i32; 256],
    field: &Field,
) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { ntt::products(out, f, g, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn multiply_add(
    acc: &mut [i32; 256],
    f: &[[i32; 256]],
    g: &[[i32; 256]],
    field: &Field,
) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { ntt::products_add(acc, f, g, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn base_multiply_add(
    acc: &mut [i32; 256],
    a: &[u16; 256],
    b: &[u16; 256],
    cache: &[u16; 128],
) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::base_multiply_add(acc, a, b, cache) };

    true
}

// The PRF output is given as the 64-bit lanes of the sponges, in stream order.
#[allow(unsafe_code)]
pub(crate) fn binomial(eta: usize, lanes: &[u64], q: u16, out: &mut [u16; 256]) -> bool {
    if !matches!((eta, lanes.len()), (2, 16) | (3, 24)) || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::binomial(eta, lanes, q, out) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn mldsa_add(out: &mut [i32; 256], a: &[i32; 256], b: &[i32; 256], q: i32) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::combine::<true>(out, a, b, q) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn mldsa_sub(out: &mut [i32; 256], a: &[i32; 256], b: &[i32; 256], q: i32) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::combine::<false>(out, a, b, q) };

    true
}

// -1 when some value reaches the bound in absolute value: the centered coefficients, or with
// gamma2 the low bits of Decompose; 0 otherwise.
#[allow(unsafe_code)]
pub(crate) fn mldsa_norm(
    values: &[i32; 256],
    bound: i32,
    gamma2: Option<i32>,
    q: i32,
) -> Option<i32> {
    if !has(AVX2) {
        return None;
    }

    // SAFETY: as in ntt.
    Some(unsafe { dsa::norm(values, bound, gamma2, q) })
}

// The hints of r and ct0, one per coefficient, and how many are set.
#[allow(unsafe_code)]
pub(crate) fn mldsa_hints(
    h: &mut [i32; 256],
    r: &[i32; 256],
    ct0: &[i32; 256],
    gamma2: i32,
    q: i32,
) -> Option<i32> {
    if !has(AVX2) {
        return None;
    }

    // SAFETY: as in ntt.
    Some(unsafe { dsa::hints(h, r, ct0, gamma2, q) })
}

// HighBits of every coefficient packed in four bits, for gamma2 = (q - 1) / 32, or six, for
// gamma2 = (q - 1) / 88.
#[allow(unsafe_code)]
pub(crate) fn mldsa_w1(out: &mut [u8], w: &[i32; 256], gamma2: i32, q: i32) -> bool {
    let bits = if gamma2 == (q - 1) / 32 { 4 } else { 6 };

    if (gamma2 != (q - 1) / 32 && gamma2 != (q - 1) / 88) || out.len() != 32 * bits || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::encode_w1(out, w, gamma2, q) };

    true
}

// The coefficients mapped as `map` says and packed in `bits` bits each.
#[allow(unsafe_code)]
pub(crate) fn mldsa_pack(out: &mut [u8], poly: &[i32; 256], bits: u32, map: Pack, q: i32) -> bool {
    if !matches!(bits, 3 | 4 | 10 | 13 | 18 | 20) || out.len() != 32 * bits as usize || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::pack(out, poly, bits, map, q) };

    true
}

// gamma1 - x modulo q for the mask's values x of 18 or 20 bits.
#[allow(unsafe_code)]
pub(crate) fn mldsa_mask(
    out: &mut [i32; 256],
    bytes: &[u8],
    bits: u32,
    gamma1: i32,
    q: i32,
) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe {
        match (bits, bytes.len()) {
            (18, 576) => dsa::unpack_mask::<18>(out, bytes, gamma1, q),
            (20, 640) => dsa::unpack_mask::<20>(out, bytes, gamma1, q),
            _ => return false,
        }
    }

    true
}

#[allow(unsafe_code)]
pub(crate) fn mlkem_matrix_vector(
    t: &mut [[u16; 256]],
    a: &[[u16; 256]],
    s: &[[u16; 256]],
    caches: &[[u16; 128]],
    e: &[[u16; 256]],
    q: u16,
) -> bool {
    let k = s.len();

    if k > 4 || a.len() != t.len() * k || caches.len() != k || e.len() != t.len() || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::matrix_vector(t, a, s, caches, e, q) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn reduce(w: &[i32; 256], factor: i32, field: &Field, out: &mut [u16; 256]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::reduce(w, factor, field.q, field.qinv, out) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn encode12(f: &[u16; 256], out: &mut [u8; 384]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::encode12(f, out) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn decode12(data: &[u8; 384], q: u16, out: &mut [u16; 256]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::decode12(data, q, out) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn mlkem_compress(
    f: &[u16; 256],
    e: &[u16; 256],
    message: Option<&[u8; 32]>,
    d: u32,
    q: u16,
    out: &mut [u8],
) -> bool {
    if !matches!(d, 1 | 4 | 5 | 10 | 11) || out.len() != 32 * d as usize || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::compress(f, e, message, d, q, out) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn mlkem_decompress(data: &[u8], d: u32, q: u16, out: &mut [u16; 256]) -> bool {
    if !matches!(d, 4 | 5 | 10 | 11) || data.len() != 32 * d as usize || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::decompress(data, d, q, out) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn mlkem_message(v: &[u16; 256], w: &[u16; 256], q: u16, out: &mut [u8; 32]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::message(v, w, q, out) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn uniform12(lanes: &[u64; 21], q: u16, a: &mut [u16; 256], count: &mut usize) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::uniform12(lanes, q, a, count) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn uniform23(lanes: &[u64; 21], q: i32, a: &mut [i32; 256], count: &mut usize) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::uniform23(lanes, q, a, count) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn bounded(lanes: &[u64; 17], eta: i32, a: &mut [i32; 256], count: &mut usize) -> bool {
    if (eta != 2 && eta != 4) || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::bounded(lanes, eta, a, count) };

    true
}

// The products b[2i + 1] gamma_i mod q of ML-KEM's base multiplication, with the gammas in
// Montgomery form for 2^16.
#[allow(unsafe_code)]
pub(crate) fn mlkem_multiply_cache(
    b: &[u16; 256],
    gammas: &[i16; 128],
    q: u16,
    cache: &mut [u16; 128],
) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::multiply_cache(b, gammas, q, cache) };

    true
}

// InvNTT of the sum of the products a[j] * b[j], with the caches of the b[j], for at most four.
#[allow(unsafe_code)]
pub(crate) fn mlkem_inner_product(
    out: &mut [u16; 256],
    a: &[&[u16; 256]],
    b: &[[u16; 256]],
    caches: &[[u16; 128]],
    field: &Field16,
) -> bool {
    if a.len() > 4 || b.len() != a.len() || caches.len() != a.len() || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::inner_product(out, a, b, caches, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn ntt16(f: &mut [u16; 256], field: &Field16) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::ntt(f, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn inverse_ntt16(acc: &[i32; 256], out: &mut [u16; 256], field: &Field16) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::inverse_ntt(acc, out, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn ascon(s: &mut [u64; 5]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: the CPU has BMI1 and BMI2, which AVX2 implies here.
    unsafe { ascon::ascon_bmi(s) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn ascon_digest(start: &[u64; 5], data: &[u8], out: &mut [u8]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ascon.
    unsafe { ascon::digest_bmi(start, data, out) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn aes_expand(key: &[u8], round_keys: &mut [[u8; 16]; 15]) -> bool {
    if !has(AES) {
        return false;
    }

    // SAFETY: the CPU has AES-NI and SSE4.1.
    unsafe { aes::expand(key, round_keys) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn aes_encrypt(round_keys: &[[u8; 16]], blocks: &mut [[u8; 16]]) -> bool {
    if !has(AES) {
        return false;
    }

    // SAFETY: as in aes_expand.
    unsafe { aes::encrypt_blocks(round_keys, blocks) };

    true
}

// Groups of four fill the AVX2 kernel.
pub(crate) const fn keccak_group() -> usize {
    4
}

// Absorbs the whole blocks of data, rate bytes each, into one state, and returns how many bytes
// that was.
#[allow(unsafe_code)]
pub(crate) fn absorb(state: &mut [u64; 25], rate: usize, data: &[u8]) -> usize {
    let length = data.len() - data.len() % rate;

    if length == 0 || !has(AVX2) {
        return 0;
    }

    let blocks = &data[..length];

    // SAFETY: the CPU has BMI1 and BMI2, which AVX2 implies here.
    unsafe {
        match rate {
            72 => keccak::absorb_bmi::<72>(state, blocks.as_chunks().0),
            104 => keccak::absorb_bmi::<104>(state, blocks.as_chunks().0),
            136 => keccak::absorb_bmi::<136>(state, blocks.as_chunks().0),
            144 => keccak::absorb_bmi::<144>(state, blocks.as_chunks().0),
            168 => keccak::absorb_bmi::<168>(state, blocks.as_chunks().0),
            _ => return 0,
        }
    }

    length
}

// The output of a sponge of the given rate and suffix that absorbs data and is read once into
// out, in one call.
#[allow(unsafe_code)]
pub(crate) fn digest(
    initial: Option<&[u64; 25]>,
    rate: usize,
    suffix: u8,
    data: &[u8],
    out: &mut [u8],
) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in absorb.
    unsafe {
        match rate {
            72 => keccak::digest_bmi::<72>(initial, data, suffix, out),
            104 => keccak::digest_bmi::<104>(initial, data, suffix, out),
            136 => keccak::digest_bmi::<136>(initial, data, suffix, out),
            144 => keccak::digest_bmi::<144>(initial, data, suffix, out),
            168 => keccak::digest_bmi::<168>(initial, data, suffix, out),
            _ => return false,
        }
    }

    true
}

#[allow(unsafe_code)]
pub(crate) fn blake2b(
    h: &mut [u64; 8],
    first: Option<&[u64; 16]>,
    blocks: &[[u8; 128]],
    counter: u128,
    last: Option<(&[u64; 16], u128)>,
) -> bool {
    if has(AVX2) {
        // SAFETY: the CPU has AVX2 and the operating system saves its registers.
        unsafe { blake2::blake2b_avx2(h, first, blocks, counter, last) };

        return true;
    }

    if has(SSE41) {
        // SAFETY: the CPU has SSSE3 and SSE4.1, all that the kernel needs.
        unsafe { blake2::blake2b_sse41(h, first, blocks, counter, last) };

        return true;
    }

    false
}

#[allow(unsafe_code)]
pub(crate) fn blake2s(
    h: &mut [u32; 8],
    first: Option<&[u32; 16]>,
    blocks: &[[u8; 64]],
    counter: u64,
    last: Option<(&[u32; 16], u128)>,
) -> bool {
    if has(AVX2) {
        let mut first = first.map(blake2::bytes32);

        let mut last = last.map(|(m, total)| (blake2::bytes32(m), total as u64));

        // SAFETY: the CPU has AVX2 and the operating system saves its registers.
        unsafe {
            blake2::blake2s_avx2(
                h,
                first.as_ref(),
                blocks,
                last.as_ref().map(|(block, total)| (block, *total)),
                counter,
                None,
            )
        };

        if let Some(bytes) = &mut first {
            wipe(bytes);
        }

        if let Some((bytes, _)) = &mut last {
            wipe(bytes);
        }

        return true;
    }

    if !has(SSE41) {
        return false;
    }

    // SAFETY: the CPU has SSSE3 and SSE4.1, all that the kernel needs.
    unsafe { blake2::blake2s_sse41(h, first, blocks, counter, last) };

    true
}

// BLAKE2's digest in one call with the state in registers throughout: the generic path's word
// conversions, chaining value copies and calls cost a 64-byte message a sixth of its time.
#[allow(unsafe_code)]
pub(crate) fn blake2b_digest(h: &[u64; 8], data: &[u8], out: &mut [u8]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: the CPU has AVX2 and the operating system saves its registers.
    unsafe { blake2::blake2b_digest_avx2(h, data, out) };

    true
}

// BLAKE2s's digest and MAC in one call of the AVX2 code each, with the blocks found here.
#[allow(unsafe_code)]
pub(crate) fn blake2s_digest(h: &[u32; 8], data: &[u8], out: &mut [u8]) -> bool {
    if !has(AVX2) {
        return false;
    }

    let (blocks, tail) = blake2::split32(data);

    blake2::final32(tail, |last| {
        let total = data.len() as u64;

        // SAFETY: the CPU has AVX2 and the operating system saves its registers.
        unsafe {
            blake2::blake2s_avx2(
                &mut h.clone(),
                None,
                blocks,
                Some((last, total)),
                0,
                Some(out),
            )
        };
    });

    true
}

// The key, zero-padded to a block, comes first, or last for empty data.
#[allow(unsafe_code)]
pub(crate) fn blake2s_mac(h: &[u32; 8], key: &[u8], data: &[u8], out: &mut [u8]) -> bool {
    if !has(AVX2) {
        return false;
    }

    let mut key_block = [0; 64];

    key_block[..key.len()].copy_from_slice(key);

    let total = 64 + data.len() as u64;

    if data.is_empty() {
        // SAFETY: the CPU has AVX2 and the operating system saves its registers.
        unsafe {
            blake2::blake2s_avx2(
                &mut h.clone(),
                None,
                &[],
                Some((&key_block, total)),
                0,
                Some(out),
            )
        };
    } else {
        let (blocks, tail) = blake2::split32(data);

        blake2::final32(tail, |last| {
            let first = Some(&key_block);

            // SAFETY: as above.
            unsafe {
                blake2::blake2s_avx2(
                    &mut h.clone(),
                    first,
                    blocks,
                    Some((last, total)),
                    0,
                    Some(out),
                )
            };
        });
    }

    wipe(&mut key_block);

    true
}

// Four states per AVX2 call, and two or three with lanes idle, which still costs less than their
// scalar permutations. One alone, as the fifth of five, takes the scalar permutation built for
// BMI1 and BMI2: four in vectors beside one in general registers measured no faster than one after
// the other, as both compete for the same ports.
#[allow(unsafe_code)]
pub(crate) fn permute_many(states: &mut [&mut [u64; 25]]) -> usize {
    if !has(AVX2) {
        return 0;
    }

    let count = states.len();

    let mut rest = states;

    while !rest.is_empty() {
        let size = rest.len().min(4);

        let (group, tail) = core::mem::take(&mut rest).split_at_mut(size);

        // SAFETY: the CPU has AVX2, BMI1 and BMI2, and the operating system saves the registers.
        unsafe {
            match group {
                [only] => keccak::permute_bmi(only),
                _ => keccak::permute4_avx2(group),
            }
        }

        rest = tail;
    }

    count
}

// Four state words as SHA256RNDS2 holds them, the first in the highest lane.
#[target_feature(enable = "sse2")]
#[inline]
fn high_first(words: [u32; 4]) -> __m128i {
    _mm_set_epi32(
        words[0] as i32,
        words[1] as i32,
        words[2] as i32,
        words[3] as i32,
    )
}

#[target_feature(enable = "sse4.1")]
#[inline]
fn from_high_first(vector: __m128i) -> [u32; 4] {
    [
        _mm_extract_epi32::<3>(vector) as u32,
        _mm_extract_epi32::<2>(vector) as u32,
        _mm_extract_epi32::<1>(vector) as u32,
        _mm_extract_epi32::<0>(vector) as u32,
    ]
}

// Schedule words in order, the first in the lowest lane.
#[target_feature(enable = "sse2")]
#[inline]
fn low_first(words: [u32; 4]) -> __m128i {
    _mm_set_epi32(
        words[3] as i32,
        words[2] as i32,
        words[1] as i32,
        words[0] as i32,
    )
}

// One SHA-256 computation in flight: abef and cdgh as SHA256RNDS2 wants them, and the sixteen
// schedule words that are live.
#[derive(Clone, Copy)]
struct Stream {
    abef: __m128i,
    cdgh: __m128i,
    m: [__m128i; 4],
}

// Four rounds of every stream with schedule vector J, two per SHA256RNDS2, which reads its two
// words of W + K from the low half; then J advances by sixteen words if more are needed. After
// two rounds the new c, d, g and h are the old a, b, e and f, so each SHA256RNDS2 writes the new
// a, b, e and f over the half that the next one reads as c, d, g and h.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[inline]
fn quarter<const N: usize, const J: usize>(streams: &mut [Stream; N], k: __m128i, schedule: bool) {
    for stream in streams.iter_mut() {
        let wk = _mm_add_epi32(stream.m[J], k);

        stream.cdgh = _mm_sha256rnds2_epu32(stream.cdgh, stream.abef, wk);

        stream.abef =
            _mm_sha256rnds2_epu32(stream.abef, stream.cdgh, _mm_shuffle_epi32::<0x0E>(wk));

        if schedule {
            let m = &mut stream.m;

            let w9 = _mm_alignr_epi8::<4>(m[(J + 3) % 4], m[(J + 2) % 4]);

            let partial = _mm_add_epi32(_mm_sha256msg1_epu32(m[J], m[(J + 1) % 4]), w9);

            m[J] = _mm_sha256msg2_epu32(partial, m[(J + 3) % 4]);
        }
    }
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[inline]
fn rounds256<const N: usize>(streams: &mut [Stream; N]) {
    let start = *streams;

    for (sixteen, k) in K256.as_chunks::<16>().0.iter().enumerate() {
        let k = k.as_chunks::<4>().0;

        let schedule = sixteen < 3;

        quarter::<N, 0>(streams, low_first(k[0]), schedule);

        quarter::<N, 1>(streams, low_first(k[1]), schedule);

        quarter::<N, 2>(streams, low_first(k[2]), schedule);

        quarter::<N, 3>(streams, low_first(k[3]), schedule);
    }

    for (stream, start) in streams.iter_mut().zip(&start) {
        stream.abef = _mm_add_epi32(stream.abef, start.abef);

        stream.cdgh = _mm_add_epi32(stream.cdgh, start.cdgh);
    }
}

// The streaming hash: the state stays in registers from one block to the next.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn compress256_sha(state: &mut [u32; 8], blocks: &[[u8; 64]], more: &[[u8; 64]]) {
    let [a, b, c, d, e, f, g, h] = *state;

    let mut streams = [Stream {
        abef: high_first([a, b, e, f]),
        cdgh: high_first([c, d, g, h]),
        m: [_mm_setzero_si128(); 4],
    }];

    // Reverses the bytes of each 32-bit word: the words of a block are big-endian.
    let swap = _mm_set_epi64x(0x0C0D_0E0F_0809_0A0B, 0x0405_0607_0001_0203);

    for block in blocks.iter().chain(more) {
        for (m, bytes) in streams[0].m.iter_mut().zip(block.as_chunks::<16>().0) {
            let [low, high] = bytes.as_chunks::<8>().0 else {
                unreachable!("sixteen bytes are two groups of eight")
            };

            let words = _mm_set_epi64x(i64::from_le_bytes(*high), i64::from_le_bytes(*low));

            *m = _mm_shuffle_epi8(words, swap);
        }

        rounds256(&mut streams);
    }

    let [a, b, e, f] = from_high_first(streams[0].abef);

    let [c, d, g, h] = from_high_first(streams[0].cdgh);

    *state = [a, b, c, d, e, f, g, h];
}

#[target_feature(enable = "sse2")]
#[inline]
fn gather<const LANES: usize>(
    states: &[[u32; LANES]; 8],
    w: &[[u32; LANES]; 16],
    lane: usize,
) -> Stream {
    let word = |i: usize| states[i][lane];

    let mut m = [_mm_setzero_si128(); 4];

    for (j, m) in m.iter_mut().enumerate() {
        *m = low_first([
            w[4 * j][lane],
            w[4 * j + 1][lane],
            w[4 * j + 2][lane],
            w[4 * j + 3][lane],
        ]);
    }

    Stream {
        abef: high_first([word(0), word(1), word(4), word(5)]),
        cdgh: high_first([word(2), word(3), word(6), word(7)]),
        m,
    }
}

#[target_feature(enable = "sse4.1")]
#[inline]
fn scatter<const LANES: usize>(states: &mut [[u32; LANES]; 8], stream: &Stream, lane: usize) {
    let [a, b, e, f] = from_high_first(stream.abef);

    let [c, d, g, h] = from_high_first(stream.cdgh);

    for (state, word) in states.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        state[lane] = word;
    }
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn compress256_lanes_sha<const LANES: usize>(
    states: &mut [[u32; LANES]; 8],
    w: &[[u32; LANES]; 16],
) {
    let mut lane = 0;

    while lane + 2 <= LANES {
        let mut streams = [gather(states, w, lane), gather(states, w, lane + 1)];

        rounds256(&mut streams);

        scatter(states, &streams[0], lane);

        scatter(states, &streams[1], lane + 1);

        lane += 2;
    }

    if lane < LANES {
        let mut streams = [gather(states, w, lane)];

        rounds256(&mut streams);

        scatter(states, &streams[0], lane);
    }
}

#[repr(C, align(32))]
struct Aligned<T>(T);

// With eight lanes or more, the state and the schedule of the portable rounds live in 32-byte
// stack slots and in w, and an access 16 bytes off a 32-byte boundary splits a cache line half of
// the time: for sixteen lanes, 660 of a call's 1430 loads and stores when the caller's stack puts
// both there. The aligned anchor makes the compiler align this frame, and with it every spill
// slot; a schedule off the boundary is moved into an aligned copy first, and wiped there.
#[target_feature(enable = "avx2")]
fn compress256_lanes_avx2<const LANES: usize>(
    states: &mut [[u32; LANES]; 8],
    w: &mut [[u32; LANES]; 16],
) {
    if LANES >= 8 {
        if !w.as_ptr().addr().is_multiple_of(32) {
            compress256_lanes_moved(states, w);

            return;
        }

        core::hint::black_box(&mut MaybeUninit::<Aligned<[u8; 32]>>::uninit());
    }

    compress256_lanes_portable(states, w);
}

#[target_feature(enable = "avx2")]
#[inline(never)]
fn compress256_lanes_moved<const LANES: usize>(
    states: &mut [[u32; LANES]; 8],
    w: &mut [[u32; LANES]; 16],
) {
    let mut aligned = Aligned(*w);

    compress256_lanes_avx2(states, &mut aligned.0);

    wipe(aligned.0.as_flattened_mut());
}
