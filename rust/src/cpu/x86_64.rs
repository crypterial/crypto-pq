// SHA-256 with the SHA extensions (SHA256RNDS2, SHA256MSG1, SHA256MSG2); AES-128 and AES-256 with
// AES-NI, which also builds the AES rows of FrodoKEM's matrix A in registers; with AVX2, BMI1 and
// BMI2 (the AVX2 tier): the SHA-256 lanes, SHA-256 without the SHA extensions and SHA-512,
// Keccak-f[1600] on four states and on one, BLAKE2b, BLAKE2s and BLAKE3, Ascon, the ML-KEM and
// ML-DSA arithmetic, sampling and encodings, and FrodoKEM's SHAKE128 rows of A and its products of
// A with the secret matrices; with AVX-512F and AVX-512VL besides, Keccak-f[1600] on four states
// and on one in 256-bit registers; BLAKE2b, BLAKE2s and BLAKE3 without AVX2 with SSE4.1. Every
// instruction that takes secret data is on Intel's list of data-operand-independent timing
// instructions or is a floating-point-domain logic, move, unpack, shuffle or blend instruction that
// SPEC D-75 counts with it, as LLVM emits some for integer intrinsics; branches, divisions and the
// other instructions take public values only, such as lengths and counts, so no branch or address
// depends on secret data. The kernels are safe code inside #[target_feature] functions, apart from
// the loads and stores of memory.rs, the assembly of the SHA-2 rounds, of BLAKE3's transposed
// rounds and of single shuffles and blends, and the volatile stores that clear BLAKE3's vector
// buffers and the vector form of Sponges; what is unsafe is calling one once its feature is known
// to be there, reading a group of that vector form once it is written, and CPUID with XGETBV.

use core::arch::x86_64::*;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};

// A function of one AVX2 instruction in assembly, for shuffles that must stay as written: as
// intrinsics, LLVM's shuffle combining rewrote them into other shuffles, in BLAKE2 a rotation by
// 16 into two of them on both of its operands, which doubled the work of the one port that runs
// shuffles on Intel cores, and in SHA-512 a lane-crossing pair into a permutation that takes two
// operations and twice the latency on AMD cores. An instruction in assembly is opaque to it.
#[cfg(any(feature = "blake2", feature = "blake3"))]
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

#[cfg(feature = "frodokem")]
mod aes;

#[cfg(feature = "ascon")]
mod ascon;

#[cfg(feature = "blake2")]
mod blake2;

#[cfg(feature = "blake3")]
mod blake3;

#[cfg(feature = "ml-dsa")]
mod dsa;

#[cfg(feature = "frodokem")]
mod frodo;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
mod keccak;

#[cfg(feature = "ml-kem")]
mod kem;

mod memory;

#[cfg(any(feature = "ml-kem", feature = "ml-dsa"))]
mod ntt;

mod sha2;

#[cfg(feature = "ml-dsa")]
use crate::cpu::Pack;
#[cfg(any(feature = "ml-kem", feature = "ml-dsa"))]
use crate::cpu::{Field, Field16};
use crate::sha2::{K256, compress256_lanes_portable};
use crate::wipe::wipe;

// The number of accepted lanes in each pattern of eight, for the rejection samplers of ML-KEM and
// ML-DSA.
#[cfg(any(feature = "ml-kem", feature = "ml-dsa"))]
static ACCEPTED: [u8; 256] = {
    let mut counts = [0; 256];

    let mut pattern = 0;

    while pattern < 256 {
        counts[pattern] = (pattern as u32).count_ones() as u8;

        pattern += 1;
    }

    counts
};

// The SHA extensions together with the SSSE3 and SSE4.1 shuffles that the kernel needs.
const SHA: u32 = 1;

// AVX2 with ymm state that the operating system saves, together with BMI1 and BMI2: every CPU
// with AVX2 has them, and the kernels that the flag selects use either.
const AVX2: u32 = 1 << 1;

// SSSE3 and SSE4.1.
const SSE41: u32 = 1 << 2;

// AES-NI, with SSE4.1 as on every CPU that has it.
const AES: u32 = 1 << 3;

// AVX-512F and AVX-512VL with the AVX2 tier, and an operating system that saves the opmask
// registers and all 32 vector registers in full. Its kernels use the EVEX forms on 256-bit
// registers only, never 512-bit ones, so that the core keeps the clock it runs AVX2 code at; they
// gain sixteen more registers, three-input logic and 64-bit rotations.
const AVX512: u32 = 1 << 4;

// AVX512 on a core that runs the one-state Keccak kernel in vector registers in less time than the
// scalar BMI kernel, by the table in one_state(). Four states take the AVX-512VL kernel on every
// core with AVX512.
const AVX512_ONE: u32 = 1 << 5;

// AVX512 on an AMD core, whose kernels take theta's values per column (keccak.rs, round_avx512).
const AVX512_AMD: u32 = 1 << 6;

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
        // AVX512_ONE and AVX512_AMD also depend on the core, which no target feature states.
        AVX512 => cfg!(all(
            target_feature = "avx512f",
            target_feature = "avx512vl",
            target_feature = "avx2",
            target_feature = "bmi1",
            target_feature = "bmi2"
        )),
        _ => false,
    }
}

// The constant-time check runs under valgrind, which cannot execute the SHA extensions or
// AVX-512, so its build leaves them out and checks the AVX2, SSE4.1 and AES-NI paths. The AVX-512
// kernels are constant-time by construction instead (keccak.rs). --cfg crypto_pq_sse41 leaves out
// AVX2, AVX-512 and the SHA extensions too, so that a CPU with them runs the SSE4.1 kernels.
const fn usable(feature: u32) -> bool {
    let avx512 = feature == AVX512 || feature == AVX512_ONE || feature == AVX512_AMD;

    if cfg!(crypto_pq_sse41) && (feature == AVX2 || avx512 || feature == SHA) {
        return false;
    }

    if cfg!(crypto_pq_ct) {
        return feature != SHA && !avx512;
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
// bit 28; leaf 7 EBX: BMI1 bit 3, AVX2 bit 5, BMI2 bit 8, AVX-512F bit 16, SHA bit 29, AVX-512VL
// bit 31. Newer Rust makes __cpuid safe, hence unused_unsafe.
// Out of line, as CPUID's registers made every kernel's caller save six, for the first call only.
#[cold]
#[inline(never)]
#[allow(unsafe_code, unused_unsafe)]
fn probe() -> u32 {
    // SAFETY: every x86-64 CPU has CPUID; the one environment where it faults, an SGX enclave,
    // compiles this module out.
    let (leaf0, leaf1) = unsafe { (__cpuid(0), __cpuid(1)) };

    let max = leaf0.eax;

    let vendor = Vendor::of(leaf0.ebx, leaf0.edx, leaf0.ecx);

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

    if found & AVX2 != 0 && leaf7.ebx & (1 << 16) != 0 && leaf7.ebx & (1 << 31) != 0 {
        // SAFETY: XGETBV exists, as AVX2 was found with OSXSAVE.
        if avx512_state(unsafe { _xgetbv(0) }) {
            found |= AVX512;

            if vendor == Vendor::Amd {
                found |= AVX512_AMD;
            }

            if one_state(vendor, leaf1.eax) {
                found |= AVX512_ONE;
            }
        }
    }

    found
}

// Whether a core with AVX512 runs the one-state AVX-512VL Keccak kernel in less time than the
// scalar BMI kernel, from the family and model in CPUID leaf 1 EAX. Measured per state, AVX-512VL
// against BMI: AMD Zen 4 (family 19h) 208 against 257 ns and Zen 5 (1Ah) 186 against 201; Intel
// Ice Lake Xeon (family 6, model 6Ah; 6Ch is Ice Lake-D, the same core) 18-23% less time on SHA-3.
// Intel's later cores have a fifth integer ALU and run the scalar kernel in as little time or
// less, BMI against AVX-512VL: Emerald Rapids (CFh) 247-254 against 254-257 ns, Granite Rapids
// (ADh) 194 against 194-203. Cores not in the table, measured or not, keep the scalar kernel, as
// before this tier, and so do cores of other vendors whatever their family and model.
fn one_state(vendor: Vendor, eax: u32) -> bool {
    let base = (eax >> 8) & 0xF;

    let family = if base == 0xF {
        base + ((eax >> 20) & 0xFF)
    } else {
        base
    };

    let model = ((eax >> 4) & 0xF)
        | if base == 0x6 || base == 0xF {
            (eax >> 12) & 0xF0
        } else {
            0
        };

    match vendor {
        Vendor::Amd => family == 0x19 || family == 0x1A,
        Vendor::Intel => family == 0x6 && (model == 0x6A || model == 0x6C),
        Vendor::Other => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
enum Vendor {
    Amd,
    Intel,
    Other,
}

impl Vendor {
    // The vendor string of CPUID leaf 0 in EBX, EDX, ECX: "AuthenticAMD" or "GenuineIntel".
    fn of(ebx: u32, edx: u32, ecx: u32) -> Self {
        match (ebx, edx, ecx) {
            (0x6874_7541, 0x6974_6E65, 0x444D_4163) => Self::Amd,
            (0x756E_6547, 0x4965_6E69, 0x6C65_746E) => Self::Intel,
            _ => Self::Other,
        }
    }
}

// XCR0 bits 5, 6 and 7 say that the operating system saves the opmask registers, the upper
// halves of zmm0-15 and zmm16-31, with bits 1 and 2 for the rest; without them an EVEX
// instruction faults.
#[cfg(not(target_os = "macos"))]
fn avx512_state(xcr0: u64) -> bool {
    xcr0 & 0xE6 == 0xE6
}

// Darwin turns the AVX-512 state on only when a thread first uses it, so XCR0 can read it as off
// while the kernel supports it; the kernel says so in sysctl instead.
#[cfg(target_os = "macos")]
fn avx512_state(_: u64) -> bool {
    sysctl_flag(c"hw.optional.avx512f") && sysctl_flag(c"hw.optional.avx512vl")
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn sysctl_flag(name: &core::ffi::CStr) -> bool {
    unsafe extern "C" {
        fn sysctlbyname(
            name: *const core::ffi::c_char,
            old: *mut core::ffi::c_void,
            length: *mut usize,
            new: *mut core::ffi::c_void,
            new_length: usize,
        ) -> core::ffi::c_int;
    }

    let mut value: u32 = 0;

    let mut length = size_of::<u32>();

    // SAFETY: name is a NUL-terminated string, and value is writable for the length passed,
    // which sysctlbyname updates to what it wrote; nothing is written to the kernel.
    let result = unsafe {
        sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &raw mut length,
            core::ptr::null_mut(),
            0,
        )
    };

    result == 0 && length == size_of::<u32>() && value == 1
}

// Whether the AVX-512VL kernels run, for four states and for one, which the kernel tests report.
#[cfg(all(
    test,
    any(
        feature = "ml-kem",
        feature = "frodokem",
        feature = "ml-dsa",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss",
        feature = "sha3"
    )
))]
pub(crate) fn avx512vl() -> (bool, bool) {
    (has(AVX512), has(AVX512_ONE))
}

// The vector form of Sponges: two groups of four sponges, lane i of sponge s of a group in word
// s of vector i. A group holds values once squeeze_wide has built it, which written records;
// ready marks the groups that hold the current sponges, and nothing reads a group before. Not
// Copy outside the tests, so that no copy of the states is made unseen.
#[cfg_attr(test, derive(Clone, Copy))]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
pub(crate) struct Wide {
    groups: [MaybeUninit<[__m256i; 25]>; 2],
    ready: u8,
    written: u8,
}

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
impl Wide {
    pub(crate) const fn new() -> Self {
        Self {
            groups: [MaybeUninit::uninit(); 2],
            ready: 0,
            written: 0,
        }
    }

    // For Sponges::start of `count` sponges: no group holds them yet. The groups that they will
    // use are written in full by their first squeeze, so only the others are wiped now; wipe wipes
    // the rest when Sponges is dropped.
    pub(crate) fn restart(&mut self, count: usize) {
        self.ready = 0;

        let reused = (1u8 << count.div_ceil(4)) - 1;

        self.clear(self.written & !reused);
    }

    // Wipes every group that holds sponges.
    pub(crate) fn wipe(&mut self) {
        self.ready = 0;

        self.clear(self.written);
    }

    #[allow(unsafe_code)]
    fn clear(&mut self, groups: u8) {
        for (g, group) in self.groups.iter_mut().enumerate() {
            if groups & (1 << g) != 0 {
                // SAFETY: written marks the groups that wide_in has written, and each store goes
                // to one of their vectors, so it is valid, aligned and exclusive; all zero bits
                // are a vector. Volatile, as the compiler must keep the stores.
                unsafe {
                    for vector in group.assume_init_mut() {
                        core::ptr::write_volatile(vector, core::mem::zeroed());
                    }
                }
            }
        }

        core::sync::atomic::compiler_fence(Ordering::SeqCst);

        self.written &= !groups;
    }
}

// BLAKE3's hash_many and extended output: eight lanes with AVX2, four with SSE4.1.
#[inline]
#[allow(unsafe_code)]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_many(input: &[u8], many: &crate::blake3::Many, out: &mut [[u8; 32]]) -> usize {
    if has(AVX2) {
        // SAFETY: the CPU has AVX2 and the operating system saves its registers.
        return unsafe { blake3::hash_many_avx2(input, many, out) };
    }

    if has(SSE41) {
        // SAFETY: the CPU has SSSE3 and SSE4.1, all that the kernel needs.
        return unsafe { blake3::hash_many_sse41(input, many, out) };
    }

    0
}

#[inline]
#[allow(unsafe_code)]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_xof(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    info: [u32; 2],
    out: &mut [[u8; 64]],
) -> usize {
    if has(AVX2) {
        // SAFETY: as in blake3_many.
        return unsafe { blake3::xof_avx2(cv, block, counter, info, out) };
    }

    if has(SSE41) {
        // SAFETY: as in blake3_many.
        return unsafe { blake3::xof_sse41(cv, block, counter, info, out) };
    }

    0
}

// BLAKE3's chain over a chunk's blocks and its single compression, a row of the state per vector.
#[inline]
#[allow(unsafe_code)]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_blocks(
    cv: &mut [u32; 8],
    blocks: &[[u8; 64]],
    counter: u64,
    flags: u32,
    edges: [u32; 2],
    last: crate::blake3::Last,
) -> bool {
    if has(AVX2) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::chain_avx2(cv, blocks, counter, flags, edges, last) };

        return true;
    }

    if has(SSE41) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::chain_sse41(cv, blocks, counter, flags, edges, last) };

        return true;
    }

    false
}

// A one-block digest of at most 32 bytes in one call.
#[inline]
#[allow(unsafe_code)]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_digest1(key: &[u32; 8], flags: u32, data: &[u8], out: &mut [u8]) -> bool {
    if has(AVX2) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::digest1_avx2(key, flags, data, out) };

        return true;
    }

    if has(SSE41) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::digest1_sse41(key, flags, data, out) };

        return true;
    }

    false
}

#[inline]
#[allow(unsafe_code)]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_compress(
    cv: &[u32; 8],
    block: &[u8; 64],
    counter: u64,
    [length, flags]: [u32; 2],
    out: &mut [u32; 16],
) -> bool {
    if has(AVX2) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::compress_avx2(cv, block, counter, length, flags, out) };

        return true;
    }

    if has(SSE41) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::compress_sse41(cv, block, counter, length, flags, out) };

        return true;
    }

    false
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
#[cfg(any(feature = "ml-kem", feature = "ml-dsa"))]
pub(crate) fn ntt(w: &mut [i32; 256], field: &Field) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: the CPU has AVX2 and the operating system saves its registers.
    unsafe { ntt::forward(w, field) };

    true
}

#[allow(unsafe_code)]
#[cfg(any(feature = "ml-kem", feature = "ml-dsa"))]
pub(crate) fn inverse_ntt(w: &mut [i32; 256], field: &Field) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { ntt::inverse(w, field) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-dsa")]
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
#[cfg(feature = "ml-dsa")]
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
#[cfg(feature = "ml-kem")]
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
#[cfg(feature = "ml-kem")]
pub(crate) fn binomial(eta: usize, lanes: &[u64], q: u16, out: &mut [u16; 256]) -> bool {
    if !matches!((eta, lanes.len()), (2, 16) | (3, 24)) || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::binomial(eta, lanes, q, out) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-dsa")]
pub(crate) fn mldsa_add(out: &mut [i32; 256], a: &[i32; 256], b: &[i32; 256], q: i32) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::combine::<true>(out, a, b, q) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-dsa")]
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
#[cfg(feature = "ml-dsa")]
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
#[cfg(feature = "ml-dsa")]
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
#[cfg(feature = "ml-dsa")]
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
#[cfg(feature = "ml-dsa")]
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
#[cfg(feature = "ml-dsa")]
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
#[cfg(feature = "ml-kem")]
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
#[cfg(feature = "ml-kem")]
pub(crate) fn reduce(w: &[i32; 256], factor: i32, field: &Field, out: &mut [u16; 256]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::reduce(w, factor, field.q, field.qinv, out) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-kem")]
pub(crate) fn encode12(f: &[u16; 256], out: &mut [u8; 384]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::encode12(f, out) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-kem")]
pub(crate) fn decode12(data: &[u8; 384], q: u16, out: &mut [u16; 256]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::decode12(data, q, out) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-kem")]
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
#[cfg(feature = "ml-kem")]
pub(crate) fn mlkem_decompress(data: &[u8], d: u32, q: u16, out: &mut [u16; 256]) -> bool {
    if !matches!(d, 4 | 5 | 10 | 11) || data.len() != 32 * d as usize || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::decompress(data, d, q, out) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-kem")]
pub(crate) fn mlkem_message(v: &[u16; 256], w: &[u16; 256], q: u16, out: &mut [u8; 32]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::message(v, w, q, out) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-kem")]
pub(crate) fn uniform12(lanes: &[u64; 21], q: u16, a: &mut [u16; 256], count: &mut usize) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::uniform12(lanes, q, a, count) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-dsa")]
pub(crate) fn uniform23(lanes: &[u64; 21], q: i32, a: &mut [i32; 256], count: &mut usize) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::uniform23(lanes, q, a, count) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-dsa")]
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
#[cfg(feature = "ml-kem")]
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
#[cfg(feature = "ml-kem")]
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
#[cfg(feature = "ml-kem")]
pub(crate) fn ntt16(f: &mut [u16; 256], field: &Field16) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::ntt(f, field) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ml-kem")]
pub(crate) fn inverse_ntt16(acc: &[i32; 256], out: &mut [u16; 256], field: &Field16) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { kem::inverse_ntt(acc, out, field) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ascon")]
pub(crate) fn ascon(s: &mut [u64; 5]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: the CPU has BMI1 and BMI2, which AVX2 implies here.
    unsafe { ascon::ascon_bmi(s) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "ascon")]
pub(crate) fn ascon_digest(start: &[u64; 5], data: &[u8], out: &mut [u8]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ascon.
    unsafe { ascon::digest_bmi(start, data, out) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "frodokem")]
pub(crate) fn aes_expand(key: &[u8], round_keys: &mut [[u8; 16]; 15]) -> bool {
    if !has(AES) {
        return false;
    }

    // SAFETY: the CPU has AES-NI and SSE4.1.
    unsafe { aes::expand(key, round_keys) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "frodokem")]
pub(crate) fn aes_encrypt(round_keys: &[[u8; 16]], blocks: &mut [[u8; 16]]) -> bool {
    if !has(AES) {
        return false;
    }

    // SAFETY: as in aes_expand.
    unsafe { aes::encrypt_blocks(round_keys, blocks) };

    true
}

// The rows of FrodoKEM's matrix A, n entries each.
#[allow(unsafe_code)]
#[cfg(feature = "frodokem")]
pub(crate) fn frodo_aes_rows(
    round_keys: &[[u8; 16]],
    rows: &mut [u16],
    n: usize,
    i0: usize,
) -> bool {
    if !has(AES) || !n.is_multiple_of(8) || n > usize::from(u16::MAX) {
        return false;
    }

    // SAFETY: as in aes_expand.
    unsafe { aes::matrix_rows(round_keys, rows, n, i0) };

    true
}

// Rows of FrodoKEM's matrix A from SHAKE128, four at a time; the number of rows must be a
// multiple of four.
#[allow(unsafe_code)]
#[cfg(feature = "frodokem")]
pub(crate) fn frodo_shake_rows(seed_a: &[u8], rows: &mut [u16], n: usize, i0: usize) -> bool {
    let Ok(seed_a) = <&[u8; 16]>::try_from(seed_a) else {
        return false;
    };

    if n == 0
        || !n.is_multiple_of(4)
        || !rows.len().is_multiple_of(4 * n)
        || i0 + rows.len() / n > 1 << 16
        || !has(AVX2)
    {
        return false;
    }

    let (wide, amd) = (has(AVX512), has(AVX512_AMD));

    for (g, group) in rows.chunks_exact_mut(4 * n).enumerate() {
        let i = i0 + 4 * g;

        // SAFETY: as in permute_many.
        unsafe {
            match (wide, amd) {
                (true, true) => keccak::matrix_rows4_avx512::<false, true>(seed_a, group, n, i),
                (true, false) => keccak::matrix_rows4_avx512::<true, false>(seed_a, group, n, i),
                _ => keccak::matrix_rows4(seed_a, group, n, i),
            }
        }
    }

    true
}

// FrodoKEM's products of eight rows of A with S, which the AVX2 kernel reads in the form S^T of
// the private key, and with S'.
#[allow(unsafe_code)]
#[cfg(feature = "frodokem")]
pub(crate) fn frodo_mul_add_as(
    acc: &mut [[u16; 8]; 8],
    rows: &[u16],
    _: &[u16],
    st: &[u8],
    n: usize,
) -> bool {
    if !n.is_multiple_of(16) || rows.len() != 8 * n || st.len() != 16 * n || !has(AVX2) {
        return false;
    }

    // SAFETY: as in permute_many.
    unsafe { frodo::mul_add_as(acc, rows, st, n) };

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "frodokem")]
pub(crate) fn frodo_mul_add_sa(
    acc: &mut [u16],
    rows: &[u16],
    column: &[[u16; 8]; 8],
    n: usize,
) -> bool {
    if !n.is_multiple_of(16) || rows.len() != 8 * n || acc.len() != 8 * n || !has(AVX2) {
        return false;
    }

    // SAFETY: as in permute_many.
    unsafe { frodo::mul_add_sa(acc, rows, column, n) };

    true
}

// Groups of four fill the AVX2 kernel.
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
pub(crate) const fn keccak_group() -> usize {
    4
}

// Absorbs the whole blocks of data, rate bytes each, into one state, and returns how many bytes
// that was.
#[allow(unsafe_code)]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
pub(crate) fn absorb(state: &mut [u64; 25], rate: usize, data: &[u8]) -> usize {
    let length = data.len() - data.len() % rate;

    if length == 0 || !has(AVX2) {
        return 0;
    }

    let blocks = &data[..length];

    if has(AVX512_ONE) {
        return absorb_avx512(state, rate, blocks);
    }

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

// absorb with the one-state AVX-512VL kernel, out of line, as permute1 is.
#[inline(never)]
#[allow(unsafe_code)]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
fn absorb_avx512(state: &mut [u64; 25], rate: usize, blocks: &[u8]) -> usize {
    let amd = has(AVX512_AMD);

    // SAFETY: absorb found AVX512_ONE: the CPU has AVX2, AVX-512F and AVX-512VL, and the operating
    // system saves the registers.
    unsafe {
        match rate {
            72 if amd => keccak::absorb_avx512::<72, false>(state, blocks.as_chunks().0),
            72 => keccak::absorb_avx512::<72, true>(state, blocks.as_chunks().0),
            104 if amd => keccak::absorb_avx512::<104, false>(state, blocks.as_chunks().0),
            104 => keccak::absorb_avx512::<104, true>(state, blocks.as_chunks().0),
            136 if amd => keccak::absorb_avx512::<136, false>(state, blocks.as_chunks().0),
            136 => keccak::absorb_avx512::<136, true>(state, blocks.as_chunks().0),
            144 if amd => keccak::absorb_avx512::<144, false>(state, blocks.as_chunks().0),
            144 => keccak::absorb_avx512::<144, true>(state, blocks.as_chunks().0),
            168 if amd => keccak::absorb_avx512::<168, false>(state, blocks.as_chunks().0),
            168 => keccak::absorb_avx512::<168, true>(state, blocks.as_chunks().0),
            _ => return 0,
        }
    }

    blocks.len()
}

// The output of a sponge of the given rate and suffix that absorbs data and is read once into
// out, in one call.
#[allow(unsafe_code)]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
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

    if has(AVX512_ONE) {
        return digest_avx512(initial, rate, suffix, data, out);
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

// digest with the one-state AVX-512VL kernel, out of line, as permute1 is.
#[inline(never)]
#[allow(unsafe_code)]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
fn digest_avx512(
    initial: Option<&[u64; 25]>,
    rate: usize,
    suffix: u8,
    data: &[u8],
    out: &mut [u8],
) -> bool {
    let amd = has(AVX512_AMD);

    // SAFETY: digest found AVX512_ONE: the CPU has AVX2, AVX-512F and AVX-512VL, and the operating
    // system saves the registers.
    unsafe {
        match rate {
            72 if amd => keccak::digest_avx512::<72, false>(initial, data, suffix, out),
            72 => keccak::digest_avx512::<72, true>(initial, data, suffix, out),
            104 if amd => keccak::digest_avx512::<104, false>(initial, data, suffix, out),
            104 => keccak::digest_avx512::<104, true>(initial, data, suffix, out),
            136 if amd => keccak::digest_avx512::<136, false>(initial, data, suffix, out),
            136 => keccak::digest_avx512::<136, true>(initial, data, suffix, out),
            144 if amd => keccak::digest_avx512::<144, false>(initial, data, suffix, out),
            144 => keccak::digest_avx512::<144, true>(initial, data, suffix, out),
            168 if amd => keccak::digest_avx512::<168, false>(initial, data, suffix, out),
            168 => keccak::digest_avx512::<168, true>(initial, data, suffix, out),
            _ => return false,
        }
    }

    true
}

#[allow(unsafe_code)]
#[cfg(feature = "blake2")]
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
#[cfg(feature = "blake2")]
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
#[cfg(feature = "blake2")]
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
#[cfg(feature = "blake2")]
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
#[cfg(feature = "blake2")]
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

// Four states per vector call, and two or three with lanes idle, which still costs less than
// their scalar permutations. One alone, as the fifth of five, takes the one-state AVX-512VL kernel
// on the cores of one_state() (AVX512_ONE), and otherwise the scalar permutation built for BMI1
// and BMI2: four in vectors beside one in general registers took no less time than one after the
// other, as both compete for the same ports.
#[inline]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
pub(crate) fn permute_many(states: &mut [&mut [u64; 25]]) -> usize {
    if !has(AVX2) {
        return 0;
    }

    let count = states.len();

    let mut rest = states;

    while !rest.is_empty() {
        let size = rest.len().min(4);

        let (group, tail) = core::mem::take(&mut rest).split_at_mut(size);

        match group {
            [only] => permute1(only),
            _ => permute4(group),
        }

        rest = tail;
    }

    count
}

// The kernels of permute_many, chosen out of line: LLVM inlines permute_many into every sponge, and
// in this form it has the size that it had with the AVX2 kernels alone, so the code around it
// stays as it was.
#[inline(never)]
#[allow(unsafe_code)]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
fn permute1(state: &mut [u64; 25]) {
    // SAFETY: permute_many found AVX2, BMI1 and BMI2, has AVX-512F and AVX-512VL where AVX512_ONE
    // is set, and the operating system saves the registers.
    unsafe {
        match (has(AVX512_ONE), has(AVX512_AMD)) {
            (true, true) => keccak::permute1_avx512::<false>(state),
            (true, false) => keccak::permute1_avx512::<true>(state),
            _ => keccak::permute_bmi(state),
        }
    }
}

#[inline(never)]
#[allow(unsafe_code)]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
fn permute4(group: &mut [&mut [u64; 25]]) {
    // SAFETY: as in permute1, with AVX512 for the AVX-512VL kernel.
    unsafe {
        if !has(AVX512) {
            keccak::permute4_avx2(group);

            return;
        }

        let mut vectors = MaybeUninit::uninit();

        let amd = has(AVX512_AMD);

        if amd {
            keccak::wide_in::<true>(&keccak::four(group), &mut vectors);
        } else {
            keccak::wide_in::<false>(&keccak::four(group), &mut vectors);
        }

        // wide_in wrote every element.
        let vectors = vectors.assume_init_mut();

        if amd {
            keccak::rounds4_avx512::<false, true>(vectors);
        } else {
            keccak::rounds4_avx512::<true, false>(vectors);
        }

        keccak::scatter4_transposed(vectors, group);
    }
}

// Whether Sponges squeezes in the vector form.
#[inline]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
pub(crate) fn squeezes_wide() -> bool {
    has(AVX512)
}

// Sponges::squeeze in the vector form, with the AVX-512VL kernel: each group of four sponges in
// which one or more are active, or which holds the spare state, is permuted in place, and the
// first `lanes` lanes of each of its active sponges are written into its state for the caller to
// read; the other lanes of the states are then out of date, and a sponge left out has moved on
// with its group in the vector form. ready marks the groups in the vector form, which the first
// squeeze after Sponges::start builds from the states. The spare state, if any, takes the slot
// after the sponges, and its lane of the vector form is wiped after use, as it lies outside the
// sponges. squeezes_wide says where there is such a kernel; elsewhere Sponges keeps its own path.
#[allow(unsafe_code)]
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
pub(crate) fn squeeze_wide(
    wide: &mut Wide,
    states: &mut [[u64; 25]],
    lanes: usize,
    active: &[bool],
    mut spare: Option<&mut [u64; 25]>,
) {
    assert!(has(AVX512), "the vector form needs the AVX-512VL kernel");

    let amd = has(AVX512_AMD);

    let count = states.len();

    for (g, group) in wide.groups.iter_mut().enumerate() {
        let sponges = (4 * g).min(count)..count.min(4 * g + 4);

        let slot = spare.is_some() && count / 4 == g;

        if !slot && !active[sponges.clone()].contains(&true) {
            continue;
        }

        // SAFETY: the CPU has AVX2, AVX-512F and AVX-512VL, and the operating system saves the
        // registers. A group is read only after wide_in has written every element of it, which
        // ready records.
        unsafe {
            if wide.ready & (1 << g) == 0 {
                let four = keccak::four_of(&states[sponges.clone()]);

                if amd {
                    keccak::wide_in::<true>(&four, group);
                } else {
                    keccak::wide_in::<false>(&four, group);
                }

                wide.ready |= 1 << g;

                wide.written |= 1 << g;
            }

            let group = group.assume_init_mut();

            let lane = spare.as_deref_mut().filter(|_| slot);

            if let Some(state) = &lane {
                keccak::spare_in(group, count % 4, state);
            }

            if amd {
                keccak::rounds4_avx512::<false, true>(group);
            } else {
                keccak::rounds4_avx512::<true, false>(group);
            }

            if let Some(state) = lane {
                keccak::spare_out(group, count % 4, state);
            }

            keccak::rows_out(group, &mut states[sponges.clone()], &active[sponges], lanes);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::Vendor::{Amd, Intel, Other};

    // CPUID leaf 1 EAX of measured and neighbouring cores, decoded with the extended family and
    // model fields.
    #[test]
    fn one_state_table() {
        let cases = [
            (Amd, 0x00A1_0F11, true),    // Zen 4, Genoa: family 19h
            (Amd, 0x00B0_0F21, true),    // Zen 5, Turin: family 1Ah
            (Amd, 0x00A0_0F11, true),    // Zen 3, Milan: family 19h, no AVX512 to reach here
            (Amd, 0x0083_0F10, false),   // Zen 2, Rome: family 17h
            (Amd, 0x0006_06A6, false),   // an Ice Lake row from AMD
            (Intel, 0x0006_06A6, true),  // Ice Lake Xeon: model 6Ah
            (Intel, 0x0006_06C1, true),  // Ice Lake-D: model 6Ch
            (Intel, 0x0005_0657, false), // Cascade Lake: model 55h
            (Intel, 0x0008_06F8, false), // Sapphire Rapids: model 8Fh
            (Intel, 0x000C_06F2, false), // Emerald Rapids: model CFh
            (Intel, 0x000A_06D1, false), // Granite Rapids: model ADh
            (Intel, 0x0007_06E5, false), // Ice Lake client: model 7Eh
            (Intel, 0x00A0_0F11, false), // a Zen 4 row from Intel
            (Intel, 0x0000_06A6, false), // model Ah without its extended model
            (Other, 0x0006_06A6, false), // an Ice Lake row from another vendor
            (Other, 0x00A0_0F11, false), // family 19h from another vendor
            (Other, 0x00B0_0F21, false), // family 1Ah from another vendor
        ];

        for (vendor, eax, expected) in cases {
            assert_eq!(
                super::one_state(vendor, eax),
                expected,
                "{vendor:?} {eax:#010x}"
            );
        }
    }

    #[test]
    fn vendor_strings() {
        let words = |name: &[u8; 12]| {
            let word =
                |i: usize| u32::from_le_bytes([name[i], name[i + 1], name[i + 2], name[i + 3]]);

            (word(0), word(4), word(8))
        };

        for (name, vendor) in [
            (b"AuthenticAMD", Amd),
            (b"GenuineIntel", Intel),
            (b"HygonGenuine", Other),
            (b"CentaurHauls", Other),
            (b"GenuineIotel", Other),
        ] {
            let (ebx, edx, ecx) = words(name);

            assert_eq!(super::Vendor::of(ebx, edx, ecx), vendor, "{name:?}");
        }
    }

    // wide_in by rows, the form of AMD cores, against the form by broadcasts, for groups of zero to
    // four states: the CPU models run both, where the native runners may all be Intel cores.
    #[test]
    #[allow(unsafe_code)]
    #[cfg(any(
        feature = "ml-kem",
        feature = "frodokem",
        feature = "ml-dsa",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss",
        feature = "sha3"
    ))]
    fn wide_in_rows_match_broadcasts() {
        use super::{keccak, memory::store256};
        use core::mem::MaybeUninit;

        if !super::has(super::AVX2) {
            return;
        }

        let mut inputs = crate::cpu::testing::Inputs::new(25);

        let states: [[u64; 25]; 4] = core::array::from_fn(|_| inputs.words());

        for count in 0..=4 {
            let four = keccak::four_of(&states[..count]);

            let mut rows = MaybeUninit::uninit();

            let mut lanes = MaybeUninit::uninit();

            let mut words = [[[0u64; 4]; 25]; 2];

            // SAFETY: the CPU has AVX2, and wide_in writes every element of both groups.
            unsafe {
                keccak::wide_in::<true>(&four, &mut rows);

                keccak::wide_in::<false>(&four, &mut lanes);

                let groups = [rows.assume_init(), lanes.assume_init()];

                for (group, out) in groups.iter().zip(&mut words) {
                    for (vector, lane) in group.iter().zip(out) {
                        store256(*vector, lane);
                    }
                }
            }

            for (i, (by_rows, by_lanes)) in words[0].iter().zip(&words[1]).enumerate() {
                let expected: [u64; 4] =
                    core::array::from_fn(|s| if s < count { states[s][i] } else { 0 });

                assert_eq!(*by_rows, expected, "{count} states, lane {i}");

                assert_eq!(*by_lanes, expected, "{count} states, lane {i}");
            }
        }
    }

    // Every form of the AVX-512VL kernels against the portable permutation, whichever vendor's
    // core runs the test: both theta forms of the four-state rounds, each fed by both forms of
    // wide_in, for one to four states, and both forms of the one-state kernel.
    #[test]
    #[allow(unsafe_code)]
    #[cfg(any(
        feature = "ml-kem",
        feature = "frodokem",
        feature = "ml-dsa",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss",
        feature = "sha3"
    ))]
    fn avx512_forms_match_portable() {
        use super::keccak;
        use core::mem::MaybeUninit;

        if !super::has(super::AVX512) {
            return;
        }

        let mut inputs = crate::cpu::testing::Inputs::new(25);

        let states: [[u64; 25]; 4] = core::array::from_fn(|_| inputs.words());

        let mut expected = states;

        for state in &mut expected {
            crate::keccak::permute(state);
        }

        type Rounds = unsafe fn(&mut [core::arch::x86_64::__m256i; 25]);

        let forms: [(&str, Rounds); 2] = [
            ("theta per lane", keccak::rounds4_avx512::<true, false>),
            ("theta per column", keccak::rounds4_avx512::<false, true>),
        ];

        for count in 1..=4 {
            for (name, rounds) in forms {
                for by_rows in [true, false] {
                    let mut out = states;

                    let mut group = MaybeUninit::uninit();

                    // SAFETY: the CPU has AVX2, AVX-512F and AVX-512VL with their state saved,
                    // and wide_in writes every element of the group.
                    unsafe {
                        if by_rows {
                            keccak::wide_in::<true>(&keccak::four_of(&states[..count]), &mut group);
                        } else {
                            keccak::wide_in::<false>(
                                &keccak::four_of(&states[..count]),
                                &mut group,
                            );
                        }

                        let group = group.assume_init_mut();

                        rounds(group);

                        let mut refs = out.each_mut();

                        keccak::scatter4_transposed(group, &mut refs[..count]);
                    }

                    assert_eq!(
                        out[..count],
                        expected[..count],
                        "{name}, rows {by_rows}, {count} states"
                    );
                }
            }
        }

        for state in &states {
            let mut expected_one = *state;

            crate::keccak::permute(&mut expected_one);

            for theta3 in [true, false] {
                let mut one = *state;

                // SAFETY: as above.
                unsafe {
                    if theta3 {
                        keccak::permute1_avx512::<true>(&mut one);
                    } else {
                        keccak::permute1_avx512::<false>(&mut one);
                    }
                }

                assert_eq!(one, expected_one, "one state, theta3 {theta3}");
            }
        }
    }
}
