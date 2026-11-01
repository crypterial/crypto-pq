// SHA-256 with the SHA extensions (SHA256RNDS2, SHA256MSG1, SHA256MSG2); AES-128 and AES-256 with
// AES-NI, which also builds the AES rows of FrodoKEM's matrix A in registers; with AVX2, BMI1 and
// BMI2 (the AVX2 tier): the SHA-256 lanes, SHA-256 without the SHA extensions and SHA-512,
// Keccak-f[1600] on four states and on one, BLAKE2b, BLAKE2s and BLAKE3, Ascon, the ML-KEM and
// ML-DSA arithmetic, sampling and encodings, and FrodoKEM's SHAKE128 rows of A and its products of
// A with the secret matrices; with AVX-512F and AVX-512VL besides, Keccak-f[1600] on four states
// and on one in 256-bit registers, and on the cores of zmm_lanes() BLAKE3 on sixteen inputs in
// 512-bit registers; BLAKE2b, BLAKE2s and BLAKE3 without AVX2 with SSE4.1. Every
// instruction that takes secret data is on Intel's list of data-operand-independent timing
// instructions or is a floating-point-domain logic, move, unpack, shuffle, insert or blend one that
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

#[cfg(feature = "blake3")]
mod blake3_zmm;

#[cfg(any(feature = "blake2", feature = "blake3"))]
mod evex;

// BLAKE's AVX-512VL kernels on every CPU with AVX512, whatever the dispatch chooses.
#[cfg(all(test, feature = "blake2", feature = "blake3"))]
mod blake_vl_tests;

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

#[cfg(feature = "blake2")]
use crate::blake2::Kernel;
#[cfg(feature = "ml-dsa")]
use crate::cpu::Pack;
#[cfg(any(feature = "ml-kem", feature = "ml-dsa"))]
use crate::cpu::{Field, Field16};
use crate::sha2::{K256, compress256_lanes_portable, last_bytes};
use crate::wipe::{wipe, wipe_unless_optimized};

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
// registers only, so that the core keeps the clock it runs AVX2 code at; they gain sixteen more
// registers, three-input logic and 64-bit rotations. The BLAKE3 kernels of ZMM_LANES alone use
// 512-bit registers.
const AVX512: u32 = 1 << 4;

// AVX512 on a core that runs the one-state Keccak kernel in vector registers in less time than the
// scalar BMI kernel, by the table in one_state(). Four states take the AVX-512VL kernel on every
// core with AVX512.
const AVX512_ONE: u32 = 1 << 5;

// AVX512 on an AMD core, whose kernels take theta's values per column (keccak.rs, round_avx512).
const AVX512_AMD: u32 = 1 << 6;

// A core that runs BLAKE2 and BLAKE3 on one message in less time in general registers than in
// the vector row form, by the table in one_message(): their single-message dispatch then chooses
// the portable code. Kernels on several messages keep the vector code, apart from BLAKE3's two
// inputs side by side in the row form (hash_many_avx2's pair).
const ONE_MESSAGE: u32 = 1 << 7;

// A core that runs BLAKE3's one-shot hashes in the code before rows_avx2 (blake3.rs, gathered), by
// the table in gather_rows(), on a core without AVX512 (whose cores of the table take the
// AVX-512VL tier). No tier test reads it.
const GATHER: u32 = 1 << 8;

// AVX512 on a core that hashes sixteen BLAKE3 inputs, and computes sixteen blocks of its extended
// output, side by side in 512-bit registers (blake3_zmm.rs), by the table in zmm_lanes().
const ZMM_LANES: u32 = 1 << 9;

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
        // AVX512_ONE, AVX512_AMD and ZMM_LANES also depend on the core, which no target feature
        // states.
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
    let avx512 =
        feature == AVX512 || feature == AVX512_ONE || feature == AVX512_AMD || feature == ZMM_LANES;

    if cfg!(crypto_pq_sse41) && (feature == AVX2 || avx512 || feature == SHA) {
        return false;
    }

    // The checks of the vector kernels run on whatever runner CI gets, so these builds keep them
    // on every core.
    let class = feature == ONE_MESSAGE || feature == GATHER;

    if class && (cfg!(crypto_pq_sse41) || cfg!(crypto_pq_ct)) {
        return false;
    }

    if cfg!(crypto_pq_ct) {
        return feature != SHA && !avx512;
    }

    true
}

static FEATURES: AtomicU32 = AtomicU32::new(0);

#[inline]
fn has(feature: u32) -> bool {
    if !usable(feature) {
        return false;
    }

    if guaranteed(feature) {
        return true;
    }

    features() & feature != 0
}

// has without the detection: false for a feature that the build does not guarantee until a call
// of has, or of features, has detected the features.
#[inline]
fn detected(feature: u32) -> bool {
    usable(feature) && (guaranteed(feature) || FEATURES.load(Ordering::Relaxed) & feature != 0)
}

// The features found, detected on the first call. Every thread that finds the cache empty computes
// the same value, so a relaxed store suffices.
#[inline]
fn features() -> u32 {
    let mut found = FEATURES.load(Ordering::Relaxed);

    if found == 0 {
        found = probe() | READY;

        FEATURES.store(found, Ordering::Relaxed);
    }

    found
}

// As has, without the first call's detection: false until another kernel's dispatch has run it.
// With no call in it, a caller whose other paths are out of line needs no saved registers.
#[inline]
#[cfg(feature = "blake3")]
fn known(feature: u32) -> bool {
    usable(feature) && (guaranteed(feature) || FEATURES.load(Ordering::Relaxed) & feature != 0)
}

// As has, for the features found by one read of them.
#[inline]
fn among(found: u32, feature: u32) -> bool {
    usable(feature) && (guaranteed(feature) || found & feature != 0)
}

// The kernels of BLAKE2 and BLAKE3 for one message, chosen by one read of the features: a read for
// each of AVX2, ONE_MESSAGE and AVX512 took a one-block digest of BLAKE3 more time.
#[cfg(any(feature = "blake2", feature = "blake3"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Blake {
    Vl,
    Avx2,
    Sse41,
    Portable,
}

// BLAKE2 takes the AVX-512VL row forms on Intel's cores only. On AMD Zen 4 (family 19h) VPRORD
// takes two cycles, where each of the two shifts and the OR it replaces takes one, and BLAKE2s-256
// of 64 bytes took 98.5 ns with VPRORD against 92.2 ns with the AVX2 form (EPYC 9V74, five
// runners); Zen 5 runs the portable code (ONE_MESSAGE).
#[inline]
#[cfg(feature = "blake2")]
fn blake2(found: u32) -> Blake {
    match blake(found) {
        Blake::Vl if among(found, AVX512_AMD) => Blake::Avx2,
        one => one,
    }
}

// Whether the word of FEATURES as read chooses the AVX2 row forms (vl false) or the AVX-512VL ones
// (vl true), as blake() would: probed, with AVX2, without ONE_MESSAGE, and without or with AVX512.
// One test of the word, where features() and blake() take a test and a branch for each bit, and
// Haswell's path to the kernel was three branches longer than before the Blake tiers.
#[inline(always)]
#[cfg(any(feature = "blake2", feature = "blake3"))]
fn tier(word: u32, vl: bool) -> bool {
    if !usable(AVX2) || vl && !usable(AVX512) {
        return false;
    }

    let mut mask = READY;

    let mut want = READY;

    if !guaranteed(AVX2) {
        mask |= AVX2;

        want |= AVX2;
    }

    if usable(ONE_MESSAGE) {
        mask |= ONE_MESSAGE;
    }

    if guaranteed(AVX512) {
        if !vl {
            return false;
        }
    } else if usable(AVX512) {
        mask |= AVX512;

        if vl {
            want |= AVX512;
        }
    }

    word & mask == want
}

// blake(features()), with the AVX2 and AVX-512VL tiers tested first on the word as read.
#[inline]
#[cfg(feature = "blake3")]
fn blake_now() -> Blake {
    let word = FEATURES.load(Ordering::Relaxed);

    if tier(word, false) {
        return Blake::Avx2;
    }

    if tier(word, true) {
        return Blake::Vl;
    }

    blake(features())
}

// blake2(features()), as blake_now.
#[inline]
#[cfg(feature = "blake2")]
fn blake2_now() -> Blake {
    if tier(FEATURES.load(Ordering::Relaxed), false) {
        return Blake::Avx2;
    }

    blake2(features())
}

#[inline]
#[cfg(any(feature = "blake2", feature = "blake3"))]
fn blake(found: u32) -> Blake {
    if among(found, AVX2) {
        if among(found, ONE_MESSAGE) {
            return Blake::Portable;
        }

        if among(found, AVX512) {
            return Blake::Vl;
        }

        return Blake::Avx2;
    }

    if among(found, SSE41) {
        return Blake::Sse41;
    }

    Blake::Portable
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

    if one_message(vendor, leaf1.eax) {
        found |= ONE_MESSAGE;
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

            if zmm_lanes(vendor, leaf1.eax) {
                found |= ZMM_LANES;
            }
        }
    }

    // Only without AVX512: a core of the table with AVX512 takes the AVX-512VL tier.
    if found & AVX512 == 0 && gather_rows(vendor, leaf1.eax) {
        found |= GATHER;
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
    let (family, model) = family_model(eax);

    match vendor {
        Vendor::Amd => family == 0x19 || family == 0x1A,
        Vendor::Intel => family == 0x6 && (model == 0x6A || model == 0x6C),
        Vendor::Other => false,
    }
}

// Whether a core with AVX512 runs BLAKE3 on sixteen inputs, or sixteen blocks of its extended
// output, in 512-bit registers (D-44), from the family and model in CPUID leaf 1 EAX: AMD Zen 4
// (family 19h) and Zen 5 (1Ah), Intel Sapphire Rapids (family 6, model 8Fh), Emerald Rapids (CFh)
// and Granite Rapids (ADh). There the blake3 crate's and rscrypto's 512-bit kernels hashed 16 KiB
// in 0.43 (Zen 5), 0.68 (Zen 4), 0.56 (Emerald Rapids) and 0.55 (Granite Rapids) of the time of
// the eight-lane AVX2 kernel (Sapphire Rapids, the core of Emerald Rapids, not measured). Ice Lake
// Xeon (6Ah, 6Ch), where those kernels took 0.70, keeps 256-bit registers, as do cores not in the
// table and cores of other vendors.
fn zmm_lanes(vendor: Vendor, eax: u32) -> bool {
    let (family, model) = family_model(eax);

    match vendor {
        Vendor::Amd => family == 0x19 || family == 0x1A,
        Vendor::Intel => family == 0x6 && matches!(model, 0x8F | 0xAD | 0xCF),
        Vendor::Other => false,
    }
}

// Whether a core runs BLAKE2b, BLAKE2s and BLAKE3 on one message in less time in general registers
// than in the vector row form, from the family and model in CPUID leaf 1 EAX. The row form is a
// chain of dependent vector instructions, and the scalar code a chain as long of one-cycle integer
// instructions. AMD Zen 5 (family 1Ah) takes two cycles for each vector integer instruction
// (EPYC 9V45: VPADDD, VPXOR and VPSHUFB each two cycles on a dependent chain, against one for
// ADD), and there the portable code took 81 ns for BLAKE2s-256 of 64 bytes, 95 ns for BLAKE2b-512
// of 64 bytes and 51 ns for BLAKE3 of 64 bytes, against 118, 141 and 74 ns for the AVX2 row forms
// (two runners).
// Cores not in the table keep the vector kernels, and so do cores of other vendors.
fn one_message(vendor: Vendor, eax: u32) -> bool {
    let (family, _) = family_model(eax);

    vendor == Vendor::Amd && family == 0x1A
}

// Whether a core runs BLAKE3's one-shot hashes in less time in the code before rows_avx2 than in
// rows_avx2 and the inlined short path, from the family and model in CPUID leaf 1 EAX: Intel's
// cores from Golden Cove on (family 6). With AVX-512 hidden, that code took 1.2% less time for 64
// bytes on Emerald Rapids (model CFh) and 2.3% less on Granite Rapids (ADh), and 0.6% less for 1
// KiB on both; its AVX2 kernels took 5% more for 1 KiB on Haswell (3Fh) and 1.1% more on AMD Zen
// 3. The other models are of the same core line, not measured: Alder Lake (97h, 9Ah), Raptor Lake
// (B7h, BAh, BFh), Sapphire Rapids (8Fh), Meteor Lake (AAh, ACh), Granite Rapids-D (AEh), Lunar
// Lake (BDh), Arrow Lake (B5h, C5h, C6h), Panther Lake (CCh, E5h) and Wildcat Lake (D5h). A core
// of the table runs that code's one-shot path behind one test of the word: its functions copied,
// its digest1 kernels instruction for instruction, and its chain and compress kernels from the
// same source, the same instructions in the release build. None of them, the E-cores of the
// hybrid chips included, falls behind that code. Intel's families 18 and 19 (Nova Lake, Diamond
// Rapids) are not in the table. Cores not in the table keep rows_avx2, and so do cores of other
// vendors.
fn gather_rows(vendor: Vendor, eax: u32) -> bool {
    const MODELS: [u32; 18] = [
        0x8F, 0x97, 0x9A, 0xAA, 0xAC, 0xAD, 0xAE, 0xB5, 0xB7, 0xBA, 0xBD, 0xBF, 0xC5, 0xC6, 0xCC,
        0xCF, 0xD5, 0xE5,
    ];

    let (family, model) = family_model(eax);

    vendor == Vendor::Intel && family == 0x6 && MODELS.contains(&model)
}

// The family and model of CPUID leaf 1 EAX, with the extended fields where they apply.
fn family_model(eax: u32) -> (u32, u32) {
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

    (family, model)
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
    let found = features();

    if among(found, AVX2) {
        let pair = !among(found, ONE_MESSAGE);

        let wide = among(found, ZMM_LANES);

        // SAFETY: the CPU has AVX2 and the operating system saves its registers, and with wide
        // AVX-512F and AVX-512VL too (ZMM_LANES is found with AVX512 only).
        return unsafe { blake3::hash_many_avx2(input, many, out, pair, wide) };
    }

    if among(found, SSE41) {
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
    let found = features();

    if among(found, AVX2) {
        if among(found, ZMM_LANES) && out.len() >= 16 {
            // SAFETY: as in blake3_many, with wide.
            return unsafe { blake3::xof_zmm(cv, block, counter, info, out) };
        }

        // SAFETY: as in blake3_many.
        return unsafe { blake3::xof_avx2(cv, block, counter, info, out) };
    }

    if among(found, SSE41) {
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
    match blake_now() {
        // SAFETY: the CPU has AVX-512F and AVX-512VL besides AVX2, and the operating system saves
        // their registers.
        Blake::Vl => unsafe { blake3::chain_vl(cv, blocks, counter, flags, edges, last) },
        // SAFETY: as in blake3_many, here and in the next.
        Blake::Avx2 => unsafe { blake3::chain_avx2(cv, blocks, counter, flags, edges, last) },
        Blake::Sse41 => unsafe { blake3::chain_sse41(cv, blocks, counter, flags, edges, last) },
        Blake::Portable => return false,
    }

    true
}

// The word of FEATURES as it is, read once for the tests of blake3_digest1_now and
// blake3_portable_now.
#[inline(always)]
#[cfg(feature = "blake3")]
pub(crate) fn word() -> u32 {
    FEATURES.load(Ordering::Relaxed)
}

// blake3_digest1 when the word of FEATURES as read chooses a vector kernel, with no probe: a test
// and a tail call, which one_shot's callers make before any frame of their own.
#[inline(always)]
#[allow(unsafe_code)]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_digest1_now(
    word: u32,
    key: &[u32; 8],
    flags: u32,
    data: &[u8],
    out: &mut [u8],
) -> bool {
    if tier(word, false) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::digest1_avx2(key, flags, data, out) };

        return true;
    }

    if tier(word, true) {
        // SAFETY: as in blake3_blocks.
        unsafe { blake3::digest1_vl(key, flags, data, out) };

        return true;
    }

    false
}

// Whether the word of FEATURES as read chooses the portable code for one message (ONE_MESSAGE).
#[inline(always)]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_portable_now(word: u32) -> bool {
    word & READY != 0 && among(word, AVX2) && among(word, ONE_MESSAGE)
}

// A one-block digest of at most 32 bytes in one call.
#[inline]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_digest1(key: &[u32; 8], flags: u32, data: &[u8], out: &mut [u8]) -> bool {
    digest1(key, flags, data, out)
}

// As blake3_digest1, from the key's bytes, which the kernels load as the words, so that the caller
// stores no converted copy of a secret key.
#[inline]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_digest1_bytes(
    key: &[u8; 32],
    flags: u32,
    data: &[u8],
    out: &mut [u8],
) -> bool {
    digest1(key, flags, data, out)
}

#[inline(always)]
#[allow(unsafe_code)]
#[cfg(feature = "blake3")]
fn digest1<K: memory::Plain, const N: usize>(
    key: &[K; N],
    flags: u32,
    data: &[u8],
    out: &mut [u8],
) -> bool {
    match blake_now() {
        // SAFETY: as in blake3_blocks.
        Blake::Vl => unsafe { blake3::digest1_vl(key, flags, data, out) },
        // SAFETY: as in blake3_many, here and in the next.
        Blake::Avx2 => unsafe { blake3::digest1_avx2(key, flags, data, out) },
        Blake::Sse41 => unsafe { blake3::digest1_sse41(key, flags, data, out) },
        Blake::Portable => return false,
    }

    true
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
    match blake_now() {
        // SAFETY: as in blake3_blocks.
        Blake::Vl => unsafe { blake3::compress_vl(cv, block, counter, length, flags, out) },
        // SAFETY: as in blake3_many, here and in the next.
        Blake::Avx2 => unsafe { blake3::compress_avx2(cv, block, counter, length, flags, out) },
        Blake::Sse41 => unsafe { blake3::compress_sse41(cv, block, counter, length, flags, out) },
        Blake::Portable => return false,
    }

    true
}

// Whether the word of FEATURES as read has GATHER: blake3.rs's digest, keyed_hash and derive_key
// then take its gathered module, one test and a branch on a word their callers have read.
#[inline(always)]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_gathered() -> bool {
    usable(GATHER) && usable(AVX2) && FEATURES.load(Ordering::Relaxed) & GATHER != 0
}

// The dispatch of blake3.rs's gathered module: blake3_digest1, blake3_digest1_bytes,
// blake3_blocks and blake3_compress of the code before rows_avx2, with its AVX2 kernels
// (rows_gather).
#[inline]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_gathered_digest1(
    key: &[u32; 8],
    flags: u32,
    data: &[u8],
    out: &mut [u8],
) -> bool {
    gathered_digest1(has, key, flags, data, out)
}

// As blake3_gathered_digest1, from the key's bytes. It does not detect the CPU (known): until
// another dispatch has, it returns false and the caller takes its blake3_gathered_digest1 path.
#[inline]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_gathered_digest1_bytes(
    key: &[u8; 32],
    flags: u32,
    data: &[u8],
    out: &mut [u8],
) -> bool {
    gathered_digest1(known, key, flags, data, out)
}

#[inline(always)]
#[allow(unsafe_code)]
#[cfg(feature = "blake3")]
fn gathered_digest1<K: memory::Plain, const N: usize>(
    has: fn(u32) -> bool,
    key: &[K; N],
    flags: u32,
    data: &[u8],
    out: &mut [u8],
) -> bool {
    if has(AVX2) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::digest1_gather(key, flags, data, out) };

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
pub(crate) fn blake3_gathered_blocks(
    cv: &mut [u32; 8],
    blocks: &[[u8; 64]],
    counter: u64,
    flags: u32,
    edges: [u32; 2],
    last: crate::blake3::Last,
) -> bool {
    if has(AVX2) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::chain_gather(cv, blocks, counter, flags, edges, last) };

        return true;
    }

    if has(SSE41) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::chain_sse41(cv, blocks, counter, flags, edges, last) };

        return true;
    }

    false
}

#[inline]
#[allow(unsafe_code)]
#[cfg(feature = "blake3")]
pub(crate) fn blake3_gathered_compress(
    cv: &[u32; 8],
    block: &[u8; 64],
    counter: u64,
    [length, flags]: [u32; 2],
    out: &mut [u32; 16],
) -> bool {
    if has(AVX2) {
        // SAFETY: as in blake3_many.
        unsafe { blake3::compress_gather(cv, block, counter, length, flags, out) };

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

// Eight lanes per vector with AVX-512VL where the count is a multiple of eight, except on AMD
// cores with SHA-NI; else SHA-NI two lanes at a time where it exists; otherwise the portable lanes
// compiled for AVX2, eight lanes per vector instead of SSE2's four. LMS, XMSS and SLH-DSA-SHA2,
// AVX-512VL against SHA-NI: Emerald Rapids 7-14% less time, Zen 4 0.5-2% and Zen 5 3-6% more.
// Always inlined: with the AVX-512VL branch LLVM no longer inlined the dispatch into
// sha2::compress256_lanes, which then paid a call per block of lanes.
#[allow(unsafe_code)]
#[inline(always)]
pub(crate) fn compress256_lanes<const LANES: usize>(
    states: &mut [[u32; LANES]; 8],
    w: &mut [[u32; LANES]; 16],
) -> bool {
    if LANES.is_multiple_of(8) && has(AVX512) && !(has(AVX512_AMD) && has(SHA)) {
        // SAFETY: the CPU has AVX-512F, AVX-512VL and AVX2, and the operating system saves their
        // registers.
        unsafe { sha2::compress256_lanes_avx512(states, w) };

        return true;
    }

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

// The one-shot hashes and HMAC in one call: with the SHA extensions the padding is built in
// registers; on the AVX2 path in memory, as the portable code does.
#[allow(unsafe_code)]
pub(crate) fn finish256(state: &mut [u32; 8], data: &[u8], bits: u64) -> bool {
    if has(SHA) {
        // SAFETY: as in compress256.
        unsafe { finish256_sha(state, data, bits) };

        return true;
    }

    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { sha2::finish256(state, data, bits) };

    true
}

// finish256 and the digest of SHA-256 or SHA-224 stored from the registers, with the SHA
// extensions; other sizes, and the other paths, store the state that finish256 leaves. Before
// the first detection this returns false, and finish256, which the caller runs then, detects:
// with no call to the detection here, a caller that takes this kernel needs no stack frame.
#[allow(unsafe_code)]
pub(crate) fn digest256(state: &[u32; 8], data: &[u8], bits: u64, out: &mut [u8]) -> bool {
    if !detected(SHA) || !matches!(out.len(), 28 | 32) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { digest256_sha(state, data, bits, out) };

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

#[allow(unsafe_code)]
pub(crate) fn hmac256(iv: &[u32; 8], key: &[u8], data: &[u8], tag: &mut [u8]) -> bool {
    if has(SHA) {
        // SAFETY: as in compress256.
        unsafe { hmac256_sha(iv, key, data, tag) };

        return true;
    }

    if !has(AVX2) {
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
    if has(SHA) {
        // SAFETY: as in compress256.
        unsafe { hmac256_keyed_sha(keyed, data, tag) };

        return true;
    }

    if !has(AVX2) {
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
// gamma2 = (q - 1) / 88; with hints, the values UseHint gives.
#[allow(unsafe_code)]
#[cfg(feature = "ml-dsa")]
pub(crate) fn mldsa_w1(
    out: &mut [u8],
    w: &[i32; 256],
    hints: Option<&[bool; 256]>,
    gamma2: i32,
    q: i32,
) -> bool {
    let bits = if gamma2 == (q - 1) / 32 { 4 } else { 6 };

    if (gamma2 != (q - 1) / 32 && gamma2 != (q - 1) / 88) || out.len() != 32 * bits || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::encode_w1(out, w, hints, gamma2, q) };

    true
}

// The coefficients mapped as `map` says and packed in `bits` bits each.
#[allow(unsafe_code)]
#[cfg(feature = "ml-dsa")]
pub(crate) fn mldsa_pack(out: &mut [u8], poly: &[i32; 256], bits: u32, map: Pack, q: i32) -> bool {
    let one = matches!(
        (bits, map),
        (3 | 4, Pack::Eta(_)) | (10, Pack::High) | (13, Pack::Low) | (18 | 20, Pack::Gamma1(_))
    );

    if !one || out.len() != 32 * bits as usize || !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::pack(out, poly, bits, map, q) };

    true
}

// t1 * 2^13 from the 320 bytes of a row of t1.
#[allow(unsafe_code)]
#[cfg(feature = "ml-dsa")]
pub(crate) fn mldsa_t1(out: &mut [i32; 256], bytes: &[u8; 320]) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { dsa::unpack_t1(out, bytes) };

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

#[cfg(feature = "ml-kem")]
pub(crate) const fn keccak_triples() -> bool {
    false
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

// Whether the word of FEATURES as read takes BLAKE2's portable code for one message
// (ONE_MESSAGE).
#[inline(always)]
#[cfg(feature = "blake2")]
fn blake2_portable(word: u32) -> bool {
    word & READY != 0 && among(word, AVX2) && among(word, ONE_MESSAGE)
}

// Whether the word of FEATURES as read takes BLAKE2's AVX2 kernels, as blake2(features()) would:
// the AVX2 tier, or the AVX-512VL one on the AMD cores that blake2() moves to AVX2 (AVX512_AMD).
#[inline(always)]
#[cfg(feature = "blake2")]
fn blake2_avx2(word: u32) -> bool {
    tier(word, false) || tier(word, true) && among(word, AVX512_AMD)
}

// The BLAKE2 functions below read FEATURES out of line: a read inlined into the generic engine
// made FEATURES visible to other crates, and so every read of it in this crate took the GOT.
#[allow(unsafe_code)]
#[cfg(feature = "blake2")]
pub(crate) fn blake2b(
    h: &mut [u64; 8],
    first: Option<&[u64; 16]>,
    blocks: &[[u8; 128]],
    counter: u128,
    last: Option<(&[u64; 16], u128)>,
) -> bool {
    match blake2_now() {
        // SAFETY: the CPU has AVX-512F and AVX-512VL besides AVX2, and the operating system saves
        // their registers.
        Blake::Vl => unsafe { blake2::blake2b_vl(h, first, blocks, counter, last) },
        // SAFETY: the CPU has AVX2 and the operating system saves its registers.
        Blake::Avx2 => unsafe { blake2::blake2b_avx2(h, first, blocks, counter, last) },
        // SAFETY: the CPU has SSSE3 and SSE4.1, all that the kernel needs.
        Blake::Sse41 => unsafe { blake2::blake2b_sse41(h, first, blocks, counter, last) },
        Blake::Portable => return false,
    }

    true
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
    let one = blake2_now();

    if let Some(kernel) = blake2s_kernel(one) {
        let mut first = first.map(blake2::bytes32);

        let mut last = last.map(|(m, total)| (blake2::bytes32(m), total as u64));

        // SAFETY: the CPU has AVX2, and AVX-512F and AVX-512VL if blake2s_kernel chose
        // their kernel; the operating system saves the registers of both.
        unsafe {
            kernel(
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

    if one != Blake::Sse41 {
        return false;
    }

    // SAFETY: the CPU has SSSE3 and SSE4.1, all that the kernel needs.
    unsafe { blake2::blake2s_sse41(h, first, blocks, counter, last) };

    true
}

// BLAKE2's digest in one call with the state in registers throughout: the generic path's word
// conversions, chaining value copies and calls cost a 64-byte message a sixth of its time.
#[cfg(feature = "blake2")]
pub(crate) fn blake2b_digest(h: &[u64; 8], data: &[u8], out: &mut [u8]) -> Kernel {
    blake2b_keyed(h, &[], data, out)
}

// BLAKE2b's MAC in the same call, the key block first.
#[cfg(feature = "blake2")]
pub(crate) fn blake2b_mac(h: &[u64; 8], key: &[u8], data: &[u8], out: &mut [u8]) -> Kernel {
    blake2b_keyed(h, key, data, out)
}

// The tiers of the word as read, then blake2b_tiers. The portable tier returns Portable, so that
// the generic code takes the portable code with no second read of FEATURES: with that read and its
// call, Zen 5 (ONE_MESSAGE) took up to 2.8% more time for a message of 0 or 64 bytes (EPYC 9V45).
// The rest out of line, so that the digest stays small enough to be inlined into its caller: out
// of line, it took 1.3 to 3.7% more time for a message of 0 or 64 bytes (EPYC 7763 and 9V74, Xeon
// 8370C).
#[inline(always)]
#[allow(unsafe_code)]
#[cfg(feature = "blake2")]
fn blake2b_keyed(h: &[u64; 8], key: &[u8], data: &[u8], out: &mut [u8]) -> Kernel {
    let word = FEATURES.load(Ordering::Relaxed);

    if blake2_avx2(word) {
        // SAFETY: the CPU has AVX2 (blake2_avx2 tests it) and the operating system saves its
        // registers.
        unsafe { blake2::blake2b_digest_avx2(h, key, data, out) };

        return Kernel::Done;
    }

    if tier(word, true) {
        // SAFETY: the CPU has AVX-512F and AVX-512VL besides AVX2 (tier tests them), and the
        // operating system saves their registers.
        unsafe { blake2::blake2b_digest_vl(h, key, data, out) };

        return Kernel::Done;
    }

    if blake2_portable(word) {
        return Kernel::Portable;
    }

    blake2b_tiers(h, key, data, out)
}

// blake2b_keyed by blake2(features()), which probes the CPU on the first call.
#[inline(never)]
#[allow(unsafe_code)]
#[cfg(feature = "blake2")]
fn blake2b_tiers(h: &[u64; 8], key: &[u8], data: &[u8], out: &mut [u8]) -> Kernel {
    match blake2(features()) {
        // SAFETY: the CPU has AVX-512F and AVX-512VL besides AVX2, and the operating system saves
        // their registers.
        Blake::Vl => unsafe { blake2::blake2b_digest_vl(h, key, data, out) },
        // SAFETY: the CPU has AVX2 and the operating system saves its registers.
        Blake::Avx2 => unsafe { blake2::blake2b_digest_avx2(h, key, data, out) },
        Blake::Sse41 => return Kernel::Blocks,
        Blake::Portable => return Kernel::Portable,
    }

    Kernel::Done
}

// The BLAKE2s kernel for one message of the AVX2 code, with AVX-512VL or without.
#[cfg(feature = "blake2")]
type Blake2sKernel = unsafe fn(
    &mut [u32; 8],
    Option<&[u8; 64]>,
    &[[u8; 64]],
    Option<(&[u8; 64], u64)>,
    u64,
    Option<&mut [u8]>,
);

#[inline]
#[cfg(feature = "blake2")]
fn blake2s_kernel(one: Blake) -> Option<Blake2sKernel> {
    match one {
        Blake::Vl => Some(blake2::blake2s_vl),
        Blake::Avx2 => Some(blake2::blake2s_avx2),
        Blake::Sse41 | Blake::Portable => None,
    }
}

// BLAKE2s's digest and MAC in one call of the AVX2 code each, with the blocks found here. One read
// of FEATURES picks the AVX2 kernel, else the portable code for one message (ONE_MESSAGE), else
// the other tiers, and one call reaches the function that calls the kernel, as before these tiers.
// Each tier calls its kernel directly, as the functions below are inlined with the kernel known.
// The digest reads FEATURES in that function, as before these tiers: on Zen 4 a read in its
// caller, then a call of the AVX2 code, took up to 1.4 ns more on a message of 0 or 64 bytes.
#[inline(never)]
#[cfg(feature = "blake2")]
pub(crate) fn blake2s_digest(h: &[u32; 8], data: &[u8], out: &mut [u8]) -> Kernel {
    let word = FEATURES.load(Ordering::Relaxed);

    if blake2_avx2(word) {
        return blake2s_digest_with(blake2::blake2s_avx2, h, data, out);
    }

    if blake2_portable(word) {
        return Kernel::Portable;
    }

    blake2s_digest_kernels(h, data, out)
}

#[cfg(feature = "blake2")]
fn blake2s_digest_kernels(h: &[u32; 8], data: &[u8], out: &mut [u8]) -> Kernel {
    match blake2(features()) {
        Blake::Vl => blake2s_digest_with(blake2::blake2s_vl, h, data, out),
        Blake::Avx2 => blake2s_digest_with(blake2::blake2s_avx2, h, data, out),
        Blake::Sse41 => Kernel::Blocks,
        Blake::Portable => Kernel::Portable,
    }
}

#[inline(always)]
#[allow(unsafe_code)]
#[cfg(feature = "blake2")]
fn blake2s_digest_with(kernel: Blake2sKernel, h: &[u32; 8], data: &[u8], out: &mut [u8]) -> Kernel {
    let (blocks, tail) = blake2::split32(data);

    // The kernel's working copy of the chaining value, wiped after it.
    let mut state = *h;

    blake2::final32(tail, |last| {
        let total = data.len() as u64;

        // SAFETY: the CPU has AVX2, and AVX-512F and AVX-512VL if blake2s_digest_kernels chose
        // their kernel (blake2_avx2 and blake2 test them); the operating system saves them.
        unsafe { kernel(&mut state, None, blocks, Some((last, total)), 0, Some(out)) };
    });

    wipe(&mut state);

    Kernel::Done
}

// The key, zero-padded to a block, comes first, or last for empty data. Dispatched as the digest.
#[inline(never)]
#[cfg(feature = "blake2")]
pub(crate) fn blake2s_mac(h: &[u32; 8], key: &[u8], data: &[u8], out: &mut [u8]) -> Kernel {
    let word = FEATURES.load(Ordering::Relaxed);

    if blake2_avx2(word) {
        return blake2s_mac_with(blake2::blake2s_avx2, h, key, data, out);
    }

    if blake2_portable(word) {
        return Kernel::Portable;
    }

    blake2s_mac_kernels(h, key, data, out)
}

#[cfg(feature = "blake2")]
fn blake2s_mac_kernels(h: &[u32; 8], key: &[u8], data: &[u8], out: &mut [u8]) -> Kernel {
    match blake2(features()) {
        Blake::Vl => blake2s_mac_with(blake2::blake2s_vl, h, key, data, out),
        Blake::Avx2 => blake2s_mac_with(blake2::blake2s_avx2, h, key, data, out),
        Blake::Sse41 => Kernel::Blocks,
        Blake::Portable => Kernel::Portable,
    }
}

#[inline(always)]
#[allow(unsafe_code)]
#[cfg(feature = "blake2")]
fn blake2s_mac_with(
    kernel: Blake2sKernel,
    h: &[u32; 8],
    key: &[u8],
    data: &[u8],
    out: &mut [u8],
) -> Kernel {
    // The kernel's working copy of the chaining value, keyed here and wiped after it: before the
    // key's copy, so that its stores reach the cache before the kernel loads them.
    let mut state = *h;

    state[0] ^= (key.len() as u32) << 8;

    let mut key_block = [0; 64];

    key_block[..key.len()].copy_from_slice(key);

    let total = 64 + data.len() as u64;

    if data.is_empty() {
        // SAFETY: the CPU has AVX2, and AVX-512F and AVX-512VL if blake2s_mac_kernels chose
        // their kernel (blake2_avx2 and blake2 test them); the operating system saves them.
        unsafe {
            kernel(
                &mut state,
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
            unsafe { kernel(&mut state, first, blocks, Some((last, total)), 0, Some(out)) };
        });
    }

    wipe(&mut key_block);

    wipe(&mut state);

    Kernel::Done
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

        wipe(memory::vector_words(vectors).as_flattened_mut());
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

// Up to four sponges of one rate and suffix, each fed a message given as its parts and read once
// into outs, all of one length of at most 64 bytes: the block is padded in the vector form,
// permuted and read from it, with no state in memory between them. It takes messages of one shape,
// the same number of parts and the same part lengths, every part but the last a whole number of
// words and fewer than rate bytes in all, which SLH-DSA's F and PRF have, and returns whether it
// did the work. One message alone takes the scalar permutation in less time than the AVX2 rounds,
// so it is left to the caller there. A missing message runs as a copy of the first, whose output
// is not read. ONE_BLOCK4: whether this build has such a kernel, which then runs where the CPU
// has AVX2.
#[cfg(feature = "slh-dsa")]
pub(crate) const ONE_BLOCK4: bool = true;

#[allow(unsafe_code)]
#[cfg(feature = "slh-dsa")]
pub(crate) fn one_block4(
    rate: usize,
    suffix: u8,
    messages: &[&[&[u8]]],
    outs: &mut [&mut [u8]],
) -> bool {
    let wide = has(AVX512);

    let count = messages.len();

    if !has(AVX2)
        || !(1..=4).contains(&count)
        || outs.len() != count
        || count == 1 && !wide
        || !rate.is_multiple_of(8)
        || !(8..=168).contains(&rate)
    {
        return false;
    }

    let shape = messages[0];

    let size = outs[0].len();

    let words = shape
        .split_last()
        .is_none_or(|(_, whole)| whole.iter().all(|part| part.len().is_multiple_of(8)));

    let length = shape
        .iter()
        .fold(0usize, |total, part| total.saturating_add(part.len()));

    let same = messages.iter().all(|message| {
        message.len() == shape.len()
            && message
                .iter()
                .zip(shape)
                .all(|(part, first)| part.len() == first.len())
    });

    if size > 64
        || size > rate
        || outs.iter().any(|out| out.len() != size)
        || !words
        || length >= rate
        || !same
    {
        return false;
    }

    let four = core::array::from_fn(|s| messages.get(s).copied().unwrap_or(shape));

    // SAFETY: the CPU has AVX2, and AVX-512F and AVX-512VL where AVX512 is set, and the operating
    // system saves the registers.
    unsafe {
        match (wide, has(AVX512_AMD)) {
            (true, true) => keccak::one_block4_avx512::<false, true>(&four, rate, suffix, outs),
            (true, false) => keccak::one_block4_avx512::<true, false>(&four, rate, suffix, outs),
            _ => keccak::one_block4_avx2(&four, rate, suffix, outs),
        }
    }

    true
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

// SAFETY: six vectors in 96 bytes, which the assertion checks, leave no room for padding.
#[cfg(not(crypto_pq_optimized))]
#[allow(unsafe_code)]
unsafe impl memory::Vectors for Stream {}

const _: () = assert!(size_of::<Stream>() == size_of::<[__m128i; 6]>());

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

// Two streams kept in step: an empty assembly block that takes and gives back the state and the
// message words of both, so that LLVM cannot run the schedule of one stream far ahead of its
// rounds. At codegen-units 16 it did, and spilled ten message words of the last 16 rounds.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[inline]
#[allow(unsafe_code)]
fn in_step(streams: &mut [Stream]) {
    if let [x, y] = streams {
        let [x0, x1, x2, x3] = &mut x.m;

        let [y0, y1, y2, y3] = &mut y.m;

        // SAFETY: the assembly is empty: it reads and writes the twelve registers it names and
        // nothing else, no memory, stack or flags.
        unsafe {
            core::arch::asm!(
                "/* {} {} {} {} {} {} {} {} {} {} {} {} */",
                inout(xmm_reg) x.abef,
                inout(xmm_reg) x.cdgh,
                inout(xmm_reg) *x0,
                inout(xmm_reg) *x1,
                inout(xmm_reg) *x2,
                inout(xmm_reg) *x3,
                inout(xmm_reg) y.abef,
                inout(xmm_reg) y.cdgh,
                inout(xmm_reg) *y0,
                inout(xmm_reg) *y1,
                inout(xmm_reg) *y2,
                inout(xmm_reg) *y3,
                options(pure, nomem, nostack, preserves_flags),
            );
        }
    }
}

// The sixteen quarters of the rounds, written out so that whether a quarter extends the schedule
// is a constant; with in_step after each, the loop over them was left rolled.
macro_rules! quarters {
    ($streams:ident, $n:literal, $k:ident; $($q:literal $j:literal $schedule:literal),+) => {
        $(
            quarter::<$n, $j>(&mut $streams, low_first($k[$q]), $schedule);

            in_step(&mut $streams);
        )+
    };
}

// The 64 rounds of N streams and the feed-forward, written out at each call site: target_feature
// functions cannot be inline(always), and rounds256::<2> was not inlined at codegen-units 16, which
// left both streams in memory.
macro_rules! rounds256 {
    ($streams:ident, $n:literal) => {{
        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut start = $streams;

        let k = K256.as_chunks::<4>().0;

        quarters!(
            $streams, $n, k;
            0 0 true, 1 1 true, 2 2 true, 3 3 true,
            4 0 true, 5 1 true, 6 2 true, 7 3 true,
            8 0 true, 9 1 true, 10 2 true, 11 3 true,
            12 0 false, 13 1 false, 14 2 false, 15 3 false
        );

        for (stream, start) in $streams.iter_mut().zip(&start) {
            stream.abef = _mm_add_epi32(stream.abef, start.abef);

            stream.cdgh = _mm_add_epi32(stream.cdgh, start.cdgh);
        }

        wipe_unless_optimized!(memory::words_of(&mut start));
    }};
}

// A state as one stream, its schedule words empty: two loads and four shuffles, where the words
// one at a time took eight loads and as many inserts on the path to the first round.
#[target_feature(enable = "sse4.1")]
#[inline]
fn stream_of(state: &[u32; 8]) -> Stream {
    let [abcd, efgh] = state.as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    // Lanes b, a, d, c and h, g, f, e.
    let badc = _mm_shuffle_epi32::<0xB1>(memory::load128(abcd));

    let hgfe = _mm_shuffle_epi32::<0x1B>(memory::load128(efgh));

    Stream {
        abef: _mm_alignr_epi8::<8>(badc, hgfe),
        cdgh: _mm_blend_epi16::<0xF0>(hgfe, badc),
        m: [_mm_setzero_si128(); 4],
    }
}

// The inverse of stream_of.
#[target_feature(enable = "sse4.1")]
#[inline]
fn state_of(stream: &Stream, state: &mut [u32; 8]) {
    let [abcd, efgh] = state.as_chunks_mut::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    // Lanes a, b, e, f and g, h, c, d.
    let abef = _mm_shuffle_epi32::<0x1B>(stream.abef);

    let ghcd = _mm_shuffle_epi32::<0xB1>(stream.cdgh);

    memory::store128(_mm_blend_epi16::<0xF0>(abef, ghcd), abcd);

    memory::store128(_mm_alignr_epi8::<8>(ghcd, abef), efgh);
}

// The words of state_of as big-endian bytes, the 32 of a digest or the 28 of SHA-224's, stored
// from the registers, so that no copy of the state waits on the stack to be swapped and wiped.
#[target_feature(enable = "ssse3,sse4.1")]
#[inline]
fn digest_of(stream: &Stream, out: &mut [u8]) {
    let abef = _mm_shuffle_epi32::<0x1B>(stream.abef);

    let ghcd = _mm_shuffle_epi32::<0xB1>(stream.cdgh);

    let swap = _mm_set_epi64x(0x0C0D_0E0F_0809_0A0B, 0x0405_0607_0001_0203);

    let abcd = _mm_shuffle_epi8(_mm_blend_epi16::<0xF0>(abef, ghcd), swap);

    let efgh = _mm_shuffle_epi8(_mm_alignr_epi8::<8>(ghcd, abef), swap);

    match out.as_chunks_mut::<16>() {
        ([first, second], []) => {
            memory::store128(abcd, first);

            memory::store128(efgh, second);
        }
        ([first], rest) => {
            memory::store128(abcd, first);

            // SHA-224's digest ends with words e, f and g.
            let ([e, f, g], []) = rest.as_chunks_mut::<4>() else {
                unreachable!("a digest of 32 or 28 bytes")
            };

            *e = _mm_cvtsi128_si32(efgh).to_le_bytes();

            *f = _mm_extract_epi32::<1>(efgh).to_le_bytes();

            *g = _mm_extract_epi32::<2>(efgh).to_le_bytes();
        }
        _ => unreachable!("a digest of 32 or 28 bytes"),
    }
}

// Sixteen bytes whose little-endian value is `value` as four big-endian schedule words, the first
// in the lowest lane.
#[target_feature(enable = "ssse3")]
#[inline]
fn value_words(value: u128) -> __m128i {
    let swap = _mm_set_epi64x(0x0C0D_0E0F_0809_0A0B, 0x0405_0607_0001_0203);

    _mm_shuffle_epi8(_mm_set_epi64x((value >> 64) as i64, value as i64), swap)
}

#[target_feature(enable = "ssse3")]
#[inline]
fn chunk_words(bytes: &[u8; 16]) -> __m128i {
    value_words(u128::from_le_bytes(*bytes))
}

// The schedule words of a block.
#[target_feature(enable = "ssse3")]
#[inline]
fn block_words(block: &[u8; 64], m: &mut [__m128i; 4]) {
    for (m, bytes) in m.iter_mut().zip(block.as_chunks::<16>().0) {
        *m = chunk_words(bytes);
    }
}

// Chunk i of a block whose bytes are whole (whole 16-byte chunks), then the bytes that chunk
// holds, then zeros: the padded last block of a message, with the marker in chunk, or an HMAC key.
#[target_feature(enable = "ssse3")]
#[inline]
fn last_chunk(whole: &[[u8; 16]], i: usize, chunk: u128) -> __m128i {
    match whole.get(i) {
        Some(bytes) => chunk_words(bytes),
        None if i == whole.len() => value_words(chunk),
        None => _mm_setzero_si128(),
    }
}

// The streaming hash: the state stays in registers from one block to the next.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn compress256_sha(state: &mut [u32; 8], blocks: &[[u8; 64]], more: &[[u8; 64]]) {
    let mut streams = [stream_of(state)];

    // One loop over both slices, so that the rounds are written out once.
    for part in [blocks, more] {
        for block in part {
            block_words(block, &mut streams[0].m);

            rounds256!(streams, 1);
        }
    }

    state_of(&streams[0], state);

    wipe_unless_optimized!(memory::words_of(&mut streams));
}

// The whole blocks of data and then its padded last block or two, on one stream, for a message of
// `bits` bits that ends with data, the padding built in registers as in the aarch64 tail256. The
// stream's schedule words keep message words, which are wiped with the stream. A macro, as
// rounds256 is, for the two functions that differ in how they store the state.
macro_rules! finish_stream256 {
    ($streams:ident, $data:expr, $bits:expr) => {{
        let data: &[u8] = $data;

        let bits: u64 = $bits;

        let (blocks, tail) = data.as_chunks::<64>();

        let (whole, rest) = tail.as_chunks::<16>();

        let marker = last_bytes(data, rest.len()) | 0x80 << (8 * rest.len());

        // The length field: words 14 and 15 of the last block.
        let length = _mm_set_epi32(bits as i32, (bits >> 32) as i32, 0, 0);

        for block in blocks {
            block_words(block, &mut $streams[0].m);

            rounds256!($streams, 1);
        }

        $streams[0].m = [
            last_chunk(whole, 0, marker),
            last_chunk(whole, 1, marker),
            last_chunk(whole, 2, marker),
            last_chunk(whole, 3, marker),
        ];

        // The padded blocks in a loop of their own, so that the rounds are written out twice, not
        // three times: the one with the tail and the marker, then, when the length does not fit
        // there, one of zeros and the length. The tail's words are built after the whole blocks,
        // so that no copy of them waits on the stack.
        let mut padded = if tail.len() + 9 > 64 {
            2
        } else {
            $streams[0].m[3] = _mm_or_si128($streams[0].m[3], length);

            1
        };

        loop {
            rounds256!($streams, 1);

            padded -= 1;

            if padded == 0 {
                break;
            }

            let zero = _mm_setzero_si128();

            $streams[0].m = [zero, zero, zero, length];
        }
    }};
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn finish256_sha(state: &mut [u32; 8], data: &[u8], bits: u64) {
    let mut streams = [stream_of(state)];

    finish_stream256!(streams, data, bits);

    state_of(&streams[0], state);

    wipe_unless_optimized!(memory::words_of(&mut streams));
}

// finish256_sha for a digest of 32 bytes or its truncation to 28, stored from the registers.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn digest256_sha(state: &[u32; 8], data: &[u8], bits: u64, out: &mut [u8]) {
    let mut streams = [stream_of(state)];

    finish_stream256!(streams, data, bits);

    digest_of(&streams[0], out);

    wipe_unless_optimized!(memory::words_of(&mut streams));
}

// The HMAC key block (a key of at most a block, zero-padded) XORed with pad in every byte, as
// schedule words: the XOR of a byte in every position commutes with the byte swap.
#[target_feature(enable = "ssse3")]
#[inline]
fn key_block(key: &[u8], pad: u8) -> [__m128i; 4] {
    debug_assert!(key.len() <= 64, "an HMAC key block takes at most 64 bytes");

    let (whole, rest) = key.as_chunks::<16>();

    let partial = last_bytes(key, rest.len());

    let pads = _mm_set1_epi8(pad as i8);

    [
        _mm_xor_si128(last_chunk(whole, 0, partial), pads),
        _mm_xor_si128(last_chunk(whole, 1, partial), pads),
        _mm_xor_si128(last_chunk(whole, 2, partial), pads),
        _mm_xor_si128(last_chunk(whole, 3, partial), pads),
    ]
}

// HMAC-SHA-256, or HMAC-SHA-224 for a 28-byte tag, of data under a key of at most a block, in one
// call: both key blocks as two streams, the inner hash through data and its padding, and the
// outer hash of the inner digest, as the aarch64 hmac256_sha2 does. The keyed states wait in
// `states`, which is wiped, for the call to finish256_sha.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn hmac256_sha(iv: &[u32; 8], key: &[u8], data: &[u8], tag: &mut [u8]) {
    debug_assert!(key.len() <= 64, "a long key is hashed first");

    let start = stream_of(iv);

    let mut keys = [start, start];

    keys[0].m = key_block(key, 0x36);

    keys[1].m = key_block(key, 0x5C);

    rounds256!(keys, 2);

    let mut states = [[0; 8]; 2];

    state_of(&keys[0], &mut states[0]);

    state_of(&keys[1], &mut states[1]);

    after_keys256_sha(&mut states, data, tag);

    wipe(states.as_flattened_mut());

    wipe_unless_optimized!(memory::words_of(&mut keys));
}

// HMAC-SHA-256 or HMAC-SHA-224 from the states after the inner and the outer key block, which
// `states` holds; the inner hash overwrites the first.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[inline]
fn after_keys256_sha(states: &mut [[u32; 8]; 2], data: &[u8], tag: &mut [u8]) {
    finish256_sha(
        &mut states[0],
        data,
        (data.len() as u64).wrapping_add(64).wrapping_mul(8),
    );

    let [first, second] = states[0].as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    let mut outer = [stream_of(&states[1])];

    // The outer block is the inner digest's words, the marker word and the length.
    let bits = ((64 + tag.len() as u32) * 8) as i32;

    let marker = 0x8000_0000_u32 as i32;

    outer[0].m = if tag.len() == 32 {
        [
            memory::load128(first),
            memory::load128(second),
            _mm_set_epi32(0, 0, 0, marker),
            _mm_set_epi32(bits, 0, 0, 0),
        ]
    } else {
        [
            memory::load128(first),
            _mm_insert_epi32::<3>(memory::load128(second), marker),
            _mm_setzero_si128(),
            _mm_set_epi32(bits, 0, 0, 0),
        ]
    };

    rounds256!(outer, 1);

    digest_of(&outer[0], tag);

    wipe_unless_optimized!(memory::words_of(&mut outer));
}

// hmac256_sha from the keyed states, for many messages under one key: HKDF's expansion.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn hmac256_keyed_sha(keyed: &[[u32; 8]; 2], data: &[u8], tag: &mut [u8]) {
    let mut states = *keyed;

    after_keys256_sha(&mut states, data, tag);

    wipe(states.as_flattened_mut());
}

#[target_feature(enable = "sse2")]
#[inline]
#[cfg_attr(crypto_pq_optimized, allow(clippy::let_and_return))]
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

    let stream = Stream {
        abef: high_first([word(0), word(1), word(4), word(5)]),
        cdgh: high_first([word(2), word(3), word(6), word(7)]),
        m,
    };

    wipe_unless_optimized!(memory::words_of(&mut m));

    stream
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

        rounds256!(streams, 2);

        scatter(states, &streams[0], lane);

        scatter(states, &streams[1], lane + 1);

        wipe_unless_optimized!(memory::words_of(&mut streams));

        lane += 2;
    }

    if lane < LANES {
        let mut streams = [gather(states, w, lane)];

        rounds256!(streams, 1);

        scatter(states, &streams[0], lane);

        wipe_unless_optimized!(memory::words_of(&mut streams));
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

#[allow(unsafe_code)]
#[cfg(feature = "ml-dsa")]
pub(crate) fn vector_scope<R>(f: impl FnOnce() -> R) -> Option<R> {
    #[target_feature(enable = "avx2")]
    fn scope<R>(f: impl FnOnce() -> R) -> R {
        f()
    }

    if !has(AVX2) {
        return None;
    }

    // SAFETY: as in ntt.
    Some(unsafe { scope(f) })
}

#[cfg(feature = "ml-dsa")]
pub(crate) fn one_state_keccak() -> bool {
    has(AVX512_ONE)
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

    // The AVX-512VL lanes of SHA-256 against the portable lanes, for eight and sixteen lanes over
    // several blocks on random inputs, edge words included.
    #[test]
    #[allow(unsafe_code)]
    fn sha256_lanes_avx512_kernel_matches_portable() {
        fn check<const LANES: usize>(inputs: &mut crate::cpu::testing::Inputs) {
            let mut kernel: [[u32; LANES]; 8] =
                core::array::from_fn(|_| core::array::from_fn(|_| inputs.next() as u32));

            let mut portable = kernel;

            for block in 0..4 {
                let w: [[u32; LANES]; 16] = core::array::from_fn(|t| {
                    core::array::from_fn(|lane| match (block + t + lane) % 7 {
                        0 => 0,
                        1 => u32::MAX,
                        _ => inputs.next() as u32,
                    })
                });

                // SAFETY: the caller checked that the CPU has AVX-512F, AVX-512VL and AVX2.
                unsafe { super::sha2::compress256_lanes_avx512(&mut kernel, &w) };

                crate::sha2::compress256_lanes_portable(&mut portable, &mut w.clone());

                assert_eq!(kernel, portable, "{LANES} lanes, block {block}");
            }
        }

        let ran = super::has(super::AVX512);

        std::eprintln!("SHA-256 lanes: AVX-512VL kernel {ran}");

        if !ran {
            return;
        }

        let mut inputs = crate::cpu::testing::Inputs::new(256);

        for _ in 0..500 {
            check::<8>(&mut inputs);

            check::<16>(&mut inputs);
        }
    }

    #[test]
    fn one_message_table() {
        let cases = [
            (Amd, 0x00B0_0F21, true),    // Zen 5, Turin: family 1Ah
            (Amd, 0x00B4_0F40, true),    // Zen 5 client: family 1Ah, model 44h
            (Amd, 0x00A1_0F11, false),   // Zen 4, Genoa: family 19h
            (Amd, 0x00A0_0F11, false),   // Zen 3, Milan: family 19h
            (Amd, 0x0083_0F10, false),   // Zen 2, Rome: family 17h
            (Intel, 0x00B0_0F21, false), // a Zen 5 row from Intel
            (Intel, 0x000C_06F2, false), // Emerald Rapids: model CFh
            (Other, 0x00B0_0F21, false), // family 1Ah from another vendor
        ];

        for (vendor, eax, expected) in cases {
            assert_eq!(
                super::one_message(vendor, eax),
                expected,
                "{vendor:?} {eax:#010x}"
            );
        }
    }

    #[test]
    fn gather_table() {
        let cases = [
            (Intel, 0x000C_06F2, true),  // Emerald Rapids: model CFh
            (Intel, 0x0008_06F8, true),  // Sapphire Rapids: model 8Fh
            (Intel, 0x0009_0672, true),  // Alder Lake-S: model 97h
            (Intel, 0x000B_0671, true),  // Raptor Lake-S: model B7h
            (Intel, 0x000A_06D1, true),  // Granite Rapids: model ADh
            (Intel, 0x000C_0662, true),  // Arrow Lake-S: model C6h
            (Intel, 0x0003_06C3, false), // Haswell: model 3Ch
            (Intel, 0x0003_06F2, false), // Haswell-E: model 3Fh
            (Intel, 0x0005_0657, false), // Cascade Lake: model 55h
            (Intel, 0x0006_06A6, false), // Ice Lake Xeon: model 6Ah
            (Intel, 0x0009_06A4, true),  // Alder Lake-P: model 9Ah
            (Intel, 0x000B_0650, true),  // Arrow Lake-U: model B5h
            (Intel, 0x000D_0650, true),  // Wildcat Lake: model D5h
            (Intel, 0x000E_0650, true),  // Panther Lake-R: model E5h
            (Intel, 0x0030_0F10, false), // Nova Lake: family 18
            (Intel, 0x000B_06E0, false), // Alder Lake-N, E-cores only: model BEh
            (Intel, 0x000A_06F3, false), // Sierra Forest, E-cores: model AFh
            (Intel, 0x0000_06F2, false), // model Fh without its extended model
            (Amd, 0x000C_06F2, false),   // an Emerald Rapids row from AMD
            (Amd, 0x00A0_0F11, false),   // Zen 3, Milan: family 19h
            (Other, 0x000C_06F2, false), // an Emerald Rapids row from another vendor
        ];

        for (vendor, eax, expected) in cases {
            assert_eq!(
                super::gather_rows(vendor, eax),
                expected,
                "{vendor:?} {eax:#010x}"
            );
        }
    }

    // rows_gather against rows_avx2, which the dispatch reaches on every other AVX2 core, on every
    // short length, the full block and a chain with and without a partial last block.
    #[test]
    #[allow(unsafe_code)]
    #[cfg(feature = "blake3")]
    fn rows_gather_matches_rows_avx2() {
        use super::blake3::{
            chain_avx2, chain_gather, compress_avx2, compress_gather, digest1_avx2, digest1_gather,
        };

        if !super::has(super::AVX2) {
            return;
        }

        let mut inputs = crate::cpu::testing::Inputs::new(26);

        let key: [u32; 8] = core::array::from_fn(|_| u32::from_le_bytes(inputs.bytes()));

        let data: [u8; 64] = inputs.bytes();

        for n in 0..=64 {
            for size in [1, 16, 31, 32] {
                let mut a = [0; 32];

                let mut b = [0; 32];

                // SAFETY: the CPU has AVX2 and the operating system saves its registers.
                unsafe {
                    digest1_avx2(&key, 11, &data[..n], &mut a[..size]);

                    digest1_gather(&key, 11, &data[..n], &mut b[..size]);
                }

                assert_eq!(a, b, "digest1 of {n} bytes into {size}");
            }
        }

        let blocks: [[u8; 64]; 5] = core::array::from_fn(|_| inputs.bytes());

        for last in [None, Some((&blocks[4], 23, 10))] {
            let mut a = key;

            let mut b = key;

            // SAFETY: as above.
            unsafe {
                chain_avx2(&mut a, &blocks[..4], 7, 0, [1, 2], last);

                chain_gather(&mut b, &blocks[..4], 7, 0, [1, 2], last);
            }

            assert_eq!(a, b, "chain, last block {:?}", last.map(|l| l.1));
        }

        let mut a = [0; 16];

        let mut b = [0; 16];

        // SAFETY: as above.
        unsafe {
            compress_avx2(&key, &blocks[0], 9, 40, 27, &mut a);

            compress_gather(&key, &blocks[0], 9, 40, 27, &mut b);
        }

        assert_eq!(a, b, "compress");
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

    // load128_bytes at every offset that keeps its sixteen bytes inside the array, and its
    // assertion at the first offset past them and at offsets where offset + 16 would wrap.
    #[test]
    #[allow(unsafe_code)]
    fn bytes_load_stays_inside() {
        use super::memory::{load128_bytes, store128};

        let lanes: [u64; 21] =
            core::array::from_fn(|i| 0x0706_0504_0302_0100 + 0x0808_0808_0808_0808 * i as u64);

        for offset in 0..=152 {
            let mut out = [0u8; 16];

            // SAFETY: every x86-64 CPU has SSE2.
            unsafe { store128(load128_bytes(&lanes, offset), &mut out) };

            let expected: [u8; 16] = core::array::from_fn(|i| (offset + i) as u8);

            assert_eq!(out, expected, "offset {offset}");
        }

        for offset in [153, usize::MAX - 15, usize::MAX] {
            // SAFETY: as above.
            let load = std::panic::catch_unwind(|| unsafe { load128_bytes(&lanes, offset) });

            assert!(load.is_err(), "offset {offset}");
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

    // spare_in and spare_out in every lane: the state goes into lane j alone and comes back out,
    // which leaves lane j zero and the other lanes as they were. Both need AVX2 only, so the CPU
    // models run them, where the AVX-512VL path that calls them needs a native runner.
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
    fn keccak_spare_lane_in_and_out() {
        use super::{keccak, memory::store256};
        use core::mem::MaybeUninit;

        if !super::has(super::AVX2) {
            return;
        }

        let mut inputs = crate::cpu::testing::Inputs::new(25);

        let states: [[u64; 25]; 4] = core::array::from_fn(|_| inputs.words());

        let spare: [u64; 25] = inputs.words();

        let words = |group: &[core::arch::x86_64::__m256i; 25]| {
            let mut words = [[0u64; 4]; 25];

            for (vector, lane) in group.iter().zip(&mut words) {
                // SAFETY: the CPU has AVX2.
                unsafe { store256(*vector, lane) };
            }

            words
        };

        for j in 0..4 {
            let mut group = MaybeUninit::uninit();

            // SAFETY: the CPU has AVX2, and wide_in writes every element of the group.
            let mut group = unsafe {
                keccak::wide_in::<false>(&keccak::four_of(&states), &mut group);

                group.assume_init()
            };

            // SAFETY: the CPU has AVX2.
            unsafe { keccak::spare_in(&mut group, j, &spare) };

            for (i, lane) in words(&group).iter().enumerate() {
                let expected: [u64; 4] =
                    core::array::from_fn(|s| if s == j { spare[i] } else { states[s][i] });

                assert_eq!(*lane, expected, "in, slot {j}, lane {i}");
            }

            let mut out = [0u64; 25];

            // SAFETY: the CPU has AVX2.
            unsafe { keccak::spare_out(&mut group, j, &mut out) };

            assert_eq!(out, spare, "out, slot {j}");

            for (i, lane) in words(&group).iter().enumerate() {
                let expected: [u64; 4] =
                    core::array::from_fn(|s| if s == j { 0 } else { states[s][i] });

                assert_eq!(*lane, expected, "cleared, slot {j}, lane {i}");
            }
        }
    }

    // Every form of the AVX-512VL kernels against the portable permutation, whichever vendor's
    // core runs the test: both theta forms of the four-state rounds, each fed by both forms of
    // wide_in, for one to four states, and both forms of the one-state kernel, which permute1 and
    // digest call, and of its absorption at every rate.
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

        let data: [u8; 336] = inputs.bytes();

        macro_rules! absorb {
            ($($rate:literal)*) => {
                $(
                    let blocks = data.as_chunks::<$rate>().0;

                    let mut portable = states[0];

                    for block in blocks {
                        for (lane, bytes) in portable.iter_mut().zip(block.as_chunks().0) {
                            *lane ^= u64::from_le_bytes(*bytes);
                        }

                        crate::keccak::permute(&mut portable);
                    }

                    for theta3 in [true, false] {
                        let mut absorbed = states[0];

                        // SAFETY: as above.
                        unsafe {
                            if theta3 {
                                keccak::absorb_avx512::<$rate, true>(&mut absorbed, blocks);
                            } else {
                                keccak::absorb_avx512::<$rate, false>(&mut absorbed, blocks);
                            }
                        }

                        assert_eq!(absorbed, portable, "rate {}, theta3 {theta3}", $rate);
                    }
                )*
            };
        }

        absorb!(72 104 136 144 168);
    }
}
