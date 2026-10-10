// SHA-256 with the ARMv8 SHA2 instructions, SHA-512 with the ARMv8.2 SHA512 instructions and
// Keccak-f[1600] with the ARMv8.2 SHA3 instructions; the NEON transforms of ML-KEM and ML-DSA and
// their noise and rejection sampling are in the submodules. All of them are on Arm's list of
// instructions whose timing does not depend on their data (FEAT_DIT), and the code around them
// has no branch or address that depends on secret data (sample.rs explains the one pattern it
// declassifies). The kernels are safe code inside #[target_feature] functions, apart from the
// loads and stores of memory.rs and the rounds of SHA-256 and Keccak that are written in
// assembly; what is otherwise unsafe is calling one once its feature is known to be there,
// asking the operating system for the features, and setting the DIT bit.

use core::arch::aarch64::*;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::keccak::{self, ROUND_CONSTANTS};
use crate::sha2::{K256, K512, last_bytes};
use crate::wipe::wipe;

mod ascon;

mod binomial;

mod dsa;

mod memory;

mod ntt;

mod pack;

mod sample;

use memory::{load_u8, load_u32, load_u64, store_u8, store_u32, store_u64};

pub(crate) use ascon::{ascon, ascon_digest};

pub(crate) use binomial::binomial;

pub(crate) use dsa::{
    add as mldsa_add, encode_w1 as mldsa_w1, hints as mldsa_hints, norm as mldsa_norm,
    sub as mldsa_sub, unpack_mask as mldsa_mask,
};

pub(crate) use pack::{encode12, reduce};

pub(crate) use sample::{bounded, uniform12, uniform23};

pub(crate) use ntt::{
    base_multiply_add, inverse_ntt, inverse_ntt16, mlkem_matrix_vector, multiply, multiply_add,
    ntt, ntt16,
};

const SHA2: u32 = 1;

// FEAT_SHA3 together with FEAT_SHA512: Rust's sha3 target feature enables both.
const SHA3: u32 = 1 << 1;

// SHA3 on a core where two Keccak states in vector registers beat two scalar permutations. Apple
// cores run EOR3, RAX1, XAR and BCAX on every vector pipe and take half the time per state.
// Neoverse N2, V1 and V2 run them on one pipe, and published measurements found them slower than
// scalar code there, so other cores keep the scalar permutation until they are measured.
const KECCAK: u32 = 1 << 2;

const DIT: u32 = 1 << 3;

const READY: u32 = 1 << 31;

// What the build guarantees needs no detection, and its check folds away. On Apple targets every
// arm is true, which clippy would rather see as matches!.
#[allow(clippy::match_like_matches_macro)]
const fn guaranteed(feature: u32) -> bool {
    if cfg!(crypto_pq_ct) {
        return false;
    }

    match feature {
        SHA2 => cfg!(target_feature = "sha2"),
        SHA3 => cfg!(target_feature = "sha3"),
        KECCAK => cfg!(all(target_vendor = "apple", target_feature = "sha3")),
        DIT => cfg!(target_feature = "dit"),
        _ => false,
    }
}

// The constant-time check runs under valgrind, which cannot execute the SHA3, SHA512 and DIT
// instructions in every version, so its build leaves them out and checks the rest.
const fn usable(feature: u32) -> bool {
    if cfg!(crypto_pq_ct) {
        return feature == SHA2;
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

// The HWCAP bits of the Linux arm64 ABI, which Android shares.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
fn probe() -> u32 {
    unsafe extern "C" {
        fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
    }

    const AT_HWCAP: core::ffi::c_ulong = 16;

    const HWCAP_SHA2: u64 = 1 << 6;

    const HWCAP_CPUID: u64 = 1 << 11;

    const HWCAP_SHA3: u64 = 1 << 17;

    const HWCAP_SHA512: u64 = 1 << 21;

    const HWCAP_DIT: u64 = 1 << 24;

    // SAFETY: getauxval reads the auxiliary vector the kernel passed to the process; it has no
    // preconditions and cannot fail.
    let hwcap = unsafe { getauxval(AT_HWCAP) };

    // c_ulong has 32 bits on the ILP32 targets.
    #[allow(clippy::useless_conversion)]
    let hwcap = u64::from(hwcap);

    let mut found = 0;

    if hwcap & HWCAP_SHA2 != 0 {
        found |= SHA2;
    }

    if hwcap & (HWCAP_SHA3 | HWCAP_SHA512) == HWCAP_SHA3 | HWCAP_SHA512 {
        found |= SHA3;

        if hwcap & HWCAP_CPUID != 0 && implementer() == APPLE {
            found |= KECCAK;
        }
    }

    if hwcap & HWCAP_DIT != 0 {
        found |= DIT;
    }

    found
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const APPLE: u64 = 0x61;

// Bits 31..24 of MIDR_EL1. All cores of one system share an implementer, even when their parts
// differ, so the core this thread happens to run on answers for all of them.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
fn implementer() -> u64 {
    let midr: u64;

    // SAFETY: only called with HWCAP_CPUID, which means that Linux traps this read of MIDR_EL1
    // from user space and emulates it. It touches no memory, stack or flags.
    unsafe {
        core::arch::asm!(
            "mrs {midr}, midr_el1",
            midr = out(reg) midr,
            options(nomem, nostack, preserves_flags),
        );
    }

    (midr >> 24) & 0xFF
}

// winnt.h: PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE (with SHA-256), PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE
// and PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE. Windows reports no core, so Keccak stays scalar.
#[cfg(windows)]
#[allow(unsafe_code)]
fn probe() -> u32 {
    #[link(name = "kernel32", kind = "raw-dylib")]
    unsafe extern "system" {
        fn IsProcessorFeaturePresent(feature: u32) -> i32;
    }

    // SAFETY: IsProcessorFeaturePresent only reads what the kernel recorded about the CPU; an
    // unknown feature number gives false.
    let present = |feature: u32| unsafe { IsProcessorFeaturePresent(feature) } != 0;

    let mut found = 0;

    if present(30) {
        found |= SHA2;
    }

    if present(64) && present(65) {
        found |= SHA3;
    }

    found
}

// Apple targets enable every feature at compile time, and the other systems keep the portable
// code: std's own detector reports no SHA3 on the BSDs either.
#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
fn probe() -> u32 {
    0
}

// PSTATE.DIT makes data-processing instructions take a time independent of their operands; on
// Apple cores it also turns off the data memory-dependent prefetcher. It is set for the life of
// the guard and cleared afterwards, unless it was already set when the guard was made. Writing
// the bit drains the pipeline (on an Apple M3 a set and a clear take about 80 cycles together,
// and a write that changes nothing about 14), so a guard inside another only reads it.
pub(crate) struct Dit(bool);

impl Dit {
    #[inline]
    pub(crate) fn new() -> Self {
        Self(has(DIT) && set_dit())
    }

    // The guard of a MAC or KDF call. KEYED is set only on a CPU with DIT.
    #[inline]
    pub(crate) fn keyed() -> Self {
        Self(KEYED.load(Ordering::Relaxed) && set_dit())
    }
}

impl Drop for Dit {
    #[inline]
    fn drop(&mut self) {
        if self.0 {
            clear_dit();
        }
    }
}

// MAC and KDF calls take DIT only after enable_data_independent_timing(): it costs 30-54 ns a call
// on an Apple M3, the whole gap on short MACs, and the prefetcher attacks it stops (GoFetch) need
// intermediates that a small key guess predicts, which ML-KEM, ML-DSA and X25519 have and keyed
// SHA-2, Keccak and BLAKE2 states, each a function of the whole key, do not.
static KEYED: AtomicBool = AtomicBool::new(false);

// From now on every MAC and KDF call, on every thread, holds DIT as the asymmetric operations
// always do; there is no way back. False when the CPU has no DIT.
pub fn enable_data_independent_timing() -> bool {
    if !has(DIT) {
        return false;
    }

    KEYED.store(true, Ordering::Relaxed);

    true
}

const DIT_BIT: u64 = 1 << 24;

// S3_3_C4_C2_5 is the DIT register, named by its encoding so that the assembler accepts it
// without the dit target feature. The asm blocks keep the default memory clobber, so that the
// compiler moves no load or store of a secret out of the guarded stretch.
#[allow(unsafe_code)]
fn set_dit() -> bool {
    #[cfg(test)]
    tests::count(&tests::READS);

    let previous: u64;

    // SAFETY: the CPU has FEAT_DIT (checked by the caller), whose register user space may read
    // and write; DIT changes timing only, never results.
    unsafe {
        core::arch::asm!(
            "mrs {previous}, s3_3_c4_c2_5",
            previous = out(reg) previous,
            options(nostack, preserves_flags),
        );
    }

    if previous & DIT_BIT != 0 {
        return false;
    }

    #[cfg(test)]
    tests::count(&tests::WRITES);

    // SAFETY: as above.
    unsafe {
        core::arch::asm!(
            "msr s3_3_c4_c2_5, {set}",
            set = in(reg) DIT_BIT,
            options(nostack, preserves_flags),
        );
    }

    true
}

#[allow(unsafe_code)]
fn clear_dit() {
    #[cfg(test)]
    tests::count(&tests::WRITES);

    // SAFETY: as in set_dit, which found the bit clear and set it.
    unsafe {
        core::arch::asm!("msr s3_3_c4_c2_5, xzr", options(nostack, preserves_flags));
    }
}

// The blocks and then the more blocks, as one stream: a one-shot hash passes its input and its
// padding without copying the input.
#[allow(unsafe_code)]
pub(crate) fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]], more: &[[u8; 64]]) -> bool {
    if !has(SHA2) {
        return false;
    }

    // SAFETY: the CPU has the SHA2 instructions, the only feature the kernel needs.
    unsafe { compress256_sha2(state, blocks, more) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn compress256_lanes<const LANES: usize>(
    states: &mut [[u32; LANES]; 8],
    w: &mut [[u32; LANES]; 16],
) -> bool {
    if !has(SHA2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { compress256_lanes_sha2(states, w) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn compress256_pair(states: &mut [[u32; 8]; 2], blocks: &[[u8; 64]; 2]) -> bool {
    if !has(SHA2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { compress256_pair_sha2(states, blocks) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn finish256(state: &mut [u32; 8], data: &[u8], bits: u64) -> bool {
    if !has(SHA2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { finish256_sha2(state, data, bits) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn finish512(state: &mut [u64; 8], data: &[u8], bits: u128) -> bool {
    if !has(SHA3) {
        return false;
    }

    // SAFETY: as in compress512.
    unsafe { finish512_sha3(state, data, bits) };

    true
}

// HMAC of data under a key of at most a block, whose tag size picks the hash: 32 or 28 bytes
// for SHA-256 or SHA-224 (hmac256), 64 or 48 bytes for SHA-512 or SHA-384 (hmac512).
#[allow(unsafe_code)]
pub(crate) fn hmac256(iv: &[u32; 8], key: &[u8], data: &[u8], tag: &mut [u8]) -> bool {
    if !has(SHA2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { hmac256_sha2(iv, key, data, tag) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn hmac512(iv: &[u64; 8], key: &[u8], data: &[u8], tag: &mut [u8]) -> bool {
    if !has(SHA3) {
        return false;
    }

    // SAFETY: as in compress512.
    unsafe { hmac512_sha3(iv, key, data, tag) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn hmac256_keyed(keyed: &[[u32; 8]; 2], data: &[u8], tag: &mut [u8]) -> bool {
    if !has(SHA2) {
        return false;
    }

    // SAFETY: as in compress256.
    unsafe { hmac256_keyed_sha2(keyed, data, tag) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn hmac512_keyed(keyed: &[[u64; 8]; 2], data: &[u8], tag: &mut [u8]) -> bool {
    if !has(SHA3) {
        return false;
    }

    // SAFETY: as in compress512.
    unsafe { hmac512_keyed_sha3(keyed, data, tag) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn compress512(state: &mut [u64; 8], blocks: &[[u8; 128]], more: &[[u8; 128]]) -> bool {
    if !has(SHA3) {
        return false;
    }

    // SAFETY: the CPU has the SHA3 and SHA512 instructions, which Rust's sha3 feature names.
    unsafe { compress512_sha3(state, blocks, more) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn compress512_pair(states: &mut [[u64; 8]; 2], blocks: &[[u8; 128]; 2]) -> bool {
    if !has(SHA3) {
        return false;
    }

    // SAFETY: as in compress512.
    unsafe { compress512_pair_sha3(states, blocks) };

    true
}

// Two states fill the vector pipes, and the scalar pipes permute a third beside them in little
// more time, so sponges run in groups of six.
pub(crate) fn keccak_group() -> usize {
    if has(KECCAK) { 6 } else { 4 }
}

// Permutes every state, three at a time where that leaves no single state over, then two, then
// one in vector registers, which is still faster than the scalar permutation; returns how many.
#[allow(unsafe_code)]
pub(crate) fn permute_many(states: &mut [&mut [u64; 25]]) -> usize {
    if !has(KECCAK) {
        return 0;
    }

    let count = states.len();

    let mut rest = states;

    while !rest.is_empty() {
        let size = match rest.len() {
            1 => 1,
            2 | 4 => 2,
            _ => 3,
        };

        let (group, tail) = core::mem::take(&mut rest).split_at_mut(size);

        // SAFETY: KECCAK is only ever found together with SHA3, all that the kernels need.
        unsafe {
            match group {
                [only] => permute1_sha3(only),
                [first, second] => permute2_sha3(first, second),
                [first, second, third] => permute3_sha3(first, second, third),
                _ => unreachable!("groups have one to three states"),
            }
        }

        rest = tail;
    }

    count
}

// Absorbs the whole blocks of data, rate bytes each, into one state, and returns how many bytes
// that was. The state stays in vector registers from one block to the next.
#[allow(unsafe_code)]
pub(crate) fn absorb(state: &mut [u64; 25], rate: usize, data: &[u8]) -> usize {
    let length = data.len() - data.len() % rate;

    if length == 0 || !has(KECCAK) {
        return 0;
    }

    let blocks = &data[..length];

    // SAFETY: KECCAK is only ever found together with SHA3.
    unsafe {
        match rate {
            72 => absorb_sha3::<72>(state, blocks.as_chunks().0),
            104 => absorb_sha3::<104>(state, blocks.as_chunks().0),
            136 => absorb_sha3::<136>(state, blocks.as_chunks().0),
            144 => absorb_sha3::<144>(state, blocks.as_chunks().0),
            168 => absorb_sha3::<168>(state, blocks.as_chunks().0),
            _ => return 0,
        }
    }

    length
}

// The output of a sponge of the given rate and suffix that absorbs data and is read once into
// out. A kernel per rate: whole blocks of a constant size keep the state in registers, which a
// rate known only at run time did not quite do.
#[allow(unsafe_code)]
pub(crate) fn digest(
    initial: Option<&[u64; 25]>,
    rate: usize,
    suffix: u8,
    data: &[u8],
    out: &mut [u8],
) -> bool {
    if !has(KECCAK) {
        return false;
    }

    // SAFETY: as in absorb.
    unsafe {
        match rate {
            72 => digest_sha3::<72>(initial, data, suffix, out),
            104 => digest_sha3::<104>(initial, data, suffix, out),
            136 => digest_sha3::<136>(initial, data, suffix, out),
            144 => digest_sha3::<144>(initial, data, suffix, out),
            168 => digest_sha3::<168>(initial, data, suffix, out),
            _ => return false,
        }
    }

    true
}

// BLAKE2 runs best on the scalar pipes as compiled: four independent G functions per step keep
// them busy, a hand-ordered assembly version measured the same, and NEON's two-cycle instructions
// and two-instruction rotations lengthen the chain.
#[inline(always)]
pub(crate) fn blake2b(
    _: &mut [u64; 8],
    _: Option<&[u64; 16]>,
    _: &[[u8; 128]],
    _: u128,
    _: Option<(&[u64; 16], u128)>,
) -> bool {
    false
}

#[inline(always)]
pub(crate) fn blake2s(
    _: &mut [u32; 8],
    _: Option<&[u32; 16]>,
    _: &[[u8; 64]],
    _: u64,
    _: Option<(&[u32; 16], u128)>,
) -> bool {
    false
}

#[target_feature(enable = "neon")]
#[inline]
fn vector32(words: &[u32; 4]) -> uint32x4_t {
    let low = u64::from(words[0]) | (u64::from(words[1]) << 32);

    let high = u64::from(words[2]) | (u64::from(words[3]) << 32);

    vreinterpretq_u32_u64(vcombine_u64(vcreate_u64(low), vcreate_u64(high)))
}

#[target_feature(enable = "neon")]
#[inline]
fn words32(vector: uint32x4_t) -> [u32; 4] {
    let halves = vreinterpretq_u64_u32(vector);

    let (low, high) = (vgetq_lane_u64::<0>(halves), vgetq_lane_u64::<1>(halves));

    [
        low as u32,
        (low >> 32) as u32,
        high as u32,
        (high >> 32) as u32,
    ]
}

#[target_feature(enable = "neon")]
#[inline]
fn vector64(low: u64, high: u64) -> uint64x2_t {
    vcombine_u64(vcreate_u64(low), vcreate_u64(high))
}

// One SHA-256 computation in flight: the state as the instructions hold it, a, b, c, d and e, f,
// g, h from the lowest lane up, and the sixteen schedule words that are live.
#[derive(Clone, Copy)]
struct Stream {
    abcd: uint32x4_t,
    efgh: uint32x4_t,
    m: [uint32x4_t; 4],
}

// Four rounds of every stream with schedule vector J, which then advances by sixteen words if
// more are needed. Each stream depends only on itself, so the streams' chains of SHA256H and
// SHA256H2 overlap and hide each other's latency.
#[target_feature(enable = "sha2")]
#[inline]
fn quarter<const N: usize, const J: usize>(
    streams: &mut [Stream; N],
    k: uint32x4_t,
    schedule: bool,
) {
    for stream in streams.iter_mut() {
        let wk = vaddq_u32(stream.m[J], k);

        let abcd = stream.abcd;

        stream.abcd = vsha256hq_u32(abcd, stream.efgh, wk);

        stream.efgh = vsha256h2q_u32(stream.efgh, abcd, wk);

        if schedule {
            let m = &mut stream.m;

            m[J] = vsha256su1q_u32(
                vsha256su0q_u32(m[J], m[(J + 1) % 4]),
                m[(J + 2) % 4],
                m[(J + 3) % 4],
            );
        }
    }
}

// Four rounds of a lone SHA-256 computation, which the latency of SHA256H and SHA256H2 bounds:
// each overwrites one half of the state and reads the other half's old value, so one half is
// copied first. The chain is shortest with the copy of abcd, which only SHA256H2 reads, through
// an input that takes a cycle longer to reach its result than its own efgh. Compilers do not
// always choose that copy, nor keep the message schedule from adding moves of its own, so the
// instructions are written out: one block took 98 cycles of an Apple M3 as compiled, 82 here.
#[target_feature(enable = "sha2")]
#[inline]
#[allow(unsafe_code)]
fn lone_quarter<const J: usize>(
    abcd: &mut uint32x4_t,
    efgh: &mut uint32x4_t,
    m: &mut [uint32x4_t; 4],
    k: uint32x4_t,
    schedule: bool,
) {
    let (next, after, last) = (m[(J + 1) % 4], m[(J + 2) % 4], m[(J + 3) % 4]);

    let word = &mut m[J];

    if schedule {
        // SAFETY: instructions on registers only, which the sha2 feature of this function
        // provides; they read and write no memory, stack or flags.
        unsafe {
            core::arch::asm!(
                "add {wk:v}.4s, {word:v}.4s, {k:v}.4s",
                "sha256su0 {word:v}.4s, {next:v}.4s",
                "mov {copy:v}.16b, {abcd:v}.16b",
                "sha256h {abcd:q}, {efgh:q}, {wk:v}.4s",
                "sha256h2 {efgh:q}, {copy:q}, {wk:v}.4s",
                "sha256su1 {word:v}.4s, {after:v}.4s, {last:v}.4s",
                abcd = inout(vreg) *abcd,
                efgh = inout(vreg) *efgh,
                word = inout(vreg) *word,
                next = in(vreg) next,
                after = in(vreg) after,
                last = in(vreg) last,
                k = in(vreg) k,
                wk = out(vreg) _,
                copy = out(vreg) _,
                options(pure, nomem, nostack, preserves_flags),
            );
        }
    } else {
        // SAFETY: as above.
        unsafe {
            core::arch::asm!(
                "add {wk:v}.4s, {word:v}.4s, {k:v}.4s",
                "mov {copy:v}.16b, {abcd:v}.16b",
                "sha256h {abcd:q}, {efgh:q}, {wk:v}.4s",
                "sha256h2 {efgh:q}, {copy:q}, {wk:v}.4s",
                abcd = inout(vreg) *abcd,
                efgh = inout(vreg) *efgh,
                word = in(vreg) *word,
                k = in(vreg) k,
                wk = out(vreg) _,
                copy = out(vreg) _,
                options(pure, nomem, nostack, preserves_flags),
            );
        }
    }
}

// lone_quarter::<0> with scheduling, which also copies the state for the addition at the end of
// the block. Made apart, the copies became moves of the working state, onto the chain of every
// block.
#[target_feature(enable = "sha2")]
#[inline]
#[allow(unsafe_code)]
fn first_quarter(
    abcd: &mut uint32x4_t,
    efgh: &mut uint32x4_t,
    m: &mut [uint32x4_t; 4],
    k: uint32x4_t,
    start: &mut (uint32x4_t, uint32x4_t),
) {
    let [word, next, after, last] = m;

    // SAFETY: as in lone_quarter.
    unsafe {
        core::arch::asm!(
            "mov {start_abcd:v}.16b, {abcd:v}.16b",
            "mov {start_efgh:v}.16b, {efgh:v}.16b",
            "add {wk:v}.4s, {word:v}.4s, {k:v}.4s",
            "sha256su0 {word:v}.4s, {next:v}.4s",
            "mov {copy:v}.16b, {abcd:v}.16b",
            "sha256h {abcd:q}, {efgh:q}, {wk:v}.4s",
            "sha256h2 {efgh:q}, {copy:q}, {wk:v}.4s",
            "sha256su1 {word:v}.4s, {after:v}.4s, {last:v}.4s",
            abcd = inout(vreg) *abcd,
            efgh = inout(vreg) *efgh,
            word = inout(vreg) *word,
            next = in(vreg) *next,
            after = in(vreg) *after,
            last = in(vreg) *last,
            k = in(vreg) k,
            start_abcd = out(vreg) start.0,
            start_efgh = out(vreg) start.1,
            wk = out(vreg) _,
            copy = out(vreg) _,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
}

#[target_feature(enable = "sha2")]
#[inline]
fn rounds256<const N: usize>(streams: &mut [Stream; N]) {
    let start = *streams;

    for (sixteen, k) in K256.as_chunks::<16>().0.iter().enumerate() {
        let k = k.as_chunks::<4>().0;

        let schedule = sixteen < 3;

        quarter::<N, 0>(streams, load_u32(&k[0]), schedule);

        quarter::<N, 1>(streams, load_u32(&k[1]), schedule);

        quarter::<N, 2>(streams, load_u32(&k[2]), schedule);

        quarter::<N, 3>(streams, load_u32(&k[3]), schedule);
    }

    for (stream, start) in streams.iter_mut().zip(&start) {
        stream.abcd = vaddq_u32(stream.abcd, start.abcd);

        stream.efgh = vaddq_u32(stream.efgh, start.efgh);
    }
}

// One block of a lone stream, given as its schedule words, with the state in registers.
#[target_feature(enable = "sha2")]
#[inline]
fn block256(
    abcd: &mut uint32x4_t,
    efgh: &mut uint32x4_t,
    mut m: [uint32x4_t; 4],
    k: &[uint32x4_t; 16],
) {
    let mut start = (*abcd, *efgh);

    for (sixteen, k) in k.as_chunks::<4>().0.iter().enumerate() {
        let schedule = sixteen < 3;

        if sixteen == 0 {
            first_quarter(abcd, efgh, &mut m, k[0], &mut start);
        } else {
            lone_quarter::<0>(abcd, efgh, &mut m, k[0], schedule);
        }

        lone_quarter::<1>(abcd, efgh, &mut m, k[1], schedule);

        lone_quarter::<2>(abcd, efgh, &mut m, k[2], schedule);

        lone_quarter::<3>(abcd, efgh, &mut m, k[3], schedule);
    }

    *abcd = vaddq_u32(*abcd, start.0);

    *efgh = vaddq_u32(*efgh, start.1);
}

// The big-endian words of a block of bytes.
#[target_feature(enable = "neon")]
#[inline]
fn words256(chunks: [uint8x16_t; 4]) -> [uint32x4_t; 4] {
    let mut words = [vdupq_n_u32(0); 4];

    for (words, chunk) in words.iter_mut().zip(chunks) {
        *words = vreinterpretq_u32_u8(vrev32q_u8(chunk));
    }

    words
}

#[target_feature(enable = "neon")]
#[inline]
fn block_chunks<const N: usize>(block: &[[u8; 16]]) -> [uint8x16_t; N] {
    let mut chunks = [vdupq_n_u8(0); N];

    for (chunk, bytes) in chunks.iter_mut().zip(block) {
        *chunk = load_u8(bytes);
    }

    chunks
}

#[target_feature(enable = "neon")]
#[inline]
fn constants256() -> [uint32x4_t; 16] {
    let mut k = [vdupq_n_u32(0); 16];

    for (k, words) in k.iter_mut().zip(K256.as_chunks::<4>().0) {
        *k = load_u32(words);
    }

    k
}

#[target_feature(enable = "neon")]
#[inline]
fn load256(state: &[u32; 8]) -> (uint32x4_t, uint32x4_t) {
    let [abcd, efgh] = state.as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    (load_u32(abcd), load_u32(efgh))
}

#[target_feature(enable = "neon")]
#[inline]
fn store256(abcd: uint32x4_t, efgh: uint32x4_t, state: &mut [u32; 8]) {
    let [abcd_out, efgh_out] = state.as_chunks_mut::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    store_u32(abcd, abcd_out);

    store_u32(efgh, efgh_out);
}

// The streaming hash: the state stays in registers from one block to the next.
#[target_feature(enable = "sha2")]
fn compress256_sha2(state: &mut [u32; 8], blocks: &[[u8; 64]], more: &[[u8; 64]]) {
    let (mut abcd, mut efgh) = load256(state);

    let k = constants256();

    for block in blocks.iter().chain(more) {
        let chunks = block_chunks(block.as_chunks::<16>().0);

        block256(&mut abcd, &mut efgh, words256(chunks), &k);
    }

    store256(abcd, efgh, state);
}

// Chunk i of the padded last block or two of a message whose bytes after its whole blocks are
// whole (whole 16-byte chunks) and then the bytes that the marker chunk holds.
#[target_feature(enable = "neon")]
#[inline]
fn last_chunk(whole: &[[u8; 16]], i: usize, marker: uint8x16_t) -> uint8x16_t {
    match whole.get(i) {
        Some(bytes) => load_u8(bytes),
        None if i == whole.len() => marker,
        None => vdupq_n_u8(0),
    }
}

// The bytes of a message tail that fill no whole chunk, then the 0x80 marker, in a vector.
#[target_feature(enable = "neon")]
#[inline]
fn marker_chunk(data: &[u8], rest: usize) -> uint8x16_t {
    let value = last_bytes(data, rest) | 0x80 << (8 * rest);

    vreinterpretq_u8_u64(vector64(value as u64, (value >> 64) as u64))
}

// The whole blocks of data and then its padded last block or two, for a message of `bits` bits
// that ends with data, into a state held in registers. The padding is built in registers, not in
// memory: a chunk written by smaller stores and loaded right away is not forwarded, and waiting
// for the stores cost the first rounds tens of cycles. No copy of the message's tail is stored.
#[target_feature(enable = "sha2")]
#[inline]
fn tail256(
    abcd: &mut uint32x4_t,
    efgh: &mut uint32x4_t,
    data: &[u8],
    bits: u64,
    k: &[uint32x4_t; 16],
) {
    let (blocks, tail) = data.as_chunks::<64>();

    for block in blocks {
        let chunks = block_chunks(block.as_chunks::<16>().0);

        block256(abcd, efgh, words256(chunks), k);
    }

    let (whole, rest) = tail.as_chunks::<16>();

    let marker = marker_chunk(data, rest.len());

    let length = vreinterpretq_u8_u64(vector64(0, bits.swap_bytes()));

    let mut last = [
        last_chunk(whole, 0, marker),
        last_chunk(whole, 1, marker),
        last_chunk(whole, 2, marker),
        last_chunk(whole, 3, marker),
    ];

    if tail.len() + 9 > 64 {
        block256(abcd, efgh, words256(last), k);

        last = [vdupq_n_u8(0), vdupq_n_u8(0), vdupq_n_u8(0), length];
    } else {
        last[3] = vorrq_u8(last[3], length);
    }

    block256(abcd, efgh, words256(last), k);
}

#[target_feature(enable = "sha2")]
fn finish256_sha2(state: &mut [u32; 8], data: &[u8], bits: u64) {
    let (mut abcd, mut efgh) = load256(state);

    tail256(&mut abcd, &mut efgh, data, bits, &constants256());

    store256(abcd, efgh, state);
}

// The key block of HMAC (a key of at most `N` chunks, zero-padded) XORed with pad in every byte.
#[target_feature(enable = "neon")]
#[inline]
fn key_block<const N: usize>(key: &[u8], pad: u8) -> [uint8x16_t; N] {
    let (whole, rest) = key.as_chunks::<16>();

    let partial = vreinterpretq_u8_u64({
        let value = last_bytes(key, rest.len());

        vector64(value as u64, (value >> 64) as u64)
    });

    let mut block = [vdupq_n_u8(0); N];

    for (i, chunk) in block.iter_mut().enumerate() {
        *chunk = veorq_u8(last_chunk(whole, i, partial), vdupq_n_u8(pad));
    }

    block
}

// A tag from the byte vectors of a final state: whole vectors, and for HMAC-SHA-224 twelve bytes
// of the last one, written without a copy in memory.
#[target_feature(enable = "neon")]
#[inline]
fn store_tag<const N: usize>(vectors: [uint8x16_t; N], tag: &mut [u8]) {
    let (chunks, rest) = tag.as_chunks_mut::<16>();

    for (chunk, vector) in chunks.iter_mut().zip(vectors) {
        store_u8(vector, chunk);
    }

    if let Some(&vector) = vectors.get(chunks.len()) {
        let halves = vreinterpretq_u64_u8(vector);

        let halves = [vgetq_lane_u64::<0>(halves), vgetq_lane_u64::<1>(halves)];

        for (i, byte) in rest.iter_mut().enumerate() {
            *byte = (halves[i / 8] >> (8 * (i % 8))) as u8;
        }
    }
}

// HMAC-SHA-256, or HMAC-SHA-224 for a 28-byte tag, of data under a key of at most a block: the two
// key blocks in registers, which the core overlaps, the inner hash through data and its padding,
// and the outer hash of the inner digest. The inner hash is a call to finish256_sha2, and the
// keyed states wait for it in `states`, which is wiped: held in registers across a call, they
// would have been saved on the stack, where nothing wipes them.
#[target_feature(enable = "sha2")]
fn hmac256_sha2(iv: &[u32; 8], key: &[u8], data: &[u8], tag: &mut [u8]) {
    let k = constants256();

    let (mut inner_abcd, mut inner_efgh) = load256(iv);

    let (mut outer_abcd, mut outer_efgh) = (inner_abcd, inner_efgh);

    block256(
        &mut inner_abcd,
        &mut inner_efgh,
        words256(key_block(key, 0x36)),
        &k,
    );

    block256(
        &mut outer_abcd,
        &mut outer_efgh,
        words256(key_block(key, 0x5C)),
        &k,
    );

    let mut states = [[0; 8]; 2];

    store256(inner_abcd, inner_efgh, &mut states[0]);

    store256(outer_abcd, outer_efgh, &mut states[1]);

    after_keys256(&mut states, data, tag, &k);

    wipe(states.as_flattened_mut());
}

// HMAC-SHA-256 or HMAC-SHA-224 from the states after the inner and the outer key block, which
// `states` holds; the inner hash overwrites the first.
#[target_feature(enable = "sha2")]
#[inline]
fn after_keys256(states: &mut [[u32; 8]; 2], data: &[u8], tag: &mut [u8], k: &[uint32x4_t; 16]) {
    finish256_sha2(
        &mut states[0],
        data,
        (data.len() as u64).wrapping_add(64).wrapping_mul(8),
    );

    let (inner_abcd, inner_efgh) = load256(&states[0]);

    let (mut outer_abcd, mut outer_efgh) = load256(&states[1]);

    // The outer block is the inner digest's words, the marker word and the length.
    let bits = (64 + tag.len() as u32) * 8;

    let mut outer = [inner_abcd, inner_efgh, vdupq_n_u32(0), vdupq_n_u32(0)];

    if tag.len() == 32 {
        outer[2] = vsetq_lane_u32::<0>(0x8000_0000, outer[2]);
    } else {
        outer[1] = vsetq_lane_u32::<3>(0x8000_0000, outer[1]);
    }

    outer[3] = vsetq_lane_u32::<3>(bits, outer[3]);

    block256(&mut outer_abcd, &mut outer_efgh, outer, k);

    store_tag(
        [
            vrev32q_u8(vreinterpretq_u8_u32(outer_abcd)),
            vrev32q_u8(vreinterpretq_u8_u32(outer_efgh)),
        ],
        tag,
    );
}

// hmac256_sha2 from the keyed states, for many messages under one key: HKDF's expansion.
#[target_feature(enable = "sha2")]
fn hmac256_keyed_sha2(keyed: &[[u32; 8]; 2], data: &[u8], tag: &mut [u8]) {
    let mut states = *keyed;

    after_keys256(&mut states, data, tag, &constants256());

    wipe(states.as_flattened_mut());
}

// A state and a block of bytes as a stream.
#[target_feature(enable = "neon")]
#[inline]
fn stream(state: &[u32; 8], block: &[u8; 64]) -> Stream {
    let [abcd, efgh] = state.as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    let mut m = [vdupq_n_u32(0); 4];

    for (m, bytes) in m.iter_mut().zip(block.as_chunks::<16>().0) {
        *m = vreinterpretq_u32_u8(vrev32q_u8(load_u8(bytes)));
    }

    Stream {
        abcd: load_u32(abcd),
        efgh: load_u32(efgh),
        m,
    }
}

#[target_feature(enable = "sha2")]
fn compress256_pair_sha2(states: &mut [[u32; 8]; 2], blocks: &[[u8; 64]; 2]) {
    let mut streams = [
        stream(&states[0], &blocks[0]),
        stream(&states[1], &blocks[1]),
    ];

    rounds256(&mut streams);

    for (state, stream) in states.iter_mut().zip(&streams) {
        let [abcd, efgh] = state.as_chunks_mut::<4>().0 else {
            unreachable!("eight words are two groups of four")
        };

        store_u32(stream.abcd, abcd);

        store_u32(stream.efgh, efgh);
    }
}

// Lane `lane` of the word-major states and schedule of compress256_lanes.
#[target_feature(enable = "neon")]
#[inline]
fn gather<const LANES: usize>(
    states: &[[u32; LANES]; 8],
    w: &[[u32; LANES]; 16],
    lane: usize,
) -> Stream {
    let word = |i: usize| states[i][lane];

    let schedule = |i: usize| w[i][lane];

    let mut m = [vdupq_n_u32(0); 4];

    for (j, m) in m.iter_mut().enumerate() {
        *m = vector32(&[
            schedule(4 * j),
            schedule(4 * j + 1),
            schedule(4 * j + 2),
            schedule(4 * j + 3),
        ]);
    }

    Stream {
        abcd: vector32(&[word(0), word(1), word(2), word(3)]),
        efgh: vector32(&[word(4), word(5), word(6), word(7)]),
        m,
    }
}

#[target_feature(enable = "neon")]
#[inline]
fn scatter<const LANES: usize>(states: &mut [[u32; LANES]; 8], stream: &Stream, lane: usize) {
    let words = words32(stream.abcd).into_iter().chain(words32(stream.efgh));

    for (state, word) in states.iter_mut().zip(words) {
        state[lane] = word;
    }
}

// Two lanes at a time: a third and fourth stream would gain under 7% more on Apple cores.
#[target_feature(enable = "sha2")]
fn compress256_lanes_sha2<const LANES: usize>(
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

// Two SHA-512 rounds with schedule vector J, which holds the words of rounds t and t + 1 and then
// advances by sixteen words if more are needed. The state pairs are ab, cd, ef and gh, the first
// letter in the low lane. SHA512H yields T1 of both rounds without the d it adds to e, so ef
// becomes cd plus that; SHA512H2 yields the two new values of a.
#[target_feature(enable = "sha3")]
#[inline]
fn double_round<const J: usize>(
    s: &mut [uint64x2_t; 4],
    m: &mut [uint64x2_t; 8],
    k: uint64x2_t,
    schedule: bool,
) {
    let [ab, cd, ef, gh] = *s;

    let wk = vaddq_u64(m[J], k);

    let t1 = vsha512hq_u64(
        vaddq_u64(gh, vextq_u64::<1>(wk, wk)),
        vextq_u64::<1>(ef, gh),
        vextq_u64::<1>(cd, ef),
    );

    *s = [vsha512h2q_u64(t1, cd, ab), ab, vaddq_u64(cd, t1), ef];

    if schedule {
        m[J] = vsha512su1q_u64(
            vsha512su0q_u64(m[J], m[(J + 1) % 8]),
            m[(J + 7) % 8],
            vextq_u64::<1>(m[(J + 4) % 8], m[(J + 5) % 8]),
        );
    }
}

// The schedule words of a block, two per vector.
#[target_feature(enable = "neon")]
#[inline]
fn message512(block: &[u8; 128]) -> [uint64x2_t; 8] {
    let mut m = [vdupq_n_u64(0); 8];

    for (pair, bytes) in m.iter_mut().zip(block.as_chunks::<16>().0) {
        *pair = vreinterpretq_u64_u8(vrev64q_u8(load_u8(bytes)));
    }

    m
}

#[target_feature(enable = "neon")]
#[inline]
fn load512(state: &[u64; 8]) -> [uint64x2_t; 4] {
    let mut s = [vdupq_n_u64(0); 4];

    for (pair, words) in s.iter_mut().zip(state.as_chunks::<2>().0) {
        *pair = load_u64(words);
    }

    s
}

#[target_feature(enable = "neon")]
#[inline]
fn store512(s: &[uint64x2_t; 4], state: &mut [u64; 8]) {
    for (words, pair) in state.as_chunks_mut::<2>().0.iter_mut().zip(s) {
        store_u64(*pair, words);
    }
}

// Double round J of every stream, which interleave so that each hides the others' latency.
#[target_feature(enable = "sha3")]
#[inline]
fn double_rounds<const N: usize, const J: usize>(
    s: &mut [[uint64x2_t; 4]; N],
    m: &mut [[uint64x2_t; 8]; N],
    k: uint64x2_t,
    schedule: bool,
) {
    for (s, m) in s.iter_mut().zip(m.iter_mut()) {
        double_round::<J>(s, m, k, schedule);
    }
}

// One block of each of N streams.
#[target_feature(enable = "sha3")]
#[inline]
fn rounds512<const N: usize>(s: &mut [[uint64x2_t; 4]; N], m: &mut [[uint64x2_t; 8]; N]) {
    let start = *s;

    for (sixteen, k) in K512.as_chunks::<16>().0.iter().enumerate() {
        let k = k.as_chunks::<2>().0;

        let schedule = sixteen < 4;

        double_rounds::<N, 0>(s, m, load_u64(&k[0]), schedule);

        double_rounds::<N, 1>(s, m, load_u64(&k[1]), schedule);

        double_rounds::<N, 2>(s, m, load_u64(&k[2]), schedule);

        double_rounds::<N, 3>(s, m, load_u64(&k[3]), schedule);

        double_rounds::<N, 4>(s, m, load_u64(&k[4]), schedule);

        double_rounds::<N, 5>(s, m, load_u64(&k[5]), schedule);

        double_rounds::<N, 6>(s, m, load_u64(&k[6]), schedule);

        double_rounds::<N, 7>(s, m, load_u64(&k[7]), schedule);
    }

    for (s, start) in s.iter_mut().zip(&start) {
        for (pair, start) in s.iter_mut().zip(start) {
            *pair = vaddq_u64(*pair, *start);
        }
    }
}

// The blocks and then the more blocks, as one stream, as in compress256_sha2.
#[target_feature(enable = "sha3")]
fn compress512_sha3(state: &mut [u64; 8], blocks: &[[u8; 128]], more: &[[u8; 128]]) {
    let mut s = [load512(state)];

    for block in blocks.iter().chain(more) {
        rounds512(&mut s, &mut [message512(block)]);
    }

    store512(&s[0], state);
}

#[target_feature(enable = "sha3")]
fn compress512_pair_sha3(states: &mut [[u64; 8]; 2], blocks: &[[u8; 128]; 2]) {
    let mut s = [load512(&states[0]), load512(&states[1])];

    rounds512(
        &mut s,
        &mut [message512(&blocks[0]), message512(&blocks[1])],
    );

    store512(&s[0], &mut states[0]);

    store512(&s[1], &mut states[1]);
}

// tail256 for SHA-512, with the whole blocks and the padding in one loop around one compression:
// with three call sites the compression was not inlined, and every block's state and words went
// through the stack, which cost about 3% a block and left them there.
#[target_feature(enable = "sha3")]
#[inline]
fn tail512(s: &mut [[uint64x2_t; 4]; 1], data: &[u8], bits: u128) {
    let (blocks, tail) = data.as_chunks::<128>();

    let (whole, rest) = tail.as_chunks::<16>();

    let marker = marker_chunk(data, rest.len());

    let mut first = [vdupq_n_u8(0); 8];

    for (i, chunk) in first.iter_mut().enumerate() {
        *chunk = last_chunk(whole, i, marker);
    }

    let length = vreinterpretq_u8_u64(vector64(
        ((bits >> 64) as u64).swap_bytes(),
        (bits as u64).swap_bytes(),
    ));

    // The length field ends the tail's block, or a second block if it does not fit after it.
    let two = tail.len() + 17 > 128;

    let mut second = [vdupq_n_u8(0); 8];

    if two {
        second[7] = length;
    } else {
        first[7] = length;
    }

    for i in 0..blocks.len() + 1 + usize::from(two) {
        let m = match blocks.get(i) {
            Some(block) => message512(block),
            None if i == blocks.len() => words512(first),
            None => words512(second),
        };

        rounds512(s, &mut [m]);
    }
}

#[target_feature(enable = "sha3")]
fn finish512_sha3(state: &mut [u64; 8], data: &[u8], bits: u128) {
    let mut s = [load512(state)];

    tail512(&mut s, data, bits);

    store512(&s[0], state);
}

// hmac256_sha2 for HMAC-SHA-512, or HMAC-SHA-384 for a 48-byte tag.
#[target_feature(enable = "sha3")]
fn hmac512_sha3(iv: &[u64; 8], key: &[u8], data: &[u8], tag: &mut [u8]) {
    let start = load512(iv);

    let mut inner = [start];

    rounds512(&mut inner, &mut [words512(key_block(key, 0x36))]);

    let mut outer = [start];

    rounds512(&mut outer, &mut [words512(key_block(key, 0x5C))]);

    let mut states = [[0; 8]; 2];

    store512(&inner[0], &mut states[0]);

    store512(&outer[0], &mut states[1]);

    after_keys512(&mut states, data, tag);

    wipe(states.as_flattened_mut());
}

// after_keys256 for SHA-512 and SHA-384.
#[target_feature(enable = "sha3")]
#[inline]
fn after_keys512(states: &mut [[u64; 8]; 2], data: &[u8], tag: &mut [u8]) {
    finish512_sha3(
        &mut states[0],
        data,
        (data.len() as u128).wrapping_add(128).wrapping_mul(8),
    );

    let mut outer = [load512(&states[1])];

    // The outer block is the inner digest's words, the marker word and the length.
    let [ab, cd, ef, gh] = load512(&states[0]);

    let (marker, zero) = (vector64(0x8000_0000_0000_0000, 0), vdupq_n_u64(0));

    let length = vector64(0, (128 + tag.len() as u64) * 8);

    let block = if tag.len() == 64 {
        [ab, cd, ef, gh, marker, zero, zero, length]
    } else {
        [ab, cd, ef, marker, zero, zero, zero, length]
    };

    rounds512(&mut outer, &mut [block]);

    let mut bytes = [vdupq_n_u8(0); 4];

    for (bytes, pair) in bytes.iter_mut().zip(outer[0]) {
        *bytes = vrev64q_u8(vreinterpretq_u8_u64(pair));
    }

    store_tag(bytes, tag);
}

#[target_feature(enable = "sha3")]
fn hmac512_keyed_sha3(keyed: &[[u64; 8]; 2], data: &[u8], tag: &mut [u8]) {
    let mut states = *keyed;

    after_keys512(&mut states, data, tag);

    wipe(states.as_flattened_mut());
}

#[target_feature(enable = "neon")]
#[inline]
fn words512(chunks: [uint8x16_t; 8]) -> [uint64x2_t; 8] {
    let mut words = [vdupq_n_u64(0); 8];

    for (words, chunk) in words.iter_mut().zip(chunks) {
        *words = vreinterpretq_u64_u8(vrev64q_u8(chunk));
    }

    words
}

// One Keccak-f[1600] round on two states, lane i of both in vector i. Theta's column parities
// take two EOR3 each and its D values one RAX1; XAR applies D and the rho rotation at once (it
// rotates right, so a left rotation by r is XAR by 64 - r) while pi picks the source lane of
// each output position; BCAX is chi's b[x] ^ (b[x + 2] & !b[x + 1]).
#[target_feature(enable = "sha3")]
#[inline]
fn round(a: &mut [uint64x2_t; 25], constant: u64) {
    let mut c = [vdupq_n_u64(0); 5];

    for (x, c) in c.iter_mut().enumerate() {
        *c = veor3q_u64(veor3q_u64(a[x], a[x + 5], a[x + 10]), a[x + 15], a[x + 20]);
    }

    let d = [
        vrax1q_u64(c[4], c[1]),
        vrax1q_u64(c[0], c[2]),
        vrax1q_u64(c[1], c[3]),
        vrax1q_u64(c[2], c[4]),
        vrax1q_u64(c[3], c[0]),
    ];

    let b = [
        veorq_u64(a[0], d[0]),
        vxarq_u64::<20>(a[6], d[1]),
        vxarq_u64::<21>(a[12], d[2]),
        vxarq_u64::<43>(a[18], d[3]),
        vxarq_u64::<50>(a[24], d[4]),
        vxarq_u64::<36>(a[3], d[3]),
        vxarq_u64::<44>(a[9], d[4]),
        vxarq_u64::<61>(a[10], d[0]),
        vxarq_u64::<19>(a[16], d[1]),
        vxarq_u64::<3>(a[22], d[2]),
        vxarq_u64::<63>(a[1], d[1]),
        vxarq_u64::<58>(a[7], d[2]),
        vxarq_u64::<39>(a[13], d[3]),
        vxarq_u64::<56>(a[19], d[4]),
        vxarq_u64::<46>(a[20], d[0]),
        vxarq_u64::<37>(a[4], d[4]),
        vxarq_u64::<28>(a[5], d[0]),
        vxarq_u64::<54>(a[11], d[1]),
        vxarq_u64::<49>(a[17], d[2]),
        vxarq_u64::<8>(a[23], d[3]),
        vxarq_u64::<2>(a[2], d[2]),
        vxarq_u64::<9>(a[8], d[3]),
        vxarq_u64::<25>(a[14], d[4]),
        vxarq_u64::<23>(a[15], d[0]),
        vxarq_u64::<62>(a[21], d[1]),
    ];

    for (plane, b) in a
        .as_chunks_mut::<5>()
        .0
        .iter_mut()
        .zip(b.as_chunks::<5>().0)
    {
        for (x, lane) in plane.iter_mut().enumerate() {
            *lane = vbcaxq_u64(b[x], b[(x + 2) % 5], b[(x + 1) % 5]);
        }
    }

    a[0] = veorq_u64(a[0], vdupq_n_u64(constant));
}

// The 24 rounds of Keccak-f[1600] on the vectors of a, with the instructions of round in
// assembly: the state in v0 to v24, theta's parities and D values in v25 to v31, which chi then
// reuses. Compiled from round, the absorption of 168-byte blocks kept a lane in memory from one
// round to the next, a store and a load on the chain of every round: 164 ns a block on an Apple
// M3 instead of 131.
#[target_feature(enable = "sha3")]
#[inline]
#[allow(unsafe_code)]
fn rounds(a: &mut [uint64x2_t; 25]) {
    // SAFETY: the assembly reads the 24 round constants and no other memory, writes no memory,
    // and changes only the registers it names and the flags.
    unsafe {
        core::arch::asm!(
            "2:",
            "eor3 v25.16b, v0.16b, v5.16b, v10.16b",
            "eor3 v26.16b, v1.16b, v6.16b, v11.16b",
            "eor3 v27.16b, v2.16b, v7.16b, v12.16b",
            "eor3 v28.16b, v3.16b, v8.16b, v13.16b",
            "eor3 v29.16b, v4.16b, v9.16b, v14.16b",
            "eor3 v25.16b, v25.16b, v15.16b, v20.16b",
            "eor3 v26.16b, v26.16b, v16.16b, v21.16b",
            "eor3 v27.16b, v27.16b, v17.16b, v22.16b",
            "eor3 v28.16b, v28.16b, v18.16b, v23.16b",
            "eor3 v29.16b, v29.16b, v19.16b, v24.16b",
            "rax1 v30.2d, v29.2d, v26.2d",
            "rax1 v31.2d, v25.2d, v27.2d",
            "rax1 v26.2d, v26.2d, v28.2d",
            "rax1 v27.2d, v27.2d, v29.2d",
            "rax1 v28.2d, v28.2d, v25.2d",
            "mov v25.16b, v1.16b",
            "xar v1.2d, v6.2d, v31.2d, #20",
            "xar v6.2d, v9.2d, v28.2d, #44",
            "xar v9.2d, v22.2d, v26.2d, #3",
            "xar v22.2d, v14.2d, v28.2d, #25",
            "xar v14.2d, v20.2d, v30.2d, #46",
            "xar v20.2d, v2.2d, v26.2d, #2",
            "xar v2.2d, v12.2d, v26.2d, #21",
            "xar v12.2d, v13.2d, v27.2d, #39",
            "xar v13.2d, v19.2d, v28.2d, #56",
            "xar v19.2d, v23.2d, v27.2d, #8",
            "xar v23.2d, v15.2d, v30.2d, #23",
            "xar v15.2d, v4.2d, v28.2d, #37",
            "xar v4.2d, v24.2d, v28.2d, #50",
            "xar v24.2d, v21.2d, v31.2d, #62",
            "xar v21.2d, v8.2d, v27.2d, #9",
            "xar v8.2d, v16.2d, v31.2d, #19",
            "xar v16.2d, v5.2d, v30.2d, #28",
            "xar v5.2d, v3.2d, v27.2d, #36",
            "xar v3.2d, v18.2d, v27.2d, #43",
            "xar v18.2d, v17.2d, v26.2d, #49",
            "xar v17.2d, v11.2d, v31.2d, #54",
            "xar v11.2d, v7.2d, v26.2d, #58",
            "xar v7.2d, v10.2d, v30.2d, #61",
            "xar v10.2d, v25.2d, v31.2d, #63",
            "eor v0.16b, v0.16b, v30.16b",
            "bcax v25.16b, v0.16b, v2.16b, v1.16b",
            "bcax v29.16b, v1.16b, v3.16b, v2.16b",
            "bcax v2.16b, v2.16b, v4.16b, v3.16b",
            "bcax v3.16b, v3.16b, v0.16b, v4.16b",
            "bcax v4.16b, v4.16b, v1.16b, v0.16b",
            "mov v0.16b, v25.16b",
            "mov v1.16b, v29.16b",
            "bcax v25.16b, v5.16b, v7.16b, v6.16b",
            "bcax v29.16b, v6.16b, v8.16b, v7.16b",
            "bcax v7.16b, v7.16b, v9.16b, v8.16b",
            "bcax v8.16b, v8.16b, v5.16b, v9.16b",
            "bcax v9.16b, v9.16b, v6.16b, v5.16b",
            "mov v5.16b, v25.16b",
            "mov v6.16b, v29.16b",
            "bcax v25.16b, v10.16b, v12.16b, v11.16b",
            "bcax v29.16b, v11.16b, v13.16b, v12.16b",
            "bcax v12.16b, v12.16b, v14.16b, v13.16b",
            "bcax v13.16b, v13.16b, v10.16b, v14.16b",
            "bcax v14.16b, v14.16b, v11.16b, v10.16b",
            "mov v10.16b, v25.16b",
            "mov v11.16b, v29.16b",
            "bcax v25.16b, v15.16b, v17.16b, v16.16b",
            "bcax v29.16b, v16.16b, v18.16b, v17.16b",
            "bcax v17.16b, v17.16b, v19.16b, v18.16b",
            "bcax v18.16b, v18.16b, v15.16b, v19.16b",
            "bcax v19.16b, v19.16b, v16.16b, v15.16b",
            "mov v15.16b, v25.16b",
            "mov v16.16b, v29.16b",
            "bcax v25.16b, v20.16b, v22.16b, v21.16b",
            "bcax v29.16b, v21.16b, v23.16b, v22.16b",
            "bcax v22.16b, v22.16b, v24.16b, v23.16b",
            "bcax v23.16b, v23.16b, v20.16b, v24.16b",
            "bcax v24.16b, v24.16b, v21.16b, v20.16b",
            "mov v20.16b, v25.16b",
            "mov v21.16b, v29.16b",
            "ld1r {{v25.2d}}, [{constants}], #8",
            "eor v0.16b, v0.16b, v25.16b",
            "subs {rounds}, {rounds}, #1",
            "b.ne 2b",
            constants = inout(reg) ROUND_CONSTANTS.as_ptr() => _,
            rounds = inout(reg) 24u64 => _,
            inout("v0") a[0],
            inout("v1") a[1],
            inout("v2") a[2],
            inout("v3") a[3],
            inout("v4") a[4],
            inout("v5") a[5],
            inout("v6") a[6],
            inout("v7") a[7],
            inout("v8") a[8],
            inout("v9") a[9],
            inout("v10") a[10],
            inout("v11") a[11],
            inout("v12") a[12],
            inout("v13") a[13],
            inout("v14") a[14],
            inout("v15") a[15],
            inout("v16") a[16],
            inout("v17") a[17],
            inout("v18") a[18],
            inout("v19") a[19],
            inout("v20") a[20],
            inout("v21") a[21],
            inout("v22") a[22],
            inout("v23") a[23],
            inout("v24") a[24],
            out("v25") _,
            out("v26") _,
            out("v27") _,
            out("v28") _,
            out("v29") _,
            out("v30") _,
            out("v31") _,
            options(nostack, readonly),
        );
    }
}

#[target_feature(enable = "sha3")]
fn permute2_sha3(first: &mut [u64; 25], second: &mut [u64; 25]) {
    let mut a = [vdupq_n_u64(0); 25];

    for (lane, (x, y)) in a.iter_mut().zip(first.iter().zip(second.iter())) {
        *lane = vector64(*x, *y);
    }

    rounds(&mut a);

    for (lane, (x, y)) in a.iter().zip(first.iter_mut().zip(second.iter_mut())) {
        *x = vgetq_lane_u64::<0>(*lane);

        *y = vgetq_lane_u64::<1>(*lane);
    }
}

// One state in both halves of the vectors: the instructions of a pair, for a state alone.
#[target_feature(enable = "sha3")]
fn permute1_sha3(state: &mut [u64; 25]) {
    let mut a = [vdupq_n_u64(0); 25];

    for (lane, x) in a.iter_mut().zip(state.iter()) {
        *lane = vdupq_n_u64(*x);
    }

    rounds(&mut a);

    for (x, lane) in state.iter_mut().zip(&a) {
        *x = vgetq_lane_u64::<0>(*lane);
    }
}

// A pair in the vector pipes and the third state in the scalar ones, their rounds alternating.
#[target_feature(enable = "sha3")]
fn permute3_sha3(first: &mut [u64; 25], second: &mut [u64; 25], third: &mut [u64; 25]) {
    let mut a = [vdupq_n_u64(0); 25];

    for (lane, (x, y)) in a.iter_mut().zip(first.iter().zip(second.iter())) {
        *lane = vector64(*x, *y);
    }

    let mut parities = keccak::parities(third);

    let mut e = [0; 25];

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        round(&mut a, constants[0]);

        keccak::round(third, &mut e, &mut parities, constants[0]);

        round(&mut a, constants[1]);

        keccak::round(&e, third, &mut parities, constants[1]);
    }

    for (lane, (x, y)) in a.iter().zip(first.iter_mut().zip(second.iter_mut())) {
        *x = vgetq_lane_u64::<0>(*lane);

        *y = vgetq_lane_u64::<1>(*lane);
    }
}

#[target_feature(enable = "sha3")]
fn absorb_sha3<const RATE: usize>(state: &mut [u64; 25], blocks: &[[u8; RATE]]) {
    let mut a = [vdupq_n_u64(0); 25];

    for (lane, x) in a.iter_mut().zip(state.iter()) {
        *lane = vdupq_n_u64(*x);
    }

    for block in blocks {
        xor_block(&mut a, block);

        rounds(&mut a);
    }

    for (x, lane) in state.iter_mut().zip(&a) {
        *x = vgetq_lane_u64::<0>(*lane);
    }
}

// The lanes of a block XORed into the first lanes of the state, in assembly that keeps the state
// in v0 to v24 as rounds does: compiled from intrinsics, the loads ran ahead of the XORs and the
// lanes they displaced went to memory. Only the low half of each vector takes the block, as only
// the low half is read out; the high half runs the same permutation on a state of its own.
macro_rules! xor_lanes {
    ($a:ident, $block:ident, $($lane:literal),+) => {
        // SAFETY: the assembly reads the block's lanes, each inside the array the pointer comes
        // from, and changes no memory, stack or flags.
        unsafe {
            core::arch::asm!(
                $(
                    concat!("ldr d25, [{block}, #", $lane, " * 8]"),
                    concat!("eor v", $lane, ".16b, v", $lane, ".16b, v25.16b"),
                )+
                block = in(reg) $block.as_ptr(),
                inout("v0") $a[0],
                inout("v1") $a[1],
                inout("v2") $a[2],
                inout("v3") $a[3],
                inout("v4") $a[4],
                inout("v5") $a[5],
                inout("v6") $a[6],
                inout("v7") $a[7],
                inout("v8") $a[8],
                inout("v9") $a[9],
                inout("v10") $a[10],
                inout("v11") $a[11],
                inout("v12") $a[12],
                inout("v13") $a[13],
                inout("v14") $a[14],
                inout("v15") $a[15],
                inout("v16") $a[16],
                inout("v17") $a[17],
                inout("v18") $a[18],
                inout("v19") $a[19],
                inout("v20") $a[20],
                inout("v21") $a[21],
                inout("v22") $a[22],
                inout("v23") $a[23],
                inout("v24") $a[24],
                out("v25") _,
                options(nostack, readonly, preserves_flags),
            );
        }
    };
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
fn xor_block<const RATE: usize>(a: &mut [uint64x2_t; 25], block: &[u8; RATE]) {
    match RATE {
        72 => xor_lanes!(a, block, 0, 1, 2, 3, 4, 5, 6, 7, 8),
        104 => xor_lanes!(a, block, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
        136 => xor_lanes!(
            a, block, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        ),
        144 => xor_lanes!(
            a, block, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
        ),
        168 => xor_lanes!(
            a, block, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
        ),
        _ => unreachable!("the rates of SHA-3 and SHAKE"),
    }
}

// The lanes of the rate stored from the state, as xor_lanes reads them.
macro_rules! store_lanes {
    ($a:ident, $out:ident, $($lane:literal),+) => {
        // SAFETY: the assembly writes the lanes inside the array the pointer comes from, reads no
        // other memory and changes no stack or flags.
        unsafe {
            core::arch::asm!(
                $(concat!("str d", $lane, ", [{out}, #", $lane, " * 8]"),)+
                out = in(reg) $out.as_mut_ptr(),
                in("v0") $a[0],
                in("v1") $a[1],
                in("v2") $a[2],
                in("v3") $a[3],
                in("v4") $a[4],
                in("v5") $a[5],
                in("v6") $a[6],
                in("v7") $a[7],
                in("v8") $a[8],
                in("v9") $a[9],
                in("v10") $a[10],
                in("v11") $a[11],
                in("v12") $a[12],
                in("v13") $a[13],
                in("v14") $a[14],
                in("v15") $a[15],
                in("v16") $a[16],
                in("v17") $a[17],
                in("v18") $a[18],
                in("v19") $a[19],
                in("v20") $a[20],
                options(nostack, preserves_flags),
            );
        }
    };
}

#[target_feature(enable = "neon")]
#[inline]
#[allow(unsafe_code)]
fn store_rate<const RATE: usize>(a: &[uint64x2_t; 25], out: &mut [u8; RATE]) {
    match RATE {
        72 => store_lanes!(a, out, 0, 1, 2, 3, 4, 5, 6, 7, 8),
        104 => store_lanes!(a, out, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
        136 => store_lanes!(
            a, out, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        ),
        144 => store_lanes!(
            a, out, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
        ),
        168 => store_lanes!(
            a, out, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
        ),
        _ => unreachable!("the rates of SHA-3 and SHAKE"),
    }
}

// The whole blocks of data and then its padded last block, and then out.len() bytes squeezed,
// with the state in registers throughout, from the initial state if there is one and from zero
// otherwise. The last block is built before the state is live, since a call to memcpy while it is
// would push it to memory, and it and the squeezed lanes pass through small buffers that are
// wiped.
#[target_feature(enable = "sha3")]
fn digest_sha3<const RATE: usize>(
    initial: Option<&[u64; 25]>,
    data: &[u8],
    suffix: u8,
    out: &mut [u8],
) {
    let (blocks, tail) = data.as_chunks::<RATE>();

    let (lanes, rest) = tail.as_chunks::<8>();

    let mut last = [0u8; RATE];

    let chunks = last.as_chunks_mut::<8>().0;

    for (chunk, bytes) in chunks.iter_mut().zip(lanes) {
        *chunk = *bytes;
    }

    // The lane after the whole ones takes the rest of data and the suffix, and the last lane of
    // the rate the final bit; each lane gets a single store, which its load forwards.
    let marker = last_bytes(data, rest.len()) as u64 | u64::from(suffix) << (8 * rest.len());

    let end = RATE / 8 - 1;

    if lanes.len() == end {
        chunks[end] = (marker ^ 0x80 << 56).to_le_bytes();
    } else {
        chunks[lanes.len()] = marker.to_le_bytes();

        chunks[end] = (0x80u64 << 56).to_le_bytes();
    }

    let mut a = [vdupq_n_u64(0); 25];

    if let Some(initial) = initial {
        for (lane, x) in a.iter_mut().zip(initial) {
            *lane = vdupq_n_u64(*x);
        }
    }

    for block in blocks {
        xor_block(&mut a, block);

        rounds(&mut a);
    }

    xor_block(&mut a, &last);

    rounds(&mut a);

    // Whole blocks of output go straight from the registers to out; the last part, through a
    // buffer once the state is no longer needed.
    let (whole, partial) = out.as_chunks_mut::<RATE>();

    for (i, block) in whole.iter_mut().enumerate() {
        if i > 0 {
            rounds(&mut a);
        }

        store_rate(&a, block);
    }

    if !partial.is_empty() {
        if !whole.is_empty() {
            rounds(&mut a);
        }

        store_rate(&a, &mut last);

        partial.copy_from_slice(&last[..partial.len()]);
    }

    wipe(&mut last);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::SHA_256;
    use crate::kdf::{HKDF_SHA_256, HKDF_SHA_512, KdfOptions};
    use crate::kem::ML_KEM_768;
    use crate::mac::{BLAKE2B_MAC, BLAKE2S_MAC, HMAC_SHA_256, HMAC_SHA_512, KMAC128, KMAC256};
    use std::boxed::Box;
    use std::cell::{Cell, RefCell};
    use std::thread::LocalKey;
    use std::vec::Vec;

    // The reads and the writes of the DIT register that set_dit and clear_dit make on this thread.
    std::thread_local! {
        pub(super) static READS: Cell<usize> = const { Cell::new(0) };

        pub(super) static WRITES: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn count(counter: &'static LocalKey<Cell<usize>>) {
        counter.with(|value| value.set(value.get() + 1));
    }

    // What a call does to the DIT register of this thread: its reads and its writes.
    fn accesses(call: &dyn Fn()) -> (usize, usize) {
        let before = (READS.with(Cell::get), WRITES.with(Cell::get));

        call();

        (
            READS.with(Cell::get) - before.0,
            WRITES.with(Cell::get) - before.1,
        )
    }

    #[allow(unsafe_code)]
    fn dit_is_set() -> bool {
        let value: u64;

        // SAFETY: only called on a CPU with FEAT_DIT; reading the register has no side effects.
        unsafe {
            core::arch::asm!(
                "mrs {value}, s3_3_c4_c2_5",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags),
            );
        }

        value & DIT_BIT != 0
    }

    // DIT holds for the life of the outermost guard, through nested ones, and a public operation
    // on secrets leaves the thread as it found it. A new thread starts with DIT clear.
    #[test]
    fn dit_guard_sets_and_restores() {
        if !has(DIT) {
            return;
        }

        assert!(!dit_is_set());

        {
            let _outer = Dit::new();

            assert!(dit_is_set());

            {
                let _inner = Dit::new();

                assert!(dit_is_set());
            }

            assert!(dit_is_set());
        }

        assert!(!dit_is_set());

        HMAC_SHA_256.digest(b"key", b"data");

        assert!(!dit_is_set());
    }

    // Every public MAC and KDF call that uses a key, each on its own state.
    fn keyed_calls() -> Vec<Box<dyn Fn()>> {
        let mut calls: Vec<Box<dyn Fn()>> = Vec::new();

        for algorithm in [
            HMAC_SHA_256,
            HMAC_SHA_512,
            KMAC128,
            KMAC256,
            BLAKE2B_MAC,
            BLAKE2S_MAC,
        ] {
            let (tag, empty) = (
                algorithm.digest(b"key", b"data"),
                algorithm.digest(b"key", b""),
            );

            let (updated, digested, verified) = (
                RefCell::new(algorithm.create(b"key")),
                algorithm.create(b"key"),
                algorithm.create(b"key"),
            );

            let expected = tag.clone();

            calls.push(Box::new(move || {
                assert_eq!(algorithm.digest(b"key", b"data"), expected)
            }));

            calls.push(Box::new(move || {
                assert!(algorithm.verify(b"key", b"data", &tag))
            }));

            calls.push(Box::new(move || drop(algorithm.create(b"key"))));

            calls.push(Box::new(move || updated.borrow_mut().update(b"data")));

            calls.push(Box::new(move || drop(digested.digest())));

            calls.push(Box::new(move || assert!(verified.verify(&empty))));
        }

        for algorithm in [HKDF_SHA_256, HKDF_SHA_512] {
            let options = KdfOptions::default();

            calls.push(Box::new(move || {
                assert!(algorithm.derive(b"ikm", 42, &options).is_ok())
            }));

            calls.push(Box::new(move || {
                assert!(algorithm.extract(b"ikm", &options).is_ok())
            }));

            calls.push(Box::new(move || {
                assert!(algorithm.expand(&[7; 64], 42, &options).is_ok())
            }));
        }

        calls
    }

    // MAC and KDF calls leave the DIT register alone until enable_data_independent_timing(), and
    // then set and clear it as the asymmetric operations always do; inside another guard they
    // only read it. Hashes never touch it.
    #[test]
    fn keyed_dit_is_opt_in() {
        KEYED.store(false, Ordering::Relaxed);

        let calls = keyed_calls();

        let pair = crate::hazmat::generate_kem_key_pair(ML_KEM_768, &[3; 64]).expect("key pair");

        let sealed = pair.public_key.encapsulate().expect("encapsulation");

        let decapsulate = || assert!(pair.private_key.decapsulate(&sealed.ciphertext).is_ok());

        let hash = || drop(SHA_256.digest(b"data"));

        let dit = has(DIT);

        for call in &calls {
            assert_eq!(accesses(call.as_ref()), (0, 0));
        }

        let (reads, writes) = accesses(&decapsulate);

        assert!(if dit {
            reads >= 1 && writes == 2
        } else {
            reads + writes == 0
        });

        assert_eq!(enable_data_independent_timing(), dit);

        assert_eq!(enable_data_independent_timing(), dit);

        assert_eq!(accesses(&hash), (0, 0));

        for call in &calls {
            if !dit {
                assert_eq!(accesses(call.as_ref()), (0, 0));

                continue;
            }

            assert_eq!(accesses(call.as_ref()), (1, 2));

            assert!(!dit_is_set());

            let outer = Dit::new();

            assert_eq!(accesses(call.as_ref()), (1, 0));

            assert!(dit_is_set());

            drop(outer);

            assert!(!dit_is_set());
        }

        KEYED.store(false, Ordering::Relaxed);
    }
}
