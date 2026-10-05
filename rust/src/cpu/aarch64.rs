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
use core::sync::atomic::{AtomicU32, Ordering};

use crate::keccak::{self, ROUND_CONSTANTS};
use crate::sha2::{K256, K512};

mod binomial;

mod dsa;

mod memory;

mod ntt;

mod pack;

mod sample;

use memory::{load_u8, load_u32, load_u64, store_u32, store_u64};

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
// the guard and cleared afterwards, unless it was already set when the guard was made.
pub(crate) struct Dit(bool);

impl Dit {
    #[inline]
    pub(crate) fn new() -> Self {
        Self(has(DIT) && set_dit())
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

const DIT_BIT: u64 = 1 << 24;

// S3_3_C4_C2_5 is the DIT register, named by its encoding so that the assembler accepts it
// without the dit target feature. The asm blocks keep the default memory clobber, so that the
// compiler moves no load or store of a secret out of the guarded stretch.
#[allow(unsafe_code)]
fn set_dit() -> bool {
    let previous: u64;

    // SAFETY: the CPU has FEAT_DIT (checked by the caller), whose register user space may read
    // and write; DIT changes timing only, never results.
    unsafe {
        core::arch::asm!(
            "mrs {previous}, s3_3_c4_c2_5",
            "msr s3_3_c4_c2_5, {set}",
            previous = out(reg) previous,
            set = in(reg) DIT_BIT,
            options(nostack, preserves_flags),
        );
    }

    previous & DIT_BIT == 0
}

#[allow(unsafe_code)]
fn clear_dit() {
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
pub(crate) fn compress512(state: &mut [u64; 8], blocks: &[[u8; 128]]) -> bool {
    if !has(SHA3) {
        return false;
    }

    // SAFETY: the CPU has the SHA3 and SHA512 instructions, which Rust's sha3 feature names.
    unsafe { compress512_sha3(state, blocks) };

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
pub(crate) fn absorb(state: &mut [u64; 25], rate: usize, data: &[u8]) -> usize {
    let length = data.len() - data.len() % rate;

    if length == 0 || !absorb_blocks(state, rate, &data[..length], &[]) {
        return 0;
    }

    length
}

// absorb of whole blocks followed by a last block of rate bytes, already padded, in one call.
pub(crate) fn absorb_last(state: &mut [u64; 25], rate: usize, data: &[u8], last: &[u8]) -> bool {
    data.len().is_multiple_of(rate) && last.len() == rate && absorb_blocks(state, rate, data, last)
}

// A kernel per rate: whole blocks of a constant size keep the state in registers, which a rate
// known only at run time did not quite do.
#[allow(unsafe_code)]
fn absorb_blocks(state: &mut [u64; 25], rate: usize, data: &[u8], last: &[u8]) -> bool {
    if !has(KECCAK) {
        return false;
    }

    // SAFETY: KECCAK is only ever found together with SHA3.
    unsafe {
        match rate {
            72 => absorb_sha3::<72>(state, data.as_chunks().0, last.as_chunks().0),
            104 => absorb_sha3::<104>(state, data.as_chunks().0, last.as_chunks().0),
            136 => absorb_sha3::<136>(state, data.as_chunks().0, last.as_chunks().0),
            144 => absorb_sha3::<144>(state, data.as_chunks().0, last.as_chunks().0),
            168 => absorb_sha3::<168>(state, data.as_chunks().0, last.as_chunks().0),
            _ => return false,
        }
    }

    true
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

// The streaming hash: the state stays in registers from one block to the next.
#[target_feature(enable = "sha2")]
fn compress256_sha2(state: &mut [u32; 8], blocks: &[[u8; 64]], more: &[[u8; 64]]) {
    let [abcd, efgh] = state.as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    let (mut abcd, mut efgh) = (load_u32(abcd), load_u32(efgh));

    let mut k = [vdupq_n_u32(0); 16];

    for (k, words) in k.iter_mut().zip(K256.as_chunks::<4>().0) {
        *k = load_u32(words);
    }

    for block in blocks.iter().chain(more) {
        let mut m = [vdupq_n_u32(0); 4];

        for (m, bytes) in m.iter_mut().zip(block.as_chunks::<16>().0) {
            *m = vreinterpretq_u32_u8(vrev32q_u8(load_u8(bytes)));
        }

        let mut start = (abcd, efgh);

        for (sixteen, k) in k.as_chunks::<4>().0.iter().enumerate() {
            let schedule = sixteen < 3;

            if sixteen == 0 {
                first_quarter(&mut abcd, &mut efgh, &mut m, k[0], &mut start);
            } else {
                lone_quarter::<0>(&mut abcd, &mut efgh, &mut m, k[0], schedule);
            }

            lone_quarter::<1>(&mut abcd, &mut efgh, &mut m, k[1], schedule);

            lone_quarter::<2>(&mut abcd, &mut efgh, &mut m, k[2], schedule);

            lone_quarter::<3>(&mut abcd, &mut efgh, &mut m, k[3], schedule);
        }

        abcd = vaddq_u32(abcd, start.0);

        efgh = vaddq_u32(efgh, start.1);
    }

    let [abcd_out, efgh_out] = state.as_chunks_mut::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    store_u32(abcd, abcd_out);

    store_u32(efgh, efgh_out);
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

#[target_feature(enable = "sha3")]
fn compress512_sha3(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    let mut s = [vdupq_n_u64(0); 4];

    for (pair, words) in s.iter_mut().zip(state.as_chunks::<2>().0) {
        *pair = load_u64(words);
    }

    for block in blocks {
        let mut m = [vdupq_n_u64(0); 8];

        for (pair, bytes) in m.iter_mut().zip(block.as_chunks::<16>().0) {
            *pair = vreinterpretq_u64_u8(vrev64q_u8(load_u8(bytes)));
        }

        let start = s;

        for (sixteen, k) in K512.as_chunks::<16>().0.iter().enumerate() {
            let k = k.as_chunks::<2>().0;

            let schedule = sixteen < 4;

            double_round::<0>(&mut s, &mut m, load_u64(&k[0]), schedule);

            double_round::<1>(&mut s, &mut m, load_u64(&k[1]), schedule);

            double_round::<2>(&mut s, &mut m, load_u64(&k[2]), schedule);

            double_round::<3>(&mut s, &mut m, load_u64(&k[3]), schedule);

            double_round::<4>(&mut s, &mut m, load_u64(&k[4]), schedule);

            double_round::<5>(&mut s, &mut m, load_u64(&k[5]), schedule);

            double_round::<6>(&mut s, &mut m, load_u64(&k[6]), schedule);

            double_round::<7>(&mut s, &mut m, load_u64(&k[7]), schedule);
        }

        for (pair, start) in s.iter_mut().zip(start) {
            *pair = vaddq_u64(*pair, start);
        }
    }

    for (words, pair) in state.as_chunks_mut::<2>().0.iter_mut().zip(s) {
        store_u64(pair, words);
    }
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
fn absorb_sha3<const RATE: usize>(
    state: &mut [u64; 25],
    blocks: &[[u8; RATE]],
    last: &[[u8; RATE]],
) {
    let mut a = [vdupq_n_u64(0); 25];

    for (lane, x) in a.iter_mut().zip(state.iter()) {
        *lane = vdupq_n_u64(*x);
    }

    for block in blocks.iter().chain(last) {
        for (lane, bytes) in a.iter_mut().zip(block.as_chunks::<8>().0) {
            *lane = veorq_u64(*lane, vdupq_n_u64(u64::from_le_bytes(*bytes)));
        }

        rounds(&mut a);
    }

    for (x, lane) in state.iter_mut().zip(&a) {
        *x = vgetq_lane_u64::<0>(*lane);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        crate::hash::HMAC_SHA_256.digest(b"key", b"data");

        assert!(!dit_is_set());
    }
}
