// SHA-256 with the ARMv8 SHA2 instructions, SHA-512 with the ARMv8.2 SHA512 instructions and
// Keccak-f[1600] with the ARMv8.2 SHA3 instructions; the NEON transforms of ML-KEM and ML-DSA and
// ML-KEM's noise sampling are in the submodules. All of them are on Arm's list of instructions
// whose timing does not depend on their data (FEAT_DIT), and the code around them has no branch
// or address that depends on the data. The kernels are safe code inside #[target_feature]
// functions; what is unsafe is calling one once its feature is known to be there, asking the
// operating system for the features, and setting the DIT bit.

use core::arch::aarch64::*;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::keccak::ROUND_CONSTANTS;
use crate::sha2::{K256, K512};

mod binomial;

mod ntt;

pub(crate) use binomial::binomial;

pub(crate) use ntt::{
    base_multiply_add, inverse_ntt, inverse_ntt16, multiply, multiply_add, ntt, ntt16,
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

#[allow(unsafe_code)]
pub(crate) fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]]) -> bool {
    if !has(SHA2) {
        return false;
    }

    // SAFETY: the CPU has the SHA2 instructions, the only feature the kernel needs.
    unsafe { compress256_sha2(state, blocks) };

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

// Permutes the states two at a time and returns how many it permuted; an odd last state is left
// to the scalar permutation, which costs half of a pair.
#[allow(unsafe_code)]
pub(crate) fn permute_many(states: &mut [&mut [u64; 25]]) -> usize {
    if !has(KECCAK) {
        return 0;
    }

    let (pairs, _) = states.as_chunks_mut::<2>();

    for [first, second] in pairs.iter_mut() {
        // SAFETY: KECCAK is only ever found together with SHA3.
        unsafe { permute2_sha3(first, second) };
    }

    2 * pairs.len()
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

#[target_feature(enable = "sha2")]
#[inline]
fn rounds256<const N: usize>(streams: &mut [Stream; N]) {
    let start = *streams;

    for (sixteen, k) in K256.as_chunks::<16>().0.iter().enumerate() {
        let k = k.as_chunks::<4>().0;

        let schedule = sixteen < 3;

        quarter::<N, 0>(streams, vector32(&k[0]), schedule);

        quarter::<N, 1>(streams, vector32(&k[1]), schedule);

        quarter::<N, 2>(streams, vector32(&k[2]), schedule);

        quarter::<N, 3>(streams, vector32(&k[3]), schedule);
    }

    for (stream, start) in streams.iter_mut().zip(&start) {
        stream.abcd = vaddq_u32(stream.abcd, start.abcd);

        stream.efgh = vaddq_u32(stream.efgh, start.efgh);
    }
}

// The streaming hash: the state stays in registers from one block to the next.
#[target_feature(enable = "sha2")]
fn compress256_sha2(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    let [abcd, efgh] = state.as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    let mut streams = [Stream {
        abcd: vector32(abcd),
        efgh: vector32(efgh),
        m: [vdupq_n_u32(0); 4],
    }];

    for block in blocks {
        for (m, bytes) in streams[0].m.iter_mut().zip(block.as_chunks::<16>().0) {
            let [low, high] = bytes.as_chunks::<8>().0 else {
                unreachable!("sixteen bytes are two groups of eight")
            };

            let swapped = vrev32q_u8(vreinterpretq_u8_u64(vector64(
                u64::from_le_bytes(*low),
                u64::from_le_bytes(*high),
            )));

            *m = vreinterpretq_u32_u8(swapped);
        }

        rounds256(&mut streams);
    }

    let (abcd, efgh) = state.split_at_mut(4);

    abcd.copy_from_slice(&words32(streams[0].abcd));

    efgh.copy_from_slice(&words32(streams[0].efgh));
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
        *pair = vector64(words[0], words[1]);
    }

    for block in blocks {
        let mut m = [vdupq_n_u64(0); 8];

        for (pair, bytes) in m.iter_mut().zip(block.as_chunks::<16>().0) {
            let [low, high] = bytes.as_chunks::<8>().0 else {
                unreachable!("sixteen bytes are two groups of eight")
            };

            *pair = vector64(u64::from_be_bytes(*low), u64::from_be_bytes(*high));
        }

        let start = s;

        for (sixteen, k) in K512.as_chunks::<16>().0.iter().enumerate() {
            let k = k.as_chunks::<2>().0;

            let schedule = sixteen < 4;

            double_round::<0>(&mut s, &mut m, vector64(k[0][0], k[0][1]), schedule);

            double_round::<1>(&mut s, &mut m, vector64(k[1][0], k[1][1]), schedule);

            double_round::<2>(&mut s, &mut m, vector64(k[2][0], k[2][1]), schedule);

            double_round::<3>(&mut s, &mut m, vector64(k[3][0], k[3][1]), schedule);

            double_round::<4>(&mut s, &mut m, vector64(k[4][0], k[4][1]), schedule);

            double_round::<5>(&mut s, &mut m, vector64(k[5][0], k[5][1]), schedule);

            double_round::<6>(&mut s, &mut m, vector64(k[6][0], k[6][1]), schedule);

            double_round::<7>(&mut s, &mut m, vector64(k[7][0], k[7][1]), schedule);
        }

        for (pair, start) in s.iter_mut().zip(start) {
            *pair = vaddq_u64(*pair, start);
        }
    }

    for (words, pair) in state.as_chunks_mut::<2>().0.iter_mut().zip(s) {
        *words = [vgetq_lane_u64::<0>(pair), vgetq_lane_u64::<1>(pair)];
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

#[target_feature(enable = "sha3")]
fn permute2_sha3(first: &mut [u64; 25], second: &mut [u64; 25]) {
    let mut a = [vdupq_n_u64(0); 25];

    for (lane, (x, y)) in a.iter_mut().zip(first.iter().zip(second.iter())) {
        *lane = vector64(*x, *y);
    }

    for &constant in &ROUND_CONSTANTS {
        round(&mut a, constant);
    }

    for (lane, (x, y)) in a.iter().zip(first.iter_mut().zip(second.iter_mut())) {
        *x = vgetq_lane_u64::<0>(*lane);

        *y = vgetq_lane_u64::<1>(*lane);
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
