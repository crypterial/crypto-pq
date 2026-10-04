// SHA-256 with the SHA extensions (SHA256RNDS2, SHA256MSG1, SHA256MSG2); the SHA-256 lanes,
// Keccak-f[1600] on four states and the ML-KEM and ML-DSA transforms with AVX2. Every
// instruction used is on Intel's list of data-operand-independent timing instructions, and the
// code around them has no branch or address that depends on the data. x86-64 has no common
// SHA-512 extension, so SHA-512 stays portable. The kernels are safe code inside
// #[target_feature] functions; what is unsafe is calling one once its feature is known to be
// there, and CPUID with XGETBV.

use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::cpu::{Field, Field16, Prepare};
use crate::keccak::ROUND_CONSTANTS;
use crate::sha2::{K256, compress256_lanes_portable};

// The SHA extensions together with the SSSE3 and SSE4.1 shuffles that the kernel needs.
const SHA: u32 = 1;

// AVX2, with ymm state that the operating system saves.
const AVX2: u32 = 1 << 1;

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
        AVX2 => cfg!(target_feature = "avx2"),
        _ => false,
    }
}

// The constant-time check runs under valgrind, which cannot execute the SHA extensions, so its
// build leaves them out and checks the AVX2 paths.
const fn usable(feature: u32) -> bool {
    if cfg!(crypto_pq_ct) {
        return feature == AVX2;
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

// CPUID leaf 1 ECX: SSSE3 bit 9, SSE4.1 bit 19, OSXSAVE bit 27, AVX bit 28; leaf 7 EBX: AVX2
// bit 5, SHA bit 29. Newer Rust makes __cpuid safe, hence unused_unsafe.
#[allow(unsafe_code, unused_unsafe)]
fn probe() -> u32 {
    // SAFETY: every x86-64 CPU has CPUID; the one environment where it faults, an SGX enclave,
    // compiles this module out.
    let (max, leaf1) = unsafe { (__cpuid(0).eax, __cpuid(1)) };

    if max < 7 {
        return 0;
    }

    // SAFETY: as above; leaf 7 exists because the highest leaf is at least 7.
    let leaf7 = unsafe { __cpuid_count(7, 0) };

    let mut found = 0;

    if leaf7.ebx & (1 << 29) != 0 && leaf1.ecx & (1 << 9) != 0 && leaf1.ecx & (1 << 19) != 0 {
        found |= SHA;
    }

    let avx = leaf7.ebx & (1 << 5) != 0 && leaf1.ecx & (1 << 28) != 0;

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
pub(crate) fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]]) -> bool {
    if !has(SHA) {
        return false;
    }

    // SAFETY: the CPU has the SHA extensions, SSSE3 and SSE4.1, all that the kernel needs.
    unsafe { compress256_sha(state, blocks) };

    true
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

#[inline(always)]
pub(crate) fn compress512(_: &mut [u64; 8], _: &[[u8; 128]]) -> bool {
    false
}

// The transforms and products of ML-KEM and ML-DSA: the portable arithmetic written once for
// both fields and compiled for AVX2, where the signed 32-bit products that SSE2 lacks give eight
// coefficients per vector.
#[allow(unsafe_code)]
pub(crate) fn ntt(w: &mut [i32; 256], field: &Field) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: the CPU has AVX2 and the operating system saves its registers.
    unsafe { forward_avx2(w, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn inverse_ntt(w: &mut [i32; 256], field: &Field) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { inverse_avx2(w, field) };

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
    unsafe { products_avx2::<false>(out, f, g, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn multiply_add(
    acc: &mut [i32; 256],
    f: &[i32; 256],
    g: &[i32; 256],
    field: &Field,
) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { products_avx2::<true>(acc, f, g, field) };

    true
}

#[allow(unsafe_code)]
pub(crate) fn base_multiply_add(
    acc: &mut [i32; 256],
    f: &[u16; 256],
    g: &[u16; 256],
    gammas: &[i32; 128],
    field: &Field,
) -> bool {
    if !has(AVX2) {
        return false;
    }

    // SAFETY: as in ntt.
    unsafe { base_products_avx2(acc, f, g, gammas, field) };

    true
}

#[inline(always)]
pub(crate) fn binomial(_: usize, _: &[u8], _: u16, _: &mut [u16; 256]) -> bool {
    false
}

// x86-64 runs ML-KEM's transforms on the 32-bit kernels above.
#[inline(always)]
pub(crate) fn ntt16(_: &mut [u16; 256], _: &Field16) -> bool {
    false
}

#[inline(always)]
pub(crate) fn inverse_ntt16(_: &[i32; 256], _: &mut [u16; 256], _: &Field16) -> bool {
    false
}

const fn high(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) >> 32) as i32
}

// The portable Montgomery product of both schemes.
const fn montgomery(a: i32, b: i32, b_qinv: i32, q: i32) -> i32 {
    high(a, b) - high(a.wrapping_mul(b_qinv), q)
}

const fn freeze(a: i32, q: i32) -> i32 {
    a + (q & (a >> 31))
}

#[target_feature(enable = "avx2")]
fn forward_avx2(w: &mut [i32; 256], field: &Field) {
    let q = field.q;

    let mut m = 1;

    let mut length = 128;

    while length >= 256 >> field.layers {
        for start in (0..256).step_by(2 * length) {
            let (zeta, zeta_qinv) = (field.forward[m], field.forward_qinv[m]);

            m += 1;

            let (low, high) = w[start..start + 2 * length].split_at_mut(length);

            for (a, b) in low.iter_mut().zip(high) {
                let t = montgomery(*b, zeta, zeta_qinv, q);

                *b = *a - t;

                *a += t;
            }
        }

        length /= 2;
    }

    if let Some(scale) = field.forward_scale {
        let scale_qinv = scale.wrapping_mul(field.qinv);

        for x in w.iter_mut() {
            *x = freeze(montgomery(*x, scale, scale_qinv, q), q);
        }
    }
}

// The inverse layers take the reversed table from 256 - 256 / d on for the layer that pairs
// coefficients d apart.
#[target_feature(enable = "avx2")]
fn inverse_avx2(w: &mut [i32; 256], field: &Field) {
    let q = field.q;

    for x in w.iter_mut() {
        *x = match field.prepare {
            Prepare::Reduce => *x - ((*x + (1 << 22)) >> 23) * q,
            Prepare::Montgomery(factor) => {
                montgomery(*x, factor, factor.wrapping_mul(field.qinv), q)
            }
        };
    }

    let mut length = 256 >> field.layers;

    while length <= 128 {
        for (m, start) in (256 - 256 / length..).zip((0..256).step_by(2 * length)) {
            let (zeta, zeta_qinv) = (field.inverse[m], field.inverse_qinv[m]);

            let (low, high) = w[start..start + 2 * length].split_at_mut(length);

            for (a, b) in low.iter_mut().zip(high) {
                let t = *a;

                *a = t + *b;

                *b = montgomery(*b - t, zeta, zeta_qinv, q);
            }
        }

        length *= 2;
    }

    let (scale, scale_qinv) = (
        field.inverse_scale,
        field.inverse_scale.wrapping_mul(field.qinv),
    );

    for x in w.iter_mut() {
        *x = freeze(montgomery(*x, scale, scale_qinv, q), q);
    }
}

#[target_feature(enable = "avx2")]
fn products_avx2<const ADD: bool>(
    out: &mut [i32; 256],
    f: &[i32; 256],
    g: &[i32; 256],
    field: &Field,
) {
    for ((x, a), b) in out.iter_mut().zip(f).zip(g) {
        let product = montgomery(*a, *b, b.wrapping_mul(field.qinv), field.q);

        *x = if ADD { *x + product } else { product };
    }
}

#[target_feature(enable = "avx2")]
fn base_products_avx2(
    acc: &mut [i32; 256],
    f: &[u16; 256],
    g: &[u16; 256],
    gammas: &[i32; 128],
    field: &Field,
) {
    let pairs = acc.as_chunks_mut::<2>().0.iter_mut();

    let factors = f.as_chunks::<2>().0.iter().zip(g.as_chunks::<2>().0);

    for ((acc, (a, b)), &gamma) in pairs.zip(factors).zip(gammas) {
        let ([a0, a1], [b0, b1]) = (a.map(i32::from), b.map(i32::from));

        let product = montgomery(a1, b1, b1.wrapping_mul(field.qinv), field.q);

        acc[0] += a0 * b0 + product * gamma;

        acc[1] += a0 * b1 + a1 * b0;
    }
}

// Four states per AVX2 call, and three with one lane idle; one or two stay with the scalar
// permutation, where a mostly idle vector call is unlikely to pay.
#[allow(unsafe_code)]
pub(crate) fn permute_many(states: &mut [&mut [u64; 25]]) -> usize {
    if !has(AVX2) {
        return 0;
    }

    let mut done = 0;

    for group in states.chunks_mut(4) {
        if group.len() < 3 {
            break;
        }

        // SAFETY: the CPU has AVX2 and the operating system saves its registers.
        unsafe { permute4_avx2(group) };

        done += group.len();
    }

    done
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
fn compress256_sha(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    let [a, b, c, d, e, f, g, h] = *state;

    let mut streams = [Stream {
        abef: high_first([a, b, e, f]),
        cdgh: high_first([c, d, g, h]),
        m: [_mm_setzero_si128(); 4],
    }];

    // Reverses the bytes of each 32-bit word: the words of a block are big-endian.
    let swap = _mm_set_epi64x(0x0C0D_0E0F_0809_0A0B, 0x0405_0607_0001_0203);

    for block in blocks {
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

#[target_feature(enable = "avx2")]
fn compress256_lanes_avx2<const LANES: usize>(
    states: &mut [[u32; LANES]; 8],
    w: &mut [[u32; LANES]; 16],
) {
    compress256_lanes_portable(states, w);
}

#[target_feature(enable = "avx2")]
#[inline]
fn rotate<const LEFT: i32, const RIGHT: i32>(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi64::<LEFT>(x), _mm256_srli_epi64::<RIGHT>(x))
}

// One Keccak-f[1600] round on four states, lane i of each in vector i, written plane by plane
// like the scalar round so that few values are live at once. AVX2 has no 64-bit rotation: the
// rotations by 8 and 56 are byte shuffles, the others two shifts and an OR.
#[target_feature(enable = "avx2")]
#[inline]
fn round(a: &mut [__m256i; 25], constant: u64) {
    let mut c = [_mm256_setzero_si256(); 5];

    for (x, c) in c.iter_mut().enumerate() {
        *c = _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_xor_si256(a[x], a[x + 5]),
                _mm256_xor_si256(a[x + 10], a[x + 15]),
            ),
            a[x + 20],
        );
    }

    let mut d = [_mm256_setzero_si256(); 5];

    for (x, d) in d.iter_mut().enumerate() {
        *d = _mm256_xor_si256(c[(x + 4) % 5], rotate::<1, 63>(c[(x + 1) % 5]));
    }

    let by8 = _mm256_set_epi64x(
        0x0E0D_0C0B_0A09_080F,
        0x0605_0403_0201_0007,
        0x0E0D_0C0B_0A09_080F,
        0x0605_0403_0201_0007,
    );

    let by56 = _mm256_set_epi64x(
        0x080F_0E0D_0C0B_0A09,
        0x0007_0605_0403_0201,
        0x080F_0E0D_0C0B_0A09,
        0x0007_0605_0403_0201,
    );

    let t = |s: usize| _mm256_xor_si256(a[s], d[s % 5]);

    let b = [
        t(0),
        rotate::<44, 20>(t(6)),
        rotate::<43, 21>(t(12)),
        rotate::<21, 43>(t(18)),
        rotate::<14, 50>(t(24)),
        rotate::<28, 36>(t(3)),
        rotate::<20, 44>(t(9)),
        rotate::<3, 61>(t(10)),
        rotate::<45, 19>(t(16)),
        rotate::<61, 3>(t(22)),
        rotate::<1, 63>(t(1)),
        rotate::<6, 58>(t(7)),
        rotate::<25, 39>(t(13)),
        _mm256_shuffle_epi8(t(19), by8),
        rotate::<18, 46>(t(20)),
        rotate::<27, 37>(t(4)),
        rotate::<36, 28>(t(5)),
        rotate::<10, 54>(t(11)),
        rotate::<15, 49>(t(17)),
        _mm256_shuffle_epi8(t(23), by56),
        rotate::<62, 2>(t(2)),
        rotate::<55, 9>(t(8)),
        rotate::<39, 25>(t(14)),
        rotate::<41, 23>(t(15)),
        rotate::<2, 62>(t(21)),
    ];

    for (plane, b) in a
        .as_chunks_mut::<5>()
        .0
        .iter_mut()
        .zip(b.as_chunks::<5>().0)
    {
        for (x, lane) in plane.iter_mut().enumerate() {
            *lane = _mm256_xor_si256(b[x], _mm256_andnot_si256(b[(x + 1) % 5], b[(x + 2) % 5]));
        }
    }

    a[0] = _mm256_xor_si256(a[0], _mm256_set1_epi64x(constant as i64));
}

// One to four states; missing ones run as zeros in their lanes and are not stored.
#[target_feature(enable = "avx2")]
fn permute4_avx2(states: &mut [&mut [u64; 25]]) {
    let lane = |state: usize, i: usize| states.get(state).map_or(0, |s| s[i] as i64);

    let mut a = [_mm256_setzero_si256(); 25];

    for (i, vector) in a.iter_mut().enumerate() {
        *vector = _mm256_set_epi64x(lane(3, i), lane(2, i), lane(1, i), lane(0, i));
    }

    for &constant in &ROUND_CONSTANTS {
        round(&mut a, constant);
    }

    for (i, vector) in a.iter().enumerate() {
        let words = [
            _mm256_extract_epi64::<0>(*vector),
            _mm256_extract_epi64::<1>(*vector),
            _mm256_extract_epi64::<2>(*vector),
            _mm256_extract_epi64::<3>(*vector),
        ];

        for (state, word) in states.iter_mut().zip(words) {
            state[i] = word as u64;
        }
    }
}
