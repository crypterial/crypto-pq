// Keccak-f[1600] on four states with AVX2, and on one state with the scalar code built for BMI1
// and BMI2: ANDN takes chi's complement and AND in one instruction and RORX rotates into another
// register, so neither needs a copy first. The one-state kernels keep the state on the stack from
// one block to the next, as the portable code does, without a call per block.

use core::arch::x86_64::*;

#[cfg(feature = "frodokem")]
use super::memory::store256;
use crate::keccak::{self, ROUND_CONSTANTS};
use crate::sha2::last_bytes;
use crate::wipe::wipe;

#[target_feature(enable = "avx2")]
#[inline]
fn rotate<const LEFT: i32, const RIGHT: i32>(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi64::<LEFT>(x), _mm256_srli_epi64::<RIGHT>(x))
}

// Theta's values of four states from their column parities.
#[target_feature(enable = "avx2")]
#[inline]
fn theta4(c: &[__m256i; 5]) -> [__m256i; 5] {
    core::array::from_fn(|x| _mm256_xor_si256(c[(x + 4) % 5], rotate::<1, 63>(c[(x + 1) % 5])))
}

// Output plane Y of a round on four states from a into e, lane i of each in vector i, as the scalar
// plane does: lane x of plane Y of the rho-pi output comes from lane (x + 3Y) % 5 + 5x of a. Going
// plane by plane keeps few values live, and the states stay in memory between planes. AVX2 has no
// 64-bit rotation: the rotations by 8 and 56 are byte shuffles, the others two shifts and an OR.
#[target_feature(enable = "avx2")]
#[inline]
fn plane4<const Y: usize>(
    a: &[__m256i; 25],
    d: &[__m256i; 5],
    e: &mut [__m256i; 25],
    next: &mut [__m256i; 5],
    constant: u64,
) {
    let t = |s: usize| _mm256_xor_si256(a[s], d[s % 5]);

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

    let b = match Y {
        0 => [
            t(0),
            rotate::<44, 20>(t(6)),
            rotate::<43, 21>(t(12)),
            rotate::<21, 43>(t(18)),
            rotate::<14, 50>(t(24)),
        ],
        1 => [
            rotate::<28, 36>(t(3)),
            rotate::<20, 44>(t(9)),
            rotate::<3, 61>(t(10)),
            rotate::<45, 19>(t(16)),
            rotate::<61, 3>(t(22)),
        ],
        2 => [
            rotate::<1, 63>(t(1)),
            rotate::<6, 58>(t(7)),
            rotate::<25, 39>(t(13)),
            _mm256_shuffle_epi8(t(19), by8),
            rotate::<18, 46>(t(20)),
        ],
        3 => [
            rotate::<27, 37>(t(4)),
            rotate::<36, 28>(t(5)),
            rotate::<10, 54>(t(11)),
            rotate::<15, 49>(t(17)),
            _mm256_shuffle_epi8(t(23), by56),
        ],
        _ => [
            rotate::<62, 2>(t(2)),
            rotate::<55, 9>(t(8)),
            rotate::<39, 25>(t(14)),
            rotate::<41, 23>(t(15)),
            rotate::<2, 62>(t(21)),
        ],
    };

    for x in 0..5 {
        let mut lane = _mm256_xor_si256(b[x], _mm256_andnot_si256(b[(x + 1) % 5], b[(x + 2) % 5]));

        // Iota on the first lane as it is written.
        if Y == 0 && x == 0 {
            lane = _mm256_xor_si256(lane, _mm256_set1_epi64x(constant as i64));
        }

        e[x + 5 * Y] = lane;

        next[x] = _mm256_xor_si256(next[x], lane);
    }
}

// One round on four states from a into e.
#[target_feature(enable = "avx2")]
#[inline]
fn round4(a: &[__m256i; 25], e: &mut [__m256i; 25], parities: &mut [__m256i; 5], constant: u64) {
    let d = theta4(parities);

    let mut next = [_mm256_setzero_si256(); 5];

    plane4::<0>(a, &d, e, &mut next, constant);

    plane4::<1>(a, &d, e, &mut next, constant);

    plane4::<2>(a, &d, e, &mut next, constant);

    plane4::<3>(a, &d, e, &mut next, constant);

    plane4::<4>(a, &d, e, &mut next, constant);

    *parities = next;
}

// The lanes of up to four states in vectors, missing states as zeros, and their column parities.
#[target_feature(enable = "avx2")]
#[inline]
fn gather4(states: &[&mut [u64; 25]]) -> ([__m256i; 25], [__m256i; 5]) {
    let lane = |state: usize, i: usize| states.get(state).map_or(0, |s| s[i] as i64);

    let mut a = [_mm256_setzero_si256(); 25];

    for (i, vector) in a.iter_mut().enumerate() {
        *vector = _mm256_set_epi64x(lane(3, i), lane(2, i), lane(1, i), lane(0, i));
    }

    let parities = core::array::from_fn(|x| {
        _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_xor_si256(a[x], a[x + 5]),
                _mm256_xor_si256(a[x + 10], a[x + 15]),
            ),
            a[x + 20],
        )
    });

    (a, parities)
}

#[target_feature(enable = "avx2")]
#[inline]
fn scatter4(a: &[__m256i; 25], states: &mut [&mut [u64; 25]]) {
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

// One to four states; missing ones run as zeros in their lanes and are not stored.
#[target_feature(enable = "avx2")]
pub(super) fn permute4_avx2(states: &mut [&mut [u64; 25]]) {
    let (mut a, mut parities) = gather4(states);

    let mut e = [_mm256_setzero_si256(); 25];

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        round4(&a, &mut e, &mut parities, constants[0]);

        round4(&e, &mut a, &mut parities, constants[1]);
    }

    scatter4(&a, states);
}

// The 24 rounds on four states that stay in vectors. Inlined, they unroll in full: 2.20 ms for the
// rows of FrodoKEM-976 on Haswell, against 2.36 ms as a call around the loop of rounds.
#[cfg(feature = "frodokem")]
#[target_feature(enable = "avx2")]
#[inline]
fn permute4_in_place(a: &mut [__m256i; 25], e: &mut [__m256i; 25]) {
    let mut parities = core::array::from_fn(|x| {
        _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_xor_si256(a[x], a[x + 5]),
                _mm256_xor_si256(a[x + 10], a[x + 15]),
            ),
            a[x + 20],
        )
    });

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        round4(a, e, &mut parities, constants[0]);

        round4(e, a, &mut parities, constants[1]);
    }
}

// Four rows of FrodoKEM's matrix A, rows i0 to i0 + 3 of n entries each: row i is the output of
// SHAKE128(i || seedA) as little-endian 16-bit values (frodokem.rs, shake_rows). The four sponges
// stay in vectors from one block to the next, and each group of four lanes is transposed into
// sixteen entries of every row. (Two groups interleaved round by round spilled more than they
// overlapped: 94 instead of 70 cycles a round per group on Haswell, by llvm-mca.) A is public.
#[cfg(feature = "frodokem")]
#[target_feature(enable = "avx2")]
pub(super) fn matrix_rows4(seed_a: &[u8; 16], rows: &mut [u16], n: usize, i0: usize) {
    let word = |bytes: &[u8]| {
        let mut word = [0; 8];

        word[..bytes.len()].copy_from_slice(bytes);

        u64::from_le_bytes(word)
    };

    // The 18-byte message i || seedA, SHAKE's suffix and the padding at the end of the rate.
    let first = word(&seed_a[..6]) << 16;

    let row = |r: usize| ((i0 + r) as u64 | first) as i64;

    let mut a = [_mm256_setzero_si256(); 25];

    a[0] = _mm256_set_epi64x(row(3), row(2), row(1), row(0));

    a[1] = _mm256_set1_epi64x(word(&seed_a[6..14]) as i64);

    a[2] = _mm256_set1_epi64x((word(&seed_a[14..]) | 0x1F << 16) as i64);

    a[20] = _mm256_set1_epi64x((0x80u64 << 56) as i64);

    let mut e = [_mm256_setzero_si256(); 25];

    let mut out = rows.chunks_exact_mut(n);

    let mut out: [&mut [u16]; 4] = core::array::from_fn(|_| out.next().expect("four rows"));

    let mut offset = 0;

    while offset < n {
        permute4_in_place(&mut a, &mut e);

        let lanes = (n - offset).min(4 * 21) / 4;

        let (groups, rest) = a[..lanes].as_chunks::<4>();

        for (q, v) in groups.iter().enumerate() {
            let low = [
                _mm256_unpacklo_epi64(v[0], v[1]),
                _mm256_unpacklo_epi64(v[2], v[3]),
            ];

            let high = [
                _mm256_unpackhi_epi64(v[0], v[1]),
                _mm256_unpackhi_epi64(v[2], v[3]),
            ];

            let states = [
                _mm256_permute2x128_si256::<0x20>(low[0], low[1]),
                _mm256_permute2x128_si256::<0x20>(high[0], high[1]),
                _mm256_permute2x128_si256::<0x31>(low[0], low[1]),
                _mm256_permute2x128_si256::<0x31>(high[0], high[1]),
            ];

            let at = offset + 16 * q;

            for (row, state) in out.iter_mut().zip(states) {
                let entries: &mut [u16; 16] =
                    (&mut row[at..at + 16]).try_into().expect("16 entries");

                store256(state, entries);
            }
        }

        for (l, v) in rest.iter().enumerate() {
            let at = offset + 16 * groups.len() + 4 * l;

            let words = [
                _mm256_extract_epi64::<0>(*v),
                _mm256_extract_epi64::<1>(*v),
                _mm256_extract_epi64::<2>(*v),
                _mm256_extract_epi64::<3>(*v),
            ];

            for (row, word) in out.iter_mut().zip(words) {
                for (k, entry) in row[at..at + 4].iter_mut().enumerate() {
                    *entry = (word as u64 >> (16 * k)) as u16;
                }
            }
        }

        offset += 4 * lanes;
    }
}

// The portable rounds, two per step from the state into a copy and back.
#[target_feature(enable = "bmi1,bmi2")]
#[inline]
fn rounds(state: &mut [u64; 25]) {
    let mut parities = keccak::parities(state);

    let mut e = [0; 25];

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        keccak::round(state, &mut e, &mut parities, constants[0]);

        keccak::round(&e, state, &mut parities, constants[1]);
    }
}

#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn permute_bmi(state: &mut [u64; 25]) {
    rounds(state);
}

#[target_feature(enable = "bmi1,bmi2")]
#[inline]
fn xor_block<const RATE: usize>(state: &mut [u64; 25], block: &[u8; RATE]) {
    for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*bytes);
    }
}

#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn absorb_bmi<const RATE: usize>(state: &mut [u64; 25], blocks: &[[u8; RATE]]) {
    for block in blocks {
        xor_block(state, block);

        rounds(state);
    }
}

// The whole blocks of data, its padded last block, and then out.len() bytes squeezed, from the
// initial state if there is one and from zero otherwise. The last block is built in a buffer,
// whose lanes each get a single store, and the buffer is wiped with the state.
#[target_feature(enable = "bmi1,bmi2")]
pub(super) fn digest_bmi<const RATE: usize>(
    initial: Option<&[u64; 25]>,
    data: &[u8],
    suffix: u8,
    out: &mut [u8],
) {
    let (blocks, tail) = data.as_chunks::<RATE>();

    let (lanes, rest) = tail.as_chunks::<8>();

    let mut state = match initial {
        Some(initial) => *initial,
        None => [0; 25],
    };

    for block in blocks {
        xor_block(&mut state, block);

        rounds(&mut state);
    }

    for (lane, bytes) in state.iter_mut().zip(lanes) {
        *lane ^= u64::from_le_bytes(*bytes);
    }

    let marker = last_bytes(data, rest.len()) as u64 | u64::from(suffix) << (8 * rest.len());

    state[lanes.len()] ^= marker;

    state[RATE / 8 - 1] ^= 0x80 << 56;

    rounds(&mut state);

    let (whole, partial) = out.as_chunks_mut::<8>();

    let mut chunks = whole.chunks_mut(RATE / 8).peekable();

    let mut squeezed = 0;

    while let Some(chunk) = chunks.next() {
        for (bytes, lane) in chunk.iter_mut().zip(&state) {
            *bytes = lane.to_le_bytes();
        }

        squeezed += chunk.len();

        if chunk.len() == RATE / 8 && (chunks.peek().is_some() || !partial.is_empty()) {
            rounds(&mut state);

            squeezed = 0;
        }
    }

    if !partial.is_empty() {
        let lane = state[squeezed].to_le_bytes();

        partial.copy_from_slice(&lane[..partial.len()]);
    }

    wipe(&mut state);
}
