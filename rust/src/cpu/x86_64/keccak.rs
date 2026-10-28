// Keccak-f[1600] on four states with AVX2, on four states and on one with AVX-512VL, and on one
// state with the scalar code built for BMI1 and BMI2: ANDN takes chi's complement and AND in one
// instruction and RORX rotates into another register, so neither needs a copy first. The one-state
// kernels keep the state on the stack, or in registers, from one block to the next, as the portable
// code does, without a call per block. With AVX-512VL, sponges squeezed side by side stay in a
// vector form, one vector per lane of four states, from one block to the next (x86_64.rs,
// squeeze_wide).
//
// Every instruction here is a logical operation, a shift, a rotation, a shuffle, a blend, a
// broadcast, a compare of public indices, or a load or store at an address that depends only on
// public lengths, whose time does not depend on the data, and no branch depends on a lane: the
// kernels are constant-time by construction, which matters for the states of the PRFs that sample
// secret vectors. The AVX-512VL kernels rest on this alone, as valgrind cannot run them. They use
// 256-bit registers only, and LLVM must not be left room to pick 512-bit ones: the functions built
// with AVX-512 hold no arrays of plain words that it could copy or clear in 512-bit moves, and the
// code that moves states between memory and vectors around them is built with AVX2 alone.

use core::arch::x86_64::*;

use core::mem::MaybeUninit;

#[cfg(not(crypto_pq_optimized))]
use super::memory::words_of;
use super::memory::{load256, store_vector_at, store128, store256};
use crate::keccak::{self, ROUND_CONSTANTS};
use crate::sha2::{last_bytes, low_bytes};
use crate::wipe::{wipe, wipe_unless_optimized};

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

// The lanes of up to four states into vectors, the missing ones as zero states: four lanes of each
// state at a time by 32-byte loads and a 4 x 4 transposition, and the last lane from broadcasts.
// Inlined, it writes the caller's array in place, at constant indices only.
#[target_feature(enable = "avx2")]
#[inline]
fn gather4(s: &[&[u64; 25]; 4], a: &mut [__m256i; 25]) {
    for k in 0..6 {
        // An array expression, which builds the array in place: core::array::from_fn built it in
        // a temporary below opt-level 3. The loads are written out, as a closure for them was a
        // call at opt-level z that returned each row through a stack temporary.
        let rows = transpose4([
            load256(&s[0].as_chunks::<4>().0[k]),
            load256(&s[1].as_chunks::<4>().0[k]),
            load256(&s[2].as_chunks::<4>().0[k]),
            load256(&s[3].as_chunks::<4>().0[k]),
        ]);

        a[4 * k..4 * k + 4].copy_from_slice(&rows);
    }

    a[24] = lane4(s, 24);
}

// The lanes of up to four states out of vectors, four lanes at a time by a 4 x 4 transposition and
// the last lane by extraction. Each state is written by its index, which is a constant: the loop
// over the states that zip builds indexes the rows at run time.
#[target_feature(enable = "avx2")]
#[inline]
fn scatter4(a: &[__m256i; 25], states: &mut [&mut [u64; 25]]) {
    for k in 0..6 {
        let rows = transpose4([a[4 * k], a[4 * k + 1], a[4 * k + 2], a[4 * k + 3]]);

        macro_rules! store {
            ($($s:literal)*) => {
                $(
                    if let Some(state) = states.get_mut($s) {
                        store256(rows[$s], &mut state.as_chunks_mut::<4>().0[k]);
                    }
                )*
            };
        }

        store!(0 1 2 3);
    }

    macro_rules! last {
        ($($s:literal)*) => {
            $(
                if let Some(state) = states.get_mut($s) {
                    state[24] = _mm256_extract_epi64::<$s>(a[24]) as u64;
                }
            )*
        };
    }

    last!(0 1 2 3);
}

// The lanes of up to four states in vectors, lane i of each in vector i: each word broadcast from
// memory and the four blended together. LLVM still builds each vector in two 128-bit halves and
// stores them apart (1.89 and 1.99 at opt-levels 2 and 3), so the first squeeze after a start
// loads each vector from two stores.
#[target_feature(enable = "avx2")]
#[inline]
fn lane4(s: &[&[u64; 25]; 4], i: usize) -> __m256i {
    // The broadcasts are written out, as in gather4: a closure for them was a call at opt-level
    // z that returned each word through a stack temporary.
    let low = _mm256_blend_epi32::<0x0C>(
        _mm256_set1_epi64x(s[0][i] as i64),
        _mm256_set1_epi64x(s[1][i] as i64),
    );

    let high = _mm256_blend_epi32::<0xC0>(
        _mm256_set1_epi64x(s[2][i] as i64),
        _mm256_set1_epi64x(s[3][i] as i64),
    );

    _mm256_blend_epi32::<0xF0>(low, high)
}

// Up to four states, the missing ones read as a zero state.
static ZERO: [u64; 25] = [0; 25];

#[inline]
pub(super) fn four<'a>(states: &'a [&mut [u64; 25]]) -> [&'a [u64; 25]; 4] {
    core::array::from_fn(|i| states.get(i).map_or(&ZERO, |s| &**s))
}

#[inline]
pub(super) fn four_of(states: &[[u64; 25]]) -> [&[u64; 25]; 4] {
    core::array::from_fn(|i| states.get(i).unwrap_or(&ZERO))
}

// The first `lanes` lanes of the active ones of up to four sponges in the vector form, into their
// states: four lanes of each sponge at a time by a 4 x 4 transposition, and the rest one by one.
// Each sponge is written out separately, by its index: LLVM built a loop over the iterators of
// states and active with the rows in memory, which took twice as long.
#[target_feature(enable = "avx2")]
pub(super) fn rows_out(
    vectors: &[__m256i; 25],
    states: &mut [[u64; 25]],
    active: &[bool],
    lanes: usize,
) {
    let whole = lanes / 4;

    let on = |s: usize| active.get(s) == Some(&true);

    let ons = [on(0), on(1), on(2), on(3)];

    for k in 0..whole {
        let rows = transpose4([
            vectors[4 * k],
            vectors[4 * k + 1],
            vectors[4 * k + 2],
            vectors[4 * k + 3],
        ]);

        macro_rules! store {
            ($($s:literal)*) => {
                $(
                    if ons[$s] {
                        store256(rows[$s], &mut states[$s].as_chunks_mut::<4>().0[k]);
                    }
                )*
            };
        }

        store!(0 1 2 3);
    }

    for (i, vector) in vectors.iter().enumerate().take(lanes).skip(4 * whole) {
        macro_rules! store {
            ($($s:literal)*) => {
                $(
                    if ons[$s] {
                        states[$s][i] = _mm256_extract_epi64::<$s>(*vector) as u64;
                    }
                )*
            };
        }

        store!(0 1 2 3);
    }
}

// A 4 x 4 matrix of 64-bit words in four vectors, transposed: four lanes of four states, one
// state per vector, become one lane per vector, and back.
#[target_feature(enable = "avx2")]
#[inline]
fn transpose4(v: [__m256i; 4]) -> [__m256i; 4] {
    let low = [
        _mm256_unpacklo_epi64(v[0], v[1]),
        _mm256_unpacklo_epi64(v[2], v[3]),
    ];

    let high = [
        _mm256_unpackhi_epi64(v[0], v[1]),
        _mm256_unpackhi_epi64(v[2], v[3]),
    ];

    [
        _mm256_permute2x128_si256::<0x20>(low[0], low[1]),
        _mm256_permute2x128_si256::<0x20>(high[0], high[1]),
        _mm256_permute2x128_si256::<0x31>(low[0], low[1]),
        _mm256_permute2x128_si256::<0x31>(high[0], high[1]),
    ]
}

// The lanes of up to four states from vectors, four lanes of each state at a time by a 4 x 4
// transposition and one store, and the last lane by extraction. As whole vectors, the stores give
// LLVM no runs of words that it could merge into 512-bit stores in the AVX-512VL kernel.
#[target_feature(enable = "avx2")]
pub(super) fn scatter4_transposed(a: &[__m256i; 25], states: &mut [&mut [u64; 25]]) {
    for (k, v) in a.as_chunks::<4>().0.iter().enumerate() {
        let rows = transpose4(*v);

        for (state, row) in states.iter_mut().zip(rows) {
            store256(row, &mut state.as_chunks_mut::<4>().0[k]);
        }
    }

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut last = [
        _mm256_extract_epi64::<0>(a[24]),
        _mm256_extract_epi64::<1>(a[24]),
        _mm256_extract_epi64::<2>(a[24]),
        _mm256_extract_epi64::<3>(a[24]),
    ];

    for (state, word) in states.iter_mut().zip(last) {
        state[24] = word as u64;
    }

    wipe_unless_optimized!(&mut last);
}

// One to four states; missing ones run as zeros in their lanes and are not stored. a, e and the
// parities are indexed with constants only, so that at opt-level 3 they are register values
// (D-76), spilled as the rounds need; below it they are wiped. With gather4 and scatter4 as loops
// over the states, a stayed in memory, and a call on four states took 8 to 11% more time on AMD
// Zen 3.
#[target_feature(enable = "avx2")]
pub(super) fn permute4_avx2(states: &mut [&mut [u64; 25]]) {
    let mut a = [_mm256_setzero_si256(); 25];

    gather4(&four(states), &mut a);

    let mut parities = parities4(&a);

    let mut e = [_mm256_setzero_si256(); 25];

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        round4(&a, &mut e, &mut parities, constants[0]);

        round4(&e, &mut a, &mut parities, constants[1]);
    }

    scatter4(&a, states);

    wipe_unless_optimized!(words_of(&mut a));

    wipe_unless_optimized!(words_of(&mut e));

    wipe_unless_optimized!(words_of(&mut parities));
}

// The 24 rounds on four states that stay in vectors. Inlined, they unroll in full: 2.20 ms for the
// rows of FrodoKEM-976 on Haswell, against 2.36 ms as a call around the loop of rounds.
#[cfg(feature = "frodokem")]
#[target_feature(enable = "avx2")]
#[inline]
fn permute4_in_place(a: &mut [__m256i; 25], e: &mut [__m256i; 25]) {
    let mut parities = parities4(a);

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
#[inline]
fn rows4_with(
    seed_a: &[u8; 16],
    rows: &mut [u16],
    n: usize,
    i0: usize,
    permute: impl Fn(&mut [__m256i; 25], &mut [__m256i; 25]),
) {
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
        permute(&mut a, &mut e);

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

// x ^ y ^ z in one three-input logic instruction.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline]
fn xor3(x: __m256i, y: __m256i, z: __m256i) -> __m256i {
    _mm256_ternarylogic_epi64::<0x96>(x, y, z)
}

// One round on up to four states held in 25 of the 32 registers: the column parities, every lane
// of the rho-pi output with theta's value added and rotated, then chi plane by plane, which writes
// the new state; LLVM turns chi's ANDN and XOR into one three-input instruction. Lane x of plane y
// of the rho-pi output comes from lane (x + 3y) % 5 + 5x.
//
// Two forms of theta, chosen per vendor in x86_64.rs from the times measured: with THETA3, theta's
// value goes into each lane in one three-input instruction, in fewer instructions, which Intel's
// cores run in less time; without it, theta's values are computed once per column and added with
// XOR, which AMD's cores run in less time (four states: Zen 5 172 against 185 ns, Zen 4 204
// against 227).
#[target_feature(enable = "avx512f,avx512vl")]
#[inline]
fn round_avx512<const THETA3: bool>(a: &mut [__m256i; 25], constant: u64) {
    // Array expressions, which build each array where it lives: core::array::from_fn built them
    // in a temporary and copied it, below opt-level 3 with 512-bit moves.
    let parity = |x: usize| xor3(xor3(a[x], a[x + 5], a[x + 10]), a[x + 15], a[x + 20]);

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut c = [parity(0), parity(1), parity(2), parity(3), parity(4)];

    let rotate = |x: usize| _mm256_rol_epi64::<1>(c[x]);

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut rotated = [rotate(0), rotate(1), rotate(2), rotate(3), rotate(4)];

    let column = |x: usize| _mm256_xor_si256(c[(x + 4) % 5], rotated[(x + 1) % 5]);

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut d = [column(0), column(1), column(2), column(3), column(4)];

    // Theta's value of column x is c[x - 1] ^ rotated[x + 1].
    macro_rules! theta {
        ($source:literal) => {
            if THETA3 {
                xor3(a[$source], c[($source + 4) % 5], rotated[($source + 1) % 5])
            } else {
                _mm256_xor_si256(a[$source], d[$source % 5])
            }
        };
    }

    macro_rules! lane {
        ($source:literal, $rotation:literal) => {
            _mm256_rol_epi64::<$rotation>(theta!($source))
        };
    }

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut b = [
        theta!(0),
        lane!(6, 44),
        lane!(12, 43),
        lane!(18, 21),
        lane!(24, 14),
        lane!(3, 28),
        lane!(9, 20),
        lane!(10, 3),
        lane!(16, 45),
        lane!(22, 61),
        lane!(1, 1),
        lane!(7, 6),
        lane!(13, 25),
        lane!(19, 8),
        lane!(20, 18),
        lane!(4, 27),
        lane!(5, 36),
        lane!(11, 10),
        lane!(17, 15),
        lane!(23, 56),
        lane!(2, 62),
        lane!(8, 55),
        lane!(14, 39),
        lane!(15, 41),
        lane!(21, 2),
    ];

    for y in 0..5 {
        for x in 0..5 {
            a[x + 5 * y] = _mm256_xor_si256(
                b[x + 5 * y],
                _mm256_andnot_si256(b[(x + 1) % 5 + 5 * y], b[(x + 2) % 5 + 5 * y]),
            );
        }
    }

    a[0] = _mm256_xor_si256(a[0], _mm256_set1_epi64x(constant as i64));

    #[cfg(not(crypto_pq_optimized))]
    wipe_baseline(words_of(&mut c));

    #[cfg(not(crypto_pq_optimized))]
    wipe_baseline(words_of(&mut rotated));

    #[cfg(not(crypto_pq_optimized))]
    wipe_baseline(words_of(&mut d));

    #[cfg(not(crypto_pq_optimized))]
    wipe_baseline(words_of(&mut b));
}

// wipe_unless_optimized for the AVX-512 kernels: a call that is never inlined keeps the crate's
// baseline target features, while wipe inlined into a kernel that enables AVX-512F has its zero
// stores widened to 512-bit ones, which this code never uses.
#[cfg(not(crypto_pq_optimized))]
#[inline(never)]
fn wipe_baseline(words: &mut [u64]) {
    wipe(words);
}

// The 24 rounds, two per loop step with PAIRS, which LLVM schedules across the pair. The
// constants are read by reference: a copy of them on the stack was made with 512-bit moves.
#[target_feature(enable = "avx2,avx512f,avx512vl")]
#[inline]
fn rounds_avx512<const THETA3: bool, const PAIRS: bool>(a: &mut [__m256i; 25]) {
    if PAIRS {
        for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
            round_avx512::<THETA3>(a, constants[0]);

            round_avx512::<THETA3>(a, constants[1]);
        }
    } else {
        for &constant in &ROUND_CONSTANTS {
            round_avx512::<THETA3>(a, constant);
        }
    }
}

// The column parities of four states.
#[target_feature(enable = "avx2")]
#[inline]
fn parities4(a: &[__m256i; 25]) -> [__m256i; 5] {
    let column = |x: usize| {
        _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_xor_si256(a[x], a[x + 5]),
                _mm256_xor_si256(a[x + 10], a[x + 15]),
            ),
            a[x + 20],
        )
    };

    // An array expression, which builds the array in place: core::array::from_fn built it in a
    // temporary and copied it below opt-level 3.
    [column(0), column(1), column(2), column(3), column(4)]
}

// The 24 rounds on four states in memory, one vector per lane, out of line: inlined, the rounds
// of two to a step left LLVM with a call of its own anyway, and copies of the states around it.
// The loads here take whole 32-byte stores directly, as the previous rounds, spare_in, rows4_with
// and wide_in by rows leave them, the last vector of wide_in apart; the halves that wide_in stores
// otherwise cost a stall on the first load of each vector.
#[target_feature(enable = "avx2,avx512f,avx512vl")]
#[inline(never)]
pub(super) fn rounds4_avx512<const THETA3: bool, const PAIRS: bool>(a: &mut [__m256i; 25]) {
    rounds_avx512::<THETA3, PAIRS>(a);
}

// Up to four states into the vector form of rounds4_avx512, the missing ones as zero states: every
// element of group is written. With ROWS, four lanes of each state at a time by 32-byte loads and a
// 4 x 4 transposition, stored whole; otherwise lane by lane from broadcasts, which LLVM stores as
// 16-byte halves. Per four-state permutation, rows against broadcasts, from the previous
// permutation's stores and then after 8-byte stores to the states: AMD Zen 5 187-202 against
// 193-208 ns and 199-214 against 207-221, Zen 4 232-240 against 233-242 and 247-257 against
// 254-263; Intel Emerald Rapids 279-299 against 278-301 and 296-316 against 289-309, Ice Lake 263
// against 262 and 285 against 281-282. Built without AVX-512, as are the other functions around
// rounds4_avx512, so that LLVM cannot join their stores into 512-bit ones.
#[target_feature(enable = "avx2")]
pub(super) fn wide_in<const ROWS: bool>(
    s: &[&[u64; 25]; 4],
    group: &mut MaybeUninit<[__m256i; 25]>,
) {
    if ROWS {
        for k in 0..6 {
            let rows = transpose4(core::array::from_fn(|j| {
                load256(&s[j].as_chunks::<4>().0[k])
            }));

            for (i, vector) in rows.into_iter().enumerate() {
                store_vector_at(vector, group, 4 * k + i);
            }
        }

        store_vector_at(lane4(s, 24), group, 24);
    } else {
        for i in 0..25 {
            store_vector_at(lane4(s, i), group, i);
        }
    }
}

// The state given as spare into lane j of the vector form for a permutation, and out of it after,
// which leaves that lane zero.
#[target_feature(enable = "avx2")]
pub(super) fn spare_in(group: &mut [__m256i; 25], j: usize, state: &[u64; 25]) {
    let mask = lane_mask(j);

    for (vector, &word) in group.iter_mut().zip(state) {
        *vector = _mm256_blendv_epi8(*vector, _mm256_set1_epi64x(word as i64), mask);
    }
}

// The lane is cleared by a blend with zero, as spare_in blends: written as an AND NOT of the
// group's own vectors, it became masked stores (VPMASKMOVQ) at opt-level 3, which are not on the
// list of data-operand-independent timing instructions.
#[target_feature(enable = "avx2")]
pub(super) fn spare_out(group: &mut [__m256i; 25], j: usize, state: &mut [u64; 25]) {
    let mask = lane_mask(j);

    let index = _mm256_setr_epi32(2 * j as i32, 2 * j as i32 + 1, 0, 0, 0, 0, 0, 0);

    for (vector, word) in group.iter_mut().zip(state) {
        let moved = _mm256_permutevar8x32_epi32(*vector, index);

        *word = _mm_cvtsi128_si64(_mm256_castsi256_si128(moved)) as u64;

        *vector = _mm256_blendv_epi8(*vector, _mm256_setzero_si256(), mask);
    }
}

// All ones in 64-bit lane j, zeros elsewhere.
#[target_feature(enable = "avx2")]
#[inline]
fn lane_mask(j: usize) -> __m256i {
    _mm256_cmpeq_epi64(_mm256_setr_epi64x(0, 1, 2, 3), _mm256_set1_epi64x(j as i64))
}

// One state with AVX-512VL, each lane in the low quarter of its own register, as the four-state
// kernel holds four: nothing is transposed. x86_64.rs selects it on the cores that run it in less
// time than the scalar rounds (AVX512_ONE).
// The lanes are loaded as written out and stored two to a 128-bit store: below opt-level 3, LLVM
// built from_fn's vectors through memory and merged the extractions into 512-bit stores.
#[target_feature(enable = "avx2,avx512f,avx512vl")]
#[inline]
fn load1(state: &[u64; 25]) -> [__m256i; 25] {
    macro_rules! lanes {
        ($($i:literal)*) => {
            [$(_mm256_set_epi64x(0, 0, 0, state[$i] as i64)),*]
        };
    }

    lanes!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24)
}

#[target_feature(enable = "avx2,avx512f,avx512vl")]
#[inline]
fn store1(a: &[__m256i; 25], state: &mut [u64; 25]) {
    let (pairs, last) = state.as_chunks_mut::<2>();

    for (pair, v) in pairs.iter_mut().zip(a.as_chunks::<2>().0) {
        let low = _mm_unpacklo_epi64(_mm256_castsi256_si128(v[0]), _mm256_castsi256_si128(v[1]));

        store128(low, pair);
    }

    last[0] = _mm256_extract_epi64::<0>(a[24]) as u64;
}

#[target_feature(enable = "avx2,avx512f,avx512vl")]
pub(super) fn permute1_avx512<const THETA3: bool>(state: &mut [u64; 25]) {
    let mut a = load1(state);

    rounds_avx512::<THETA3, false>(&mut a);

    store1(&a, state);
}

#[target_feature(enable = "avx2,avx512f,avx512vl")]
pub(super) fn absorb_avx512<const RATE: usize, const THETA3: bool>(
    state: &mut [u64; 25],
    blocks: &[[u8; RATE]],
) {
    let mut a = load1(state);

    for block in blocks {
        for (lane, bytes) in a.iter_mut().zip(block.as_chunks::<8>().0) {
            let word = _mm256_set_epi64x(0, 0, 0, i64::from_le_bytes(*bytes));

            *lane = _mm256_xor_si256(*lane, word);
        }

        rounds_avx512::<THETA3, false>(&mut a);
    }

    store1(&a, state);
}

#[cfg(feature = "frodokem")]
#[target_feature(enable = "avx2")]
pub(super) fn matrix_rows4(seed_a: &[u8; 16], rows: &mut [u16], n: usize, i0: usize) {
    rows4_with(seed_a, rows, n, i0, |a, e| permute4_in_place(a, e));
}

// matrix_rows4 with the AVX-512VL permutation. As digest_avx512, this code itself is built without
// AVX-512, and the states pass through memory once per permutation.
//
// SAFETY: the caller makes sure that the CPU has AVX2, AVX-512F and AVX-512VL and that the
// operating system saves their registers.
#[cfg(feature = "frodokem")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_code)]
pub(super) unsafe fn matrix_rows4_avx512<const THETA3: bool, const PAIRS: bool>(
    seed_a: &[u8; 16],
    rows: &mut [u16],
    n: usize,
    i0: usize,
) {
    // SAFETY: the caller's guarantee above.
    rows4_with(seed_a, rows, n, i0, |a, _| unsafe {
        rounds4_avx512::<THETA3, PAIRS>(a)
    });
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

    wipe_unless_optimized!(&mut e);

    wipe_unless_optimized!(&mut parities);
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
// whose lanes each get a single store, and the buffer is wiped with the state. One body for both
// permutations, so that the code of each is what it would be on its own.
macro_rules! digest {
    ($(#[$attribute:meta])* fn $name:ident, $state:ident => $permute:expr) => {
        digest!(@ $(#[$attribute])* [] $name [], $state => $permute);
    };
    (
        $(#[$attribute:meta])* unsafe fn $name:ident<$($form:ident),*>,
        $state:ident => $permute:expr
    ) => {
        digest!(@ $(#[$attribute])* [unsafe] $name [$($form),*], $state => $permute);
    };
    (
        @ $(#[$attribute:meta])* [$($unsafe:ident)?] $name:ident [$($form:ident),*],
        $state:ident => $permute:expr
    ) => {
        $(#[$attribute])*
        pub(super) $($unsafe)? fn $name<const RATE: usize $(, const $form: bool)*>(
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

                let $state = &mut state;

                $permute;
            }

            for (lane, bytes) in state.iter_mut().zip(lanes) {
                *lane ^= u64::from_le_bytes(*bytes);
            }

            let marker =
                last_bytes(data, rest.len()) as u64 | u64::from(suffix) << (8 * rest.len());

            state[lanes.len()] ^= marker;

            state[RATE / 8 - 1] ^= 0x80 << 56;

            let $state = &mut state;

            $permute;

            let (whole, partial) = out.as_chunks_mut::<8>();

            let mut chunks = whole.chunks_mut(RATE / 8).peekable();

            let mut squeezed = 0;

            while let Some(chunk) = chunks.next() {
                for (bytes, lane) in chunk.iter_mut().zip(&state) {
                    *bytes = lane.to_le_bytes();
                }

                squeezed += chunk.len();

                if chunk.len() == RATE / 8 && (chunks.peek().is_some() || !partial.is_empty()) {
                    let $state = &mut state;

                    $permute;

                    squeezed = 0;
                }
            }

            if !partial.is_empty() {
                low_bytes(state[squeezed], partial);
            }

            wipe(&mut state);
        }
    };
}

digest!(
    #[target_feature(enable = "bmi1,bmi2")]
    fn digest_bmi,
    state => rounds(state)
);

// digest_bmi with the one-state AVX-512VL permutation. This code itself is built without AVX-512,
// as LLVM would copy and clear its buffers in 512-bit registers; the state passes through memory
// once per permutation.
//
// SAFETY: the caller makes sure that the CPU has AVX2, BMI1, BMI2, AVX-512F and AVX-512VL and that
// the operating system saves their registers.
digest!(
    #[target_feature(enable = "bmi1,bmi2")]
    #[allow(unsafe_code)]
    unsafe fn digest_avx512<THETA3>,
    // SAFETY: the caller's guarantee above.
    state => unsafe { permute1_avx512::<THETA3>(state) }
);
