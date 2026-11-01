// BLAKE3 with AVX2 or SSE4.1, in two forms.
//
// Many inputs at once, as the reference implementation's hash_many: each vector holds one state
// word of eight inputs (AVX2) or four (SSE4.1), so a G function of the specification runs on all
// of them with each instruction. The message words are transposed into that form as each block
// is loaded: with AVX2, the 128-bit loads of inputs i and i + 4 share a register (an insert from
// memory, which avoids the shuffle port), and four-word transpositions follow within each half.
// The extended output of the root runs the same way on consecutive output blocks, which share the
// chaining value and the message and differ in the counter.
//
// One input at a time, for a chunk's blocks in order: a row of the state per vector, as in the
// BLAKE2s kernels, so the four G functions of a step run in the lanes; between the column and the
// diagonal steps the rows a, c and d rotate, so that b, whose chain links the steps, never waits
// for a shuffle. The message stays in four registers: each round builds its half steps' vectors
// from the previous round's with shuffles, unpacks and blends, as the reference SSE4.1 code does
// (with AVX-512VL, two two-table permutations). The state stays in registers from one block to
// the next.
//
// Rotations by 16 and 8 are byte shuffles, by 12 and 7 two shifts and an OR (each one VPRORD with
// AVX-512VL). Every instruction is on Intel's list of data-operand-independent timing
// instructions, or counts as on it by D-75 (SHUFPS), and no branch or address depends on the data.

use core::arch::x86_64::*;
use core::mem::MaybeUninit;

use super::blake3_zmm::Table16;
#[cfg(not(crypto_pq_optimized))]
use super::memory::words_of;
use super::memory::{Plain, clear, load128, load128_bytes, load256, store128, store256};
use crate::blake3::{Many, PERMUTATION};
use crate::sha2::IV_256;
use crate::wipe::{wipe, wipe_unless_optimized};

// The message word order of each round.
const fn schedule() -> [[usize; 16]; 7] {
    let mut rounds = [[0; 16]; 7];

    let mut i = 0;

    while i < 16 {
        rounds[0][i] = i;

        i += 1;
    }

    let mut r = 1;

    while r < 7 {
        let mut i = 0;

        while i < 16 {
            rounds[r][i] = rounds[r - 1][PERMUTATION[i]];

            i += 1;
        }

        r += 1;
    }

    rounds
}

const SCHEDULE: [[usize; 16]; 7] = schedule();

// The words of the four gathers of each round of the row form, in lane order: the column step's
// first and second words, then the diagonal step's, where lane j computes G(j - 1) as row a has
// moved down a word.
const fn gathers() -> [[[usize; 4]; 4]; 7] {
    let mut table = [[[0; 4]; 4]; 7];

    let mut r = 0;

    while r < 7 {
        let mut i = 0;

        while i < 4 {
            table[r][0][i] = SCHEDULE[r][2 * i];

            table[r][1][i] = SCHEDULE[r][2 * i + 1];

            table[r][2][i] = SCHEDULE[r][8 + 2 * ((i + 3) % 4)];

            table[r][3][i] = SCHEDULE[r][9 + 2 * ((i + 3) % 4)];

            i += 1;
        }

        r += 1;
    }

    table
}

const GATHERS: [[[usize; 4]; 4]; 7] = gathers();

// The words a, b, c and d of the four G functions of the column and of the diagonal step.
const COLUMNS: [[usize; 4]; 4] = [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]];

const DIAGONALS: [[usize; 4]; 4] = [[0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14]];

const ROTATE16: [u8; 16] = [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13];

const ROTATE8: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];

// Byte shuffle controls for the end of a short input: lane i of the sixteen from 16 - n on takes
// byte 16 - n + i of the load that ends at the input's end, the input's byte i of its last n,
// for i below n, and zero (the high bit) from n on.
const TAIL: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
];

// The bytes of an input shorter than sixteen bytes as two little-endian words with zeros after
// them, from loads of its first and last bytes, which overlap where the input is short, shifted
// into place. The length, which is public, alone picks the loads and the shifts.
fn short_words(data: &[u8]) -> [u64; 2] {
    let n = data.len();

    if let (Some(first), Some(last)) = (data.first_chunk::<8>(), data.last_chunk::<8>()) {
        // Bytes 8 to n of the input are the top n - 8 bytes of the last eight.
        let high = u64::from_le_bytes(*last)
            .checked_shr(8 * (16 - n) as u32)
            .unwrap_or(0);

        return [u64::from_le_bytes(*first), high];
    }

    if let (Some(first), Some(last)) = (data.first_chunk::<4>(), data.last_chunk::<4>()) {
        let high = u64::from(u32::from_le_bytes(*last)) >> (8 * (8 - n));

        return [u64::from(u32::from_le_bytes(*first)) | high << 32, 0];
    }

    let low = data
        .iter()
        .enumerate()
        .fold(0, |word, (i, &byte)| word | u64::from(byte) << (8 * i));

    [low, 0]
}

// The words of at most a block of input with zeros after it, in four vectors of four words in
// order, from loads of the input alone. Read back from a zeroed copy, the words would span the
// copy's stores, which a processor does not forward to a load: the loads would wait for the
// stores to reach the cache, at the head of the compression's chain.
#[target_feature(enable = "sse2,ssse3")]
#[inline]
fn message_short(data: &[u8]) -> [__m128i; 4] {
    assert!(data.len() <= 64, "at most a block of input");

    let (whole, rest) = data.as_chunks::<16>();

    let zero = _mm_setzero_si128();

    let last = tail(data, rest.len());

    match whole {
        [] => [last, zero, zero, zero],
        [a] => [load128(a), last, zero, zero],
        [a, b] => [load128(a), load128(b), last, zero],
        [a, b, c] => [load128(a), load128(b), load128(c), last],
        [a, b, c, d, ..] => [load128(a), load128(b), load128(c), load128(d)],
    }
}

// The last count bytes of data, fewer than sixteen, in the low bytes of a vector, zeros above
// them. From sixteen bytes of data on, one load ends at its end and a byte shuffle moves the
// count bytes down: the control's lanes from 16 - count on of TAIL.
#[target_feature(enable = "sse2,ssse3")]
#[inline]
fn tail(data: &[u8], count: usize) -> __m128i {
    if count == 0 {
        return _mm_setzero_si128();
    }

    let Some(end) = data.last_chunk::<16>() else {
        let [low, high] = short_words(data);

        return _mm_set_epi64x(high as i64, low as i64);
    };

    let Some(control) = TAIL[16 - count..].first_chunk::<16>() else {
        unreachable!("sixteen lanes of TAIL from 16 - count on")
    };

    _mm_shuffle_epi8(load128(end), load128(control))
}

// The row form, generated for SSE4.1 and for AVX2 (whose 128-bit instructions take three
// operands), from the including module's shuffles, among them those of the message schedule,
// which build each round's half-step vectors from the previous round's.
macro_rules! rows {
    ($feature:literal) => {
        #[target_feature(enable = $feature)]
        #[inline]
        fn rotate<const R: u32>(x: __m128i) -> __m128i {
            match R {
                16 => shuffle(x, load128(&ROTATE16)),
                8 => shuffle(x, load128(&ROTATE8)),
                12 => _mm_or_si128(_mm_srli_epi32::<12>(x), _mm_slli_epi32::<20>(x)),
                7 => _mm_or_si128(_mm_srli_epi32::<7>(x), _mm_slli_epi32::<25>(x)),
                _ => unreachable!("the rotations of BLAKE3"),
            }
        }

        #[target_feature(enable = $feature)]
        #[inline]
        fn half<const R1: u32, const R2: u32>(row: &mut [__m128i; 4], m: __m128i) {
            let [a, b, c, d] = row;

            *a = _mm_add_epi32(_mm_add_epi32(*a, m), *b);

            *d = rotate::<R1>(_mm_xor_si128(*d, *a));

            *c = _mm_add_epi32(*c, *d);

            *b = rotate::<R2>(_mm_xor_si128(*b, *c));
        }

        // The block's words in order, in four vectors.
        #[target_feature(enable = $feature)]
        #[inline]
        fn message(block: &[u8; 64]) -> [__m128i; 4] {
            let [m0, m1, m2, m3] = block.as_chunks::<16>().0 else {
                unreachable!("64 bytes are four groups of 16")
            };

            [load128(m0), load128(m1), load128(m2), load128(m3)]
        }

        // Round R's four half-step vectors, in lane order, from the previous round's (the block's
        // words in order for round 0), as the reference SSE4.1 code builds them: the first round
        // takes the even and the odd words of each half, every later round the permutation of
        // the message words, in registers.
        #[target_feature(enable = $feature)]
        #[inline]
        fn schedule<const R: usize>([m0, m1, m2, m3]: [__m128i; 4]) -> [__m128i; 4] {
            if R == 0 {
                return [
                    pick_even(m0, m1),
                    pick_odd(m0, m1),
                    word_down(pick_even(m2, m3)),
                    word_down(pick_odd(m2, m3)),
                ];
            }

            [
                word_up(pick_2113(m0, m1)),
                blend_odd(order_3300(m0), pick_2233(m2, m3)),
                order_0231(blend_fourth(low_quads(m3, m1), m2)),
                order_2310(low_words(m2, high_words(m1, m3))),
            ]
        }

        // Round R on the message vectors m, which become round R's. For the diagonal step, a
        // moves down a word and c and d up one and two.
        #[target_feature(enable = $feature)]
        #[inline]
        fn round<const R: usize>(row: &mut [__m128i; 4], m: &mut [__m128i; 4]) {
            *m = schedule::<R>(*m);

            half::<16, 12>(row, m[0]);

            half::<8, 7>(row, m[1]);

            row[0] = word_down(row[0]);

            row[2] = word_up(row[2]);

            row[3] = words_across(row[3]);

            half::<16, 12>(row, m[2]);

            half::<8, 7>(row, m[3]);

            row[0] = word_up(row[0]);

            row[2] = word_down(row[2]);

            row[3] = words_across(row[3]);
        }

        #[target_feature(enable = $feature)]
        #[inline]
        fn start(cv: [__m128i; 2], counter: u64, length: u32, flags: u32) -> [__m128i; 4] {
            let [low, _] = IV_256.as_chunks::<4>().0 else {
                unreachable!("eight words are two groups of four")
            };

            [
                cv[0],
                cv[1],
                load128(low),
                _mm_set_epi64x(
                    (u64::from(flags) << 32 | u64::from(length)) as i64,
                    counter as i64,
                ),
            ]
        }

        // The chaining value after the blocks, the first with `start` added to the flags and the
        // last with `end`. The rounds are written out here, so that the rows stay in registers
        // from one block to the next: through a function of their own, they went through memory.
        #[target_feature(enable = $feature)]
        pub(in crate::cpu) fn chain(
            cv: &mut [u32; 8],
            blocks: &[[u8; 64]],
            counter: u64,
            flags: u32,
            [first, end]: [u32; 2],
            last: crate::blake3::Last,
        ) {
            let [low, high] = cv.as_chunks_mut::<4>().0 else {
                unreachable!("eight words are two groups of four")
            };

            let mut h = [load128(low), load128(high)];

            let whole = blocks.len();

            for i in 0..whole + usize::from(last.is_some()) {
                let (block, length, f) = match last {
                    Some(last) if i == whole => last,
                    _ => {
                        let mut f = flags;

                        if i == 0 {
                            f |= first;
                        }

                        if i + 1 == whole {
                            f |= end;
                        }

                        (&blocks[i], 64, f)
                    }
                };

                let mut row = start(h, counter, length, f);

                let mut m = message(block);

                round::<0>(&mut row, &mut m);

                round::<1>(&mut row, &mut m);

                round::<2>(&mut row, &mut m);

                round::<3>(&mut row, &mut m);

                round::<4>(&mut row, &mut m);

                round::<5>(&mut row, &mut m);

                round::<6>(&mut row, &mut m);

                h = [_mm_xor_si128(row[0], row[2]), _mm_xor_si128(row[1], row[3])];

                wipe_unless_optimized!(words_of(&mut row));

                wipe_unless_optimized!(words_of(&mut m));
            }

            store128(h[0], low);

            store128(h[1], high);

            wipe_unless_optimized!(words_of(&mut h));
        }

        // At most 32 bytes of the root's output for at most a block of input, whose flags the
        // caller gives: one compression, from the key to the output in registers. The key is
        // eight words or their 32 bytes in little-endian order, which in memory are the same.
        #[target_feature(enable = $feature)]
        pub(in crate::cpu::x86_64) fn digest1<K: Plain, const N: usize>(
            key: &[K; N],
            flags: u32,
            data: &[u8],
            out: &mut [u8],
        ) {
            const { assert!(size_of::<[K; N]>() == 32) };

            let mut m = message_short(data);

            let cv = [load128_bytes(key, 0), load128_bytes(key, 16)];

            let mut row = start(cv, 0, data.len() as u32, flags);

            round::<0>(&mut row, &mut m);

            round::<1>(&mut row, &mut m);

            round::<2>(&mut row, &mut m);

            round::<3>(&mut row, &mut m);

            round::<4>(&mut row, &mut m);

            round::<5>(&mut row, &mut m);

            round::<6>(&mut row, &mut m);

            #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
            let mut h = [_mm_xor_si128(row[0], row[2]), _mm_xor_si128(row[1], row[3])];

            let mut bytes = [0; 32];

            let target = match <&mut [u8; 32]>::try_from(&mut *out) {
                Ok(whole) => whole,
                Err(_) => &mut bytes,
            };

            let [first, second] = target.as_chunks_mut::<16>().0 else {
                unreachable!("32 bytes are two groups of 16")
            };

            store128(h[0], first);

            store128(h[1], second);

            if out.len() < 32 {
                out.copy_from_slice(&bytes[..out.len()]);

                wipe(&mut bytes);
            }

            wipe_unless_optimized!(words_of(&mut row));

            wipe_unless_optimized!(words_of(&mut h));

            wipe_unless_optimized!(words_of(&mut m));
        }

        // All sixteen output words of one compression.
        #[target_feature(enable = $feature)]
        pub(in crate::cpu) fn compress(
            cv: &[u32; 8],
            block: &[u8; 64],
            counter: u64,
            length: u32,
            flags: u32,
            out: &mut [u32; 16],
        ) {
            let [low, high] = cv.as_chunks::<4>().0 else {
                unreachable!("eight words are two groups of four")
            };

            #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
            let mut h = [load128(low), load128(high)];

            let mut row = start(h, counter, length, flags);

            let mut m = message(block);

            round::<0>(&mut row, &mut m);

            round::<1>(&mut row, &mut m);

            round::<2>(&mut row, &mut m);

            round::<3>(&mut row, &mut m);

            round::<4>(&mut row, &mut m);

            round::<5>(&mut row, &mut m);

            round::<6>(&mut row, &mut m);

            let [o0, o1, o2, o3] = out.as_chunks_mut::<4>().0 else {
                unreachable!("sixteen words are four groups of four")
            };

            store128(_mm_xor_si128(row[0], row[2]), o0);

            store128(_mm_xor_si128(row[1], row[3]), o1);

            store128(_mm_xor_si128(row[2], h[0]), o2);

            store128(_mm_xor_si128(row[3], h[1]), o3);

            wipe_unless_optimized!(words_of(&mut row));

            wipe_unless_optimized!(words_of(&mut h));

            wipe_unless_optimized!(words_of(&mut m));
        }
    };
}

mod rows_sse41 {
    use super::*;

    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    #[inline]
    fn shuffle(x: __m128i, control: __m128i) -> __m128i {
        _mm_shuffle_epi8(x, control)
    }

    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    #[inline]
    fn word_down(x: __m128i) -> __m128i {
        _mm_shuffle_epi32::<0x93>(x)
    }

    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    #[inline]
    fn word_up(x: __m128i) -> __m128i {
        _mm_shuffle_epi32::<0x39>(x)
    }

    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    #[inline]
    fn words_across(x: __m128i) -> __m128i {
        _mm_shuffle_epi32::<0x4E>(x)
    }

    // One SSE instruction on registers: `two` takes x in place and y, `one` writes out from x.
    // As intrinsics, LLVM merged the schedule's shuffles into word shuffles, inserts and copies.
    macro_rules! sse {
        (two $name:ident, $template:literal) => {
            #[target_feature(enable = "sse2,ssse3,sse4.1")]
            #[inline]
            #[allow(unsafe_code)]
            fn $name(x: __m128i, y: __m128i) -> __m128i {
                let out;

                // SAFETY: one SSE4.1 instruction on registers, which this function's target
                // features provide; it reads and writes no memory, stack or flags.
                unsafe {
                    core::arch::asm!(
                        $template,
                        x = inout(xmm_reg) x => out,
                        y = in(xmm_reg) y,
                        options(pure, nomem, nostack, preserves_flags),
                    );
                }

                out
            }
        };
        (one $name:ident, $template:literal) => {
            #[target_feature(enable = "sse2,ssse3,sse4.1")]
            #[inline]
            #[allow(unsafe_code)]
            fn $name(x: __m128i) -> __m128i {
                let out;

                // SAFETY: as above.
                unsafe {
                    core::arch::asm!(
                        $template,
                        out = lateout(xmm_reg) out,
                        x = in(xmm_reg) x,
                        options(pure, nomem, nostack, preserves_flags),
                    );
                }

                out
            }
        };
    }

    // The message schedule's shuffles, named for the words each lane takes, from lane 0 up: of
    // x, then of y.
    sse!(two pick_even, "shufps {x}, {y}, 0x88");

    sse!(two pick_odd, "shufps {x}, {y}, 0xDD");

    sse!(two pick_2113, "shufps {x}, {y}, 0xD6");

    sse!(two pick_2233, "shufps {x}, {y}, 0xFA");

    sse!(one order_3300, "pshufd {out}, {x}, 0x0F");

    sse!(one order_0231, "pshufd {out}, {x}, 0x78");

    sse!(one order_2310, "pshufd {out}, {x}, 0x1E");

    sse!(two blend_odd, "pblendw {x}, {y}, 0xCC");

    sse!(two blend_fourth, "pblendw {x}, {y}, 0xC0");

    sse!(two low_quads, "punpcklqdq {x}, {y}");

    sse!(two low_words, "punpckldq {x}, {y}");

    sse!(two high_words, "punpckhdq {x}, {y}");

    rows!("sse2,ssse3,sse4.1");

    // hash_many's chains of two inputs side by side, round by round: one alone leaves most of
    // the vector ports idle while each step's chain completes. With AVX2, rows_pair holds both
    // in the halves of the same registers instead.
    #[target_feature(enable = "sse2,ssse3,sse4.1")]
    pub(super) fn chain2(input: &[[u8; 64]], many: &Many, first: usize, out: &mut [[u8; 32]; 2]) {
        let blocks = many.blocks;

        let [low, high] = many.key.as_chunks::<4>().0 else {
            unreachable!("eight words are two groups of four")
        };

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut key = [load128(low), load128(high)];

        let mut h = [key, key];

        let counter = |i: usize| {
            if many.increment {
                many.counter + (first + i) as u64
            } else {
                many.counter
            }
        };

        let counters = [counter(0), counter(1)];

        let x = &input[first * blocks..(first + 1) * blocks];

        let y = &input[(first + 1) * blocks..(first + 2) * blocks];

        for (i, (bx, by)) in x.iter().zip(y).enumerate() {
            let mut f = many.flags;

            if i == 0 {
                f |= many.start;
            }

            if i + 1 == blocks {
                f |= many.end;
            }

            let mut rx = start(h[0], counters[0], 64, f);

            let mut ry = start(h[1], counters[1], 64, f);

            let mut mx = message(bx);

            let mut my = message(by);

            round::<0>(&mut rx, &mut mx);

            round::<0>(&mut ry, &mut my);

            round::<1>(&mut rx, &mut mx);

            round::<1>(&mut ry, &mut my);

            round::<2>(&mut rx, &mut mx);

            round::<2>(&mut ry, &mut my);

            round::<3>(&mut rx, &mut mx);

            round::<3>(&mut ry, &mut my);

            round::<4>(&mut rx, &mut mx);

            round::<4>(&mut ry, &mut my);

            round::<5>(&mut rx, &mut mx);

            round::<5>(&mut ry, &mut my);

            round::<6>(&mut rx, &mut mx);

            round::<6>(&mut ry, &mut my);

            h = [
                [_mm_xor_si128(rx[0], rx[2]), _mm_xor_si128(rx[1], rx[3])],
                [_mm_xor_si128(ry[0], ry[2]), _mm_xor_si128(ry[1], ry[3])],
            ];

            wipe_unless_optimized!(words_of(&mut rx));

            wipe_unless_optimized!(words_of(&mut ry));

            wipe_unless_optimized!(words_of(&mut mx));

            wipe_unless_optimized!(words_of(&mut my));
        }

        for (cv, h) in out.iter_mut().zip(h) {
            let [low, high] = cv.as_chunks_mut::<16>().0 else {
                unreachable!("32 bytes are two groups of 16")
            };

            store128(h[0], low);

            store128(h[1], high);
        }

        wipe_unless_optimized!(words_of(&mut key));

        wipe_unless_optimized!(words_of(&mut h));
    }
}

// With AVX2 the shuffles and blends are single instructions in assembly: as intrinsics, LLVM
// turned the rotation by 16 into two shuffles, on the one shuffle port of Intel's cores before
// Ice Lake.
mod rows_avx2 {
    use super::*;

    instruction!(
        shuffle,
        __m128i,
        xmm_reg,
        "vpshufb {out}, {x}, {control}",
        x,
        control
    );

    instruction!(word_down, __m128i, xmm_reg, "vpshufd {out}, {x}, 0x93", x);

    instruction!(word_up, __m128i, xmm_reg, "vpshufd {out}, {x}, 0x39", x);

    instruction!(
        words_across,
        __m128i,
        xmm_reg,
        "vpshufd {out}, {x}, 0x4E",
        x
    );

    // The message schedule's shuffles, as in rows_sse41; the blends are VPBLENDD, which Haswell
    // runs on three ports rather than the shuffle port.
    instruction!(
        pick_even,
        __m128i,
        xmm_reg,
        "vshufps {out}, {x}, {y}, 0x88",
        x,
        y
    );

    instruction!(
        pick_odd,
        __m128i,
        xmm_reg,
        "vshufps {out}, {x}, {y}, 0xDD",
        x,
        y
    );

    instruction!(
        pick_2113,
        __m128i,
        xmm_reg,
        "vshufps {out}, {x}, {y}, 0xD6",
        x,
        y
    );

    instruction!(
        pick_2233,
        __m128i,
        xmm_reg,
        "vshufps {out}, {x}, {y}, 0xFA",
        x,
        y
    );

    instruction!(order_3300, __m128i, xmm_reg, "vpshufd {out}, {x}, 0x0F", x);

    instruction!(order_0231, __m128i, xmm_reg, "vpshufd {out}, {x}, 0x78", x);

    instruction!(order_2310, __m128i, xmm_reg, "vpshufd {out}, {x}, 0x1E", x);

    instruction!(
        blend_odd,
        __m128i,
        xmm_reg,
        "vpblendd {out}, {x}, {y}, 0xA",
        x,
        y
    );

    instruction!(
        blend_fourth,
        __m128i,
        xmm_reg,
        "vpblendd {out}, {x}, {y}, 0x8",
        x,
        y
    );

    instruction!(
        low_quads,
        __m128i,
        xmm_reg,
        "vpunpcklqdq {out}, {x}, {y}",
        x,
        y
    );

    instruction!(
        low_words,
        __m128i,
        xmm_reg,
        "vpunpckldq {out}, {x}, {y}",
        x,
        y
    );

    instruction!(
        high_words,
        __m128i,
        xmm_reg,
        "vpunpckhdq {out}, {x}, {y}",
        x,
        y
    );

    rows!("avx2");
}

// The row form with each half step's four message words broadcast from the block in memory and
// blended, and a short block copied into a buffer first: the AVX2 form before the message moved
// into registers, for blake3.rs's gathered module, which the cores of GATHER (x86_64.rs,
// gather_rows()) take.
macro_rules! rows_gather {
    ($feature:literal) => {
        #[target_feature(enable = $feature)]
        #[inline]
        fn rotate<const R: u32>(x: __m128i) -> __m128i {
            match R {
                16 => shuffle(x, load128(&ROTATE16)),
                8 => shuffle(x, load128(&ROTATE8)),
                12 => _mm_or_si128(_mm_srli_epi32::<12>(x), _mm_slli_epi32::<20>(x)),
                7 => _mm_or_si128(_mm_srli_epi32::<7>(x), _mm_slli_epi32::<25>(x)),
                _ => unreachable!("the rotations of BLAKE3"),
            }
        }

        #[target_feature(enable = $feature)]
        #[inline]
        fn half<const R1: u32, const R2: u32>(row: &mut [__m128i; 4], m: __m128i) {
            let [a, b, c, d] = row;

            *a = _mm_add_epi32(_mm_add_epi32(*a, m), *b);

            *d = rotate::<R1>(_mm_xor_si128(*d, *a));

            *c = _mm_add_epi32(*c, *d);

            *b = rotate::<R2>(_mm_xor_si128(*b, *c));
        }

        // Round R. For the diagonal step, a moves down a word and c and d up one and two.
        #[target_feature(enable = $feature)]
        #[inline]
        fn round<const R: usize>(row: &mut [__m128i; 4], block: &[u8; 64]) {
            half::<16, 12>(row, gather::<R, 0>(block));

            half::<8, 7>(row, gather::<R, 1>(block));

            row[0] = word_down(row[0]);

            row[2] = word_up(row[2]);

            row[3] = words_across(row[3]);

            half::<16, 12>(row, gather::<R, 2>(block));

            half::<8, 7>(row, gather::<R, 3>(block));

            row[0] = word_up(row[0]);

            row[2] = word_down(row[2]);

            row[3] = words_across(row[3]);
        }

        #[target_feature(enable = $feature)]
        #[inline]
        fn start(cv: [__m128i; 2], counter: u64, length: u32, flags: u32) -> [__m128i; 4] {
            let [low, _] = IV_256.as_chunks::<4>().0 else {
                unreachable!("eight words are two groups of four")
            };

            [
                cv[0],
                cv[1],
                load128(low),
                _mm_set_epi64x(
                    (u64::from(flags) << 32 | u64::from(length)) as i64,
                    counter as i64,
                ),
            ]
        }

        // As rows!'s chain.
        #[target_feature(enable = $feature)]
        pub(in crate::cpu) fn chain(
            cv: &mut [u32; 8],
            blocks: &[[u8; 64]],
            counter: u64,
            flags: u32,
            [first, end]: [u32; 2],
            last: crate::blake3::Last,
        ) {
            let [low, high] = cv.as_chunks_mut::<4>().0 else {
                unreachable!("eight words are two groups of four")
            };

            let mut h = [load128(low), load128(high)];

            let whole = blocks.len();

            for i in 0..whole + usize::from(last.is_some()) {
                let (block, length, f) = match last {
                    Some(last) if i == whole => last,
                    _ => {
                        let mut f = flags;

                        if i == 0 {
                            f |= first;
                        }

                        if i + 1 == whole {
                            f |= end;
                        }

                        (&blocks[i], 64, f)
                    }
                };

                let mut row = start(h, counter, length, f);

                round::<0>(&mut row, block);

                round::<1>(&mut row, block);

                round::<2>(&mut row, block);

                round::<3>(&mut row, block);

                round::<4>(&mut row, block);

                round::<5>(&mut row, block);

                round::<6>(&mut row, block);

                h = [_mm_xor_si128(row[0], row[2]), _mm_xor_si128(row[1], row[3])];

                wipe_unless_optimized!(words_of(&mut row));
            }

            store128(h[0], low);

            store128(h[1], high);

            wipe_unless_optimized!(words_of(&mut h));
        }

        // As rows!'s digest1, with a short block copied into a buffer that is wiped after.
        #[target_feature(enable = $feature)]
        pub(in crate::cpu::x86_64) fn digest1<K: Plain, const N: usize>(
            key: &[K; N],
            flags: u32,
            data: &[u8],
            out: &mut [u8],
        ) {
            const { assert!(size_of::<[K; N]>() == 32) };

            let mut copy = [0; 64];

            let block = match <&[u8; 64]>::try_from(data) {
                Ok(block) => block,
                Err(_) => {
                    copy[..data.len()].copy_from_slice(data);

                    &copy
                }
            };

            let cv = [load128_bytes(key, 0), load128_bytes(key, 16)];

            let mut row = start(cv, 0, data.len() as u32, flags);

            round::<0>(&mut row, block);

            round::<1>(&mut row, block);

            round::<2>(&mut row, block);

            round::<3>(&mut row, block);

            round::<4>(&mut row, block);

            round::<5>(&mut row, block);

            round::<6>(&mut row, block);

            #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
            let mut h = [_mm_xor_si128(row[0], row[2]), _mm_xor_si128(row[1], row[3])];

            let mut bytes = [0; 32];

            let target = match <&mut [u8; 32]>::try_from(&mut *out) {
                Ok(whole) => whole,
                Err(_) => &mut bytes,
            };

            let [first, second] = target.as_chunks_mut::<16>().0 else {
                unreachable!("32 bytes are two groups of 16")
            };

            store128(h[0], first);

            store128(h[1], second);

            if out.len() < 32 {
                out.copy_from_slice(&bytes[..out.len()]);

                wipe(&mut bytes);
            }

            wipe(&mut copy);

            wipe_unless_optimized!(words_of(&mut row));

            wipe_unless_optimized!(words_of(&mut h));
        }

        // As rows!'s compress.
        #[target_feature(enable = $feature)]
        pub(in crate::cpu) fn compress(
            cv: &[u32; 8],
            block: &[u8; 64],
            counter: u64,
            length: u32,
            flags: u32,
            out: &mut [u32; 16],
        ) {
            let [low, high] = cv.as_chunks::<4>().0 else {
                unreachable!("eight words are two groups of four")
            };

            #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
            let mut h = [load128(low), load128(high)];

            let mut row = start(h, counter, length, flags);

            round::<0>(&mut row, block);

            round::<1>(&mut row, block);

            round::<2>(&mut row, block);

            round::<3>(&mut row, block);

            round::<4>(&mut row, block);

            round::<5>(&mut row, block);

            round::<6>(&mut row, block);

            let [o0, o1, o2, o3] = out.as_chunks_mut::<4>().0 else {
                unreachable!("sixteen words are four groups of four")
            };

            store128(_mm_xor_si128(row[0], row[2]), o0);

            store128(_mm_xor_si128(row[1], row[3]), o1);

            store128(_mm_xor_si128(row[2], h[0]), o2);

            store128(_mm_xor_si128(row[3], h[1]), o3);

            wipe_unless_optimized!(words_of(&mut row));

            wipe_unless_optimized!(words_of(&mut h));
        }
    };
}

// rows_gather!'s AVX2 instance, with the shuffles and blends in assembly as in rows_avx2.
mod rows_gather {
    use super::*;

    instruction!(
        shuffle,
        __m128i,
        xmm_reg,
        "vpshufb {out}, {x}, {control}",
        x,
        control
    );

    instruction!(word_down, __m128i, xmm_reg, "vpshufd {out}, {x}, 0x93", x);

    instruction!(word_up, __m128i, xmm_reg, "vpshufd {out}, {x}, 0x39", x);

    instruction!(
        words_across,
        __m128i,
        xmm_reg,
        "vpshufd {out}, {x}, 0x4E",
        x
    );

    instruction!(
        blend_second,
        __m128i,
        xmm_reg,
        "vpblendd {out}, {x}, {y}, 0x2",
        x,
        y
    );

    instruction!(
        blend_fourth,
        __m128i,
        xmm_reg,
        "vpblendd {out}, {x}, {y}, 0x8",
        x,
        y
    );

    instruction!(
        blend_high,
        __m128i,
        xmm_reg,
        "vpblendd {out}, {x}, {y}, 0xC",
        x,
        y
    );

    // Four broadcasts from memory, which run on the load ports, and three blends.
    #[target_feature(enable = "avx2")]
    #[inline]
    fn gather<const R: usize, const K: usize>(block: &[u8; 64]) -> __m128i {
        let words = block.as_chunks::<4>().0;

        let [w0, w1, w2, w3] = GATHERS[R][K];

        let [w0, w1, w2, w3] = [
            _mm_set1_epi32(i32::from_le_bytes(words[w0])),
            _mm_set1_epi32(i32::from_le_bytes(words[w1])),
            _mm_set1_epi32(i32::from_le_bytes(words[w2])),
            _mm_set1_epi32(i32::from_le_bytes(words[w3])),
        ];

        blend_high(blend_second(w0, w1), blend_fourth(w2, w3))
    }

    rows_gather!("avx2");
}

// Two inputs in the row form with AVX2: each ymm register holds a row of the first input in its
// low half and of the second in its high half, so one instruction advances both, at the cost of
// one. The message words of each half step are broadcast from both blocks, joined and blended.
mod rows_pair {
    use super::*;

    instruction!(
        shuffle,
        __m256i,
        ymm_reg,
        "vpshufb {out}, {x}, {control}",
        x,
        control
    );

    instruction!(word_down, __m256i, ymm_reg, "vpshufd {out}, {x}, 0x93", x);

    instruction!(word_up, __m256i, ymm_reg, "vpshufd {out}, {x}, 0x39", x);

    instruction!(
        words_across,
        __m256i,
        ymm_reg,
        "vpshufd {out}, {x}, 0x4E",
        x
    );

    instruction!(
        halves,
        __m256i,
        ymm_reg,
        "vpblendd {out}, {x}, {y}, 0xF0",
        x,
        y
    );

    instruction!(
        blend_second,
        __m256i,
        ymm_reg,
        "vpblendd {out}, {x}, {y}, 0x22",
        x,
        y
    );

    instruction!(
        blend_fourth,
        __m256i,
        ymm_reg,
        "vpblendd {out}, {x}, {y}, 0x88",
        x,
        y
    );

    instruction!(
        blend_high,
        __m256i,
        ymm_reg,
        "vpblendd {out}, {x}, {y}, 0xCC",
        x,
        y
    );

    #[target_feature(enable = "avx2")]
    #[inline]
    fn rotate<const R: u32>(x: __m256i, controls: &[__m256i; 2]) -> __m256i {
        match R {
            16 => shuffle(x, controls[0]),
            8 => shuffle(x, controls[1]),
            12 => _mm256_or_si256(_mm256_srli_epi32::<12>(x), _mm256_slli_epi32::<20>(x)),
            7 => _mm256_or_si256(_mm256_srli_epi32::<7>(x), _mm256_slli_epi32::<25>(x)),
            _ => unreachable!("the rotations of BLAKE3"),
        }
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn half<const R1: u32, const R2: u32>(
        row: &mut [__m256i; 4],
        m: __m256i,
        controls: &[__m256i; 2],
    ) {
        let [a, b, c, d] = row;

        *a = _mm256_add_epi32(_mm256_add_epi32(*a, m), *b);

        *d = rotate::<R1>(_mm256_xor_si256(*d, *a), controls);

        *c = _mm256_add_epi32(*c, *d);

        *b = rotate::<R2>(_mm256_xor_si256(*b, *c), controls);
    }

    // Word w of the first block in the low half and of the second in the high half.
    #[target_feature(enable = "avx2")]
    #[inline]
    fn both(blocks: [&[u8; 64]; 2], w: usize) -> __m256i {
        let [x, y] = blocks.map(|block| block.as_chunks::<4>().0[w]);

        halves(
            _mm256_set1_epi32(i32::from_le_bytes(x)),
            _mm256_set1_epi32(i32::from_le_bytes(y)),
        )
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn gather<const R: usize, const K: usize>(blocks: [&[u8; 64]; 2]) -> __m256i {
        let [w0, w1, w2, w3] = GATHERS[R][K];

        blend_high(
            blend_second(both(blocks, w0), both(blocks, w1)),
            blend_fourth(both(blocks, w2), both(blocks, w3)),
        )
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn round<const R: usize>(
        row: &mut [__m256i; 4],
        blocks: [&[u8; 64]; 2],
        controls: &[__m256i; 2],
    ) {
        half::<16, 12>(row, gather::<R, 0>(blocks), controls);

        half::<8, 7>(row, gather::<R, 1>(blocks), controls);

        row[0] = word_down(row[0]);

        row[2] = word_up(row[2]);

        row[3] = words_across(row[3]);

        half::<16, 12>(row, gather::<R, 2>(blocks), controls);

        half::<8, 7>(row, gather::<R, 3>(blocks), controls);

        row[0] = word_up(row[0]);

        row[2] = word_down(row[2]);

        row[3] = words_across(row[3]);
    }

    // hash_many's inputs `first` and `first + 1`.
    #[target_feature(enable = "avx2")]
    pub(super) fn chain2(input: &[[u8; 64]], many: &Many, first: usize, out: &mut [[u8; 32]; 2]) {
        let blocks = many.blocks;

        let [low, high] = many.key.as_chunks::<4>().0 else {
            unreachable!("eight words are two groups of four")
        };

        let mut h = [
            _mm256_broadcastsi128_si256(load128(low)),
            _mm256_broadcastsi128_si256(load128(high)),
        ];

        let [iv, _] = IV_256.as_chunks::<4>().0 else {
            unreachable!("eight words are two groups of four")
        };

        let iv = _mm256_broadcastsi128_si256(load128(iv));

        let controls = [
            _mm256_broadcastsi128_si256(load128(&ROTATE16)),
            _mm256_broadcastsi128_si256(load128(&ROTATE8)),
        ];

        let counter = |i: usize| {
            if many.increment {
                many.counter + (first + i) as u64
            } else {
                many.counter
            }
        };

        let x = &input[first * blocks..(first + 1) * blocks];

        let y = &input[(first + 1) * blocks..(first + 2) * blocks];

        for (i, (bx, by)) in x.iter().zip(y).enumerate() {
            let mut f = many.flags;

            if i == 0 {
                f |= many.start;
            }

            if i + 1 == blocks {
                f |= many.end;
            }

            let tail = u64::from(f) << 32 | 64;

            let mut row = [
                h[0],
                h[1],
                iv,
                _mm256_set_epi64x(
                    tail as i64,
                    counter(1) as i64,
                    tail as i64,
                    counter(0) as i64,
                ),
            ];

            let pair = [bx, by];

            round::<0>(&mut row, pair, &controls);

            round::<1>(&mut row, pair, &controls);

            round::<2>(&mut row, pair, &controls);

            round::<3>(&mut row, pair, &controls);

            round::<4>(&mut row, pair, &controls);

            round::<5>(&mut row, pair, &controls);

            round::<6>(&mut row, pair, &controls);

            h = [
                _mm256_xor_si256(row[0], row[2]),
                _mm256_xor_si256(row[1], row[3]),
            ];

            wipe_unless_optimized!(words_of(&mut row));
        }

        for (l, cv) in out.iter_mut().enumerate() {
            let [first, second] = cv.as_chunks_mut::<16>().0 else {
                unreachable!("32 bytes are two groups of 16")
            };

            let (a, b) = if l == 0 {
                (_mm256_castsi256_si128(h[0]), _mm256_castsi256_si128(h[1]))
            } else {
                (
                    _mm256_extracti128_si256::<1>(h[0]),
                    _mm256_extracti128_si256::<1>(h[1]),
                )
            };

            store128(a, first);

            store128(b, second);
        }

        wipe_unless_optimized!(words_of(&mut h));
    }
}

// The row form with AVX-512VL on xmm registers: each rotation is one VPRORD, which takes the
// chain of a half step from eight cycles to six where the AVX2 form rotates by 12 and 7 with two
// shifts and an OR. The message words of a round stay in two ymm registers, the vectors of its
// four half steps in lane order, and two VPERMT2D take them to the next round's order, in place
// of the AVX2 form's sixteen broadcasts and 84 blends per block, which LLVM spilled. The EVEX
// instructions are inline assembly in AVX2 code (evex.rs).
mod rows_vl {
    use super::super::evex::{permute2, ror32};
    use super::*;

    // The schedule slot of lane j of half step k, as in gathers().
    const fn slot(k: usize, j: usize) -> usize {
        match k {
            0 => 2 * j,
            1 => 2 * j + 1,
            2 => 8 + 2 * ((j + 3) % 4),
            _ => 9 + 2 * ((j + 3) % 4),
        }
    }

    // Word p of the two vectors, half step p / 4 and lane p % 4: the block's word that the first
    // round takes there, within its half of the block (FIRST), and the word of the current
    // round's vectors that the next round takes, 0 to 7 in the first and 8 to 15 in the second
    // (NEXT).
    const fn orders() -> [[[u32; 8]; 2]; 2] {
        let mut orders = [[[0; 8]; 2]; 2];

        let mut p = 0;

        while p < 16 {
            orders[0][p / 8][p % 8] = (slot(p / 4, p % 4) % 8) as u32;

            let target = PERMUTATION[slot(p / 4, p % 4)];

            let mut q = 0;

            while slot(q / 4, q % 4) != target {
                q += 1;
            }

            orders[1][p / 8][p % 8] = q as u32;

            p += 1;
        }

        orders
    }

    const ORDERS: [[[u32; 8]; 2]; 2] = orders();

    // As an intrinsic, LLVM wrote the swap of d's halves as VSHUFPD, a shuffle of the floating
    // point domain, on the d row's dependency chain.
    instruction!(
        words_across,
        __m128i,
        xmm_reg,
        "vpshufd {out}, {x}, 0x4E",
        x
    );

    // Private to this module, whose entry points are unsafe and require AVX-512F and AVX-512VL:
    // every call of half and rounds_words comes from one of them.
    #[target_feature(enable = "avx2")]
    #[inline]
    #[allow(unsafe_code)]
    fn half<const R1: u32, const R2: u32>(row: &mut [__m128i; 4], m: __m128i) {
        let [a, b, c, d] = row;

        *a = _mm_add_epi32(_mm_add_epi32(*a, m), *b);

        // SAFETY: the CPU has AVX-512F and AVX-512VL, as the entry points require; here and in
        // the next.
        *d = unsafe { ror32::<R1>(_mm_xor_si128(*d, *a)) };

        *c = _mm_add_epi32(*c, *d);

        *b = unsafe { ror32::<R2>(_mm_xor_si128(*b, *c)) };
    }

    // One round on the message vectors m. For the diagonal step, a moves down a word and c and d
    // up one and two.
    #[target_feature(enable = "avx2")]
    #[inline]
    fn round(row: &mut [__m128i; 4], m: &[__m256i; 2]) {
        half::<16, 12>(row, _mm256_castsi256_si128(m[0]));

        half::<8, 7>(row, _mm256_extracti128_si256::<1>(m[0]));

        row[0] = _mm_shuffle_epi32::<0x93>(row[0]);

        row[2] = _mm_shuffle_epi32::<0x39>(row[2]);

        row[3] = words_across(row[3]);

        half::<16, 12>(row, _mm256_castsi256_si128(m[1]));

        half::<8, 7>(row, _mm256_extracti128_si256::<1>(m[1]));

        row[0] = _mm_shuffle_epi32::<0x39>(row[0]);

        row[2] = _mm_shuffle_epi32::<0x93>(row[2]);

        row[3] = words_across(row[3]);
    }

    // The seven rounds of a block on row, the message vectors built and permuted in m.
    #[target_feature(enable = "avx2")]
    #[inline]
    fn rounds(row: &mut [__m128i; 4], block: &[u8; 64], m: &mut [__m256i; 2]) {
        rounds_words(row, halves(block), m);
    }

    // The block's words in order, in two vectors.
    #[target_feature(enable = "avx2")]
    #[inline]
    fn halves(block: &[u8; 64]) -> [__m256i; 2] {
        let [low, high] = block.as_chunks::<32>().0 else {
            unreachable!("64 bytes are two groups of 32")
        };

        [load256(low), load256(high)]
    }

    // rounds for the block's words in order in two vectors.
    #[target_feature(enable = "avx2")]
    #[inline]
    #[allow(unsafe_code)]
    fn rounds_words(row: &mut [__m128i; 4], words: [__m256i; 2], m: &mut [__m256i; 2]) {
        let [first, next] = &ORDERS;

        *m = [
            _mm256_permutevar8x32_epi32(words[0], load256(&first[0])),
            _mm256_permutevar8x32_epi32(words[1], load256(&first[1])),
        ];

        let next = [load256(&next[0]), load256(&next[1])];

        for r in 0..7 {
            round(row, m);

            if r < 6 {
                // SAFETY: as in half.
                *m = unsafe { [permute2(m[0], next[0], m[1]), permute2(m[0], next[1], m[1])] };
            }
        }
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    fn start(cv: [__m128i; 2], counter: u64, length: u32, flags: u32) -> [__m128i; 4] {
        let [low, _] = IV_256.as_chunks::<4>().0 else {
            unreachable!("eight words are two groups of four")
        };

        [
            cv[0],
            cv[1],
            load128(low),
            _mm_set_epi64x(
                (u64::from(flags) << 32 | u64::from(length)) as i64,
                counter as i64,
            ),
        ]
    }

    /// As rows!'s chain.
    ///
    /// # Safety
    ///
    /// The CPU has AVX-512F and AVX-512VL, and the operating system saves their registers.
    #[target_feature(enable = "avx2")]
    #[allow(unsafe_code)]
    pub(in crate::cpu) unsafe fn chain(
        cv: &mut [u32; 8],
        blocks: &[[u8; 64]],
        counter: u64,
        flags: u32,
        [first, end]: [u32; 2],
        last: crate::blake3::Last,
    ) {
        let [low, high] = cv.as_chunks_mut::<4>().0 else {
            unreachable!("eight words are two groups of four")
        };

        let mut h = [load128(low), load128(high)];

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut m = [_mm256_setzero_si256(); 2];

        let whole = blocks.len();

        let body = blocks.iter().enumerate().map(|(i, block)| {
            let mut f = flags;

            if i == 0 {
                f |= first;
            }

            if i + 1 == whole {
                f |= end;
            }

            (block, 64, f)
        });

        for (block, length, f) in body.chain(last) {
            let mut row = start(h, counter, length, f);

            rounds(&mut row, block, &mut m);

            h = [_mm_xor_si128(row[0], row[2]), _mm_xor_si128(row[1], row[3])];

            wipe_unless_optimized!(words_of(&mut row));
        }

        store128(h[0], low);

        store128(h[1], high);

        wipe_unless_optimized!(words_of(&mut h));

        wipe_unless_optimized!(words_of(&mut m));
    }

    /// As rows!'s digest1.
    ///
    /// # Safety
    ///
    /// As for chain.
    #[target_feature(enable = "avx2")]
    #[allow(unsafe_code)]
    pub(in crate::cpu::x86_64) unsafe fn digest1<K: Plain, const N: usize>(
        key: &[K; N],
        flags: u32,
        data: &[u8],
        out: &mut [u8],
    ) {
        const { assert!(size_of::<[K; N]>() == 32) };

        // A whole block takes two 32-byte loads, a short one message_short's four vectors.
        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut words = match <&[u8; 64]>::try_from(data) {
            Ok(block) => halves(block),
            Err(_) => {
                let [a, b, c, d] = message_short(data);

                [_mm256_set_m128i(b, a), _mm256_set_m128i(d, c)]
            }
        };

        let cv = [load128_bytes(key, 0), load128_bytes(key, 16)];

        let mut row = start(cv, 0, data.len() as u32, flags);

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut m = [_mm256_setzero_si256(); 2];

        rounds_words(&mut row, words, &mut m);

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut h = [_mm_xor_si128(row[0], row[2]), _mm_xor_si128(row[1], row[3])];

        let mut bytes = [0; 32];

        let target = match <&mut [u8; 32]>::try_from(&mut *out) {
            Ok(whole) => whole,
            Err(_) => &mut bytes,
        };

        let [first, second] = target.as_chunks_mut::<16>().0 else {
            unreachable!("32 bytes are two groups of 16")
        };

        store128(h[0], first);

        store128(h[1], second);

        if out.len() < 32 {
            out.copy_from_slice(&bytes[..out.len()]);

            wipe(&mut bytes);
        }

        wipe_unless_optimized!(words_of(&mut words));

        wipe_unless_optimized!(words_of(&mut row));

        wipe_unless_optimized!(words_of(&mut h));

        wipe_unless_optimized!(words_of(&mut m));
    }

    /// As rows!'s compress.
    ///
    /// # Safety
    ///
    /// As for chain.
    #[target_feature(enable = "avx2")]
    #[allow(unsafe_code)]
    pub(in crate::cpu) unsafe fn compress(
        cv: &[u32; 8],
        block: &[u8; 64],
        counter: u64,
        length: u32,
        flags: u32,
        out: &mut [u32; 16],
    ) {
        let [low, high] = cv.as_chunks::<4>().0 else {
            unreachable!("eight words are two groups of four")
        };

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut h = [load128(low), load128(high)];

        let mut row = start(h, counter, length, flags);

        #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
        let mut m = [_mm256_setzero_si256(); 2];

        rounds(&mut row, block, &mut m);

        let [o0, o1, o2, o3] = out.as_chunks_mut::<4>().0 else {
            unreachable!("sixteen words are four groups of four")
        };

        store128(_mm_xor_si128(row[0], row[2]), o0);

        store128(_mm_xor_si128(row[1], row[3]), o1);

        store128(_mm_xor_si128(row[2], h[0]), o2);

        store128(_mm_xor_si128(row[3], h[1]), o3);

        wipe_unless_optimized!(words_of(&mut row));

        wipe_unless_optimized!(words_of(&mut h));

        wipe_unless_optimized!(words_of(&mut m));
    }
}

pub(super) use rows_avx2::{
    chain as chain_avx2, compress as compress_avx2, digest1 as digest1_avx2,
};
pub(super) use rows_gather::{
    chain as chain_gather, compress as compress_gather, digest1 as digest1_gather,
};
pub(super) use rows_sse41::{
    chain as chain_sse41, compress as compress_sse41, digest1 as digest1_sse41,
};

pub(super) use rows_vl::{chain as chain_vl, compress as compress_vl, digest1 as digest1_vl};

// The transposed form's rounds with AVX2 in assembly, for eight lanes in ymm or four in xmm
// registers: as intrinsics, LLVM kept the rotations' byte controls in two of the sixteen
// registers and spilled state words around every step, and its per-block code around them came
// to a sixth more than the rounds. Words v0 to v15 stay in registers 0 to 15, and the message
// words are memory operands, read in each round's order. A rotation needs one more register: v8
// then waits in a slot in memory, and comes back as the memory operand of its next c += d. The
// rotations by 16 and 8 take their control into register 8 meanwhile. hash_many's blocks run in
// one loop, the chaining values in registers 0 to 7 from one block to the next, as the
// transposition of each block's message uses registers 8 to 15 only.
//
// The macros build the template text: `$r` names the registers, `$w` and `$size` the vectors in
// memory, `$slot` the address of v8's slot.
macro_rules! asm_add {
    ($r:literal, $x:literal, $y:literal) => {
        concat!("vpaddd ", $r, $x, ", ", $r, $x, ", ", $r, $y, "\n")
    };
}

macro_rules! asm_xor {
    ($r:literal, $x:literal, $y:literal) => {
        concat!("vpxor ", $r, $x, ", ", $r, $x, ", ", $r, $y, "\n")
    };
}

// Register x from (or into) vector i at the operand named base.
macro_rules! asm_load {
    ($r:literal, $w:literal, $size:literal, $x:literal, $base:literal, $i:literal) => {
        concat!(
            "vmovdqu ", $r, $x, ", ", $w, " ptr [", $base, " + ", $size, " * ", $i, "]\n"
        )
    };
}

macro_rules! asm_store {
    ($r:literal, $w:literal, $size:literal, $x:literal, $base:literal, $i:literal) => {
        concat!(
            "vmovdqu ", $w, " ptr [", $base, " + ", $size, " * ", $i, "], ", $r, $x, "\n"
        )
    };
}

// a += message word i.
macro_rules! asm_message {
    ($r:literal, $w:literal, $size:literal, $a:literal, $i:literal) => {
        concat!(
            "vpaddd ",
            $r,
            $a,
            ", ",
            $r,
            $a,
            ", ",
            $w,
            " ptr [{m} + ",
            $size,
            " * ",
            $i,
            "]\n"
        )
    };
}

// c += d, where c = v8 comes back from its slot. The words are token trees, so that 8 matches as
// itself.
macro_rules! asm_c {
    ($r:literal, $w:literal, $slot:literal, 8, $d:literal) => {
        concat!(
            "vpaddd ", $r, "8, ", $r, $d, ", ", $w, " ptr [", $slot, "]\n"
        )
    };
    ($r:literal, $w:literal, $slot:literal, $c:tt, $d:literal) => {
        asm_add!($r, $c, $d)
    };
}

macro_rules! asm_shuffle {
    ($r:literal, $x:literal) => {
        concat!("vpshufb ", $r, $x, ", ", $r, $x, ", ", $r, "8\n")
    };
}

// x = x >>> n, with register 8 as the temporary.
macro_rules! asm_rotate {
    ($r:literal, $x:literal, $n:literal, $left:literal) => {
        concat!(
            "vpsrld ", $r, "8, ", $r, $x, ", ", $n, "\n", "vpslld ", $r, $x, ", ", $r, $x, ", ",
            $left, "\n", "vpor ", $r, $x, ", ", $r, $x, ", ", $r, "8\n",
        )
    };
}

// Half a step of the four G functions: a += m + b, d = (d ^ a) >>> $dr by the control at
// {table} + 32 * $control, c += d, b = (b ^ c) >>> $br.
#[rustfmt::skip]
macro_rules! asm_half {
    (
        $r:literal, $w:literal, $size:literal, $slot:literal,
        [$a0:literal, $a1:literal, $a2:literal, $a3:literal],
        [$b0:literal, $b1:literal, $b2:literal, $b3:literal],
        [$c0:tt, $c1:tt, $c2:tt, $c3:tt],
        [$d0:literal, $d1:literal, $d2:literal, $d3:literal],
        [$m0:literal, $m1:literal, $m2:literal, $m3:literal],
        $control:literal, $br:literal, $bl:literal
    ) => {
        concat!(
            asm_message!($r, $w, $size, $a0, $m0), asm_message!($r, $w, $size, $a1, $m1),
            asm_message!($r, $w, $size, $a2, $m2), asm_message!($r, $w, $size, $a3, $m3),
            asm_add!($r, $a0, $b0), asm_add!($r, $a1, $b1),
            asm_add!($r, $a2, $b2), asm_add!($r, $a3, $b3),
            asm_xor!($r, $d0, $a0), asm_xor!($r, $d1, $a1),
            asm_xor!($r, $d2, $a2), asm_xor!($r, $d3, $a3),
            "vmovdqu ", $r, "8, ", $w, " ptr [{table} + 32 * ", $control, "]\n",
            asm_shuffle!($r, $d0), asm_shuffle!($r, $d1),
            asm_shuffle!($r, $d2), asm_shuffle!($r, $d3),
            asm_c!($r, $w, $slot, $c0, $d0), asm_c!($r, $w, $slot, $c1, $d1),
            asm_c!($r, $w, $slot, $c2, $d2), asm_c!($r, $w, $slot, $c3, $d3),
            asm_xor!($r, $b0, $c0), asm_xor!($r, $b1, $c1),
            asm_xor!($r, $b2, $c2), asm_xor!($r, $b3, $c3),
            "vmovdqu ", $w, " ptr [", $slot, "], ", $r, "8\n",
            asm_rotate!($r, $b0, $br, $bl), asm_rotate!($r, $b1, $br, $bl),
            asm_rotate!($r, $b2, $br, $bl), asm_rotate!($r, $b3, $br, $bl),
        )
    };
}

// A round with the message words in its order s: the columns, then the diagonals.
#[rustfmt::skip]
macro_rules! asm_round {
    (
        $r:literal, $w:literal, $size:literal, $slot:literal,
        [
            $s0:literal, $s1:literal, $s2:literal, $s3:literal, $s4:literal, $s5:literal,
            $s6:literal, $s7:literal, $s8:literal, $s9:literal, $s10:literal, $s11:literal,
            $s12:literal, $s13:literal, $s14:literal, $s15:literal
        ]
    ) => {
        concat!(
            asm_half!(
                $r, $w, $size, $slot, [0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11],
                [12, 13, 14, 15], [$s0, $s2, $s4, $s6], 0, 12, 20
            ),
            asm_half!(
                $r, $w, $size, $slot, [0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11],
                [12, 13, 14, 15], [$s1, $s3, $s5, $s7], 1, 7, 25
            ),
            asm_half!(
                $r, $w, $size, $slot, [0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9],
                [15, 12, 13, 14], [$s8, $s10, $s12, $s14], 0, 12, 20
            ),
            asm_half!(
                $r, $w, $size, $slot, [0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9],
                [15, 12, 13, 14], [$s9, $s11, $s13, $s15], 1, 7, 25
            ),
        )
    };
}

// The seven rounds on the state in registers, v8 in its slot.
#[rustfmt::skip]
macro_rules! asm_seven {
    ($r:literal, $w:literal, $size:literal, $slot:literal) => {
        concat!(
            asm_round!(
                $r, $w, $size, $slot, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            ),
            asm_round!(
                $r, $w, $size, $slot, [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
            ),
            asm_round!(
                $r, $w, $size, $slot, [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1]
            ),
            asm_round!(
                $r, $w, $size, $slot, [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6]
            ),
            asm_round!(
                $r, $w, $size, $slot, [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4]
            ),
            asm_round!(
                $r, $w, $size, $slot, [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7]
            ),
            asm_round!(
                $r, $w, $size, $slot, [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13]
            ),
        )
    };
}

// The rounds on the whole state at {v}, whose word 8 is at {slot}.
#[rustfmt::skip]
macro_rules! asm_rounds {
    ($r:literal, $w:literal, $size:literal) => {
        concat!(
            asm_load!($r, $w, $size, 0, "{v}", 0), asm_load!($r, $w, $size, 1, "{v}", 1),
            asm_load!($r, $w, $size, 2, "{v}", 2), asm_load!($r, $w, $size, 3, "{v}", 3),
            asm_load!($r, $w, $size, 4, "{v}", 4), asm_load!($r, $w, $size, 5, "{v}", 5),
            asm_load!($r, $w, $size, 6, "{v}", 6), asm_load!($r, $w, $size, 7, "{v}", 7),
            asm_load!($r, $w, $size, 9, "{v}", 9), asm_load!($r, $w, $size, 10, "{v}", 10),
            asm_load!($r, $w, $size, 11, "{v}", 11), asm_load!($r, $w, $size, 12, "{v}", 12),
            asm_load!($r, $w, $size, 13, "{v}", 13), asm_load!($r, $w, $size, 14, "{v}", 14),
            asm_load!($r, $w, $size, 15, "{v}", 15),
            asm_seven!($r, $w, $size, "{slot}"),
            asm_store!($r, $w, $size, 0, "{v}", 0), asm_store!($r, $w, $size, 1, "{v}", 1),
            asm_store!($r, $w, $size, 2, "{v}", 2), asm_store!($r, $w, $size, 3, "{v}", 3),
            asm_store!($r, $w, $size, 4, "{v}", 4), asm_store!($r, $w, $size, 5, "{v}", 5),
            asm_store!($r, $w, $size, 6, "{v}", 6), asm_store!($r, $w, $size, 7, "{v}", 7),
            asm_store!($r, $w, $size, 9, "{v}", 9), asm_store!($r, $w, $size, 10, "{v}", 10),
            asm_store!($r, $w, $size, 11, "{v}", 11), asm_store!($r, $w, $size, 12, "{v}", 12),
            asm_store!($r, $w, $size, 13, "{v}", 13), asm_store!($r, $w, $size, 14, "{v}", 14),
            asm_store!($r, $w, $size, 15, "{v}", 15),
        )
    };
}

// The four-word transposition of registers 8 to 11 within each 128-bit half, through 12 to 15:
// word i of register 8 + j to word j of register 8 + i.
#[rustfmt::skip]
macro_rules! asm_transpose {
    ($r:literal) => {
        concat!(
            "vpunpckldq ", $r, "12, ", $r, "8, ", $r, "9\n",
            "vpunpckhdq ", $r, "13, ", $r, "8, ", $r, "9\n",
            "vpunpckldq ", $r, "14, ", $r, "10, ", $r, "11\n",
            "vpunpckhdq ", $r, "15, ", $r, "10, ", $r, "11\n",
            "vpunpcklqdq ", $r, "8, ", $r, "12, ", $r, "14\n",
            "vpunpckhqdq ", $r, "9, ", $r, "12, ", $r, "14\n",
            "vpunpcklqdq ", $r, "10, ", $r, "13, ", $r, "15\n",
            "vpunpckhqdq ", $r, "11, ", $r, "13, ", $r, "15\n",
        )
    };
}

// Words 4q to 4q + 3 of the current block of lane i (and of lane i + 4 in the high half) into
// register 8 + i, transposed, then into message rows 4q to 4q + 3. The lanes' inputs are at r8
// to r15, the block's offset in each is rax.
#[rustfmt::skip]
macro_rules! asm_quarter8 {
    ($q:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal) => {
        concat!(
            "vmovdqu xmm8, xmmword ptr [r8 + rax + 16 * ", $q, "]\n",
            "vmovdqu xmm9, xmmword ptr [r9 + rax + 16 * ", $q, "]\n",
            "vmovdqu xmm10, xmmword ptr [r10 + rax + 16 * ", $q, "]\n",
            "vmovdqu xmm11, xmmword ptr [r11 + rax + 16 * ", $q, "]\n",
            "vinserti128 ymm8, ymm8, xmmword ptr [r12 + rax + 16 * ", $q, "], 1\n",
            "vinserti128 ymm9, ymm9, xmmword ptr [r13 + rax + 16 * ", $q, "], 1\n",
            "vinserti128 ymm10, ymm10, xmmword ptr [r14 + rax + 16 * ", $q, "], 1\n",
            "vinserti128 ymm11, ymm11, xmmword ptr [r15 + rax + 16 * ", $q, "], 1\n",
            asm_transpose!("ymm"),
            asm_store!("ymm", "ymmword", 32, 8, "{m}", $r0),
            asm_store!("ymm", "ymmword", 32, 9, "{m}", $r1),
            asm_store!("ymm", "ymmword", 32, 10, "{m}", $r2),
            asm_store!("ymm", "ymmword", 32, 11, "{m}", $r3),
        )
    };
}

#[rustfmt::skip]
macro_rules! asm_quarter4 {
    ($q:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal) => {
        concat!(
            "vmovdqu xmm8, xmmword ptr [r8 + rax + 16 * ", $q, "]\n",
            "vmovdqu xmm9, xmmword ptr [r9 + rax + 16 * ", $q, "]\n",
            "vmovdqu xmm10, xmmword ptr [r10 + rax + 16 * ", $q, "]\n",
            "vmovdqu xmm11, xmmword ptr [r11 + rax + 16 * ", $q, "]\n",
            asm_transpose!("xmm"),
            asm_store!("xmm", "xmmword", 16, 8, "{m}", $r0),
            asm_store!("xmm", "xmmword", 16, 9, "{m}", $r1),
            asm_store!("xmm", "xmmword", 16, 10, "{m}", $r2),
            asm_store!("xmm", "xmmword", 16, 11, "{m}", $r3),
        )
    };
}

// hash_many's blocks of every lane, the chaining values at {h} in and out, the message rows and
// v8's slot at {m}, and at {table} the rotations' controls, the IV, the counters and the length
// (at 32-byte strides) and from byte 320 the flags of block b at 64 b. rcx is the end of the
// lanes' inputs.
#[rustfmt::skip]
macro_rules! asm_hash {
    ($r:literal, $w:literal, $size:literal, $quarter:ident, $slot:literal) => {
        concat!(
            asm_load!($r, $w, $size, 0, "{h}", 0), asm_load!($r, $w, $size, 1, "{h}", 1),
            asm_load!($r, $w, $size, 2, "{h}", 2), asm_load!($r, $w, $size, 3, "{h}", 3),
            asm_load!($r, $w, $size, 4, "{h}", 4), asm_load!($r, $w, $size, 5, "{h}", 5),
            asm_load!($r, $w, $size, 6, "{h}", 6), asm_load!($r, $w, $size, 7, "{h}", 7),
            "xor eax, eax\n",
            ".p2align 5\n",
            "2:\n",
            $quarter!(0, 0, 1, 2, 3),
            $quarter!(1, 4, 5, 6, 7),
            $quarter!(2, 8, 9, 10, 11),
            $quarter!(3, 12, 13, 14, 15),
            asm_load!($r, $w, 32, 8, "{table}", 2),
            "vmovdqu ", $w, " ptr [", $slot, "], ", $r, "8\n",
            asm_load!($r, $w, 32, 9, "{table}", 3), asm_load!($r, $w, 32, 10, "{table}", 4),
            asm_load!($r, $w, 32, 11, "{table}", 5), asm_load!($r, $w, 32, 12, "{table}", 6),
            asm_load!($r, $w, 32, 13, "{table}", 7), asm_load!($r, $w, 32, 14, "{table}", 8),
            "vmovdqu ", $r, "15, ", $w, " ptr [{table} + rax + 320]\n",
            asm_seven!($r, $w, $size, $slot),
            "vpxor ", $r, "0, ", $r, "0, ", $w, " ptr [", $slot, "]\n",
            asm_xor!($r, 1, 9), asm_xor!($r, 2, 10), asm_xor!($r, 3, 11), asm_xor!($r, 4, 12),
            asm_xor!($r, 5, 13), asm_xor!($r, 6, 14), asm_xor!($r, 7, 15),
            "add rax, 64\n",
            "cmp rax, rcx\n",
            "jne 2b\n",
            asm_store!($r, $w, $size, 0, "{h}", 0), asm_store!($r, $w, $size, 1, "{h}", 1),
            asm_store!($r, $w, $size, 2, "{h}", 2), asm_store!($r, $w, $size, 3, "{h}", 3),
            asm_store!($r, $w, $size, 4, "{h}", 4), asm_store!($r, $w, $size, 5, "{h}", 5),
            asm_store!($r, $w, $size, 6, "{h}", 6), asm_store!($r, $w, $size, 7, "{h}", 7),
        )
    };
}

// The byte controls of the rotations by 16 and by 8, for both halves of a ymm register.
static CONTROLS: [[u8; 32]; 2] = {
    let mut controls = [[0; 32]; 2];

    let mut i = 0;

    while i < 32 {
        controls[0][i] = ROTATE16[i % 16];

        controls[1][i] = ROTATE8[i % 16];

        i += 1;
    }

    controls
};

// The assembly with every vector register declared clobbered (on Windows, the compiler then
// saves the callee-saved xmm6 to xmm15 around it).
macro_rules! vector_asm {
    ($($operand:tt)*) => {
        core::arch::asm!(
            $($operand)*
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
            out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
            options(nostack),
        )
    };
}

// The rounds of the extended output on eight lanes: the state at v, its word 8 through slot.
#[target_feature(enable = "avx2")]
#[inline]
#[allow(unsafe_code)]
fn rounds8(v: &mut [__m256i; 16], m: &[__m256i; 16]) {
    let v = v.as_mut_ptr();

    // SAFETY: AVX2 instructions, which this function's target feature provides, on the vector
    // registers, all declared clobbered. They read the 512 bytes of m and the 64 of CONTROLS,
    // and read and write the 512 bytes of v, at the offsets that the template names; no stack.
    unsafe {
        vector_asm!(
            asm_rounds!("ymm", "ymmword", 32),
            v = in(reg) v,
            slot = in(reg) v.wrapping_add(8),
            m = in(reg) m.as_ptr(),
            table = in(reg) CONTROLS.as_ptr(),
        )
    };
}

#[target_feature(enable = "avx2")]
#[inline]
#[allow(unsafe_code)]
fn rounds4(v: &mut [__m128i; 16], m: &[__m128i; 16]) {
    let v = v.as_mut_ptr();

    // SAFETY: as in rounds8, for 256 bytes of v and m and the first 16 bytes of each control.
    unsafe {
        vector_asm!(
            asm_rounds!("xmm", "xmmword", 16),
            v = in(reg) v,
            slot = in(reg) v.wrapping_add(8),
            m = in(reg) m.as_ptr(),
            table = in(reg) CONTROLS.as_ptr(),
        )
    };
}

// The constants of hash_many's assembly at 32-byte strides, whatever the vector width: the
// rotations' controls, the IV, the counters of the lanes and the block length; then the flags of
// each block at a 64-byte stride, in the first half of each row. Only the rows of the call's
// blocks are written, and the assembly reads no others: zeroing all of them cost a kilobyte of
// stores per call.
#[repr(C, align(32))]
struct Table {
    head: [[u32; 8]; 10],
    flags: [[MaybeUninit<[u32; 8]>; 2]; 16],
}

// Word i of a rotation's byte control, repeated over 32 bytes.
const fn control(rotate: &[u8; 16], i: usize) -> u32 {
    let k = 4 * (i % 4);

    u32::from_le_bytes([rotate[k], rotate[k + 1], rotate[k + 2], rotate[k + 3]])
}

// The table's head as every call starts it: the rotations' controls, the IV and the block length,
// the counters zero.
static HEAD: [[u32; 8]; 10] = {
    let mut head = [[0; 8]; 10];

    let mut i = 0;

    while i < 8 {
        head[0][i] = control(&ROTATE16, i);

        head[1][i] = control(&ROTATE8, i);

        let mut row = 0;

        while row < 4 {
            head[2 + row][i] = IV_256[row];

            row += 1;
        }

        head[8][i] = 64;

        i += 1;
    }

    head
};

// The flags of the blocks into the table, once per hash_many_avx2 call: every block's row gets
// the same value, then start and end go into the first and the last. Chosen block by block,
// LLVM 20 vectorized the choice with a vmovq from xmm8 to xmm4 encoded with opcode D6, which
// valgrind before 3.24 does not decode (KDE bug 391148).
#[target_feature(enable = "avx2")]
#[inline]
fn flags(table: &mut Table, many: &Many) {
    let rows = &mut table.flags[..many.blocks];

    for row in rows.iter_mut() {
        row[0] = MaybeUninit::new([many.flags; 8]);
    }

    let start = many.flags | many.start;

    let end = if many.blocks == 1 { start } else { many.flags } | many.end;

    rows[0][0] = MaybeUninit::new([start; 8]);

    rows[many.blocks - 1][0] = MaybeUninit::new([end; 8]);
}

// The inputs of the lanes, `first` on: an index past the last input repeats the last one.
fn lanes<'a, const L: usize>(
    input: &'a [[u8; 64]],
    many: &Many,
    first: usize,
    count: usize,
) -> [&'a [[u8; 64]]; L] {
    core::array::from_fn(|l| {
        let lane = (first + l).min(count - 1);

        &input[lane * many.blocks..(lane + 1) * many.blocks]
    })
}

// The counters of the lanes into the table, low and high words.
fn counters<const L: usize>(table: &mut Table, many: &Many, first: usize, count: usize) {
    let [_, _, _, _, _, _, low, high, _, _] = &mut table.head;

    for (l, (low, high)) in low.iter_mut().zip(high.iter_mut()).take(L).enumerate() {
        let lane = (first + l).min(count - 1);

        let counter = if many.increment {
            many.counter + lane as u64
        } else {
            many.counter
        };

        *low = counter as u32;

        *high = (counter >> 32) as u32;
    }
}

// hash_many's inputs `first` to `first + 7` with AVX2, every block in one loop of assembly.
#[target_feature(enable = "avx2")]
#[allow(unsafe_code)]
fn hash8(input: &[[u8; 64]], many: &Many, table: &mut Table, first: usize, out: &mut [[u8; 32]]) {
    let count = out.len();

    let lanes = lanes::<8>(input, many, first, count);

    counters::<8>(table, many, first, count);

    let key = &many.key;

    // Written out, not array::map: map was not inlined at codegen-units 16, and a broadcast key
    // word stayed in its frame.
    let mut h = [
        _mm256_set1_epi32(key[0] as i32),
        _mm256_set1_epi32(key[1] as i32),
        _mm256_set1_epi32(key[2] as i32),
        _mm256_set1_epi32(key[3] as i32),
        _mm256_set1_epi32(key[4] as i32),
        _mm256_set1_epi32(key[5] as i32),
        _mm256_set1_epi32(key[6] as i32),
        _mm256_set1_epi32(key[7] as i32),
    ];

    // Written by the assembly before it reads it.
    let mut m = [MaybeUninit::<__m256i>::uninit(); 17];

    let [l0, l1, l2, l3, l4, l5, l6, l7] = lanes.map(|lane| lane.as_ptr());

    // SAFETY: AVX2 instructions, which this function's target feature provides, on the vector
    // registers, all declared clobbered, and on the registers named below. The loop runs at least
    // once and reads the flags of each block from table's 16 rows, so it needs 1 <= blocks <= 16,
    // which hash_many_avx2, the only caller, checks. For every block offset below rcx = 64
    // blocks, they read the 64 bytes there of each lane's input, which has `blocks` blocks; they
    // read and write the 256 bytes of h and the 544 of m, and read table, at the offsets that the
    // template names; no stack.
    unsafe {
        vector_asm!(
            asm_hash!("ymm", "ymmword", 32, asm_quarter8, "{m} + 32 * 16"),
            h = in(reg) h.as_mut_ptr(),
            m = in(reg) m.as_mut_ptr(),
            table = in(reg) &raw const *table,
            in("rcx") 64 * many.blocks,
            out("rax") _,
            in("r8") l0, in("r9") l1, in("r10") l2, in("r11") l3,
            in("r12") l4, in("r13") l5, in("r14") l6, in("r15") l7,
        )
    };

    let mut words = cvs8(&h);

    for (l, words) in words.iter().enumerate() {
        if first + l < count {
            out[first + l] = *words;
        }
    }

    wipe(words.as_flattened_mut());

    clear(&mut h, _mm256_setzero_si256());

    clear(&mut m, MaybeUninit::new(_mm256_setzero_si256()));
}

// The flags of the blocks into the table of the 512-bit kernel, as flags() does for Table.
fn flags16(table: &mut Table16, many: &Many) {
    let rows = &mut table.flags[..many.blocks];

    rows.fill(many.flags);

    let start = many.flags | many.start;

    let end = if many.blocks == 1 { start } else { many.flags } | many.end;

    rows[0] = start;

    rows[many.blocks - 1] = end;
}

// The counters of sixteen lanes into the table of the 512-bit kernel, from `first` on, each one
// more than the last if `increment`.
fn counters16(table: &mut Table16, first: u64, increment: bool) {
    for (l, (low, high)) in table.low.iter_mut().zip(table.high.iter_mut()).enumerate() {
        let counter = if increment {
            first.wrapping_add(l as u64)
        } else {
            first
        };

        *low = counter as u32;

        *high = (counter >> 32) as u32;
    }
}

// hash_many's inputs `first` to `first + 15` with the 512-bit kernel, their chaining values
// written straight into out.
#[target_feature(enable = "avx2")]
#[allow(unsafe_code)]
fn hash16(
    input: &[[u8; 64]],
    many: &Many,
    table: &mut Table16,
    first: usize,
    out: &mut [[u8; 32]],
) {
    let start = if many.increment {
        many.counter.wrapping_add(first as u64)
    } else {
        many.counter
    };

    counters16(table, start, many.increment);

    let inputs = &input[first * many.blocks..(first + 16) * many.blocks];

    let out =
        <&mut [[u8; 32]; 16]>::try_from(&mut out[first..first + 16]).expect("sixteen outputs");

    // SAFETY: hash_many_avx2 calls this only when wide is set, which is on a CPU with AVX-512F and
    // AVX-512VL whose registers the operating system saves (zmm_lanes() is tested with AVX512
    // only); 1 <= blocks <= 16, as hash_many_avx2 checks; inputs holds sixteen inputs of `blocks`
    // blocks each, input i at 64 * blocks * i bytes.
    unsafe {
        super::blake3_zmm::hash16_zmm(inputs.as_ptr().cast(), many.blocks, many.key, table, out)
    };
}

// hash_many's inputs `first` to `first + 3` with AVX2 on xmm registers.
#[target_feature(enable = "avx2")]
#[allow(unsafe_code)]
fn hash4(input: &[[u8; 64]], many: &Many, table: &mut Table, first: usize, out: &mut [[u8; 32]]) {
    let count = out.len();

    let lanes = lanes::<4>(input, many, first, count);

    counters::<4>(table, many, first, count);

    let key = &many.key;

    // Written out, not array::map, as in hash8.
    let mut h = [
        _mm_set1_epi32(key[0] as i32),
        _mm_set1_epi32(key[1] as i32),
        _mm_set1_epi32(key[2] as i32),
        _mm_set1_epi32(key[3] as i32),
        _mm_set1_epi32(key[4] as i32),
        _mm_set1_epi32(key[5] as i32),
        _mm_set1_epi32(key[6] as i32),
        _mm_set1_epi32(key[7] as i32),
    ];

    // As in hash8.
    let mut m = [MaybeUninit::<__m128i>::uninit(); 17];

    let [l0, l1, l2, l3] = lanes.map(|lane| lane.as_ptr());

    // SAFETY: as in hash8, for four lanes, 16-byte vectors, 128 bytes of h and 272 of m.
    unsafe {
        vector_asm!(
            asm_hash!("xmm", "xmmword", 16, asm_quarter4, "{m} + 16 * 16"),
            h = in(reg) h.as_mut_ptr(),
            m = in(reg) m.as_mut_ptr(),
            table = in(reg) &raw const *table,
            in("rcx") 64 * many.blocks,
            out("rax") _,
            in("r8") l0, in("r9") l1, in("r10") l2, in("r11") l3,
        )
    };

    let mut words = cvs4(&h);

    for (l, words) in words.iter().enumerate() {
        if first + l < count {
            out[first + l] = *words;
        }
    }

    wipe(words.as_flattened_mut());

    clear(&mut h, _mm_setzero_si128());

    clear(&mut m, MaybeUninit::new(_mm_setzero_si128()));
}

// The four G functions of a step of the transposed form side by side, instruction by
// instruction: G k on words a[k], b[k], c[k] and d[k] with message words x[k] and y[k].
macro_rules! step {
    ($v:ident, $words:expr, $x:expr, $y:expr, $add:ident, $xor:ident) => {{
        let [a, b, c, d]: [[usize; 4]; 4] = $words;

        let x = $x;

        let y = $y;

        for k in 0..4 {
            $v[a[k]] = $add($add($v[a[k]], x[k]), $v[b[k]]);
        }

        for k in 0..4 {
            $v[d[k]] = rotate::<16>($xor($v[d[k]], $v[a[k]]));
        }

        for k in 0..4 {
            $v[c[k]] = $add($v[c[k]], $v[d[k]]);
        }

        for k in 0..4 {
            $v[b[k]] = rotate::<12>($xor($v[b[k]], $v[c[k]]));
        }

        for k in 0..4 {
            $v[a[k]] = $add($add($v[a[k]], y[k]), $v[b[k]]);
        }

        for k in 0..4 {
            $v[d[k]] = rotate::<8>($xor($v[d[k]], $v[a[k]]));
        }

        for k in 0..4 {
            $v[c[k]] = $add($v[c[k]], $v[d[k]]);
        }

        for k in 0..4 {
            $v[b[k]] = rotate::<7>($xor($v[b[k]], $v[c[k]]));
        }
    }};
}

// Round R of the transposed form, whose message words are read in their order of the round: the
// message stays where it is, and the words become memory operands.
macro_rules! round {
    ($v:ident, $m:ident, $r:literal, $add:ident, $xor:ident) => {{
        let s = &SCHEDULE[$r];

        step!(
            $v,
            COLUMNS,
            [$m[s[0]], $m[s[2]], $m[s[4]], $m[s[6]]],
            [$m[s[1]], $m[s[3]], $m[s[5]], $m[s[7]]],
            $add,
            $xor
        );

        step!(
            $v,
            DIAGONALS,
            [$m[s[8]], $m[s[10]], $m[s[12]], $m[s[14]]],
            [$m[s[9]], $m[s[11]], $m[s[13]], $m[s[15]]],
            $add,
            $xor
        );
    }};
}

// The transposed form with intrinsics, for SSE4.1: `$message` transposes a block of each lane
// into rows, word i of every lane in row i, and `$cvs` the chaining values back. The vectors in
// memory that held state or message words are cleared afterwards.
macro_rules! lanes_hash {
    (
        $feature:literal, $vector:ty, $lanes:literal,
        $add:ident, $xor:ident, $or:ident, $srli:ident, $slli:ident, $rotate16:ident,
        $rotate8:ident, $set1:ident, $zero:ident, $load:ident, $message:ident, $cvs:ident
    ) => {
        #[target_feature(enable = $feature)]
        #[inline]
        fn rotate<const R: u32>(x: $vector) -> $vector {
            match R {
                16 => $rotate16(x),
                8 => $rotate8(x),
                12 => $or($srli::<12>(x), $slli::<20>(x)),
                7 => $or($srli::<7>(x), $slli::<25>(x)),
                _ => unreachable!("the rotations of BLAKE3"),
            }
        }

        // The seven rounds as intrinsics, in one function: as functions of their own, the steps
        // were not inlined, and their state went through memory.
        #[target_feature(enable = $feature)]
        #[inline]
        fn rounds(v: &mut [$vector; 16], m: &[$vector; 16]) {
            round!(v, m, 0, $add, $xor);

            round!(v, m, 1, $add, $xor);

            round!(v, m, 2, $add, $xor);

            round!(v, m, 3, $add, $xor);

            round!(v, m, 4, $add, $xor);

            round!(v, m, 5, $add, $xor);

            round!(v, m, 6, $add, $xor);
        }

        // A block of hash_many: the next chaining values from h and the state's other words in
        // init. The state goes through v, which the caller owns, as rounds, out of line, takes it
        // in memory.
        #[target_feature(enable = $feature)]
        #[inline]
        fn block(
            h: &mut [$vector; 8],
            init: &[$vector; 8],
            m: &[$vector; 16],
            v: &mut [$vector; 16],
        ) {
            *v = [
                h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], init[0], init[1], init[2], init[3],
                init[4], init[5], init[6], init[7],
            ];

            rounds(v, m);

            for i in 0..8 {
                h[i] = $xor(v[i], v[i + 8]);
            }
        }

        // Inputs `first` to `first + LANES - 1` of hash_many; an index past the last input
        // repeats the last one, whose result is then dropped.
        #[target_feature(enable = $feature)]
        pub(super) fn hash_group(
            input: &[[u8; 64]],
            many: &Many,
            first: usize,
            out: &mut [[u8; 32]],
        ) {
            let blocks = many.blocks;

            let count = out.len();

            let mut lanes = [0; $lanes];

            for (l, lane) in lanes.iter_mut().enumerate() {
                *lane = (first + l).min(count - 1);
            }

            let mut h = [$zero(); 8];

            for (word, key) in h.iter_mut().zip(many.key) {
                *word = $set1(*key as i32);
            }

            let mut low = [0u32; $lanes];

            let mut high = [0u32; $lanes];

            for (l, &lane) in lanes.iter().enumerate() {
                let counter = if many.increment {
                    many.counter + lane as u64
                } else {
                    many.counter
                };

                low[l] = counter as u32;

                high[l] = (counter >> 32) as u32;
            }

            let mut init = [
                $set1(IV_256[0] as i32),
                $set1(IV_256[1] as i32),
                $set1(IV_256[2] as i32),
                $set1(IV_256[3] as i32),
                $load(&low),
                $load(&high),
                $set1(64),
                $zero(),
            ];

            let (mut m, mut v) = ([$zero(); 16], [$zero(); 16]);

            for b in 0..blocks {
                let mut flags = many.flags;

                if b == 0 {
                    flags |= many.start;
                }

                if b + 1 == blocks {
                    flags |= many.end;
                }

                init[7] = $set1(flags as i32);

                let mut rows = [&input[0]; $lanes];

                for (row, &lane) in rows.iter_mut().zip(&lanes) {
                    *row = &input[lane * blocks + b];
                }

                m = $message(&rows);

                block(&mut h, &init, &m, &mut v);
            }

            let mut words = $cvs(&h);

            for (l, words) in words.iter().enumerate() {
                if first + l < count {
                    out[first + l] = *words;
                }
            }

            wipe(words.as_flattened_mut());

            clear(&mut h, $zero());

            clear(&mut m, $zero());

            clear(&mut v, $zero());
        }
    };
}

// The extended output in the transposed form: `$rounds` are the rounds, `$blocks` transposes
// the output words back into blocks.
macro_rules! lanes_xof {
    (
        $feature:literal, $vector:ty, $lanes:literal, $xor:ident, $set1:ident, $zero:ident,
        $load:ident, $blocks:ident, $rounds:ident
    ) => {
        // Output blocks counter to counter + LANES - 1 of the root.
        #[target_feature(enable = $feature)]
        pub(super) fn xof_group(
            cv: &[u32; 8],
            block: &[u32; 16],
            counter: u64,
            [length, flags]: [u32; 2],
            out: &mut [[u8; 64]; $lanes],
        ) {
            let mut m = [$zero(); 16];

            for (word, value) in m.iter_mut().zip(block) {
                *word = $set1(*value as i32);
            }

            let mut h = [$zero(); 8];

            for (word, value) in h.iter_mut().zip(cv) {
                *word = $set1(*value as i32);
            }

            let mut low = [0u32; $lanes];

            let mut high = [0u32; $lanes];

            for l in 0..$lanes {
                let c = counter.wrapping_add(l as u64);

                low[l] = c as u32;

                high[l] = (c >> 32) as u32;
            }

            let mut v = [
                h[0],
                h[1],
                h[2],
                h[3],
                h[4],
                h[5],
                h[6],
                h[7],
                $set1(IV_256[0] as i32),
                $set1(IV_256[1] as i32),
                $set1(IV_256[2] as i32),
                $set1(IV_256[3] as i32),
                $load(&low),
                $load(&high),
                $set1(length as i32),
                $set1(flags as i32),
            ];

            $rounds(&mut v, &m);

            let mut words = [$zero(); 16];

            for i in 0..8 {
                words[i] = $xor(v[i], v[i + 8]);

                words[i + 8] = $xor(v[i + 8], h[i]);
            }

            $blocks(&words, out);

            clear(&mut v, $zero());

            clear(&mut m, $zero());

            clear(&mut h, $zero());

            clear(&mut words, $zero());
        }
    };
}

// AVX2: words 4q to 4q + 3 of lanes i and i + 4 in one register, then four-word transpositions
// within each half.
#[target_feature(enable = "avx2")]
#[inline]
fn transpose4x2(x: [__m256i; 4]) -> [__m256i; 4] {
    let t0 = _mm256_unpacklo_epi32(x[0], x[1]);

    let t1 = _mm256_unpackhi_epi32(x[0], x[1]);

    let t2 = _mm256_unpacklo_epi32(x[2], x[3]);

    let t3 = _mm256_unpackhi_epi32(x[2], x[3]);

    [
        _mm256_unpacklo_epi64(t0, t2),
        _mm256_unpackhi_epi64(t0, t2),
        _mm256_unpacklo_epi64(t1, t3),
        _mm256_unpackhi_epi64(t1, t3),
    ]
}

// The eight words of each lane: word j of the lanes in h[j].
#[target_feature(enable = "avx2")]
#[inline]
fn cvs8(h: &[__m256i; 8]) -> [[u8; 32]; 8] {
    let low = transpose4x2([h[0], h[1], h[2], h[3]]);

    let high = transpose4x2([h[4], h[5], h[6], h[7]]);

    let mut out = [[0; 32]; 8];

    for l in 0..4 {
        let first = _mm256_permute2x128_si256::<0x20>(low[l], high[l]);

        let second = _mm256_permute2x128_si256::<0x31>(low[l], high[l]);

        store256(first, &mut out[l]);

        store256(second, &mut out[l + 4]);
    }

    out
}

#[target_feature(enable = "avx2")]
#[inline]
fn blocks8(words: &[__m256i; 16], out: &mut [[u8; 64]; 8]) {
    for half in 0..2 {
        let low = transpose4x2([
            words[8 * half],
            words[8 * half + 1],
            words[8 * half + 2],
            words[8 * half + 3],
        ]);

        let high = transpose4x2([
            words[8 * half + 4],
            words[8 * half + 5],
            words[8 * half + 6],
            words[8 * half + 7],
        ]);

        for l in 0..4 {
            let (first, _) = out[l].as_chunks_mut::<32>();

            store256(
                _mm256_permute2x128_si256::<0x20>(low[l], high[l]),
                &mut first[half],
            );

            let (second, _) = out[l + 4].as_chunks_mut::<32>();

            store256(
                _mm256_permute2x128_si256::<0x31>(low[l], high[l]),
                &mut second[half],
            );
        }
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn load8(words: &[u32; 8]) -> __m256i {
    load256(words)
}

mod lanes_avx2 {
    use super::*;

    lanes_xof!(
        "avx2",
        __m256i,
        8,
        _mm256_xor_si256,
        _mm256_set1_epi32,
        _mm256_setzero_si256,
        load8,
        blocks8,
        rounds8
    );
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn transpose4(x: [__m128i; 4]) -> [__m128i; 4] {
    let t0 = _mm_unpacklo_epi32(x[0], x[1]);

    let t1 = _mm_unpackhi_epi32(x[0], x[1]);

    let t2 = _mm_unpacklo_epi32(x[2], x[3]);

    let t3 = _mm_unpackhi_epi32(x[2], x[3]);

    [
        _mm_unpacklo_epi64(t0, t2),
        _mm_unpackhi_epi64(t0, t2),
        _mm_unpacklo_epi64(t1, t3),
        _mm_unpackhi_epi64(t1, t3),
    ]
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn message4(rows: &[&[u8; 64]; 4]) -> [__m128i; 16] {
    let mut m = [_mm_setzero_si128(); 16];

    for q in 0..4 {
        let mut x = [_mm_setzero_si128(); 4];

        for (i, x) in x.iter_mut().enumerate() {
            let (pieces, _) = rows[i].as_chunks::<16>();

            *x = load128(&pieces[q]);
        }

        m[4 * q..4 * q + 4].copy_from_slice(&transpose4(x));
    }

    m
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn cvs4(h: &[__m128i; 8]) -> [[u8; 32]; 4] {
    let low = transpose4([h[0], h[1], h[2], h[3]]);

    let high = transpose4([h[4], h[5], h[6], h[7]]);

    let mut out = [[0; 32]; 4];

    for l in 0..4 {
        let (pieces, _) = out[l].as_chunks_mut::<16>();

        store128(low[l], &mut pieces[0]);

        store128(high[l], &mut pieces[1]);
    }

    out
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn blocks4(words: &[__m128i; 16], out: &mut [[u8; 64]; 4]) {
    for q in 0..4 {
        let columns = transpose4([
            words[4 * q],
            words[4 * q + 1],
            words[4 * q + 2],
            words[4 * q + 3],
        ]);

        for l in 0..4 {
            let (pieces, _) = out[l].as_chunks_mut::<16>();

            store128(columns[l], &mut pieces[q]);
        }
    }
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn rotate16x4(x: __m128i) -> __m128i {
    _mm_shuffle_epi8(x, load128(&ROTATE16))
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn rotate8x4(x: __m128i) -> __m128i {
    _mm_shuffle_epi8(x, load128(&ROTATE8))
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn load4(words: &[u32; 4]) -> __m128i {
    load128(words)
}

mod lanes_sse41 {
    use super::*;

    lanes_hash!(
        "sse2,ssse3,sse4.1",
        __m128i,
        4,
        _mm_add_epi32,
        _mm_xor_si128,
        _mm_or_si128,
        _mm_srli_epi32,
        _mm_slli_epi32,
        rotate16x4,
        rotate8x4,
        _mm_set1_epi32,
        _mm_setzero_si128,
        load4,
        message4,
        cvs4
    );

    lanes_xof!(
        "sse2,ssse3,sse4.1",
        __m128i,
        4,
        _mm_xor_si128,
        _mm_set1_epi32,
        _mm_setzero_si128,
        load4,
        blocks4,
        rounds
    );
}

// The four-lane form compiled for AVX2, for the inputs that do not fill eight lanes.
mod lanes_avx2_4 {
    use super::*;

    lanes_xof!(
        "avx2",
        __m128i,
        4,
        _mm_xor_si128,
        _mm_set1_epi32,
        _mm_setzero_si128,
        load4,
        blocks4,
        rounds4
    );
}

// hash_many on a CPU with AVX2: eight inputs at a time, the last five to seven as eight, three
// or four as four, two side by side in the row form if `pair`; returns how many it hashed, from
// the first on. One input left, and two without `pair`, go back to the caller: one through the
// dispatch of the row form's chain, two through the scalar code.
// wide: sixteen inputs at a time with the 512-bit kernel first, on a core of zmm_lanes()'s table.
#[target_feature(enable = "avx2")]
pub(super) fn hash_many_avx2(
    input: &[u8],
    many: &Many,
    out: &mut [[u8; 32]],
    pair: bool,
    wide: bool,
) -> usize {
    // The assembly takes one to sixteen blocks per input; anything else is left to the portable
    // code.
    if !(1..=16).contains(&many.blocks) {
        return 0;
    }

    let (input, _) = input.as_chunks::<64>();

    let count = out.len();

    let mut done = 0;

    if wide {
        let mut table = Table16::new();

        flags16(&mut table, many);

        while count - done >= 16 {
            hash16(input, many, &mut table, done, out);

            done += 16;
        }
    }

    if count - done >= 3 {
        let mut table = Table {
            head: HEAD,
            flags: [[MaybeUninit::uninit(); 2]; 16],
        };

        flags(&mut table, many);

        while count - done >= 5 {
            hash8(input, many, &mut table, done, out);

            done = count.min(done + 8);
        }

        if count - done >= 3 {
            hash4(input, many, &mut table, done, out);

            done = count;
        }
    }

    if pair && count - done == 2 {
        let pair = (&mut out[done..done + 2]).try_into().expect("two inputs");

        rows_pair::chain2(input, many, done, pair);

        done = count;
    }

    done
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
pub(super) fn hash_many_sse41(input: &[u8], many: &Many, out: &mut [[u8; 32]]) -> usize {
    // As in hash_many_avx2: one to sixteen blocks per input, as every caller passes.
    if !(1..=16).contains(&many.blocks) {
        return 0;
    }

    let (input, _) = input.as_chunks::<64>();

    let count = out.len();

    let mut done = 0;

    while count - done >= 3 {
        lanes_sse41::hash_group(input, many, done, out);

        done = count.min(done + 4);
    }

    if count - done == 2 {
        let pair = (&mut out[done..done + 2]).try_into().expect("two inputs");

        rows_sse41::chain2(input, many, done, pair);

        done = count;
    }

    done
}

// Output blocks of the root into out, eight and then four at a time; returns how many.
// wide: sixteen output blocks at a time with the 512-bit kernel first, as in hash_many_avx2.
#[target_feature(enable = "avx2")]
#[allow(unsafe_code)]
pub(super) fn xof_avx2(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    [length, flags]: [u32; 2],
    out: &mut [[u8; 64]],
    wide: bool,
) -> usize {
    let info = [length, flags];

    let mut next = counter;

    let mut sixteen = 0;

    if wide {
        let (groups, _) = out.as_chunks_mut::<16>();

        let mut table = Table16::new();

        table.length = length;

        table.flags[0] = flags;

        for group in groups.iter_mut() {
            counters16(&mut table, next, true);

            // SAFETY: wide is set only on a CPU with AVX-512F and AVX-512VL whose registers the
            // operating system saves (zmm_lanes() is tested with AVX512 only).
            unsafe { super::blake3_zmm::xof16_zmm(cv, block, &table, group) };

            next = next.wrapping_add(16);
        }

        sixteen = 16 * groups.len();
    }

    let out = &mut out[sixteen..];

    let (eights, rest) = out.as_chunks_mut::<8>();

    for group in eights.iter_mut() {
        lanes_avx2::xof_group(cv, block, next, info, group);

        next = next.wrapping_add(8);
    }

    let (fours, _) = rest.as_chunks_mut::<4>();

    for group in fours.iter_mut() {
        lanes_avx2_4::xof_group(cv, block, next, info, group);

        next = next.wrapping_add(4);
    }

    sixteen + 8 * eights.len() + 4 * fours.len()
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
pub(super) fn xof_sse41(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    info: [u32; 2],
    out: &mut [[u8; 64]],
) -> usize {
    let (fours, _) = out.as_chunks_mut::<4>();

    let mut next = counter;

    for group in fours.iter_mut() {
        lanes_sse41::xof_group(cv, block, next, info, group);

        next = next.wrapping_add(4);
    }

    4 * fours.len()
}
