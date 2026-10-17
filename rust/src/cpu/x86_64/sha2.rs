// SHA-256 and SHA-512 on one message with AVX2, BMI1 and BMI2, for CPUs without the SHA
// extensions. Blocks go in pairs: the message schedule of both is computed at once, block A in the
// low half of each vector and block B in the high half, and the words plus round constants are
// stored for the rounds, which run on the scalar pipes, RORX for the rotations and ANDN for the
// choice. The rounds of block A are written between the steps of the schedule, so that the vector
// and the scalar pipes work side by side; block B's rounds then read the stored words. The
// schedule of a lone block runs with its copy in the high half. HMAC takes its two key blocks as
// one pair. (Measured on Haswell: the whole schedule first and then both blocks' rounds as loops
// ran 10% slower; block A's rounds in halves of four between the steps, or a lone SHA-512 block's
// own four-word schedule, were no faster.)
//
// The rounds are written in assembly on registers only, eight at a time, with each variable in its
// rotated role as in the portable code; block B's eight at a time in a loop.

use core::arch::x86_64::*;
use core::mem::MaybeUninit;

use super::memory::{load128, load256, store256_at};
use crate::sha2::{K256, K512, pad};
use crate::wipe::wipe;

// K256 with each group of four constants twice, for both halves of a vector.
static K256_PAIRS: [[u32; 8]; 16] = {
    let mut table = [[0; 8]; 16];

    let mut i = 0;

    while i < 64 {
        table[i / 4][i % 4] = K256[i];

        table[i / 4][4 + i % 4] = K256[i];

        i += 1;
    }

    table
};

static K512_PAIRS: [[u64; 4]; 40] = {
    let mut table = [[0; 4]; 40];

    let mut i = 0;

    while i < 80 {
        table[i / 2][i % 2] = K512[i];

        table[i / 2][2 + i % 2] = K512[i];

        i += 1;
    }

    table
};

// The words plus constants of a pair of blocks: group g holds words 4g to 4g + 3 of block A, then
// of block B (SHA-512: words 2g and 2g + 1 of each). The buffer is not zeroed when it is made, as
// that would cost as many stores as its wipe at the end: the schedule writes every group before
// the rounds read it.
type Schedule256 = MaybeUninit<[[u32; 8]; 16]>;

type Schedule512 = MaybeUninit<[[u64; 4]; 40]>;

// One round in assembly on the registers holding a to h in their rotated roles, with 32-bit
// registers (modifier e) for SHA-256 and 64-bit ones (r) for SHA-512: h takes W + K from the
// schedule at byte `off` from wk, then ~e & g and e & f, which are disjoint and so added, and
// Sigma1(e), ready last; d takes T1; h takes Sigma0(a) and Maj(a, b, c) = ((a ^ b) & (b ^ c)) ^ b.
// bc holds b ^ c, the previous round's a ^ b, and t is a temporary that ends with this round's
// a ^ b, so the next round swaps the two.
macro_rules! round {
    (
        $w:literal, $size:literal, [$e1:literal, $e2:literal, $e3:literal],
        [$a1:literal, $a2:literal, $a3:literal], $a:ident, $b:ident, $c:ident, $d:ident,
        $e:ident, $f:ident, $g:ident, $h:ident, $bc:ident, $t:ident, $off:literal
    ) => {
        concat!(
            "rorx {s:", $w, "}, {", stringify!($e), ":", $w, "}, ", $e1, "\n",
            "rorx {", stringify!($t), ":", $w, "}, {", stringify!($e), ":", $w, "}, ", $e2, "\n",
            "add {", stringify!($h), ":", $w, "}, ", $size, " ptr [{wk} + ", $off, "]\n",
            "xor {s:", $w, "}, {", stringify!($t), ":", $w, "}\n",
            "rorx {", stringify!($t), ":", $w, "}, {", stringify!($e), ":", $w, "}, ", $e3, "\n",
            "xor {s:", $w, "}, {", stringify!($t), ":", $w, "}\n",
            "andn {", stringify!($t), ":", $w, "}, {", stringify!($e), ":", $w, "}, {",
            stringify!($g), ":", $w, "}\n",
            "add {", stringify!($h), ":", $w, "}, {", stringify!($t), ":", $w, "}\n",
            "mov {", stringify!($t), ":", $w, "}, {", stringify!($f), ":", $w, "}\n",
            "and {", stringify!($t), ":", $w, "}, {", stringify!($e), ":", $w, "}\n",
            "add {", stringify!($h), ":", $w, "}, {", stringify!($t), ":", $w, "}\n",
            "add {", stringify!($h), ":", $w, "}, {s:", $w, "}\n",
            "add {", stringify!($d), ":", $w, "}, {", stringify!($h), ":", $w, "}\n",
            "rorx {s:", $w, "}, {", stringify!($a), ":", $w, "}, ", $a1, "\n",
            "rorx {", stringify!($t), ":", $w, "}, {", stringify!($a), ":", $w, "}, ", $a2, "\n",
            "xor {s:", $w, "}, {", stringify!($t), ":", $w, "}\n",
            "rorx {", stringify!($t), ":", $w, "}, {", stringify!($a), ":", $w, "}, ", $a3, "\n",
            "xor {s:", $w, "}, {", stringify!($t), ":", $w, "}\n",
            "mov {", stringify!($t), ":", $w, "}, {", stringify!($a), ":", $w, "}\n",
            "xor {", stringify!($t), ":", $w, "}, {", stringify!($b), ":", $w, "}\n",
            "and {", stringify!($bc), ":", $w, "}, {", stringify!($t), ":", $w, "}\n",
            "xor {", stringify!($bc), ":", $w, "}, {", stringify!($b), ":", $w, "}\n",
            "add {", stringify!($h), ":", $w, "}, {s:", $w, "}\n",
            "add {", stringify!($h), ":", $w, "}, {", stringify!($bc), ":", $w, "}\n",
        )
    };
}

macro_rules! round256 {
    ($($operands:tt)*) => {
        round!("e", "dword", [6, 11, 25], [2, 13, 22], $($operands)*)
    };
}

macro_rules! round512 {
    ($($operands:tt)*) => {
        round!("r", "qword", [14, 18, 41], [28, 34, 39], $($operands)*)
    };
}

// Eight rounds, starting in the state's own roles, where eight rounds bring them back, with x
// holding b ^ c before and after; round r reads its word plus constant at the r-th offset, in
// bytes from wk. Compiled from Rust, the rounds took 26 instructions each, with copies the
// compiler added; written out they take 24, on registers only, with W + K read by the first
// addition.
macro_rules! eight {
    (
        $round:ident, $o0:literal, $o1:literal, $o2:literal, $o3:literal, $o4:literal,
        $o5:literal, $o6:literal, $o7:literal
    ) => {
        concat!(
            $round!(a, b, c, d, e, f, g, h, x, y, $o0),
            $round!(h, a, b, c, d, e, f, g, y, x, $o1),
            $round!(g, h, a, b, c, d, e, f, x, y, $o2),
            $round!(f, g, h, a, b, c, d, e, y, x, $o3),
            $round!(e, f, g, h, a, b, c, d, x, y, $o4),
            $round!(d, e, f, g, h, a, b, c, y, x, $o5),
            $round!(c, d, e, f, g, h, a, b, x, y, $o6),
            $round!(b, c, d, e, f, g, h, a, y, x, $o7),
        )
    };
}

// The rounds of block A or B of a pair: four words of a group, then four of the next.
macro_rules! eight256 {
    () => {
        eight!(round256, "0", "4", "8", "12", "32", "36", "40", "44")
    };
}

// SHA-512's: two words of each of four groups.
macro_rules! eight512 {
    () => {
        eight!(round512, "0", "8", "32", "40", "64", "72", "96", "104")
    };
}

// Eight rounds of block A from groups i and i + 1, between two steps of the schedule; bc holds
// b ^ c.
#[target_feature(enable = "bmi1,bmi2")]
#[inline]
#[allow(unsafe_code)]
fn rounds256(state: &mut [u32; 8], bc: &mut u32, wk: &Schedule256, i: usize) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    assert!(i < 15, "groups {i} and {} of 16", i + 1);

    let words = wk.as_ptr().cast::<[u32; 8]>().wrapping_add(i).cast::<u32>();

    // SAFETY: the instructions are on registers, apart from the reads of words 0 to 3 and 8 to 11
    // from `words`, block A's words of groups i and i + 1, which the schedule has written; BMI1
    // and BMI2, which ANDN and RORX need, are this function's target features. The flags are
    // written, and no stack is used.
    unsafe {
        core::arch::asm!(
            eight256!(),
            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            e = inout(reg) e,
            f = inout(reg) f,
            g = inout(reg) g,
            h = inout(reg) h,
            x = inout(reg) *bc,
            y = out(reg) _,
            s = out(reg) _,
            wk = in(reg) words,
            options(pure, readonly, nostack),
        );
    }

    *state = [a, b, c, d, e, f, g, h];
}

// Eight rounds of block A from groups i to i + 3.
#[target_feature(enable = "bmi1,bmi2")]
#[inline]
#[allow(unsafe_code)]
fn rounds512(state: &mut [u64; 8], bc: &mut u64, wk: &Schedule512, i: usize) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    assert!(i < 37, "groups {i} to {} of 40", i + 3);

    let words = wk.as_ptr().cast::<[u64; 4]>().wrapping_add(i).cast::<u64>();

    // SAFETY: the instructions are on registers, apart from the reads of words 0, 1, 4, 5, 8, 9,
    // 12 and 13 from `words`, block A's words of groups i to i + 3, which the schedule has
    // written; BMI1 and BMI2, which ANDN and RORX need, are this function's target features. The
    // flags are written, and no stack is used.
    unsafe {
        core::arch::asm!(
            eight512!(),
            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            e = inout(reg) e,
            f = inout(reg) f,
            g = inout(reg) g,
            h = inout(reg) h,
            x = inout(reg) *bc,
            y = out(reg) _,
            s = out(reg) _,
            wk = in(reg) words,
            options(pure, readonly, nostack),
        );
    }

    *state = [a, b, c, d, e, f, g, h];
}

// sigma0 of four words in each half: rotations by 7 and 18 and a shift by 3, as five shifts.
#[target_feature(enable = "avx2")]
#[inline]
fn sigma0_256(x: __m256i) -> __m256i {
    let right3 = _mm256_srli_epi32::<3>(x);

    let right7 = _mm256_srli_epi32::<7>(x);

    let left14 = _mm256_slli_epi32::<14>(x);

    let sum = _mm256_xor_si256(right3, right7);

    let sum = _mm256_xor_si256(sum, left14);

    let sum = _mm256_xor_si256(sum, _mm256_srli_epi32::<11>(right7));

    _mm256_xor_si256(sum, _mm256_slli_epi32::<11>(left14))
}

// sigma1 of words 2 and 3 of each half (FROM_HIGH) or of words 0 and 1, each word copied into
// both halves of a 64-bit lane, where a 64-bit shift right by 17 or 19 leaves the rotation in the
// low half; the results are in words 0 and 2, with garbage in words 1 and 3.
#[target_feature(enable = "avx2")]
#[inline]
fn sigma1_pairs<const FROM_HIGH: bool>(x: __m256i) -> __m256i {
    let doubled = if FROM_HIGH {
        _mm256_shuffle_epi32::<0xFA>(x)
    } else {
        _mm256_shuffle_epi32::<0x50>(x)
    };

    let right17 = _mm256_srli_epi64::<17>(doubled);

    let sum = _mm256_xor_si256(_mm256_srli_epi32::<10>(doubled), right17);

    _mm256_xor_si256(sum, _mm256_srli_epi64::<2>(right17))
}

// Words t to t + 3 of both blocks from the sixteen before them, x[0] holding words t - 16 to
// t - 13; x moves on by four words and the words are returned plus the constants k.
#[target_feature(enable = "avx2")]
#[inline]
fn step256(x: &mut [__m256i; 4], k: __m256i) -> __m256i {
    // Words 0 and 2 of a sigma1 result to words 0 and 1 of the half, or to words 2 and 3; the
    // others become zero.
    let low = _mm256_setr_epi8(
        0, 1, 2, 3, 8, 9, 10, 11, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 8, 9, 10, 11, -1, -1,
        -1, -1, -1, -1, -1, -1,
    );

    let high = _mm256_setr_epi8(
        -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 8, 9, 10, 11, -1, -1, -1, -1, -1, -1, -1, -1,
        0, 1, 2, 3, 8, 9, 10, 11,
    );

    let w15 = _mm256_alignr_epi8::<4>(x[1], x[0]);

    let w7 = _mm256_alignr_epi8::<4>(x[3], x[2]);

    let mut w = _mm256_add_epi32(_mm256_add_epi32(x[0], w7), sigma0_256(w15));

    w = _mm256_add_epi32(w, _mm256_shuffle_epi8(sigma1_pairs::<true>(x[3]), low));

    w = _mm256_add_epi32(w, _mm256_shuffle_epi8(sigma1_pairs::<false>(w), high));

    *x = [x[1], x[2], x[3], w];

    _mm256_add_epi32(w, k)
}

// Rotations right of each 64-bit lane.
#[target_feature(enable = "avx2")]
#[inline]
fn ror64<const RIGHT: i32, const LEFT: i32>(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_srli_epi64::<RIGHT>(x), _mm256_slli_epi64::<LEFT>(x))
}

// Words t and t + 1 of both blocks, x[0] holding words t - 16 and t - 15.
#[target_feature(enable = "avx2")]
#[inline]
fn step512(x: &mut [__m256i; 8], k: __m256i) -> __m256i {
    // A rotation right by eight bytes of each 64-bit lane.
    let by8 = _mm256_setr_epi8(
        1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8, 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11,
        12, 13, 14, 15, 8,
    );

    let w15 = _mm256_alignr_epi8::<8>(x[1], x[0]);

    let w7 = _mm256_alignr_epi8::<8>(x[5], x[4]);

    let sigma0 = _mm256_xor_si256(
        _mm256_xor_si256(ror64::<1, 63>(w15), _mm256_shuffle_epi8(w15, by8)),
        _mm256_srli_epi64::<7>(w15),
    );

    let sigma1 = _mm256_xor_si256(
        _mm256_xor_si256(ror64::<19, 45>(x[7]), ror64::<61, 3>(x[7])),
        _mm256_srli_epi64::<6>(x[7]),
    );

    let w = _mm256_add_epi64(_mm256_add_epi64(x[0], w7), _mm256_add_epi64(sigma0, sigma1));

    *x = [x[1], x[2], x[3], x[4], x[5], x[6], x[7], w];

    _mm256_add_epi64(w, k)
}

// Sixteen bytes of each block, in the two halves of a vector.
#[target_feature(enable = "avx2")]
#[inline]
fn halves(a: &[u8; 16], b: &[u8; 16]) -> __m256i {
    _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(load128(a)), load128(b))
}

#[target_feature(enable = "avx2")]
#[inline]
fn load_k256(g: usize) -> __m256i {
    load256(&K256_PAIRS[g])
}

#[target_feature(enable = "avx2")]
#[inline]
fn load_k512(g: usize) -> __m256i {
    load256(&K512_PAIRS[g])
}

// The schedule of blocks a and b, and the rounds of block a into state; second256 then runs those
// of block b, into the same state for a stream or into another. Neither is inlined: one copy of
// each keeps the code of the rounds within the decoded-instruction cache, which a 4-wide x86
// front end needs to issue the rounds at full rate.
#[target_feature(enable = "avx2,bmi1,bmi2")]
#[inline(never)]
fn first256(state: &mut [u32; 8], a: &[u8; 64], b: &[u8; 64], wk: &mut Schedule256) {
    let swap = _mm256_setr_epi8(
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8,
        15, 14, 13, 12,
    );

    let (a, b) = (a.as_chunks::<16>().0, b.as_chunks::<16>().0);

    let mut x: [__m256i; 4] =
        core::array::from_fn(|j| _mm256_shuffle_epi8(halves(&a[j], &b[j]), swap));

    for (j, x) in x.iter().enumerate() {
        store256_at(_mm256_add_epi32(*x, load_k256(j)), wk, j);
    }

    let mut s = *state;

    let mut bc = s[1] ^ s[2];

    for g in (0..16).step_by(2) {
        if g < 12 {
            let words = step256(&mut x, load_k256(4 + g));

            store256_at(words, wk, 4 + g);

            let words = step256(&mut x, load_k256(5 + g));

            store256_at(words, wk, 5 + g);
        }

        rounds256(&mut s, &mut bc, wk, g);
    }

    for (word, value) in state.iter_mut().zip(s) {
        *word = word.wrapping_add(value);
    }
}

// The 64 rounds of block b from the stored schedule, as a loop over eight rounds at a time.
#[target_feature(enable = "bmi1,bmi2")]
#[inline(never)]
#[allow(unsafe_code)]
fn second256(state: &mut [u32; 8], wk: &Schedule256) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    // Block b's words: the high half of each group.
    let words = wk.as_ptr().cast::<u32>().wrapping_add(4);

    // SAFETY: the instructions are on registers, apart from the reads of words 16i to 16i + 3 and
    // 16i + 8 to 16i + 11 from `words` for i = 0 to 7, block B's words of every group, the last
    // of them word 127 of the buffer, all of which first256 has written; BMI1 and BMI2, which
    // ANDN and RORX need, are this function's target features. The flags are written, and no
    // stack is used.
    unsafe {
        core::arch::asm!(
            "2:",
            eight256!(),
            "add {wk}, 64",
            "dec {n}",
            "jnz 2b",
            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            e = inout(reg) e,
            f = inout(reg) f,
            g = inout(reg) g,
            h = inout(reg) h,
            x = inout(reg) b ^ c => _,
            y = out(reg) _,
            s = out(reg) _,
            wk = inout(reg) words => _,
            n = inout(reg) 8usize => _,
            options(pure, readonly, nostack),
        );
    }

    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
#[inline(never)]
fn first512(state: &mut [u64; 8], a: &[u8; 128], b: &[u8; 128], wk: &mut Schedule512) {
    let swap = _mm256_setr_epi8(
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13,
        12, 11, 10, 9, 8,
    );

    let (a, b) = (a.as_chunks::<16>().0, b.as_chunks::<16>().0);

    let mut x: [__m256i; 8] =
        core::array::from_fn(|j| _mm256_shuffle_epi8(halves(&a[j], &b[j]), swap));

    for (j, x) in x.iter().enumerate() {
        store256_at(_mm256_add_epi64(*x, load_k512(j)), wk, j);
    }

    let mut s = *state;

    let mut bc = s[1] ^ s[2];

    for g in (0..40).step_by(4) {
        if g < 32 {
            for i in 0..4 {
                let words = step512(&mut x, load_k512(8 + g + i));

                store256_at(words, wk, 8 + g + i);
            }
        }

        rounds512(&mut s, &mut bc, wk, g);
    }

    for (word, value) in state.iter_mut().zip(s) {
        *word = word.wrapping_add(value);
    }
}

// The 80 rounds of block b, as second256's.
#[target_feature(enable = "bmi1,bmi2")]
#[inline(never)]
#[allow(unsafe_code)]
fn second512(state: &mut [u64; 8], wk: &Schedule512) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    let words = wk.as_ptr().cast::<u64>().wrapping_add(2);

    // SAFETY: the instructions are on registers, apart from the reads of words 16i, 16i + 1,
    // 16i + 4, 16i + 5, 16i + 8, 16i + 9, 16i + 12 and 16i + 13 from `words` for i = 0 to 9, block
    // B's words of every group, the last of them word 159 of the buffer, all of which first512 has
    // written; BMI1 and BMI2, which ANDN and RORX need, are this function's target features. The
    // flags are written, and no stack is used.
    unsafe {
        core::arch::asm!(
            "2:",
            eight512!(),
            "add {wk}, 128",
            "dec {n}",
            "jnz 2b",
            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            e = inout(reg) e,
            f = inout(reg) f,
            g = inout(reg) g,
            h = inout(reg) h,
            x = inout(reg) b ^ c => _,
            y = out(reg) _,
            s = out(reg) _,
            wk = inout(reg) words => _,
            n = inout(reg) 10usize => _,
            options(pure, readonly, nostack),
        );
    }

    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}

// The blocks and then the more blocks, as one stream, two at a time, through the schedule buffer.
#[target_feature(enable = "avx2,bmi1,bmi2")]
#[inline]
fn stream256(state: &mut [u32; 8], blocks: &[[u8; 64]], more: &[[u8; 64]], wk: &mut Schedule256) {
    let mut stream = blocks.iter().chain(more);

    while let Some(a) = stream.next() {
        match stream.next() {
            Some(b) => {
                first256(state, a, b, wk);

                second256(state, wk);
            }
            None => first256(state, a, a, wk),
        }
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
#[inline]
fn stream512(state: &mut [u64; 8], blocks: &[[u8; 128]], more: &[[u8; 128]], wk: &mut Schedule512) {
    let mut stream = blocks.iter().chain(more);

    while let Some(a) = stream.next() {
        match stream.next() {
            Some(b) => {
                first512(state, a, b, wk);

                second512(state, wk);
            }
            None => first512(state, a, a, wk),
        }
    }
}

// The schedule buffer, which holds words of the message, is wiped at the end.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]], more: &[[u8; 64]]) {
    let mut wk = Schedule256::uninit();

    stream256(state, blocks, more, &mut wk);

    wipe(wk.write([[0; 8]; 16]).as_flattened_mut());
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn compress512(state: &mut [u64; 8], blocks: &[[u8; 128]], more: &[[u8; 128]]) {
    let mut wk = Schedule512::uninit();

    stream512(state, blocks, more, &mut wk);

    wipe(wk.write([[0; 4]; 40]).as_flattened_mut());
}

// One block into each of two states: HMAC's key blocks.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn compress256_pair(states: &mut [[u32; 8]; 2], blocks: &[[u8; 64]; 2]) {
    let mut wk = Schedule256::uninit();

    let [first, second] = states;

    first256(first, &blocks[0], &blocks[1], &mut wk);

    second256(second, &wk);

    wipe(wk.write([[0; 8]; 16]).as_flattened_mut());
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn compress512_pair(states: &mut [[u64; 8]; 2], blocks: &[[u8; 128]; 2]) {
    let mut wk = Schedule512::uninit();

    let [first, second] = states;

    first512(first, &blocks[0], &blocks[1], &mut wk);

    second512(second, &wk);

    wipe(wk.write([[0; 4]; 40]).as_flattened_mut());
}

// The whole blocks of data and then its padding, as one stream, for a message of `bits` bits that
// ends with data.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn finish256(state: &mut [u32; 8], data: &[u8], bits: u64) {
    let mut last = [[0; 64]; 2];

    let used = pad(data, u128::from(bits), 8, &mut last);

    compress256(state, data.as_chunks::<64>().0, &last[..used]);

    wipe(last.as_flattened_mut());
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn finish512(state: &mut [u64; 8], data: &[u8], bits: u128) {
    let mut last = [[0; 128]; 2];

    let used = pad(data, bits, 16, &mut last);

    compress512(state, data.as_chunks::<128>().0, &last[..used]);

    wipe(last.as_flattened_mut());
}

// HMAC from the states after the key blocks: the inner hash of data, then the outer hash of the
// inner digest's leading tag.len() bytes, with one schedule buffer and one padding buffer for both
// and the states kept here, where the generic code's two one-shot hashes each copied, padded,
// stored and wiped their own.
#[target_feature(enable = "avx2,bmi1,bmi2")]
fn mac256(keyed: &[[u32; 8]; 2], data: &[u8], tag: &mut [u8], wk: &mut Schedule256) {
    let [mut inner, mut outer] = *keyed;

    let mut last = [[0; 64]; 2];

    let bits = (64 + data.len() as u128) * 8;

    let used = pad(data, bits, 8, &mut last);

    stream256(&mut inner, data.as_chunks::<64>().0, &last[..used], wk);

    let mut digest = [0; 32];

    store_words(&inner, &mut digest);

    last = [[0; 64]; 2];

    let used = pad(
        &digest[..tag.len()],
        (64 + tag.len() as u128) * 8,
        8,
        &mut last,
    );

    stream256(&mut outer, &[], &last[..used], wk);

    store_words(&outer, tag);

    wipe(last.as_flattened_mut());

    wipe(&mut digest);

    wipe(&mut inner);

    wipe(&mut outer);
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
fn mac512(keyed: &[[u64; 8]; 2], data: &[u8], tag: &mut [u8], wk: &mut Schedule512) {
    let [mut inner, mut outer] = *keyed;

    let mut last = [[0; 128]; 2];

    let bits = (128 + data.len() as u128) * 8;

    let used = pad(data, bits, 16, &mut last);

    stream512(&mut inner, data.as_chunks::<128>().0, &last[..used], wk);

    let mut digest = [0; 64];

    store_words(&inner, &mut digest);

    last = [[0; 128]; 2];

    let used = pad(
        &digest[..tag.len()],
        (128 + tag.len() as u128) * 8,
        16,
        &mut last,
    );

    stream512(&mut outer, &[], &last[..used], wk);

    store_words(&outer, tag);

    wipe(last.as_flattened_mut());

    wipe(&mut digest);

    wipe(&mut inner);

    wipe(&mut outer);
}

// The words of a state as big-endian bytes, as many as out holds.
#[inline]
fn store_words<T: Copy + Into<u64>, const N: usize>(state: &[T; N], out: &mut [u8]) {
    let size = size_of::<T>();

    for (chunk, &word) in out.chunks_mut(size).zip(state) {
        let bytes = word.into().to_be_bytes();

        chunk.copy_from_slice(&bytes[8 - size..8 - size + chunk.len()]);
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn hmac256_keyed(keyed: &[[u32; 8]; 2], data: &[u8], tag: &mut [u8]) {
    let mut wk = Schedule256::uninit();

    mac256(keyed, data, tag, &mut wk);

    wipe(wk.write([[0; 8]; 16]).as_flattened_mut());
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn hmac512_keyed(keyed: &[[u64; 8]; 2], data: &[u8], tag: &mut [u8]) {
    let mut wk = Schedule512::uninit();

    mac512(keyed, data, tag, &mut wk);

    wipe(wk.write([[0; 4]; 40]).as_flattened_mut());
}

// HMAC (RFC 2104) under a key of at most a block: the key's two blocks as one pair, then mac256.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn hmac256(iv: &[u32; 8], key: &[u8], data: &[u8], tag: &mut [u8]) {
    let mut pads = [[0x36; 64], [0x5C; 64]];

    for pad in &mut pads {
        for (byte, key) in pad.iter_mut().zip(key) {
            *byte ^= key;
        }
    }

    let mut keyed = [*iv; 2];

    let mut wk = Schedule256::uninit();

    let [inner, outer] = &mut keyed;

    first256(inner, &pads[0], &pads[1], &mut wk);

    second256(outer, &wk);

    mac256(&keyed, data, tag, &mut wk);

    wipe(pads.as_flattened_mut());

    wipe(keyed.as_flattened_mut());

    wipe(wk.write([[0; 8]; 16]).as_flattened_mut());
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) fn hmac512(iv: &[u64; 8], key: &[u8], data: &[u8], tag: &mut [u8]) {
    let mut pads = [[0x36; 128], [0x5C; 128]];

    for pad in &mut pads {
        for (byte, key) in pad.iter_mut().zip(key) {
            *byte ^= key;
        }
    }

    let mut keyed = [*iv; 2];

    let mut wk = Schedule512::uninit();

    let [inner, outer] = &mut keyed;

    first512(inner, &pads[0], &pads[1], &mut wk);

    second512(outer, &wk);

    mac512(&keyed, data, tag, &mut wk);

    wipe(pads.as_flattened_mut());

    wipe(keyed.as_flattened_mut());

    wipe(wk.write([[0; 4]; 40]).as_flattened_mut());
}
