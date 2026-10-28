// BLAKE2b with AVX2 (or SSE4.1) and BLAKE2s with AVX2 (or SSE4.1), one message at a time: a row
// of the state per vector (four 64-bit or four 32-bit words; two vectors for BLAKE2b on SSE4.1),
// so the four G functions of a step run in the lanes. x86-64 has sixteen general registers, too
// few for the sixteen state words and the message, so the scalar code spills; the vectors hold the
// state in four registers, or eight.
//
// With AVX2 the message words of each half step are gathered with one shuffle or blend per pair of
// words from the block's 128-bit pieces (BLAKE2b) or broadcast from the block and blended
// (BLAKE2s), and between the column and the diagonal steps the rows a, c and d rotate instead of
// b, c and d: lane i then computes the diagonal G of group i - 1, whose message words are gathered
// in that order. Row b is the last one each half step writes and the first one the next reads, so
// a rotation of b sits on the chain from one step to the next; a is written first, and its
// rotation overlaps the rest of the step. The SSE4.1 kernels gather the words one at a time. The
// one-shot digests, and BLAKE2s's MAC, keep the state in registers from the first block to the
// output. (Message words moved by scalar stores into a ring that the rounds read with vector loads
// measured 35 to 60% slower than these gathers: the loads waited on the stores.)

use core::arch::x86_64::*;

#[cfg(not(crypto_pq_optimized))]
use super::memory::words_of;
use super::memory::{clear, load128, load256, store128, store256};
use crate::blake2::SIGMA;
use crate::sha2::{IV_256, IV_512};
use crate::wipe::{wipe, wipe_unless_optimized};

instruction!(swap32, __m256i, ymm_reg, "vpshufd {out}, {x}, 0xB1", x);

instruction!(
    shuffle,
    __m256i,
    ymm_reg,
    "vpshufb {out}, {x}, {control}",
    x,
    control
);

instruction!(lane_down, __m256i, ymm_reg, "vpermq {out}, {x}, 0x93", x);

instruction!(lane_up, __m256i, ymm_reg, "vpermq {out}, {x}, 0x39", x);

instruction!(lanes_across, __m256i, ymm_reg, "vpermq {out}, {x}, 0x4E", x);

instruction!(
    even_pair,
    __m256i,
    ymm_reg,
    "vpunpcklqdq {out}, {x}, {y}",
    x,
    y
);

instruction!(
    odd_pair,
    __m256i,
    ymm_reg,
    "vpunpckhqdq {out}, {x}, {y}",
    x,
    y
);

instruction!(
    odd_even_pair,
    __m256i,
    ymm_reg,
    "vpalignr {out}, {y}, {x}, 8",
    x,
    y
);

instruction!(
    even_odd_pair,
    __m256i,
    ymm_reg,
    "vpblendd {out}, {x}, {y}, 0xCC",
    x,
    y
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
    shuffle128,
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

// Right rotations of each 64-bit lane: by 32 a swap of its halves, by 24 and 16 a byte shuffle,
// by 63 a doubling (the left shift by one) ORed with the top bit.
#[target_feature(enable = "avx2")]
#[inline]
fn rotate64<const R: u32>(x: __m256i) -> __m256i {
    match R {
        32 => swap32(x),
        24 => shuffle(
            x,
            _mm256_setr_epi8(
                3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11,
                12, 13, 14, 15, 8, 9, 10,
            ),
        ),
        16 => shuffle(
            x,
            _mm256_setr_epi8(
                2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10,
                11, 12, 13, 14, 15, 8, 9,
            ),
        ),
        63 => _mm256_or_si256(_mm256_add_epi64(x, x), _mm256_srli_epi64::<63>(x)),
        _ => unreachable!("the rotations of BLAKE2b"),
    }
}

// The sixteen words of a block as eight pairs, each pair in both halves of a vector, which a
// broadcast load gives.
#[target_feature(enable = "avx2")]
#[inline]
fn pairs64(words: &[[u64; 2]; 8]) -> [__m256i; 8] {
    core::array::from_fn(|k| _mm256_broadcastsi128_si256(load128(&words[k])))
}

#[target_feature(enable = "avx2")]
#[inline]
fn block64(block: &[u8; 128]) -> [__m256i; 8] {
    core::array::from_fn(|k| _mm256_broadcastsi128_si256(load128(&block.as_chunks::<16>().0[k])))
}

// Words w0 and w1 of the message in each half of a vector, from the pairs that hold them: one
// instruction, whatever the words. The word indices are constants once a round is inlined.
#[target_feature(enable = "avx2")]
#[inline]
fn pair64(m: &[__m256i; 8], w0: usize, w1: usize) -> __m256i {
    let (x, y) = (m[w0 / 2], m[w1 / 2]);

    match (w0 % 2, w1 % 2) {
        (0, 1) if w0 / 2 == w1 / 2 => x,
        (0, 0) => even_pair(x, y),
        (1, 1) => odd_pair(x, y),
        (1, _) => odd_even_pair(x, y),
        _ => even_odd_pair(x, y),
    }
}

// The message words of four G functions, in lane order.
#[target_feature(enable = "avx2")]
#[inline]
fn gather64(m: &[__m256i; 8], w: [usize; 4]) -> __m256i {
    halves(pair64(m, w[0], w[1]), pair64(m, w[2], w[3]))
}

// Half of the four G functions of a step: a += m, a += b, d = ror(d ^ a), c += d, b = ror(b ^ c).
#[target_feature(enable = "avx2")]
#[inline]
fn half64<const R1: u32, const R2: u32>(row: &mut [__m256i; 4], m: __m256i) {
    let [a, b, c, d] = row;

    *a = _mm256_add_epi64(_mm256_add_epi64(*a, m), *b);

    *d = rotate64::<R1>(_mm256_xor_si256(*d, *a));

    *c = _mm256_add_epi64(*c, *d);

    *b = rotate64::<R2>(_mm256_xor_si256(*b, *c));
}

// Round R, with the row of SIGMA a constant: an instance per round, each called once and inlined,
// so that every index into the message is a constant. For the diagonal step, a moves down a lane
// and c and d up one and two.
#[target_feature(enable = "avx2")]
#[inline]
fn round64<const R: usize>(row: &mut [__m256i; 4], m: &[__m256i; 8]) {
    let s = &SIGMA[R % 10];

    half64::<32, 24>(row, gather64(m, [s[0], s[2], s[4], s[6]]));

    half64::<16, 63>(row, gather64(m, [s[1], s[3], s[5], s[7]]));

    row[0] = lane_down(row[0]);

    row[2] = lane_up(row[2]);

    row[3] = lanes_across(row[3]);

    half64::<32, 24>(row, gather64(m, [s[14], s[8], s[10], s[12]]));

    half64::<16, 63>(row, gather64(m, [s[15], s[9], s[11], s[13]]));

    row[0] = lane_up(row[0]);

    row[2] = lane_down(row[2]);

    row[3] = lanes_across(row[3]);
}

#[target_feature(enable = "avx2")]
#[inline]
fn set64(words: &[u64]) -> __m256i {
    _mm256_set_epi64x(
        words[3] as i64,
        words[2] as i64,
        words[1] as i64,
        words[0] as i64,
    )
}

#[target_feature(enable = "avx2")]
#[inline]
fn compress64(h: &mut [__m256i; 2], m: &[__m256i; 8], counter: u128, last: bool) {
    let flag = if last { -1 } else { 0 };

    let mut row = [
        h[0],
        h[1],
        set64(&IV_512[..4]),
        _mm256_xor_si256(
            set64(&IV_512[4..]),
            _mm256_set_epi64x(0, flag, (counter >> 64) as i64, counter as i64),
        ),
    ];

    round64::<0>(&mut row, m);

    round64::<1>(&mut row, m);

    round64::<2>(&mut row, m);

    round64::<3>(&mut row, m);

    round64::<4>(&mut row, m);

    round64::<5>(&mut row, m);

    round64::<6>(&mut row, m);

    round64::<7>(&mut row, m);

    round64::<8>(&mut row, m);

    round64::<9>(&mut row, m);

    round64::<10>(&mut row, m);

    round64::<11>(&mut row, m);

    h[0] = _mm256_xor_si256(h[0], _mm256_xor_si256(row[0], row[2]));

    h[1] = _mm256_xor_si256(h[1], _mm256_xor_si256(row[1], row[3]));

    wipe_unless_optimized!(words_of(&mut row));
}

#[target_feature(enable = "avx2")]
pub(super) fn blake2b_avx2(
    h: &mut [u64; 8],
    first: Option<&[u64; 16]>,
    blocks: &[[u8; 128]],
    counter: u128,
    last: Option<(&[u64; 16], u128)>,
) {
    let [low, high] = h.as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    // compress64 stays out of line, so the state and the message words, the MAC's key block
    // among them, go to it through memory, where they are cleared at the end.
    let mut state = [load256(low), load256(high)];

    let mut m = [_mm256_setzero_si256(); 8];

    let mut counter = counter;

    if let Some(first) = first {
        counter = counter.wrapping_add(128);

        m = pairs64(first.as_chunks().0.try_into().expect("eight"));

        compress64(&mut state, &m, counter, false);
    }

    for block in blocks {
        counter = counter.wrapping_add(128);

        m = block64(block);

        compress64(&mut state, &m, counter, false);
    }

    if let Some((last, total)) = last {
        m = pairs64(last.as_chunks().0.try_into().expect("eight"));

        compress64(&mut state, &m, total, true);
    }

    let [low, high] = h.as_chunks_mut::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    store256(state[0], low);

    store256(state[1], high);

    clear(&mut state, _mm256_setzero_si256());

    clear(&mut m, _mm256_setzero_si256());
}

// The digest of data from the chaining value h, out.len() bytes: the whole blocks straight from
// data, then the last block, which holds at least one byte unless data is empty, from a zeroed
// copy. The copy and the digest's bytes are wiped.
#[target_feature(enable = "avx2")]
pub(super) fn blake2b_digest_avx2(h: &[u64; 8], data: &[u8], out: &mut [u8]) {
    let [low, high] = h.as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    let mut state = [load256(low), load256(high)];

    let (blocks, tail) = data.split_at(data.len().saturating_sub(1) / 128 * 128);

    let mut counter = 0;

    // compress64 stays out of line, so the message words go to it through memory, where they are
    // cleared at the end.
    let mut m: [__m256i; 8];

    for block in blocks.as_chunks::<128>().0 {
        counter += 128;

        m = block64(block);

        compress64(&mut state, &m, counter, false);
    }

    let mut last = [0; 128];

    last[..tail.len()].copy_from_slice(tail);

    m = block64(&last);

    compress64(&mut state, &m, data.len() as u128, true);

    let mut bytes = [0; 64];

    let [low, high] = bytes.as_chunks_mut::<32>().0 else {
        unreachable!("64 bytes are two groups of 32")
    };

    store256(state[0], low);

    store256(state[1], high);

    out.copy_from_slice(&bytes[..out.len()]);

    wipe(&mut last);

    wipe(&mut bytes);

    // compress64 takes the state through memory.
    clear(&mut state, _mm256_setzero_si256());

    clear(&mut m, _mm256_setzero_si256());
}

// BLAKE2b with SSE4.1, for x86-64 CPUs without AVX2: each row in two vectors of two words, the
// rotations of the AVX2 code on half the lanes, and the rows' rotation by whole words between the
// steps with PALIGNR.
#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn rotate64_sse<const R: u32>(x: __m128i) -> __m128i {
    match R {
        32 => _mm_shuffle_epi32::<0xB1>(x),
        24 => _mm_shuffle_epi8(
            x,
            _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10),
        ),
        16 => _mm_shuffle_epi8(
            x,
            _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9),
        ),
        63 => _mm_or_si128(_mm_add_epi64(x, x), _mm_srli_epi64::<63>(x)),
        _ => unreachable!("the rotations of BLAKE2b"),
    }
}

// Row r in row[r]: words 0 and 1, then words 2 and 3.
type Rows = [[__m128i; 2]; 4];

#[target_feature(enable = "sse2")]
#[inline]
fn pair(low: u64, high: u64) -> __m128i {
    _mm_set_epi64x(high as i64, low as i64)
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn half64_sse<const R1: u32, const R2: u32>(
    row: &mut Rows,
    m: &[u64; 16],
    s: &[usize; 16],
    first: usize,
) {
    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut m = [
        pair(m[s[first]], m[s[first + 2]]),
        pair(m[s[first + 4]], m[s[first + 6]]),
    ];

    for (i, m) in m.into_iter().enumerate() {
        row[0][i] = _mm_add_epi64(_mm_add_epi64(row[0][i], m), row[1][i]);

        row[3][i] = rotate64_sse::<R1>(_mm_xor_si128(row[3][i], row[0][i]));

        row[2][i] = _mm_add_epi64(row[2][i], row[3][i]);

        row[1][i] = rotate64_sse::<R2>(_mm_xor_si128(row[1][i], row[2][i]));
    }

    wipe_unless_optimized!(words_of(&mut m));
}

// Rows b, c and d rotated left by one, two and three words: (v5, v6, v7, v4) from b, and so on.
#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn diagonalize(row: &mut Rows) {
    let ([b0, b1], [c0, c1], [d0, d1]) = (row[1], row[2], row[3]);

    row[1] = [_mm_alignr_epi8::<8>(b1, b0), _mm_alignr_epi8::<8>(b0, b1)];

    row[2] = [c1, c0];

    row[3] = [_mm_alignr_epi8::<8>(d0, d1), _mm_alignr_epi8::<8>(d1, d0)];
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn undiagonalize(row: &mut Rows) {
    let ([b0, b1], [c0, c1], [d0, d1]) = (row[1], row[2], row[3]);

    row[1] = [_mm_alignr_epi8::<8>(b0, b1), _mm_alignr_epi8::<8>(b1, b0)];

    row[2] = [c1, c0];

    row[3] = [_mm_alignr_epi8::<8>(d1, d0), _mm_alignr_epi8::<8>(d0, d1)];
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn round64_sse<const R: usize>(row: &mut Rows, m: &[u64; 16]) {
    let s = &SIGMA[R % 10];

    half64_sse::<32, 24>(row, m, s, 0);

    half64_sse::<16, 63>(row, m, s, 1);

    diagonalize(row);

    half64_sse::<32, 24>(row, m, s, 8);

    half64_sse::<16, 63>(row, m, s, 9);

    undiagonalize(row);
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn compress64_sse(h: &mut [__m128i; 4], m: &[u64; 16], counter: u128, last: bool) {
    let iv = IV_512;

    let flag = if last { u64::MAX } else { 0 };

    let mut row = [
        [h[0], h[1]],
        [h[2], h[3]],
        [pair(iv[0], iv[1]), pair(iv[2], iv[3])],
        [
            pair(iv[4] ^ counter as u64, iv[5] ^ (counter >> 64) as u64),
            pair(iv[6] ^ flag, iv[7]),
        ],
    ];

    round64_sse::<0>(&mut row, m);

    round64_sse::<1>(&mut row, m);

    round64_sse::<2>(&mut row, m);

    round64_sse::<3>(&mut row, m);

    round64_sse::<4>(&mut row, m);

    round64_sse::<5>(&mut row, m);

    round64_sse::<6>(&mut row, m);

    round64_sse::<7>(&mut row, m);

    round64_sse::<8>(&mut row, m);

    round64_sse::<9>(&mut row, m);

    round64_sse::<10>(&mut row, m);

    round64_sse::<11>(&mut row, m);

    for (i, h) in h.iter_mut().enumerate() {
        *h = _mm_xor_si128(*h, _mm_xor_si128(row[i / 2][i % 2], row[2 + i / 2][i % 2]));
    }

    wipe_unless_optimized!(words_of(&mut row));
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
pub(super) fn blake2b_sse41(
    h: &mut [u64; 8],
    first: Option<&[u64; 16]>,
    blocks: &[[u8; 128]],
    counter: u128,
    last: Option<(&[u64; 16], u128)>,
) {
    let mut state = [
        pair(h[0], h[1]),
        pair(h[2], h[3]),
        pair(h[4], h[5]),
        pair(h[6], h[7]),
    ];

    let mut counter = counter;

    if let Some(first) = first {
        counter = counter.wrapping_add(128);

        compress64_sse(&mut state, first, counter, false);
    }

    // The message words, which compress64_sse takes through memory too; cleared after the last
    // block. A message of one block has none here.
    if !blocks.is_empty() {
        let mut m = [0u64; 16];

        for block in blocks {
            for (word, bytes) in m.iter_mut().zip(block.as_chunks::<8>().0) {
                *word = u64::from_le_bytes(*bytes);
            }

            counter = counter.wrapping_add(128);

            compress64_sse(&mut state, &m, counter, false);
        }

        wipe(&mut m);
    }

    if let Some((m, total)) = last {
        compress64_sse(&mut state, m, total, true);
    }

    for (words, vector) in h.as_chunks_mut::<2>().0.iter_mut().zip(state) {
        *words = [
            _mm_extract_epi64::<0>(vector) as u64,
            _mm_extract_epi64::<1>(vector) as u64,
        ];
    }

    // compress64_sse takes the state through memory.
    clear(&mut state, _mm_setzero_si128());
}

// Right rotations of each 32-bit lane: by 16 and 8 a byte shuffle, by 12 and 7 two shifts and an
// OR.
#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn rotate32<const R: u32>(x: __m128i) -> __m128i {
    match R {
        16 => _mm_shuffle_epi8(
            x,
            _mm_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13),
        ),
        8 => _mm_shuffle_epi8(
            x,
            _mm_setr_epi8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12),
        ),
        12 => _mm_or_si128(_mm_srli_epi32::<12>(x), _mm_slli_epi32::<20>(x)),
        7 => _mm_or_si128(_mm_srli_epi32::<7>(x), _mm_slli_epi32::<25>(x)),
        _ => unreachable!("the rotations of BLAKE2s"),
    }
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn gather32(m: &[u32; 16], s: &[usize; 16], first: usize) -> __m128i {
    _mm_set_epi32(
        m[s[first + 6]] as i32,
        m[s[first + 4]] as i32,
        m[s[first + 2]] as i32,
        m[s[first]] as i32,
    )
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn half32<const R1: u32, const R2: u32>(row: &mut [__m128i; 4], m: __m128i) {
    let [a, b, c, d] = row;

    *a = _mm_add_epi32(_mm_add_epi32(*a, m), *b);

    *d = rotate32::<R1>(_mm_xor_si128(*d, *a));

    *c = _mm_add_epi32(*c, *d);

    *b = rotate32::<R2>(_mm_xor_si128(*b, *c));
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn round32<const R: usize>(row: &mut [__m128i; 4], m: &[u32; 16]) {
    let s = &SIGMA[R];

    half32::<16, 12>(row, gather32(m, s, 0));

    half32::<8, 7>(row, gather32(m, s, 1));

    row[1] = _mm_shuffle_epi32::<0x39>(row[1]);

    row[2] = _mm_shuffle_epi32::<0x4E>(row[2]);

    row[3] = _mm_shuffle_epi32::<0x93>(row[3]);

    half32::<16, 12>(row, gather32(m, s, 8));

    half32::<8, 7>(row, gather32(m, s, 9));

    row[1] = _mm_shuffle_epi32::<0x93>(row[1]);

    row[2] = _mm_shuffle_epi32::<0x4E>(row[2]);

    row[3] = _mm_shuffle_epi32::<0x39>(row[3]);
}

#[target_feature(enable = "sse2")]
#[inline]
fn set32(words: &[u32]) -> __m128i {
    _mm_set_epi32(
        words[3] as i32,
        words[2] as i32,
        words[1] as i32,
        words[0] as i32,
    )
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
#[inline]
fn compress32(h: &mut [__m128i; 2], m: &[u32; 16], counter: u64, last: bool) {
    let flag = if last { -1 } else { 0 };

    let mut row = [
        h[0],
        h[1],
        set32(&IV_256[..4]),
        _mm_xor_si128(
            set32(&IV_256[4..]),
            _mm_set_epi32(0, flag, (counter >> 32) as i32, counter as i32),
        ),
    ];

    round32::<0>(&mut row, m);

    round32::<1>(&mut row, m);

    round32::<2>(&mut row, m);

    round32::<3>(&mut row, m);

    round32::<4>(&mut row, m);

    round32::<5>(&mut row, m);

    round32::<6>(&mut row, m);

    round32::<7>(&mut row, m);

    round32::<8>(&mut row, m);

    round32::<9>(&mut row, m);

    h[0] = _mm_xor_si128(h[0], _mm_xor_si128(row[0], row[2]));

    h[1] = _mm_xor_si128(h[1], _mm_xor_si128(row[1], row[3]));

    wipe_unless_optimized!(words_of(&mut row));
}

#[target_feature(enable = "sse2,ssse3,sse4.1")]
pub(super) fn blake2s_sse41(
    h: &mut [u32; 8],
    first: Option<&[u32; 16]>,
    blocks: &[[u8; 64]],
    counter: u64,
    last: Option<(&[u32; 16], u128)>,
) {
    let mut state = [set32(&h[..4]), set32(&h[4..])];

    let mut counter = counter;

    if let Some(first) = first {
        counter = counter.wrapping_add(64);

        compress32(&mut state, first, counter, false);
    }

    // The message words, which compress32 takes through memory too; cleared after the last block.
    // A message of one block has none here.
    if !blocks.is_empty() {
        let mut m = [0u32; 16];

        for block in blocks {
            for (word, bytes) in m.iter_mut().zip(block.as_chunks::<4>().0) {
                *word = u32::from_le_bytes(*bytes);
            }

            counter = counter.wrapping_add(64);

            compress32(&mut state, &m, counter, false);
        }

        wipe(&mut m);
    }

    if let Some((m, total)) = last {
        compress32(&mut state, m, total as u64, true);
    }

    for (words, vector) in h.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *words = [
            _mm_extract_epi32::<0>(vector) as u32,
            _mm_extract_epi32::<1>(vector) as u32,
            _mm_extract_epi32::<2>(vector) as u32,
            _mm_extract_epi32::<3>(vector) as u32,
        ];
    }

    // compress32 takes the state through memory.
    clear(&mut state, _mm_setzero_si128());
}

// BLAKE2s with AVX2's three-operand forms. The message words of each half step are broadcast
// from the block and blended into their lanes, which leaves the shuffle port, the only one of
// Intel's cores before Ice Lake, to the rotations of d and of the rows: permutations of the
// block's halves there measured 11% slower per block on Haswell, and taking b's rotations by 12
// and 7 apart into ror(b) ^ ror(c), which shortens the chain but puts two more shifts on the one
// shift port, 7% slower.
//
// The words of the four gathers of each round, in lane order: the two steps' first and second
// words, with the diagonal step's lanes in the order of the rotated rows, where lane j computes
// G(j - 1).
const fn gathers() -> [[[usize; 4]; 4]; 10] {
    let mut table = [[[0; 4]; 4]; 10];

    let mut r = 0;

    while r < 10 {
        let mut i = 0;

        while i < 4 {
            table[r][0][i] = SIGMA[r][2 * i];

            table[r][1][i] = SIGMA[r][2 * i + 1];

            table[r][2][i] = SIGMA[r][8 + 2 * ((i + 3) % 4)];

            table[r][3][i] = SIGMA[r][9 + 2 * ((i + 3) % 4)];

            i += 1;
        }

        r += 1;
    }

    table
}

const GATHERS: [[[usize; 4]; 4]; 10] = gathers();

#[target_feature(enable = "avx2")]
#[inline]
fn gather32_avx2<const R: usize, const K: usize>(block: &[u8; 64]) -> __m128i {
    let words = block.as_chunks::<4>().0;

    let [w0, w1, w2, w3] = GATHERS[R][K].map(|w| _mm_set1_epi32(i32::from_le_bytes(words[w])));

    blend32::<0b1100>(blend32::<0b0010>(w0, w1), blend32::<0b1000>(w2, w3))
}

// One blend in assembly, as LLVM turned the broadcasts and blends into unpacks and inserts on the
// shuffle port.
#[target_feature(enable = "avx2")]
#[inline]
#[allow(unsafe_code)]
fn blend32<const MASK: u8>(x: __m128i, y: __m128i) -> __m128i {
    let out: __m128i;

    // SAFETY: one AVX2 instruction on registers, which this function's target feature provides;
    // it reads and writes no memory, stack or flags.
    unsafe {
        core::arch::asm!(
            "vpblendd {out}, {x}, {y}, {mask}",
            out = lateout(xmm_reg) out,
            x = in(xmm_reg) x,
            y = in(xmm_reg) y,
            mask = const MASK,
            options(pure, nomem, nostack, preserves_flags),
        );
    }

    out
}

// Right rotations of each 32-bit lane with AVX2: by 16 and 8 a byte shuffle, by 12 and 7 two
// shifts and an OR.
#[target_feature(enable = "avx2")]
#[inline]
fn rotate32_avx2<const R: u32>(x: __m128i) -> __m128i {
    match R {
        16 => shuffle128(
            x,
            _mm_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13),
        ),
        8 => shuffle128(
            x,
            _mm_setr_epi8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12),
        ),
        12 => _mm_or_si128(_mm_srli_epi32::<12>(x), _mm_slli_epi32::<20>(x)),
        7 => _mm_or_si128(_mm_srli_epi32::<7>(x), _mm_slli_epi32::<25>(x)),
        _ => unreachable!("the rotations of BLAKE2s"),
    }
}

#[target_feature(enable = "avx2")]
#[inline]
fn half32_avx2<const R1: u32, const R2: u32>(row: &mut [__m128i; 4], m: __m128i) {
    let [a, b, c, d] = row;

    *a = _mm_add_epi32(_mm_add_epi32(*a, m), *b);

    *d = rotate32_avx2::<R1>(_mm_xor_si128(*d, *a));

    *c = _mm_add_epi32(*c, *d);

    *b = rotate32_avx2::<R2>(_mm_xor_si128(*b, *c));
}

// Round R. For the diagonal step, a moves down a lane and c and d up one and two.
#[target_feature(enable = "avx2")]
#[inline]
fn round32_avx2<const R: usize>(row: &mut [__m128i; 4], block: &[u8; 64]) {
    half32_avx2::<16, 12>(row, gather32_avx2::<R, 0>(block));

    half32_avx2::<8, 7>(row, gather32_avx2::<R, 1>(block));

    row[0] = word_down(row[0]);

    row[2] = word_up(row[2]);

    row[3] = words_across(row[3]);

    half32_avx2::<16, 12>(row, gather32_avx2::<R, 2>(block));

    half32_avx2::<8, 7>(row, gather32_avx2::<R, 3>(block));

    row[0] = word_up(row[0]);

    row[2] = word_down(row[2]);

    row[3] = words_across(row[3]);
}

#[target_feature(enable = "avx2")]
#[inline]
fn compress32_avx2(h: &mut [__m128i; 2], block: &[u8; 64], counter: u64, last: bool) {
    let flag = if last { -1 } else { 0 };

    let [low, high] = IV_256.as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    let mut row = [
        h[0],
        h[1],
        load128(low),
        _mm_xor_si128(
            load128(high),
            _mm_set_epi32(0, flag, (counter >> 32) as i32, counter as i32),
        ),
    ];

    round32_avx2::<0>(&mut row, block);

    round32_avx2::<1>(&mut row, block);

    round32_avx2::<2>(&mut row, block);

    round32_avx2::<3>(&mut row, block);

    round32_avx2::<4>(&mut row, block);

    round32_avx2::<5>(&mut row, block);

    round32_avx2::<6>(&mut row, block);

    round32_avx2::<7>(&mut row, block);

    round32_avx2::<8>(&mut row, block);

    round32_avx2::<9>(&mut row, block);

    h[0] = _mm_xor_si128(h[0], _mm_xor_si128(row[0], row[2]));

    h[1] = _mm_xor_si128(h[1], _mm_xor_si128(row[1], row[3]));

    wipe_unless_optimized!(words_of(&mut row));
}

// The first out.len() bytes of the chaining value in state, a whole digest straight from the
// registers.
#[target_feature(enable = "avx2")]
#[inline]
fn output32(state: &[__m128i; 2], out: &mut [u8]) {
    let mut bytes = [0; 32];

    let target = match <&mut [u8; 32]>::try_from(&mut *out) {
        Ok(whole) => whole,
        Err(_) => &mut bytes,
    };

    let [low, high] = target.as_chunks_mut::<16>().0 else {
        unreachable!("32 bytes are two groups of 16")
    };

    store128(state[0], low);

    store128(state[1], high);

    if out.len() < 32 {
        out.copy_from_slice(&bytes[..out.len()]);

        wipe(&mut bytes);
    }
}

// BLAKE2s from h, in order: first (a MAC's key block), the whole blocks, and last with its
// counter, the only block with the final flag; counter counts the bytes before the first of them.
// The result goes into out, h left as it is, or into h without out. This is the compression's one
// call site, so it is inlined and the state stays in registers from the first block to the
// output: called for each block, it went through memory each time.
#[target_feature(enable = "avx2")]
pub(super) fn blake2s_avx2(
    h: &mut [u32; 8],
    first: Option<&[u8; 64]>,
    blocks: &[[u8; 64]],
    last: Option<(&[u8; 64], u64)>,
    counter: u64,
    out: Option<&mut [u8]>,
) {
    let [low, high] = h.as_chunks::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    let mut state = [load128(low), load128(high)];

    let mut counter = counter;

    let total = last.map_or(0, |(_, total)| total);

    let parts = [
        first.map_or(&[][..], core::slice::from_ref),
        blocks,
        last.map_or(&[][..], |(block, _)| core::slice::from_ref(block)),
    ];

    for (part, blocks) in parts.into_iter().enumerate() {
        for block in blocks {
            let last = part == 2;

            counter = if last {
                total
            } else {
                counter.wrapping_add(64)
            };

            compress32_avx2(&mut state, block, counter, last);
        }
    }

    if let Some(out) = out {
        output32(&state, out);

        wipe_unless_optimized!(words_of(&mut state));

        return;
    }

    let [low, high] = h.as_chunks_mut::<4>().0 else {
        unreachable!("eight words are two groups of four")
    };

    store128(state[0], low);

    store128(state[1], high);

    wipe_unless_optimized!(words_of(&mut state));
}

// The bytes of sixteen words, for the blocks that come as words.
pub(super) fn bytes32(words: &[u32; 16]) -> [u8; 64] {
    let mut bytes = [0; 64];

    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }

    bytes
}

// The whole blocks of data before its final block, and the bytes of the final block: the last 1
// to 64, or none for empty data.
pub(super) fn split32(data: &[u8]) -> (&[[u8; 64]], &[u8]) {
    let (blocks, tail) = data.split_at(data.len().saturating_sub(1) / 64 * 64);

    (blocks.as_chunks::<64>().0, tail)
}

// f with the final block of the bytes of tail: straight from tail when they are a whole block,
// else zero-padded in a copy, which is then wiped.
pub(super) fn final32(tail: &[u8], f: impl FnOnce(&[u8; 64])) {
    match <&[u8; 64]>::try_from(tail) {
        Ok(block) => f(block),
        Err(_) => {
            let mut copy = [0; 64];

            copy[..tail.len()].copy_from_slice(tail);

            f(&copy);

            wipe(&mut copy);
        }
    }
}
