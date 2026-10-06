// BLAKE2b with AVX2 (or SSE4.1) and BLAKE2s with SSE4.1, one message at a time: a row of the state
// per vector (four 64-bit or four 32-bit words; two vectors for BLAKE2b on SSE4.1), so the four G
// functions of a step run in the lanes, and the rows b, c and d rotate by one, two and three words
// between the column and the diagonal steps. The message words of each half step are gathered into
// a vector in the order of SIGMA. x86-64 has sixteen general registers, too few for the sixteen
// state words and the message, so the scalar code spills; the vectors hold the state in four
// registers, or eight.

use core::arch::x86_64::*;

use crate::blake2::SIGMA;
use crate::sha2::{IV_256, IV_512};

// Right rotations of each 64-bit lane: by 32 a swap of its halves, by 24 and 16 a byte shuffle,
// by 63 a doubling (the left shift by one) ORed with the top bit.
#[target_feature(enable = "avx2")]
#[inline]
fn rotate64<const R: u32>(x: __m256i) -> __m256i {
    match R {
        32 => _mm256_shuffle_epi32::<0xB1>(x),
        24 => _mm256_shuffle_epi8(
            x,
            _mm256_setr_epi8(
                3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11,
                12, 13, 14, 15, 8, 9, 10,
            ),
        ),
        16 => _mm256_shuffle_epi8(
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

// The message words of four G functions, in lane order.
#[target_feature(enable = "avx2")]
#[inline]
fn gather64(m: &[u64; 16], s: &[usize; 16], first: usize) -> __m256i {
    _mm256_set_epi64x(
        m[s[first + 6]] as i64,
        m[s[first + 4]] as i64,
        m[s[first + 2]] as i64,
        m[s[first]] as i64,
    )
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
// so that every index into the message is a constant.
#[target_feature(enable = "avx2")]
#[inline]
fn round64<const R: usize>(row: &mut [__m256i; 4], m: &[u64; 16]) {
    let s = &SIGMA[R % 10];

    half64::<32, 24>(row, gather64(m, s, 0));

    half64::<16, 63>(row, gather64(m, s, 1));

    row[1] = _mm256_permute4x64_epi64::<0x39>(row[1]);

    row[2] = _mm256_permute4x64_epi64::<0x4E>(row[2]);

    row[3] = _mm256_permute4x64_epi64::<0x93>(row[3]);

    half64::<32, 24>(row, gather64(m, s, 8));

    half64::<16, 63>(row, gather64(m, s, 9));

    row[1] = _mm256_permute4x64_epi64::<0x93>(row[1]);

    row[2] = _mm256_permute4x64_epi64::<0x4E>(row[2]);

    row[3] = _mm256_permute4x64_epi64::<0x39>(row[3]);
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
fn compress64(h: &mut [__m256i; 2], m: &[u64; 16], counter: u128, last: bool) {
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
}

#[target_feature(enable = "avx2")]
pub(super) fn blake2b_avx2(
    h: &mut [u64; 8],
    first: Option<&[u64; 16]>,
    blocks: &[[u8; 128]],
    counter: u128,
    last: Option<(&[u64; 16], u128)>,
) {
    let mut state = [set64(&h[..4]), set64(&h[4..])];

    let mut counter = counter;

    if let Some(first) = first {
        counter = counter.wrapping_add(128);

        compress64(&mut state, first, counter, false);
    }

    for block in blocks {
        let words = block.as_chunks::<8>().0;

        let m: [u64; 16] = core::array::from_fn(|i| u64::from_le_bytes(words[i]));

        counter = counter.wrapping_add(128);

        compress64(&mut state, &m, counter, false);
    }

    if let Some((m, total)) = last {
        compress64(&mut state, m, total, true);
    }

    for (words, vector) in h.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *words = [
            _mm256_extract_epi64::<0>(vector) as u64,
            _mm256_extract_epi64::<1>(vector) as u64,
            _mm256_extract_epi64::<2>(vector) as u64,
            _mm256_extract_epi64::<3>(vector) as u64,
        ];
    }
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
    let m = [
        pair(m[s[first]], m[s[first + 2]]),
        pair(m[s[first + 4]], m[s[first + 6]]),
    ];

    for (i, m) in m.into_iter().enumerate() {
        row[0][i] = _mm_add_epi64(_mm_add_epi64(row[0][i], m), row[1][i]);

        row[3][i] = rotate64_sse::<R1>(_mm_xor_si128(row[3][i], row[0][i]));

        row[2][i] = _mm_add_epi64(row[2][i], row[3][i]);

        row[1][i] = rotate64_sse::<R2>(_mm_xor_si128(row[1][i], row[2][i]));
    }
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

    for block in blocks {
        let words = block.as_chunks::<8>().0;

        let m: [u64; 16] = core::array::from_fn(|i| u64::from_le_bytes(words[i]));

        counter = counter.wrapping_add(128);

        compress64_sse(&mut state, &m, counter, false);
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

    for block in blocks {
        let words = block.as_chunks::<4>().0;

        let m: [u32; 16] = core::array::from_fn(|i| u32::from_le_bytes(words[i]));

        counter = counter.wrapping_add(64);

        compress32(&mut state, &m, counter, false);
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
}
